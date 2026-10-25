//! PFS0 (NSP) and HFS0 (XCI) partition parsing.

use std::fs::File;
use std::path::Path;

use crate::error::{fmt_err, Error, Result};
use crate::storage::Storage;
use crate::util::{cstr, read_at, read_vec_at, u32le, u64le};

/// Sanity limits so a corrupt header can't make us allocate gigabytes.
const MAX_ENTRIES: usize = 0x10000;
const MAX_STRING_TABLE: usize = 16 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerKind {
    Nsp,
    Xci,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    /// Absolute offset in the container file.
    pub offset: u64,
    pub size: u64,
}

/// Parses a PFS0 header held in memory. Returned offsets are relative to `data`.
pub fn parse_pfs0_bytes(data: &[u8]) -> Result<Vec<Entry>> {
    if data.len() < 0x10 || &data[..4] != b"PFS0" {
        return fmt_err("not a PFS0 partition");
    }
    let n = u32le(data, 4) as usize;
    let strtab = u32le(data, 8) as usize;
    if n > MAX_ENTRIES || strtab > MAX_STRING_TABLE {
        return fmt_err("PFS0 header is implausibly large");
    }
    let str_off = 0x10 + n * 0x18;
    let data_off = (str_off + strtab) as u64;
    if data.len() < str_off + strtab {
        return fmt_err("truncated PFS0 header");
    }
    let strings = &data[str_off..str_off + strtab];
    (0..n)
        .map(|i| {
            let e = 0x10 + i * 0x18;
            let name_off = u32le(data, e + 0x10) as usize;
            if name_off >= strings.len() {
                return fmt_err("bad PFS0 name offset");
            }
            let Some(offset) = data_off.checked_add(u64le(data, e)) else {
                return fmt_err("bad PFS0 entry offset");
            };
            Ok(Entry { name: cstr(strings, name_off), offset, size: u64le(data, e + 8) })
        })
        .collect()
}

/// Lists the files of a PFS0 image held in `s` (offset 0 = "PFS0" magic). Entry offsets are
/// relative to the start of `s`, and every entry is checked to lie within it.
pub fn parse_pfs0_storage(s: &mut dyn Storage) -> Result<Vec<Entry>> {
    let mut head = [0u8; 0x10];
    s.read(0, &mut head)?;
    if &head[..4] != b"PFS0" {
        return fmt_err("not a PFS0 partition");
    }
    let (n, strtab) = (u32le(&head, 4) as usize, u32le(&head, 8) as usize);
    if n > MAX_ENTRIES || strtab > MAX_STRING_TABLE {
        return fmt_err("PFS0 header is implausibly large");
    }
    // Both counts are bounded by the limits above, so this can't overflow.
    let len = 0x10 + n * 0x18 + strtab;
    if len as u64 > s.size() {
        return fmt_err("truncated PFS0 header");
    }
    let mut full = vec![0u8; len];
    s.read(0, &mut full)?;
    let entries = parse_pfs0_bytes(&full)?;
    let size = s.size();
    for e in &entries {
        if e.offset.checked_add(e.size).is_none_or(|end| end > size) {
            return fmt_err(format!("PFS0 file {} extends past the end of the image", e.name));
        }
    }
    Ok(entries)
}

fn parse_pfs0(f: &mut File, base: u64) -> Result<Vec<Entry>> {
    let head = read_vec_at(f, base, 0x10)?;
    if &head[..4] != b"PFS0" {
        return fmt_err("not a PFS0 partition");
    }
    let (n, strtab) = (u32le(&head, 4) as usize, u32le(&head, 8) as usize);
    if n > MAX_ENTRIES || strtab > MAX_STRING_TABLE {
        return fmt_err("PFS0 header is implausibly large");
    }
    let len = 0x10 + n * 0x18 + strtab;
    let full = read_vec_at(f, base, len)?;
    let mut entries = parse_pfs0_bytes(&full)?;
    for e in &mut entries {
        e.offset += base;
    }
    Ok(entries)
}

fn parse_hfs0(f: &mut File, base: u64) -> Result<Vec<Entry>> {
    let head = read_vec_at(f, base, 0x10)?;
    if &head[..4] != b"HFS0" {
        return fmt_err("not an HFS0 partition");
    }
    let n = u32le(&head, 4) as usize;
    let strtab = u32le(&head, 8) as usize;
    if n > MAX_ENTRIES || strtab > MAX_STRING_TABLE {
        return fmt_err("HFS0 header is implausibly large");
    }
    let str_off = 0x10 + n * 0x40;
    let full = read_vec_at(f, base, str_off + strtab)?;
    let strings = &full[str_off..];
    let data_off = base + (str_off + strtab) as u64;
    (0..n)
        .map(|i| {
            let e = 0x10 + i * 0x40;
            Ok(Entry {
                name: cstr(strings, u32le(&full, e + 0x10) as usize),
                offset: data_off + u64le(&full, e),
                size: u64le(&full, e + 8),
            })
        })
        .collect()
}

/// Opens an NSP/NSZ (PFS0) or XCI/XCZ and lists the files that hold title content
/// (the whole PFS0 for NSP, the secure partition for XCI).
pub fn open(path: &Path) -> Result<(File, ContainerKind, Vec<Entry>)> {
    let mut f = File::open(path).map_err(|e| Error::File { path: path.to_path_buf(), source: e })?;
    let mut magic = [0u8; 4];
    read_at(&mut f, 0, &mut magic)?;
    if &magic == b"PFS0" {
        let entries = parse_pfs0(&mut f, 0)?;
        return Ok((f, ContainerKind::Nsp, entries));
    }

    // XCI: "HEAD" at 0x100, or 0x1100 for dumps that include the key area.
    for base in [0u64, 0x1000] {
        let mut hdr = [0u8; 0x200];
        if read_at(&mut f, base, &mut hdr).is_err() || &hdr[0x100..0x104] != b"HEAD" {
            continue;
        }
        let root_off = base + u64le(&hdr, 0x130);
        let root = parse_hfs0(&mut f, root_off)?;
        let Some(secure) = root.iter().find(|e| e.name == "secure") else {
            return fmt_err("XCI has no secure partition");
        };
        let entries = parse_hfs0(&mut f, secure.offset)?;
        return Ok((f, ContainerKind::Xci, entries));
    }
    fmt_err("not an NSP/NSZ/XCI/XCZ file")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::build_pfs0;

    #[test]
    fn storage_round_trip() {
        let mut img = build_pfs0(&[("a.nca", b"hello world"), ("b.tik", b"0123456789abcdef")]);
        let entries = parse_pfs0_storage(&mut img).unwrap();
        assert_eq!(entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["a.nca", "b.tik"]);
        let mut got = Vec::new();
        for e in &entries {
            let mut buf = vec![0u8; e.size as usize];
            img.read(e.offset, &mut buf).unwrap();
            got.push(buf);
        }
        assert_eq!(got, [b"hello world".to_vec(), b"0123456789abcdef".to_vec()]);
    }

    #[test]
    fn storage_entry_past_end_is_an_error() {
        let mut img = build_pfs0(&[("a.nca", b"hello world"), ("b.tik", b"0123456789abcdef")]);
        img.pop();
        assert!(parse_pfs0_storage(&mut img).is_err());
    }

    #[test]
    fn storage_entry_offset_overflow_is_an_error() {
        let mut img = build_pfs0(&[("a.nca", b"hello")]);
        img[0x10..0x18].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse_pfs0_storage(&mut img).is_err());
        img[0x10..0x18].copy_from_slice(&0u64.to_le_bytes());
        img[0x18..0x20].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse_pfs0_storage(&mut img).is_err());
    }

    #[test]
    fn storage_wrong_magic_is_an_error() {
        let mut img = build_pfs0(&[("a.nca", b"hello")]);
        img[0] = b'X';
        assert!(parse_pfs0_storage(&mut img).is_err());
    }

    #[test]
    fn storage_truncated_header_is_an_error() {
        let img = build_pfs0(&[("a.nca", b"hello"), ("b.tik", b"world")]);
        let header_len = 0x10 + 2 * 0x18 + 0x20;
        for len in 0..header_len {
            let mut short = img[..len].to_vec();
            assert!(parse_pfs0_storage(&mut short).is_err(), "prefix of {len} bytes");
        }
    }

    #[test]
    fn storage_huge_counts_are_an_error() {
        let mut img = build_pfs0(&[("a.nca", b"hello")]);
        img[4..8].copy_from_slice(&(MAX_ENTRIES as u32 + 1).to_le_bytes());
        assert!(parse_pfs0_storage(&mut img).is_err());
        img[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_pfs0_storage(&mut img).is_err());
        img[4..8].copy_from_slice(&1u32.to_le_bytes());
        img[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_pfs0_storage(&mut img).is_err());
    }
}
