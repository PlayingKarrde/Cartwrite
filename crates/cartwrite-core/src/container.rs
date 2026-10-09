//! PFS0 (NSP) and HFS0 (XCI) partition parsing.

use std::fs::File;
use std::path::Path;

use crate::error::{fmt_err, Error, Result};
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
            Ok(Entry { name: cstr(strings, name_off), offset: data_off + u64le(data, e), size: u64le(data, e + 8) })
        })
        .collect()
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
