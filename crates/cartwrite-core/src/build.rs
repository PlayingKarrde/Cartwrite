//! Multi-content XCI builder (port of NSC_Builder's `-dmul -t xci`).
//!
//! Output layout:
//! ```text
//! 0x0000  XCI header (random signature, no Nintendo cert)
//! 0x0190  encrypted gamecard info
//! 0x7000  certificate area (0xFF)
//! 0xF000  root HFS0 -> update (empty), normal (empty), secure (all NCAs)
//! ```
//! Every NCA is written with its title rights removed (title key moved into the key area)
//! so no tickets are needed, and cnmt RequiredSystemVersion can optionally be lowered.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use sha2::{Digest, Sha256};

use crate::cnmt::RSV_OFFSET;
use crate::container::parse_pfs0_bytes;
use crate::error::{fmt_err, Error, Result};
use crate::keys::Keys;
use crate::nca::{self, NcaHeader, HEADER_SIZE};
use crate::ncz::{NczInfo, UNCOMPRESSED_HEADER};
use crate::scan::{NcaRef, Title};
use crate::util::{read_at, read_vec_at, slice};

/// FAT32 split size used by NSC_Builder (0xFFFF8000).
pub const FAT32_CHUNK: u64 = 0xFFFF_8000;
const COPY_BUF: usize = 8 << 20;

#[derive(Clone, Debug)]
pub struct BuildOptions {
    /// Lower RequiredSystemVersion to the first firmware with the content's master key.
    pub patch_rsv: bool,
    /// Keep delta fragments from updates (useless for XCI installs; off by default).
    pub include_deltas: bool,
    /// Split output into 4 GiB parts (.xc0, .xc1, ...) for FAT32 SD cards.
    pub split_fat32: bool,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self { patch_rsv: true, include_deltas: false, split_fat32: false }
    }
}

#[derive(Clone, Debug)]
pub enum Progress {
    Log(String),
    /// Bytes written so far / total.
    Bytes {
        done: u64,
        total: u64,
    },
}

/// One NCA as it will be written.
struct Item<'a> {
    nca: &'a NcaRef,
    name: String,
    size: u64,
    /// sha256 of the first 0x200 bytes as written (HFS0 hashed region).
    hash: [u8; 32],
    payload: Payload,
}

enum Payload {
    /// Fully prepared in memory (patched meta NCAs).
    Memory(Vec<u8>),
    /// New encrypted header followed by the body copied/decompressed from the source.
    Stream { header: Vec<u8> },
}

/// Builds `output` (a `.xci` path) from the given titles. Returns the files written.
pub fn build_xci(
    keys: &Keys,
    titles: &[&Title],
    output: &Path,
    opts: &BuildOptions,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(Progress),
) -> Result<Vec<PathBuf>> {
    if titles.is_empty() {
        return fmt_err("nothing selected to build");
    }
    let mut files: HashMap<PathBuf, File> = HashMap::new();
    let mut open = |p: &PathBuf| -> Result<File> {
        if let Some(f) = files.get(p) {
            return Ok(f.try_clone()?);
        }
        let f = File::open(p).map_err(|e| Error::File { path: p.clone(), source: e })?;
        files.insert(p.clone(), f.try_clone()?);
        Ok(f)
    };

    // 1. Prepare every NCA header.
    let mut items: Vec<Item> = Vec::new();
    let mut seen = HashSet::new();
    for title in titles {
        let rsv_target = match (opts.patch_rsv, title.required_system_version) {
            (true, Some(rsv)) => crate::rsv::patched_rsv(rsv, title.key_generation()),
            _ => None,
        };
        for n in title.ncas(opts.include_deltas) {
            if !seen.insert(n.out_name.clone()) {
                continue;
            }
            check_cancel(cancel)?;
            let mut f = open(&n.source)?;
            let enc = read_vec_at(&mut f, n.offset, HEADER_SIZE)?;
            let mut header = NcaHeader::decrypt(&enc, keys)?;
            if let Some(tk) = title.title_key(keys, &header)? {
                header.remove_title_rights(keys, &tk)?;
            }
            let is_meta = n.content_type == crate::cnmt::CT_META;
            let payload = match rsv_target.filter(|_| is_meta) {
                Some(new_rsv) => {
                    progress(Progress::Log(format!(
                        "{:016X}: RequiredSystemVersion {} -> {}",
                        title.title_id,
                        crate::rsv::format_rsv(title.required_system_version.unwrap_or(0)),
                        crate::rsv::format_rsv(new_rsv)
                    )));
                    Payload::Memory(patch_meta_rsv(keys, &mut f, n, header, new_rsv)?)
                }
                None => Payload::Stream { header: header.encrypt(keys) },
            };
            let first = match &payload {
                Payload::Memory(v) => &v[..0x200],
                Payload::Stream { header } => &header[..0x200],
            };
            items.push(Item {
                nca: n,
                name: n.out_name.clone(),
                size: n.nca_size,
                hash: Sha256::digest(first).into(),
                payload,
            });
        }
    }

    // 2. Headers.
    let sec = hfs0_header(&items.iter().map(|i| (i.name.as_str(), i.size, i.hash, 0x200)).collect::<Vec<_>>());
    let upd = hfs0_header(&[]);
    let norm = hfs0_header(&[]);
    let sec_files: u64 = items.iter().map(|i| i.size).sum();
    let part_sizes = [upd.len() as u64, norm.len() as u64, sec.len() as u64 + sec_files];
    let root = hfs0_header(&[
        ("update", part_sizes[0], Sha256::digest(&upd).into(), upd.len() as u32),
        ("normal", part_sizes[1], Sha256::digest(&norm).into(), norm.len() as u32),
        ("secure", part_sizes[2], Sha256::digest(&sec).into(), sec.len() as u32),
    ]);
    let root_offset = 0xF000u64;
    let secure_start = root_offset + root.len() as u64 + part_sizes[0] + part_sizes[1];
    let total = root_offset + root.len() as u64 + part_sizes.iter().sum::<u64>();
    let xci_head = xci_header(keys, &root, secure_start, total);

    // 3. Write.
    progress(Progress::Log(format!("Writing {} ({} NCAs)", output.display(), items.len())));
    let split = (opts.split_fat32 && total > FAT32_CHUNK).then_some(FAT32_CHUNK);
    let mut out = SplitWriter::create(output, split)?;
    let result = (|| -> Result<()> {
        let mut done = 0u64;
        let mut emit = |out: &mut SplitWriter, data: &[u8], done: &mut u64| -> Result<()> {
            out.write_all(data)?;
            *done += data.len() as u64;
            progress(Progress::Bytes { done: *done, total });
            Ok(())
        };
        emit(&mut out, &xci_head, &mut done)?;
        emit(&mut out, &vec![0u8; 0x7000 - 0x200], &mut done)?;
        emit(&mut out, &vec![0xFFu8; 0x8000], &mut done)?;
        emit(&mut out, &root, &mut done)?;
        emit(&mut out, &upd, &mut done)?;
        emit(&mut out, &norm, &mut done)?;
        emit(&mut out, &sec, &mut done)?;

        let mut buf = vec![0u8; COPY_BUF];
        for item in &items {
            check_cancel(cancel)?;
            let n = item.nca;
            match &item.payload {
                Payload::Memory(data) => emit(&mut out, data, &mut done)?,
                Payload::Stream { header } => {
                    let mut f = open(&n.source)?;
                    emit(&mut out, header, &mut done)?;
                    if n.is_ncz {
                        // The rest of the uncompressed 0x4000-byte head (less for tiny NCAs).
                        let head_end = UNCOMPRESSED_HEADER.min(n.nca_size);
                        let raw = read_vec_at(
                            &mut f,
                            n.offset + HEADER_SIZE as u64,
                            (head_end - HEADER_SIZE as u64) as usize,
                        )?;
                        emit(&mut out, &raw, &mut done)?;
                        let info = NczInfo::parse(&mut f, n.offset, n.stored_size)?;
                        let mut pos = UNCOMPRESSED_HEADER;
                        info.decompress(&f, n.nca_size, &mut |chunk| {
                            check_cancel(cancel)?;
                            let take = chunk.len().min(n.nca_size.saturating_sub(pos) as usize);
                            let mut c = chunk[..take].to_vec();
                            info.reencrypt(pos, &mut c);
                            pos += take as u64;
                            emit(&mut out, &c, &mut done)
                        })?;
                    } else {
                        let mut off = HEADER_SIZE as u64;
                        while off < n.stored_size {
                            check_cancel(cancel)?;
                            let len = ((n.stored_size - off) as usize).min(buf.len());
                            read_at(&mut f, n.offset + off, &mut buf[..len])?;
                            emit(&mut out, &buf[..len], &mut done)?;
                            off += len as u64;
                        }
                    }
                }
            }
        }
        if done != total {
            return fmt_err(format!("internal size mismatch: wrote {done} of {total} bytes"));
        }
        Ok(())
    })();

    // Close sources first so the output may replace one of them (Windows locks open files).
    drop(open);
    drop(files);
    match result {
        Ok(()) => out.finish(),
        Err(e) => {
            out.abort();
            Err(e)
        }
    }
}

fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

/// Reads a meta NCA fully, lowers the cnmt RequiredSystemVersion and fixes up the
/// hash table, master hash and FS header hash. Returns the re-encrypted NCA.
fn patch_meta_rsv(keys: &Keys, f: &mut File, n: &NcaRef, mut header: NcaHeader, new_rsv: u32) -> Result<Vec<u8>> {
    if n.is_ncz || n.nca_size > 64 << 20 {
        return fmt_err("unexpected compressed or oversized meta NCA");
    }
    let mut data = read_vec_at(f, n.offset, n.nca_size as usize)?;
    let key = header.section_key(keys, None)?;
    let s = header.section(0).ok_or_else(|| Error::Format("meta NCA has no section 0".into()))?;
    let layout = nca::sha256_layout(&header, 0)?;
    let (start, end) = (s.start as usize, s.end as usize);
    if end > data.len() {
        return fmt_err("meta NCA section out of range");
    }
    let sec = &mut data[start..end];
    nca::decrypt_in_place(&header, &key, s.start, sec)?;

    let bad = || Error::Format("meta NCA hash layout out of range".into());
    let pfs0 = slice(sec, layout.data_offset, layout.data_size).ok_or_else(bad)?;
    let entries = parse_pfs0_bytes(pfs0)?;
    let cnmt = entries
        .iter()
        .find(|e| e.name.ends_with(".cnmt"))
        .ok_or_else(|| Error::Format("no .cnmt in meta NCA".into()))?;
    if cnmt.size < (RSV_OFFSET + 4) as u64 || cnmt.offset + cnmt.size > layout.data_size {
        return Err(bad());
    }
    let pos = (layout.data_offset + cnmt.offset) as usize + RSV_OFFSET;
    sec[pos..pos + 4].copy_from_slice(&new_rsv.to_le_bytes());

    // Level-1 hash table: sha256 of each block of the PFS0.
    let bs = layout.block_size as usize;
    if bs == 0 {
        return Err(bad());
    }
    let pfs0 = slice(sec, layout.data_offset, layout.data_size).ok_or_else(bad)?;
    let hashes: Vec<[u8; 32]> = pfs0.chunks(bs).map(|b| Sha256::digest(b).into()).collect();
    if (hashes.len() * 32) as u64 > layout.hash_table_size {
        return Err(bad());
    }
    let ht = layout.hash_table_offset as usize;
    slice(sec, layout.hash_table_offset, layout.hash_table_size).ok_or_else(bad)?;
    for (i, h) in hashes.iter().enumerate() {
        sec[ht + i * 32..ht + i * 32 + 32].copy_from_slice(h);
    }
    let master = Sha256::digest(slice(sec, layout.hash_table_offset, layout.hash_table_size).ok_or_else(bad)?);
    header.fs_header_mut(0)[0x8..0x28].copy_from_slice(&master);
    header.update_fs_header_hash(0);

    nca::decrypt_in_place(&header, &key, s.start, sec)?; // CTR: same op re-encrypts
    data[..HEADER_SIZE].copy_from_slice(&header.encrypt(keys));
    Ok(data)
}

/// Builds an HFS0 header for (name, size, hash, hashed_region_size) entries, padded to 0x200.
fn hfs0_header(entries: &[(&str, u64, [u8; 32], u32)]) -> Vec<u8> {
    let mut strings = Vec::new();
    let mut name_offsets = Vec::new();
    for (name, ..) in entries {
        name_offsets.push(strings.len() as u32);
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
    }
    let unpadded = 0x10 + entries.len() * 0x40 + strings.len();
    let padded = unpadded.div_ceil(0x200).max(1) * 0x200;
    strings.resize(strings.len() + (padded - unpadded), 0);

    let mut h = Vec::with_capacity(padded);
    h.extend_from_slice(b"HFS0");
    h.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    h.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    h.extend_from_slice(&[0; 4]);
    let mut offset = 0u64;
    for (i, (_, size, hash, region)) in entries.iter().enumerate() {
        h.extend_from_slice(&offset.to_le_bytes());
        h.extend_from_slice(&size.to_le_bytes());
        h.extend_from_slice(&name_offsets[i].to_le_bytes());
        h.extend_from_slice(&region.to_le_bytes());
        h.extend_from_slice(&[0; 8]);
        h.extend_from_slice(hash);
        offset += size;
    }
    h.extend_from_slice(&strings);
    h
}

/// Card size byte as NSC_Builder picks it.
fn card_size(total: u64) -> (u8, bool) {
    let gb = ((total as f64 / (1u64 << 30) as f64) * 100.0).round() / 100.0;
    let large = gb >= 4.0;
    let code = match gb {
        g if g >= 32.0 => 0xE3,
        g if g >= 16.0 => 0xE2,
        g if g >= 8.0 => 0xE1,
        g if g >= 4.0 => 0xE0,
        g if g >= 2.0 => 0xF0,
        g if g >= 1.0 => 0xF8,
        _ => 0xFA,
    };
    (code, large)
}

/// 0x200-byte XCI header including the encrypted gamecard info.
fn xci_header(keys: &Keys, root: &[u8], secure_start: u64, total: u64) -> Vec<u8> {
    let (card, large) = card_size(total);
    let mut h = vec![0u8; 0x200];
    rand::Rng::fill(&mut rand::thread_rng(), &mut h[..0x100]);
    h[0x100..0x104].copy_from_slice(b"HEAD");
    h[0x104..0x108].copy_from_slice(&((secure_start / 0x200) as u32).to_le_bytes());
    h[0x108..0x10C].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    h[0x10C] = 0;
    h[0x10D] = card;
    h[0x10E] = 0;
    h[0x10F] = 0;
    h[0x110..0x118].copy_from_slice(&0x8750F4C0A9C5A966u64.to_be_bytes());
    h[0x118..0x120].copy_from_slice(&((total - 1) / 0x200).to_le_bytes());
    let iv: [u8; 16] = if keys.xci_header_key.is_some() {
        rand::random()
    } else {
        0x5B408B145E277E81E5BF677C94888D7Bu128.to_be_bytes()
    };
    h[0x120..0x130].copy_from_slice(&iv);
    h[0x130..0x138].copy_from_slice(&0xF000u64.to_le_bytes());
    h[0x138..0x140].copy_from_slice(&(root.len() as u64).to_le_bytes());
    h[0x140..0x160].copy_from_slice(&Sha256::digest(root));
    h[0x160..0x180].copy_from_slice(&INITIAL_DATA_HASH);
    h[0x180..0x184].copy_from_slice(&1u32.to_le_bytes());
    h[0x184..0x188].copy_from_slice(&2u32.to_le_bytes());
    h[0x188..0x18C].copy_from_slice(&0u32.to_le_bytes());
    h[0x18C..0x190].copy_from_slice(&((secure_start / 0x200) as u32).to_le_bytes());
    h[0x190..0x200].copy_from_slice(&game_info(keys, &iv, large));
    h
}

const INITIAL_DATA_HASH: [u8; 32] = [
    0x1A, 0xB7, 0xC7, 0xB2, 0x63, 0xE7, 0x4E, 0x44, 0xCD, 0x3C, 0x68, 0xE4, 0x0F, 0x7E, 0xF4, 0xA4, 0xD6, 0x57, 0x15,
    0x51, 0xD0, 0x43, 0xFC, 0xA8, 0xEC, 0xF5, 0xC4, 0x89, 0xF2, 0xC6, 0x6E, 0x7E,
];

/// Encrypted gamecard info. Without `xci_header_key` we use NSC_Builder's pre-encrypted
/// blobs, which pair with the fixed IV above.
fn game_info(keys: &Keys, iv: &[u8; 16], large: bool) -> Vec<u8> {
    let Some(key) = keys.xci_header_key else {
        return parse_hex_const(if large { GAMEINFO_LARGE } else { GAMEINFO_SMALL });
    };
    let mut plain = Vec::with_capacity(0x70);
    plain.extend_from_slice(&parse_hex_const("0100000000000000"));
    plain.extend_from_slice(&parse_hex_const(if large { "1000a100" } else { "1100a100" }));
    plain.extend_from_slice(&parse_hex_const("88130000000000000000000000000000"));
    plain.extend_from_slice(&parse_hex_const("00110C005a00020000000000"));
    plain.extend_from_slice(&parse_hex_const("9bfb03ddbb7c5fca1608000000000001"));
    plain.resize(0x70, 0);
    // AES-128-CBC with the byte-reversed IV.
    let mut prev: [u8; 16] = *iv;
    prev.reverse();
    let c = aes::Aes128::new(GenericArray::from_slice(&key));
    for block in plain.as_chunks_mut::<16>().0 {
        for i in 0..16 {
            block[i] ^= prev[i];
        }
        c.encrypt_block(GenericArray::from_mut_slice(block));
        prev.copy_from_slice(block);
    }
    plain
}

const GAMEINFO_LARGE: &str =
    concat!(
    "9298F35088F09F7D", "a89a60d4", "cba6f96f", "a45bb6ac", "abc751f9", "5d398742", "6b38c3f2", "10da0b70",
    "0e5ece29", "a13cbe1da6d052cb", "f2087ce9af590538",
    "570d78b9cdd27fbeb4a0ac2adff9ba77754dd6675ac76223506b3bdabcb2e212fa465111ab7d51afc8b5b2b21c4b3f40654598620282add6"
);
const GAMEINFO_SMALL: &str =
    concat!(
    "9109FF82971EE993", "5011ca06", "3f3c4d87", "a13d28a9", "928d74f1", "49919eb7", "82e1f0cf", "e4a5a3bd",
    "f978295c", "d52639a4991bdb1f", "ed841779a3f85d23",
    "aa4242135616f5187c03cf0d97e5d218fdb245381fd1cf8dfb796fbeda4bf7f7d6b128ce89bc9eaa8552d42f597c5db866c67bb0dd8eea11"
);

fn parse_hex_const(s: &str) -> Vec<u8> {
    crate::util::parse_hex(s).expect("valid hex constant")
}

/// Writes to `<name>.part` files, optionally rolling over every `split` bytes
/// (`.xc0`, `.xc1`, ...), and renames them into place on success.
struct SplitWriter {
    base: PathBuf,
    split: Option<u64>,
    cur: Option<BufWriter<File>>,
    cur_len: u64,
    parts: Vec<PathBuf>,
}

impl SplitWriter {
    fn create(path: &Path, split: Option<u64>) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut w = Self { base: path.to_path_buf(), split, cur: None, cur_len: 0, parts: Vec::new() };
        w.open_next()?;
        Ok(w)
    }

    fn final_path(&self, index: usize) -> PathBuf {
        match self.split {
            None => self.base.clone(),
            Some(_) => self.base.with_extension(format!("xc{index}")),
        }
    }

    fn open_next(&mut self) -> Result<()> {
        if let Some(mut w) = self.cur.take() {
            w.flush()?;
        }
        let final_path = self.final_path(self.parts.len());
        let part = part_path(&final_path);
        let f = File::create(&part).map_err(|e| Error::File { path: part.clone(), source: e })?;
        self.cur = Some(BufWriter::with_capacity(4 << 20, f));
        self.parts.push(final_path);
        self.cur_len = 0;
        Ok(())
    }

    fn write_all(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            let room = self.split.map_or(u64::MAX, |s| s - self.cur_len);
            if room == 0 {
                self.open_next()?;
                continue;
            }
            let n = (data.len() as u64).min(room) as usize;
            self.cur.as_mut().unwrap().write_all(&data[..n])?;
            self.cur_len += n as u64;
            data = &data[n..];
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<PathBuf>> {
        if let Some(mut w) = self.cur.take() {
            w.flush()?;
            w.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        }
        for p in &self.parts {
            if p.exists() {
                std::fs::remove_file(p)?;
            }
            std::fs::rename(part_path(p), p)?;
        }
        Ok(std::mem::take(&mut self.parts))
    }

    fn abort(mut self) {
        self.cur.take();
        for p in &self.parts {
            let _ = std::fs::remove_file(part_path(p));
        }
    }
}

fn part_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".part");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hfs0_is_one_sector() {
        let h = hfs0_header(&[]);
        assert_eq!(h.len(), 0x200);
        assert_eq!(&h[..4], b"HFS0");
    }

    #[test]
    fn hfs0_entries_are_contiguous() {
        use crate::util::{cstr, u32le, u64le};
        let h = hfs0_header(&[("a.nca", 0x1234, [1; 32], 0x200), ("b.cnmt.nca", 0x10, [2; 32], 0x200)]);
        assert_eq!(h.len() % 0x200, 0);
        assert_eq!(u32le(&h, 4), 2);
        let entry = |i: usize| 0x10 + i * 0x40;
        assert_eq!(u64le(&h, entry(1)), 0x1234); // second file starts right after the first
        let strings = 0x10 + 2 * 0x40;
        assert_eq!(cstr(&h[strings..], u32le(&h, entry(1) + 0x10) as usize), "b.cnmt.nca");
        assert_eq!(&h[entry(1) + 0x20..entry(1) + 0x40], &[2; 32]);
    }

    #[test]
    fn gameinfo_blobs_are_0x70() {
        assert_eq!(parse_hex_const(GAMEINFO_LARGE).len(), 0x70);
        assert_eq!(parse_hex_const(GAMEINFO_SMALL).len(), 0x70);
    }
}
