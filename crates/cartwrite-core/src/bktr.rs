//! Update ("patch") sections, which hold only what changed since the base game.
//!
//! An update's RomFS section (crypto type [`CRYPT_BKTR`](crate::nca::CRYPT_BKTR)) is read in
//! three layers, following Atmosphère's `NcaFileSystemDriver`:
//!
//! 1. [`AesCtrExStorage`]: the section's own data, decrypted with a counter whose generation
//!    changes from region to region (the AesCtrEx table). The table itself sits at
//!    `aes_ctr_ex_offset` and is encrypted with the section's ordinary counter.
//! 2. [`IndirectStorage`]: the patched section, built from pieces of the base game's section
//!    (storage 0) and of layer 1 (storage 1), as listed by the indirect table at
//!    `indirect_offset`. That table is read *through* layer 1.
//! 3. The update's own IVFC header then locates the RomFS image inside the patched section.
//!
//! Both tables are bucket trees: 0x4000-byte nodes, an L1 node (and, for very large tables, L2
//! nodes) of offsets, then entry sets each starting with a node header. The offset nodes only
//! speed up lookups, so this reads every entry set into memory and searches that instead.

use crate::crypto::{Ctr, Key128};
use crate::error::{fmt_err, Result};
use crate::nca::{NcaHeader, CRYPT_NONE};
use crate::storage::{RawSection, Storage, SubStorage};
use crate::util::{u32le, u64le};

const NODE_SIZE: usize = 0x4000;
const NODE_HEADER_SIZE: usize = 0x10;
/// Offsets per L1/L2 node.
const OFFSETS_PER_NODE: usize = (NODE_SIZE - NODE_HEADER_SIZE) / 8;
/// Far above real tables (a full game patch has tens of thousands of entries), and keeps a
/// corrupt header from making us allocate gigabytes.
const MAX_ENTRIES: usize = 4_000_000;

/// The patch fields of a section's FS header (`NcaPatchInfo`, at 0x100).
#[derive(Clone, Copy, Debug)]
pub struct PatchInfo {
    pub indirect_offset: u64,
    pub indirect_size: u64,
    pub indirect_header: [u8; 0x10],
    pub aes_ctr_ex_offset: u64,
    pub aes_ctr_ex_size: u64,
    pub aes_ctr_ex_header: [u8; 0x10],
}

impl PatchInfo {
    pub fn parse(header: &NcaHeader, section: usize) -> Self {
        let fs = header.fs_header(section);
        Self {
            indirect_offset: u64le(fs, 0x100),
            indirect_size: u64le(fs, 0x108),
            indirect_header: fs[0x110..0x120].try_into().unwrap(),
            aes_ctr_ex_offset: u64le(fs, 0x120),
            aes_ctr_ex_size: u64le(fs, 0x128),
            aes_ctr_ex_header: fs[0x130..0x140].try_into().unwrap(),
        }
    }

    /// True if the section is a patch (has an indirect table).
    pub fn has_indirect_table(&self) -> bool {
        self.indirect_size != 0
    }

    pub fn has_aes_ctr_ex_table(&self) -> bool {
        self.aes_ctr_ex_size != 0
    }
}

/// Number of L2 offset nodes a tree with `sets` entry sets has (Atmosphère's `GetNodeL2Count`).
/// Only trees with more entry sets than one L1 node can index have any.
fn l2_node_count(sets: usize) -> usize {
    if sets <= OFFSETS_PER_NODE {
        return 0;
    }
    let n = sets.div_ceil(OFFSETS_PER_NODE);
    (sets - (OFFSETS_PER_NODE - (n - 1))).div_ceil(OFFSETS_PER_NODE)
}

/// An entry type stored in a bucket tree.
pub(crate) trait BucketEntry: Sized {
    const SIZE: usize;
    fn parse(b: &[u8]) -> Self;
    /// The (virtual) offset where this entry's range starts.
    fn offset(&self) -> u64;
}

/// A bucket tree's entries in offset order. Entry `i` covers `[offset(i), offset(i + 1))`,
/// and the last one runs to `end`.
pub(crate) struct BucketTree<E> {
    pub(crate) entries: Vec<E>,
    pub(crate) end: u64,
}

impl<E: BucketEntry> BucketTree<E> {
    /// Reads a tree whose nodes start at offset 0 of `meta`, described by the 0x10-byte
    /// bucket tree `header` from the FS header.
    pub(crate) fn read(meta: &mut dyn Storage, header: &[u8; 0x10], what: &str) -> Result<Self> {
        if &header[..4] != b"BKTR" {
            return fmt_err(format!("{what} table has no BKTR header"));
        }
        if u32le(header, 4) > 1 {
            return fmt_err(format!("{what} table has unsupported version {}", u32le(header, 4)));
        }
        let count = u32le(header, 8) as i32;
        if count <= 0 || count as usize > MAX_ENTRIES {
            return fmt_err(format!("{what} table has a bad entry count ({count})"));
        }
        let count = count as usize;
        let per_set = (NODE_SIZE - NODE_HEADER_SIZE) / E::SIZE;
        let sets = count.div_ceil(per_set);

        // The entry sets follow the L1 node and any L2 nodes.
        let entries_start = (1 + l2_node_count(sets)) * NODE_SIZE;
        if (entries_start + sets * NODE_SIZE) as u64 > meta.size() {
            return fmt_err(format!("{what} table is truncated"));
        }

        let mut node = vec![0u8; NODE_SIZE];
        meta.read(0, &mut node)?;
        let l1_count = u32le(&node, 4) as usize;
        let end = u64le(&node, 8);
        if u32le(&node, 0) != 0 || l1_count == 0 || l1_count > OFFSETS_PER_NODE || end > i64::MAX as u64 {
            return fmt_err(format!("{what} table has a bad L1 node"));
        }

        let mut entries: Vec<E> = Vec::with_capacity(count);
        for i in 0..sets {
            meta.read((entries_start + i * NODE_SIZE) as u64, &mut node)?;
            let n = u32le(&node, 4) as usize;
            if u32le(&node, 0) as usize != i || n == 0 || n > per_set || entries.len() + n > count {
                return fmt_err(format!("{what} table has a bad entry set {i}"));
            }
            for j in 0..n {
                let at = NODE_HEADER_SIZE + j * E::SIZE;
                entries.push(E::parse(&node[at..at + E::SIZE]));
            }
        }
        if entries.len() != count {
            return fmt_err(format!("{what} table has {} entries, header says {count}", entries.len()));
        }
        // Each entry must start before the next, and all of them before the end.
        let offsets_ok = entries.windows(2).all(|w| w[0].offset() < w[1].offset());
        if !offsets_ok || entries.last().is_some_and(|e| e.offset() >= end) {
            return fmt_err(format!("{what} table entries are out of order"));
        }
        Ok(Self { entries, end })
    }

    pub(crate) fn start(&self) -> u64 {
        self.entries[0].offset()
    }

    /// Index of the entry covering `offset`, which must be in `[start, end)`.
    pub(crate) fn find(&self, offset: u64) -> usize {
        self.entries.partition_point(|e| e.offset() <= offset) - 1
    }

    /// End of entry `i`'s range.
    pub(crate) fn entry_end(&self, i: usize) -> u64 {
        self.entries.get(i + 1).map_or(self.end, |e| e.offset())
    }

    pub(crate) fn check_range(&self, offset: u64, len: usize, what: &str) -> Result<()> {
        match offset.checked_add(len as u64) {
            Some(end) if offset >= self.start() && end <= self.end => Ok(()),
            _ => fmt_err(format!("read outside the {what} table's range")),
        }
    }
}

/// `AesCtrCounterExtendedStorage::Entry`.
#[derive(Clone, Copy, Debug)]
struct CtrExEntry {
    offset: u64,
    encrypted: bool,
    generation: u32,
}

impl BucketEntry for CtrExEntry {
    const SIZE: usize = 0x10;
    fn parse(b: &[u8]) -> Self {
        // Encryption value 0 = encrypted, 1 = not encrypted.
        Self { offset: u64le(b, 0), encrypted: b[8] == 0, generation: u32le(b, 0xC) }
    }
    fn offset(&self) -> u64 {
        self.offset
    }
}

/// `IndirectStorage::Entry`.
#[derive(Clone, Copy, Debug)]
struct IndirectEntry {
    virtual_offset: u64,
    physical_offset: u64,
    storage_index: u32,
}

impl BucketEntry for IndirectEntry {
    const SIZE: usize = 0x14;
    fn parse(b: &[u8]) -> Self {
        Self { virtual_offset: u64le(b, 0), physical_offset: u64le(b, 8), storage_index: u32le(b, 0x10) }
    }
    fn offset(&self) -> u64 {
        self.virtual_offset
    }
}

/// Layer 1: an update section's own data, decrypted region by region.
pub struct AesCtrExStorage<'a> {
    raw: RawSection<'a>,
    table: BucketTree<CtrExEntry>,
    key: Key128,
    secure_value: u32,
    /// Absolute NCA offset of the section, which the counter is based on.
    counter_offset: u64,
    /// `aes_ctr_ex_offset`: everything before the AesCtrEx table.
    data_size: u64,
    /// Where the per-region counters stop; from here to `data_size` the section's ordinary
    /// counter applies. See [`AesCtrExStorage::new`].
    regions_end: u64,
    /// The section's ordinary counter (`None` if the section is unencrypted).
    header_nonce: Option<[u8; 8]>,
}

impl<'a> AesCtrExStorage<'a> {
    /// Usually the AesCtrEx regions cover everything up to the AesCtrEx table, indirect table
    /// included. Sections with a patch meta hash layer (FS header byte 5 = 1, e.g. Breath of
    /// the Wild's updates) instead keep both tables under the ordinary counter, and their
    /// regions stop at `indirect_offset` (Atmosphère's `CreatePatchMetaStorage`). Any bytes
    /// the regions don't cover use the ordinary counter either way, as hactool reads them.
    pub fn new(mut raw: RawSection<'a>, header: &NcaHeader, key: Key128, section: usize) -> Result<Self> {
        let info = PatchInfo::parse(header, section);
        if !info.has_aes_ctr_ex_table() || !info.has_indirect_table() {
            return fmt_err("update section has no patch tables");
        }
        if info.indirect_offset.checked_add(info.indirect_size).is_none_or(|e| e > info.aes_ctr_ex_offset) {
            return fmt_err("update section's patch tables overlap");
        }
        let counter_offset = header.section(section).map_or(0, |s| s.start);

        // The table is encrypted with the section's ordinary counter (unless the section is
        // unencrypted), padded to 0x200.
        let meta_size = info.aes_ctr_ex_size.div_ceil(0x200) * 0x200;
        let mut meta = SubStorage::new(&mut raw, info.aes_ctr_ex_offset, meta_size)?;
        if meta_size > 256 << 20 {
            return fmt_err("AesCtrEx table is implausibly large");
        }
        let mut plain = vec![0u8; meta_size as usize];
        meta.read(0, &mut plain)?;
        if header.section_crypto(section) != CRYPT_NONE {
            Ctr::new(&key, header.section_nonce(section)).apply(counter_offset + info.aes_ctr_ex_offset, &mut plain);
        }
        let table: BucketTree<CtrExEntry> = BucketTree::read(&mut plain, &info.aes_ctr_ex_header, "AesCtrEx")?;
        if table.end > info.aes_ctr_ex_offset {
            return fmt_err("AesCtrEx table covers its own table");
        }
        // Regions are whole AES blocks, as Atmosphère requires.
        if !table.end.is_multiple_of(16) || table.entries.iter().any(|e| !e.offset.is_multiple_of(16)) {
            return fmt_err("AesCtrEx table has a region that isn't 16-byte aligned");
        }
        if table.start() != 0 {
            return fmt_err("AesCtrEx table doesn't start at offset 0");
        }
        let secure_value = u32le(header.fs_header(section), 0x144);
        let header_nonce = (header.section_crypto(section) != CRYPT_NONE).then(|| header.section_nonce(section));
        let has_meta_hash_layer = header.fs_header(section)[5] == 1;
        let regions_end = if has_meta_hash_layer { table.end.min(info.indirect_offset) } else { table.end };
        Ok(Self {
            raw,
            table,
            key,
            secure_value,
            counter_offset,
            data_size: info.aes_ctr_ex_offset,
            regions_end,
            header_nonce,
        })
    }
}

impl Storage for AesCtrExStorage<'_> {
    /// Everything before the AesCtrEx table.
    fn size(&self) -> u64 {
        self.data_size
    }

    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        if offset.checked_add(buf.len() as u64).is_none_or(|end| end > self.data_size) {
            return fmt_err("read outside the AesCtrEx table's range");
        }
        self.raw.read(offset, buf)?;
        let end = offset + buf.len() as u64;
        let mut pos = offset;
        // Past the regions: the section's ordinary counter.
        let regions_end = self.regions_end;
        if end > regions_end {
            let from = pos.max(regions_end);
            if let Some(nonce) = self.header_nonce {
                Ctr::new(&self.key, nonce).apply(self.counter_offset + from, &mut buf[(from - offset) as usize..]);
            }
            if pos >= regions_end {
                return Ok(());
            }
        }
        let end = end.min(regions_end);
        let mut i = self.table.find(offset);
        while pos < end {
            let e = self.table.entries[i];
            let piece_end = self.table.entry_end(i).min(end);
            if e.encrypted {
                // Upper IV: secure value, then this region's generation (both big-endian).
                let nonce = ((self.secure_value as u64) << 32 | e.generation as u64).to_be_bytes();
                let piece = &mut buf[(pos - offset) as usize..(piece_end - offset) as usize];
                Ctr::new(&self.key, nonce).apply(self.counter_offset + pos, piece);
            }
            pos = piece_end;
            i += 1;
        }
        Ok(())
    }
}

/// Layer 2: the patched section, read from the base game (storage 0) or the update (storage 1).
pub struct IndirectStorage<'a> {
    original: &'a mut dyn Storage,
    patch: &'a mut dyn Storage,
    /// Storage 1 is the update data before its tables: `[0, indirect_offset)`.
    patch_size: u64,
    table: BucketTree<IndirectEntry>,
}

impl<'a> IndirectStorage<'a> {
    /// `original` is the base game's decrypted section (same section index); `patch` is the
    /// update's [`AesCtrExStorage`].
    pub fn new(
        original: &'a mut dyn Storage,
        patch: &'a mut dyn Storage,
        header: &NcaHeader,
        section: usize,
    ) -> Result<Self> {
        let info = PatchInfo::parse(header, section);
        let table: BucketTree<IndirectEntry> = {
            let mut meta = SubStorage::new(&mut *patch, info.indirect_offset, info.indirect_size)?;
            BucketTree::read(&mut meta, &info.indirect_header, "indirect")?
        };
        if table.start() != 0 {
            return fmt_err("indirect table doesn't start at offset 0");
        }
        if let Some(e) = table.entries.iter().find(|e| e.storage_index > 1) {
            return fmt_err(format!("indirect table refers to unknown storage {}", e.storage_index));
        }
        Ok(Self { original, patch, patch_size: info.indirect_offset, table })
    }
}

impl Storage for IndirectStorage<'_> {
    fn size(&self) -> u64 {
        self.table.end
    }

    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        self.table.check_range(offset, buf.len(), "indirect")?;
        let end = offset + buf.len() as u64;
        let mut i = self.table.find(offset);
        let mut pos = offset;
        while pos < end {
            let e = self.table.entries[i];
            let piece_end = self.table.entry_end(i).min(end);
            let len = piece_end - pos;
            let (target, target_size): (&mut dyn Storage, u64) = if e.storage_index == 0 {
                let size = self.original.size();
                (&mut *self.original, size)
            } else {
                (&mut *self.patch, self.patch_size)
            };
            let phys = e.physical_offset.checked_add(pos - e.virtual_offset);
            let Some(phys) = phys.filter(|p| p.checked_add(len).is_some_and(|pe| pe <= target_size)) else {
                return fmt_err(format!(
                    "indirect entry at {:#x} points outside storage {}",
                    e.virtual_offset, e.storage_index
                ));
            };
            target.read(phys, &mut buf[(pos - offset) as usize..(piece_end - offset) as usize])?;
            pos = piece_end;
            i += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
    use aes::Aes128;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::keys::Keys;
    use crate::nca::{self, NcaContentType, NcaSource, CRYPT_BKTR, HEADER_SIZE};
    use crate::storage::NcaSection;
    use crate::testutil::{
        bucket_tree, bucket_tree_header, ctr_ex_entry, indirect_entry, pattern, BuiltNca, ImageBuilder, NcaBuilder,
        PatchLayout, PatchSection, Section, TempDir, TestKeys, BUCKET_NODE_SIZE, META_HASH_SIZE,
    };

    // These tests describe update sections from the format (the bucket tree and AesCtrEx layouts of Atmosphère's
    // libstratosphere) and check the readers against that. The fixtures come from `testutil` and from the helpers
    // below, never from the code under test.

    const KEY: Key128 =
        [0x6B, 0x21, 0xF4, 0x08, 0x95, 0xDA, 0x3C, 0x7E, 0x12, 0xA9, 0x50, 0xC3, 0x8D, 0x47, 0xEB, 0x02];

    fn put_u32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put_u64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// splitmix64: a deterministic stream for picking test data.
    struct Rng(u64);

    impl Rng {
        fn draw(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        /// A value in `0..n`.
        fn below(&mut self, n: u64) -> u64 {
            self.draw() % n
        }
    }

    /// The upper half of a region's counter: the secure value, then the generation, both big-endian.
    fn upper(secure_value: u32, generation: u32) -> [u8; 8] {
        ((u64::from(secure_value) << 32) | u64::from(generation)).to_be_bytes()
    }

    /// Asserts that `result` failed with a message containing `expected`.
    fn assert_fails<T>(result: Result<T>, expected: &str) {
        match result {
            Ok(_) => panic!("accepted, but should have failed with {expected:?}"),
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains(expected), "expected an error mentioning {expected:?}, got {msg:?}");
            }
        }
    }

    fn read_vec(s: &mut dyn Storage, offset: u64, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        s.read(offset, &mut buf).unwrap_or_else(|e| panic!("reading {len:#x} bytes at {offset:#x}: {e}"));
        buf
    }

    /// Fails with a short message (not a dump of kilobytes) if the two differ.
    fn assert_same(what: &str, got: &[u8], want: &[u8]) {
        if got != want {
            let first = got.iter().zip(want).position(|(a, b)| a != b);
            panic!("{what}: got {} bytes, want {}; first difference at {first:?}", got.len(), want.len());
        }
    }

    /// An NCA held in memory. `read_plain` decrypts like a real source, `read_raw` returns the stored bytes.
    struct VecNca(Vec<u8>);

    impl VecNca {
        fn stored(&self, offset: u64, len: usize) -> Result<&[u8]> {
            let range = usize::try_from(offset).ok().and_then(|o| Some(o..o.checked_add(len)?));
            match range.and_then(|r| self.0.get(r)) {
                Some(bytes) => Ok(bytes),
                None => fmt_err("read outside the test NCA"),
            }
        }
    }

    impl NcaSource for VecNca {
        fn read_plain(&mut self, header: &NcaHeader, key: &Key128, offset: u64, buf: &mut [u8]) -> Result<()> {
            let mut copy = self.stored(offset, buf.len())?.to_vec();
            nca::decrypt_in_place(header, key, offset, &mut copy)?;
            buf.copy_from_slice(&copy);
            Ok(())
        }

        fn read_raw(&mut self, _header: &NcaHeader, _key: &Key128, offset: u64, buf: &mut [u8]) -> Result<()> {
            buf.copy_from_slice(self.stored(offset, buf.len())?);
            Ok(())
        }
    }

    /// The fields of a patch section's FS header (and of its entry in the section table) that the readers use.
    #[derive(Clone, Default)]
    struct Fs {
        start: u64,
        len: u64,
        crypto: u8,
        indirect_offset: u64,
        indirect_size: u64,
        indirect_entries: usize,
        ctr_ex_offset: u64,
        ctr_ex_size: u64,
        ctr_ex_entries: usize,
        generation: u32,
        secure_value: u32,
    }

    impl Fs {
        /// An NCA header whose section 0 is described by `self`.
        fn header(&self) -> NcaHeader {
            let mut h = NcaHeader { raw: Box::new([0u8; HEADER_SIZE]) };
            put_u32(&mut h.raw[..], 0x240, (self.start / 0x200) as u32);
            put_u32(&mut h.raw[..], 0x244, ((self.start + self.len) / 0x200) as u32);
            let fs = h.fs_header_mut(0);
            fs[4] = self.crypto;
            put_u64(fs, 0x100, self.indirect_offset);
            put_u64(fs, 0x108, self.indirect_size);
            fs[0x110..0x120].copy_from_slice(&bucket_tree_header(self.indirect_entries));
            put_u64(fs, 0x120, self.ctr_ex_offset);
            put_u64(fs, 0x128, self.ctr_ex_size);
            fs[0x130..0x140].copy_from_slice(&bucket_tree_header(self.ctr_ex_entries));
            put_u32(fs, 0x140, self.generation);
            put_u32(fs, 0x144, self.secure_value);
            h
        }
    }

    // -----------------------------------------------------------------------------------------------------
    // The patch info in the FS header, counters, node counts
    // -----------------------------------------------------------------------------------------------------

    #[test]
    fn patch_info_is_read_from_the_documented_offsets() {
        let fs = Fs {
            start: 0x1000,
            len: 0x1000,
            crypto: CRYPT_BKTR,
            indirect_offset: 0x1_2345_6000,
            indirect_size: 0x8000,
            indirect_entries: 77,
            ctr_ex_offset: 0x2_0000_0000,
            ctr_ex_size: 0x4000,
            ctr_ex_entries: 5,
            generation: 0x1111_2222,
            secure_value: 0x3333_4444,
        };
        let header = fs.header();
        let info = PatchInfo::parse(&header, 0);
        assert_eq!((info.indirect_offset, info.indirect_size), (0x1_2345_6000, 0x8000));
        assert_eq!((info.aes_ctr_ex_offset, info.aes_ctr_ex_size), (0x2_0000_0000, 0x4000));
        assert_eq!(info.indirect_header, bucket_tree_header(77));
        assert_eq!(info.aes_ctr_ex_header, bucket_tree_header(5));
        assert!(info.has_indirect_table() && info.has_aes_ctr_ex_table());
        // The header's generation and secure value are one little-endian u64, i.e. these counter bytes.
        assert_eq!(header.section_nonce(0), upper(0x3333_4444, 0x1111_2222));
        assert_eq!(header.section_nonce(0), [0x33, 0x33, 0x44, 0x44, 0x11, 0x11, 0x22, 0x22]);

        let none = PatchInfo::parse(&Fs::default().header(), 0);
        assert!(!none.has_indirect_table() && !none.has_aes_ctr_ex_table());
    }

    #[test]
    fn ctr_counter_is_the_upper_half_then_the_block_number() {
        let upper_half = [1, 2, 3, 4, 5, 6, 7, 8];
        let offset = 0x1A35u64; // not a multiple of 16
        let plain = pattern(100, 9);
        let mut got = plain.clone();
        Ctr::new(&KEY, upper_half).apply(offset, &mut got);

        let cipher = Aes128::new(GenericArray::from_slice(&KEY));
        let want: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, byte)| {
                let at = offset + i as u64;
                let mut counter = [0u8; 16];
                counter[..8].copy_from_slice(&upper_half);
                counter[8..].copy_from_slice(&(at / 16).to_be_bytes());
                let mut block = GenericArray::from(counter);
                cipher.encrypt_block(&mut block);
                byte ^ block[(at % 16) as usize]
            })
            .collect();
        assert_same("keystream", &got, &want);
    }

    #[test]
    fn l2_node_count_follows_the_formula() {
        // One L1 node indexes 2046 entry sets; only bigger trees have L2 nodes.
        assert_eq!(l2_node_count(1), 0);
        assert_eq!(l2_node_count(2046), 0);
        assert_eq!(l2_node_count(2047), 1);
        assert_eq!(l2_node_count(4092), 2);
    }

    // -----------------------------------------------------------------------------------------------------
    // Bucket trees
    // -----------------------------------------------------------------------------------------------------

    /// The meta region and header of an indirect tree with `n` entries at 0x100 intervals, all reading storage 0.
    fn simple_indirect_tree(n: usize) -> (Vec<u8>, [u8; 0x10]) {
        let entries: Vec<Vec<u8>> = (0..n).map(|i| indirect_entry(i as u64 * 0x100, i as u64 * 0x100, 0)).collect();
        (bucket_tree(&entries, n as u64 * 0x100), bucket_tree_header(n))
    }

    fn read_indirect_tree(meta: &mut Vec<u8>, header: &[u8; 0x10]) -> Result<BucketTree<IndirectEntry>> {
        BucketTree::read(meta, header, "indirect")
    }

    /// Where the node of entry set `set` starts in the meta region (the L1 node is first).
    fn set_node(set: usize) -> usize {
        BUCKET_NODE_SIZE * (1 + set)
    }

    #[test]
    fn a_well_formed_tree_is_read_completely() {
        // 900 entries of 0x14 bytes: 818 fit in a set, so two sets.
        let (mut meta, header) = simple_indirect_tree(900);
        assert_eq!(meta.len(), 3 * BUCKET_NODE_SIZE);
        let tree = read_indirect_tree(&mut meta, &header).unwrap();
        assert_eq!(tree.entries.len(), 900);
        assert_eq!(tree.end, 900 * 0x100);
        assert_eq!(tree.start(), 0);
        assert!(tree.entries.iter().enumerate().all(|(i, e)| e.virtual_offset == i as u64 * 0x100));
        assert_eq!(tree.find(0), 0);
        assert_eq!(tree.find(0xFF), 0);
        assert_eq!(tree.find(0x100), 1);
        assert_eq!(tree.find(817 * 0x100 + 5), 817);
        assert_eq!(tree.find(818 * 0x100), 818);
        assert_eq!(tree.find(900 * 0x100 - 1), 899);
        assert_eq!(tree.entry_end(0), 0x100);
        assert_eq!(tree.entry_end(899), 900 * 0x100);
    }

    #[test]
    fn malformed_trees_are_rejected() {
        type Mutate = fn(&mut Vec<u8>, &mut [u8; 0x10]);
        // Offsets of the entries in the 900-entry tree: entry i is at i * 0x100, 818 entries (0x14 bytes each) to a set.
        let cases: Vec<(&str, Mutate, &str)> = vec![
            ("bad magic", |_, h| h[..4].copy_from_slice(b"BKTX"), "no BKTR header"),
            ("version 2", |_, h| put_u32(h, 4, 2), "unsupported version 2"),
            ("entry count 0", |_, h| put_u32(h, 8, 0), "bad entry count (0)"),
            ("negative entry count", |_, h| put_u32(h, 8, u32::MAX), "bad entry count (-1)"),
            ("absurd entry count", |_, h| put_u32(h, 8, 4_000_001), "bad entry count"),
            ("set index mismatch", |m, _| put_u32(m, set_node(1), 5), "bad entry set 1"),
            ("first set has the wrong index", |m, _| put_u32(m, set_node(0), 1), "bad entry set 0"),
            ("more entries than fit in a set", |m, _| put_u32(m, set_node(0) + 4, 819), "bad entry set 0"),
            ("empty set", |m, _| put_u32(m, set_node(1) + 4, 0), "bad entry set 1"),
            ("fewer entries than the header says", |m, _| put_u32(m, set_node(1) + 4, 81), "has 899 entries"),
            ("more entries than the header says", |m, _| put_u32(m, set_node(1) + 4, 83), "bad entry set 1"),
            ("equal offsets", |m, _| put_u64(m, set_node(0) + 0x10 + 5 * 0x14, 4 * 0x100), "entries are out of order"),
            (
                "decreasing offsets",
                |m, _| put_u64(m, set_node(0) + 0x10 + 5 * 0x14, 3 * 0x100),
                "entries are out of order",
            ),
            (
                "offsets decrease across sets",
                |m, _| put_u64(m, set_node(1) + 0x10, 817 * 0x100 - 1),
                "entries are out of order",
            ),
            ("last offset equals the end", |m, _| put_u64(m, 8, 899 * 0x100), "entries are out of order"),
            ("last offset past the end", |m, _| put_u64(m, 8, 10), "entries are out of order"),
            ("L1 index", |m, _| put_u32(m, 0, 1), "bad L1 node"),
            ("L1 without offsets", |m, _| put_u32(m, 4, 0), "bad L1 node"),
            ("L1 with too many offsets", |m, _| put_u32(m, 4, 2047), "bad L1 node"),
            ("end beyond i64", |m, _| put_u64(m, 8, 1 << 63), "bad L1 node"),
            ("meta missing its last byte", |m, _| m.truncate(3 * BUCKET_NODE_SIZE - 1), "is truncated"),
            ("meta missing a whole set", |m, _| m.truncate(2 * BUCKET_NODE_SIZE), "is truncated"),
            ("meta with only the L1 node", |m, _| m.truncate(BUCKET_NODE_SIZE), "is truncated"),
        ];
        for (name, mutate, expected) in cases {
            let (mut meta, mut header) = simple_indirect_tree(900);
            mutate(&mut meta, &mut header);
            match read_indirect_tree(&mut meta, &header) {
                Ok(_) => panic!("{name}: accepted, but should have failed with {expected:?}"),
                Err(e) => {
                    let msg = e.to_string();
                    assert!(msg.contains(expected), "{name}: expected an error mentioning {expected:?}, got {msg:?}");
                    assert!(msg.contains("indirect table"), "{name}: the message should name the table: {msg:?}");
                }
            }
        }
    }

    /// An indirect table over a base section and update data, laid out as layer 1 presents them: the update data
    /// padded to 0x200, then the table.
    struct IndirectFx {
        base: Vec<u8>,
        /// Update data followed by the indirect table.
        patch: Vec<u8>,
        header: NcaHeader,
    }

    /// `entries` are `(virtual offset, physical offset, storage index)`; `end` is where the last one stops.
    fn indirect_fx(base: Vec<u8>, update_data: &[u8], entries: &[(u64, u64, u32)], end: u64) -> IndirectFx {
        assert_eq!(update_data.len() % 0x200, 0);
        let encoded: Vec<Vec<u8>> = entries.iter().map(|&(v, p, s)| indirect_entry(v, p, s)).collect();
        let table = bucket_tree(&encoded, end);
        let fs = Fs {
            indirect_offset: update_data.len() as u64,
            indirect_size: table.len() as u64,
            indirect_entries: entries.len(),
            ..Fs::default()
        };
        let mut patch = update_data.to_vec();
        patch.extend_from_slice(&table);
        IndirectFx { base, patch, header: fs.header() }
    }

    impl IndirectFx {
        fn open(&mut self) -> Result<IndirectStorage<'_>> {
            IndirectStorage::new(&mut self.base, &mut self.patch, &self.header, 0)
        }
    }

    /// The virtual bytes `entries` describe, worked out by copying each range from where its entry says.
    fn expected_virtual(base: &[u8], update_data: &[u8], entries: &[(u64, u64, u32)], end: u64) -> Vec<u8> {
        let mut out = vec![0u8; end as usize];
        for (i, &(v, p, s)) in entries.iter().enumerate() {
            let next = entries.get(i + 1).map_or(end, |e| e.0);
            let source = if s == 0 { base } else { update_data };
            let (v, p, len) = (v as usize, p as usize, (next - v) as usize);
            out[v..v + len].copy_from_slice(&source[p..p + len]);
        }
        out
    }

    #[test]
    fn indirect_storage_with_one_entry_set() {
        let base = pattern(4096, 1);
        let update_data = pattern(0x600, 2);
        // [0, 50) from base@100, [50, 300) from update@0x203, [300, 1000) from base@0.
        let entries = [(0u64, 100u64, 0u32), (50, 0x203, 1), (300, 0, 0)];
        let end = 1000;
        let want = expected_virtual(&base, &update_data, &entries, end);
        assert_same("fixture", &want[..50], &base[100..150]);
        assert_same("fixture", &want[50..300], &update_data[0x203..0x203 + 250]);
        assert_same("fixture", &want[300..], &base[..700]);

        let mut fx = indirect_fx(base, &update_data, &entries, end);
        assert_eq!(fx.patch.len(), 0x600 + 2 * BUCKET_NODE_SIZE);
        let mut s = fx.open().unwrap();
        assert_eq!(s.size(), end);
        assert_same("all", &read_vec(&mut s, 0, 1000), &want);
        for (offset, len) in [(0, 1), (49, 2), (50, 1), (299, 2), (300, 1), (999, 1), (7, 900), (45, 10), (295, 10)] {
            assert_same(&format!("{len} at {offset}"), &read_vec(&mut s, offset, len), &want[offset as usize..][..len]);
        }
        let mut buf = [0u8; 2];
        assert_fails(s.read(999, &mut buf), "read outside the indirect table's range");
        assert_fails(s.read(1000, &mut buf[..1]), "read outside the indirect table's range");
        assert_fails(s.read(u64::MAX, &mut buf[..1]), "read outside the indirect table's range");
    }

    #[test]
    fn indirect_storage_across_many_entry_sets() {
        // 2000 entries of 0x14 bytes, 818 to a set: three sets, with random sources and lengths.
        let mut rng = Rng(7);
        let base = pattern(150_000, 1);
        let update_data = pattern(80 * 1024, 2);
        let mut entries = Vec::new();
        let mut at = 0u64;
        for i in 0..2000 {
            let len = 1 + rng.below(if i % 10 == 0 { 2000 } else { 200 });
            let storage = rng.below(2) as u32;
            let size = if storage == 0 { base.len() } else { update_data.len() } as u64;
            // Some storage-0 entries read the offset they stand for; most don't.
            let physical = if storage == 0 && i % 7 == 3 && at + len <= size { at } else { rng.below(size - len + 1) };
            entries.push((at, physical, storage));
            at += len;
        }
        let end = at;
        assert!(entries.iter().filter(|e| e.2 == 0 && e.1 != e.0).count() > 100);
        assert!(entries.iter().filter(|e| e.2 == 0 && e.1 == e.0).count() > 10);
        assert!(entries.iter().filter(|e| e.2 == 1 && e.1 != e.0).count() > 100);
        let want = expected_virtual(&base, &update_data, &entries, end);

        let mut fx = indirect_fx(base, &update_data, &entries, end);
        assert_eq!(fx.patch.len(), update_data.len() + 4 * BUCKET_NODE_SIZE);
        let mut s = fx.open().unwrap();
        assert_eq!(s.size(), end);
        assert_same("everything", &read_vec(&mut s, 0, end as usize), &want);

        // Both ends of every entry, and reads straddling each boundary.
        for (i, &(v, _, _)) in entries.iter().enumerate() {
            let next = entries.get(i + 1).map_or(end, |e| e.0);
            assert_eq!(read_vec(&mut s, v, 1)[0], want[v as usize], "first byte of entry {i}");
            assert_eq!(read_vec(&mut s, next - 1, 1)[0], want[next as usize - 1], "last byte of entry {i}");
            if v > 0 {
                assert_same("straddling", &read_vec(&mut s, v - 1, 2), &want[v as usize - 1..v as usize + 1]);
                let (lo, hi) = (v.saturating_sub(40), (v + 40).min(end));
                assert_same("around", &read_vec(&mut s, lo, (hi - lo) as usize), &want[lo as usize..hi as usize]);
            }
        }
        assert_eq!(read_vec(&mut s, end - 1, 1)[0], want[end as usize - 1]);

        // Arbitrary ranges, most of them spanning many entries.
        for _ in 0..300 {
            let offset = rng.below(end);
            let len = 1 + rng.below((end - offset).min(6000));
            let got = read_vec(&mut s, offset, len as usize);
            assert_same(&format!("{len} at {offset}"), &got, &want[offset as usize..][..len as usize]);
        }
        let mut one = [0u8; 1];
        assert_fails(s.read(end, &mut one), "read outside the indirect table's range");
    }

    #[test]
    fn indirect_storage_rejects_bad_entries() {
        let base = pattern(0x2000, 1);
        let update_data = pattern(0x400, 2);
        let mut buf = [0u8; 0x80];

        // A storage index other than 0 and 1.
        let mut fx = indirect_fx(base.clone(), &update_data, &[(0, 0, 0), (0x100, 0, 2)], 0x200);
        assert_fails(fx.open(), "unknown storage 2");

        // The first entry has to start at virtual offset 0.
        let mut fx = indirect_fx(base.clone(), &update_data, &[(0x10, 0, 0), (0x100, 0, 1)], 0x200);
        assert_fails(fx.open(), "doesn't start at offset 0");

        // An entry's physical range may end exactly where its storage ends, but not go past it.
        let exact = [(0, 0x2000 - 0x80, 0), (0x80, 0x400 - 0x80, 1)];
        let mut fx = indirect_fx(base.clone(), &update_data, &exact, 0x100);
        let mut s = fx.open().unwrap();
        let want = expected_virtual(&base, &update_data, &exact, 0x100);
        assert_same("exact fit", &read_vec(&mut s, 0, 0x100), &want);
        drop(s);

        // One byte past the base game's section. The second entry is fine, and only what is read counts.
        let past_base = [(0, 0x2000 - 0x7F, 0), (0x80, 0, 1)];
        let mut fx = indirect_fx(base.clone(), &update_data, &past_base, 0x100);
        let mut s = fx.open().unwrap();
        assert_fails(s.read(0, &mut buf), "points outside storage 0");
        s.read(0x80, &mut buf).unwrap();
        assert_same("second entry", &buf, &update_data[..0x80]);
        drop(s);

        // The update's data ends where the indirect table starts, though the table is in the same storage.
        let past_data = [(0, 0, 0), (0x80, 0x400 - 0x7F, 1)];
        let mut fx = indirect_fx(base.clone(), &update_data, &past_data, 0x100);
        let mut s = fx.open().unwrap();
        assert_fails(s.read(0x80, &mut buf), "points outside storage 1");
        s.read(0, &mut buf).unwrap();
        assert_same("first entry", &buf, &base[..0x80]);
        drop(s);

        // Offsets that overflow.
        let overflow = [(0, u64::MAX - 5, 0), (0x80, 0, 1)];
        let mut fx = indirect_fx(base.clone(), &update_data, &overflow, 0x100);
        let mut s = fx.open().unwrap();
        assert_fails(s.read(0, &mut buf), "points outside storage 0");
        drop(s);

        // The second entry runs 0x70 bytes past the base game's section if read to its end, but its first 0x10
        // bytes end exactly at the end of the section.
        let shifted = [(0, 0, 0), (0x80, 0x2000 - 0x10, 0)];
        let mut fx = indirect_fx(base.clone(), &update_data, &shifted, 0x100);
        let mut s = fx.open().unwrap();
        let mut small = [0u8; 0x10];
        s.read(0x80, &mut small).unwrap();
        assert_same("start of the entry", &small, &base[0x2000 - 0x10..]);
        assert_fails(s.read(0x90, &mut small), "points outside storage 0");
    }

    // -----------------------------------------------------------------------------------------------------
    // AesCtrEx
    // -----------------------------------------------------------------------------------------------------

    /// One AesCtrEx region: `(offset, encrypted, generation)`.
    type Region = (u64, bool, u32);

    /// An NCA holding an AesCtrEx section made by a [`CtrExSpec`].
    struct CtrExNca {
        nca: VecNca,
        header: NcaHeader,
        /// The data of layer 1, `[0, ctr_ex_offset)`, as stored (before the AesCtrEx table).
        stored: Vec<u8>,
    }

    /// How to lay out an AesCtrEx section: its data, encrypted region by region, followed by the table.
    struct CtrExSpec {
        /// Absolute offset of the section in the NCA.
        start: u64,
        /// The generation in the FS header, which the table is encrypted with.
        generation: u32,
        secure_value: u32,
        /// The FS header's encryption type.
        crypto: u8,
        encrypt_table: bool,
        regions: Vec<Region>,
        /// The tree's end offset, if not the end of the data.
        end: Option<u64>,
    }

    impl CtrExSpec {
        fn new(start: u64, regions: Vec<Region>) -> Self {
            let (generation, secure_value) = (4, 0xAABB_CCDD);
            Self { start, generation, secure_value, crypto: CRYPT_BKTR, encrypt_table: true, regions, end: None }
        }

        /// Encrypts one region's data the way the format says: counter = secure value, region generation, then
        /// the absolute offset / 16.
        fn cipher(&self) -> impl Fn(u64, u32, &mut [u8]) {
            let (start, secure_value) = (self.start, self.secure_value);
            move |offset, generation, data| Ctr::new(&KEY, upper(secure_value, generation)).apply(start + offset, data)
        }

        /// Lays out `plain` (a multiple of 0x200 long), encrypting each encrypted region with
        /// `cipher(region offset, region generation, region data)`.
        fn build(&self, plain: &[u8], cipher: &dyn Fn(u64, u32, &mut [u8])) -> CtrExNca {
            assert!(plain.len().is_multiple_of(0x200) && self.start.is_multiple_of(0x200));
            let mut stored = plain.to_vec();
            for (i, &(offset, encrypted, generation)) in self.regions.iter().enumerate() {
                let end = self.regions.get(i + 1).map_or(plain.len() as u64, |r| r.0);
                if encrypted {
                    cipher(offset, generation, &mut stored[offset as usize..end as usize]);
                }
            }
            let entries: Vec<Vec<u8>> = self.regions.iter().map(|&(o, e, g)| ctr_ex_entry(o, e, g)).collect();
            let mut table = bucket_tree(&entries, self.end.unwrap_or(plain.len() as u64));
            let table_size = table.len() as u64;
            if self.encrypt_table {
                // The table sits after the data and is encrypted like the rest of the section, with the header's
                // own generation.
                let at = self.start + plain.len() as u64;
                Ctr::new(&KEY, upper(self.secure_value, self.generation)).apply(at, &mut table);
            }
            let mut bytes = vec![0u8; self.start as usize];
            bytes.extend_from_slice(&stored);
            bytes.extend_from_slice(&table);
            let fs = Fs {
                start: self.start,
                len: (stored.len() + table.len()) as u64,
                crypto: self.crypto,
                indirect_offset: 0, // the indirect table's place doesn't matter to layer 1
                indirect_size: 0x200,
                indirect_entries: 1,
                ctr_ex_offset: plain.len() as u64,
                ctr_ex_size: table_size,
                ctr_ex_entries: self.regions.len(),
                generation: self.generation,
                secure_value: self.secure_value,
            };
            CtrExNca { nca: VecNca(bytes), header: fs.header(), stored }
        }
    }

    fn open_ctr_ex(c: &mut CtrExNca) -> Result<AesCtrExStorage<'_>> {
        let raw = RawSection::new(&mut c.nca, &c.header, KEY, 0)?;
        AesCtrExStorage::new(raw, &c.header, KEY, 0)
    }

    /// Reads all of `s`, every range around each of `boundaries` and 300 random ranges (so most start and end at
    /// odd offsets), and checks them against `want`.
    fn check_reads(s: &mut dyn Storage, want: &[u8], boundaries: &[u64], seed: u64) {
        assert_eq!(s.size(), want.len() as u64);
        assert_same("all", &read_vec(s, 0, want.len()), want);
        let len = want.len() as u64;
        for &b in boundaries {
            let around =
                [(b.saturating_sub(1), b + 1), (b.saturating_sub(5), b + 7), (b, b + 1), (b.saturating_sub(1), b)];
            for (lo, hi) in around {
                let (lo, hi) = (lo.min(len), hi.min(len));
                if lo < hi {
                    let got = read_vec(s, lo, (hi - lo) as usize);
                    assert_same(&format!("{lo:#x}..{hi:#x}"), &got, &want[lo as usize..hi as usize]);
                }
            }
        }
        let mut rng = Rng(seed);
        for _ in 0..300 {
            let offset = rng.below(len);
            let n = 1 + rng.below((len - offset).min(3000));
            let got = read_vec(s, offset, n as usize);
            assert_same(&format!("{n} at {offset}"), &got, &want[offset as usize..][..n as usize]);
        }
    }

    /// Region boundaries that don't line up with anything: a tiny first region, odd multiples of 16, one region that
    /// isn't encrypted, one whose generation is the header's (4) and one with the largest generation.
    const REGIONS: [Region; 6] = [
        (0x0, true, 1),
        (0x30, true, 2),
        (0xF10, false, 9),
        (0x1A20, true, 4),
        (0x2000, true, u32::MAX),
        (0x4B70, true, 5),
    ];
    const LEN: usize = 0x5200;

    fn region_end(i: usize) -> u64 {
        REGIONS.get(i + 1).map_or(LEN as u64, |r| r.0)
    }

    #[test]
    fn ctr_ex_regions_decrypt_with_their_own_counters() {
        let spec = CtrExSpec::new(0x1A00, REGIONS.to_vec());
        let plain = pattern(LEN, 11);
        let mut fx = spec.build(&plain, &spec.cipher());
        // The data really is stored encrypted, except for the region marked not encrypted.
        for (i, &(offset, encrypted, _)) in REGIONS.iter().enumerate() {
            let range = offset as usize..region_end(i) as usize;
            assert_eq!(fx.stored[range.clone()] == plain[range], !encrypted, "region at {offset:#x}");
        }

        let mut s = open_ctr_ex(&mut fx).unwrap();
        let boundaries: Vec<u64> = REGIONS.iter().map(|r| r.0).chain([LEN as u64]).collect();
        check_reads(&mut s, &plain, &boundaries, 1);
        let mut buf = [0u8; 2];
        assert_fails(s.read(LEN as u64 - 1, &mut buf), "read outside the AesCtrEx table's range");
        assert_fails(s.read(LEN as u64, &mut buf[..1]), "read outside the AesCtrEx table's range");
    }

    /// A way to encrypt a region's data: `(region offset, region generation, region data)`.
    type Cipher = Box<dyn Fn(u64, u32, &mut [u8])>;

    fn boxed(f: impl Fn(u64, u32, &mut [u8]) + 'static) -> Cipher {
        Box::new(f)
    }

    #[test]
    fn ctr_ex_counters_come_from_each_regions_generation_the_secure_value_and_the_absolute_offset() {
        let spec = CtrExSpec::new(0x1A00, REGIONS.to_vec());
        let (start, header_generation, secure_value) = (spec.start, spec.generation, spec.secure_value);
        let plain = pattern(LEN, 12);

        // Wrong ways to encrypt, and the regions each still happens to get right besides the ones not encrypted.
        let wrong: Vec<(&str, Cipher, Vec<u64>)> = vec![
            (
                "the header's generation for every region",
                boxed(move |off, _gen, data| {
                    Ctr::new(&KEY, upper(secure_value, header_generation)).apply(start + off, data)
                }),
                vec![0x1A20], // the region whose generation is the header's
            ),
            (
                "no secure value",
                boxed(move |off, gen, data| Ctr::new(&KEY, upper(0, gen)).apply(start + off, data)),
                vec![],
            ),
            (
                "generation and secure value swapped",
                boxed(move |off, gen, data| Ctr::new(&KEY, upper(gen, secure_value)).apply(start + off, data)),
                vec![],
            ),
            (
                "offsets counted from the start of the section",
                boxed(move |off, gen, data| Ctr::new(&KEY, upper(secure_value, gen)).apply(off, data)),
                vec![],
            ),
        ];
        for (what, cipher, still_right) in wrong {
            let mut fx = spec.build(&plain, &*cipher);
            let mut s = open_ctr_ex(&mut fx).unwrap();
            for (i, &(offset, encrypted, generation)) in REGIONS.iter().enumerate() {
                let end = region_end(i);
                let got = read_vec(&mut s, offset, (end - offset) as usize);
                let decrypts = got == plain[offset as usize..end as usize];
                assert_eq!(
                    decrypts,
                    !encrypted || still_right.contains(&offset),
                    "encrypted with {what}: region at {offset:#x} (generation {generation})"
                );
            }
        }
    }

    #[test]
    fn ctr_ex_tables_with_several_entry_sets() {
        // 1536 regions of 0x30 bytes: 1023 entries fit in a set, so two sets.
        let mut rng = Rng(3);
        let len = 0x12000usize;
        let regions: Vec<Region> =
            (0..len as u64 / 0x30).map(|i| (i * 0x30, i % 7 != 3, rng.below(1000) as u32)).collect();
        assert_eq!(regions.len(), 1536);
        let spec = CtrExSpec::new(0xC00, regions.clone());
        let plain = pattern(len, 13);
        let mut fx = spec.build(&plain, &spec.cipher());
        assert_eq!(fx.nca.0.len(), 0xC00 + len + 3 * BUCKET_NODE_SIZE);
        assert_eq!(fx.stored[3 * 0x30..4 * 0x30], plain[3 * 0x30..4 * 0x30]); // region 3 isn't encrypted
        assert_ne!(fx.stored[0x30..2 * 0x30], plain[0x30..2 * 0x30]);

        let boundaries: Vec<u64> = regions.iter().map(|r| r.0).collect();
        let mut s = open_ctr_ex(&mut fx).unwrap();
        check_reads(&mut s, &plain, &boundaries, 2);
        // The boundary between the two sets.
        let b = 1023 * 0x30;
        assert_same("across the sets", &read_vec(&mut s, b - 0x20, 0x40), &plain[b as usize - 0x20..b as usize + 0x20]);
    }

    #[test]
    fn ctr_ex_table_is_read_as_is_when_the_section_is_not_encrypted() {
        let regions = vec![(0, false, 3), (0x1000, false, 8)];
        let plain = pattern(0x2000, 14);
        let mut spec = CtrExSpec::new(0x200, regions.clone());
        spec.crypto = CRYPT_NONE;
        spec.encrypt_table = false;
        let mut fx = spec.build(&plain, &spec.cipher());
        assert_eq!(fx.stored, plain);
        let mut s = open_ctr_ex(&mut fx).unwrap();
        check_reads(&mut s, &plain, &[0, 0x1000, 0x2000], 4);
        drop(s);

        // The same with an encrypted table, or an encrypted section with a plain table, doesn't parse.
        for (crypto, encrypt_table) in [(CRYPT_NONE, true), (CRYPT_BKTR, false)] {
            let mut spec = CtrExSpec::new(0x200, regions.clone());
            spec.crypto = crypto;
            spec.encrypt_table = encrypt_table;
            let mut fx = spec.build(&plain, &spec.cipher());
            assert_fails(open_ctr_ex(&mut fx), "AesCtrEx table has a bad");
        }
    }

    #[test]
    fn ctr_ex_section_with_bad_tables_is_rejected() {
        type Mutate = fn(&mut NcaHeader);
        let plain = pattern(LEN, 15);
        let spec = CtrExSpec::new(0x1A00, REGIONS.to_vec());
        let cases: Vec<(&str, Mutate, &str)> = vec![
            ("no indirect table", |h| put_u64(h.fs_header_mut(0), 0x108, 0), "no patch tables"),
            ("no AesCtrEx table", |h| put_u64(h.fs_header_mut(0), 0x128, 0), "no patch tables"),
            (
                "tables overlap",
                |h| {
                    put_u64(h.fs_header_mut(0), 0x100, LEN as u64 - 0x100);
                    put_u64(h.fs_header_mut(0), 0x108, 0x200);
                },
                "overlap",
            ),
            (
                "table offsets overflow",
                |h| {
                    put_u64(h.fs_header_mut(0), 0x100, u64::MAX);
                    put_u64(h.fs_header_mut(0), 0x108, 2);
                },
                "overlap",
            ),
            (
                "bad magic",
                |h| h.fs_header_mut(0)[0x130..0x134].copy_from_slice(b"BKTX"),
                "AesCtrEx table has no BKTR header",
            ),
            ("version 2", |h| put_u32(h.fs_header_mut(0), 0x134, 2), "AesCtrEx table has unsupported version 2"),
            ("no entries", |h| put_u32(h.fs_header_mut(0), 0x138, 0), "AesCtrEx table has a bad entry count (0)"),
        ];
        for (name, mutate, expected) in cases {
            let mut fx = spec.build(&plain, &spec.cipher());
            mutate(&mut fx.header);
            match open_ctr_ex(&mut fx) {
                Ok(_) => panic!("{name}: accepted, but should have failed with {expected:?}"),
                Err(e) => {
                    let msg = e.to_string();
                    assert!(msg.contains(expected), "{name}: expected an error mentioning {expected:?}, got {msg:?}");
                }
            }
        }

        // The regions have to end where the table starts, not beyond it.
        let mut over = CtrExSpec::new(0x1A00, REGIONS.to_vec());
        over.end = Some(LEN as u64 + 0x200);
        let mut fx = over.build(&plain, &over.cipher());
        assert_fails(open_ctr_ex(&mut fx), "covers its own table");
    }

    #[test]
    fn default_read_raw_gives_back_the_stored_bytes() {
        /// A source that only knows how to read plaintext.
        struct PlainOnly(VecNca);

        impl NcaSource for PlainOnly {
            fn read_plain(&mut self, header: &NcaHeader, key: &Key128, offset: u64, buf: &mut [u8]) -> Result<()> {
                self.0.read_plain(header, key, offset, buf)
            }
        }

        let spec = CtrExSpec::new(0x1A00, REGIONS.to_vec());
        let fx = spec.build(&pattern(LEN, 16), &spec.cipher());
        let mut src = PlainOnly(VecNca(fx.nca.0.clone()));
        for (offset, len) in [(0x1A00u64, LEN), (0x1A00 + 0x123, 1000), (0x1A00 + LEN as u64, 0x4000)] {
            let mut raw = vec![0u8; len];
            src.read_raw(&fx.header, &KEY, offset, &mut raw).unwrap();
            assert_same(&format!("{len:#x} at {offset:#x}"), &raw, &fx.nca.0[offset as usize..][..len]);
        }
        // Whereas what read_plain returns for this section isn't what is stored.
        let mut plain = vec![0u8; 0x100];
        src.read_plain(&fx.header, &KEY, 0x1A00, &mut plain).unwrap();
        assert_ne!(plain, fx.nca.0[0x1A00..0x1B00]);
    }

    // -----------------------------------------------------------------------------------------------------
    // The whole stack, on sections made by `testutil::PatchSection`
    // -----------------------------------------------------------------------------------------------------

    #[test]
    fn patch_sections_read_back_whatever_their_layout() {
        const BASE_ID: u64 = 0x0100_0000_0001_0000;
        const UPDATE_KEY: Key128 =
            [0x33, 0xC0, 0x9A, 0x71, 0x05, 0xE8, 0x4D, 0xB2, 0x6F, 0x19, 0xA4, 0x80, 0x3B, 0xD6, 0x5E, 0xF7];
        let tmp = TempDir::new("bktr");
        let keys = TestKeys::keys(tmp.path());

        let keep = pattern(300_000, 1);
        let changes = pattern(50_000, 2);
        let mut old = ImageBuilder::new();
        old.file("a/keep.bin", &keep);
        old.file("b/change.bin", &changes);
        old.file("gone.bin", &pattern(30_000, 3));
        old.file("c/tail.txt", b"unchanged tail");
        old.dir("empty");
        // Everything after the first file moves.
        let mut shifted = ImageBuilder::new();
        shifted.file("fresh.bin", &pattern(20_000, 4));
        shifted.file("a/keep.bin", &keep);
        shifted.file("b/change.bin", &pattern(50_001, 5));
        shifted.file("c/tail.txt", b"unchanged tail");
        shifted.file("c/more/added.bin", &pattern(3_000, 6));
        shifted.dir("empty");
        // Same layout as the old image, with one file's contents changed.
        let mut edited = ImageBuilder::new();
        edited.file("a/keep.bin", &keep);
        edited.file("b/change.bin", &pattern(50_000, 7));
        edited.file("gone.bin", &pattern(30_000, 3));
        edited.file("c/tail.txt", b"unchanged tail");
        edited.dir("empty");

        let base_section = Section::romfs(old.build());
        let base_plain = base_section.plaintext();
        let base_nca = NcaBuilder::new(NcaContentType::Program, BASE_ID).section(base_section).build(&keys);
        let base_header = NcaHeader::decrypt(&base_nca.bytes, &keys).unwrap();
        let base_key = base_header.section_key(&keys, None).unwrap();

        for (target, new_image) in [("shifted", shifted.build()), ("edited in place", edited.build())] {
            let want = Section::romfs(new_image.clone()).plaintext();
            let new_patch = || PatchSection::new(&base_plain, &new_image);
            let variants: Vec<(&str, PatchSection)> = vec![
                ("defaults", new_patch()),
                ("chunks of 0x200, an entry for each", new_patch().chunk_size(0x200).merge_chunks(false)),
                ("chunks of 0x10", new_patch().chunk_size(0x10)),
                (
                    "a region per block, so several sets of AesCtrEx entries",
                    new_patch().ctr_ex_regions(0x10, &[(3, true), (1, true), (2, false), (0xFFFF_FFFF, true)]),
                ),
                (
                    "generation 0, secure value 0, no gap, regions on 0x200 boundaries",
                    new_patch().generation(0).secure_value(0).table_gap(0).ctr_ex_regions(0x2000, &[(0, true)]),
                ),
                (
                    "largest generation and secure value, a large gap",
                    new_patch().generation(u32::MAX).secure_value(u32::MAX).table_gap(0x1_0000),
                ),
                ("one region", new_patch().ctr_ex_regions(1 << 30, &[(5, true)])),
                ("nothing encrypted", new_patch().ctr_ex_regions(0x3010, &[(1, false)])),
            ];
            for (variant, patch) in variants {
                let label = format!("{target}, {variant}");
                let layout = patch.layout();
                assert_eq!(layout.entries.iter().map(|e| e.len).sum::<u64>(), want.len() as u64, "{label}");
                let update_nca = NcaBuilder::new(NcaContentType::Program, BASE_ID | 0x800)
                    .section_key(UPDATE_KEY)
                    .section(Section::patch(patch))
                    .build(&keys);

                let up_header = NcaHeader::decrypt(&update_nca.bytes, &keys).unwrap();
                let up_key = up_header.section_key(&keys, None).unwrap();
                assert_eq!(up_key, UPDATE_KEY);
                assert_eq!(up_header.section_crypto(0), CRYPT_BKTR, "{label}");
                let info = PatchInfo::parse(&up_header, 0);
                assert_eq!((info.indirect_offset, info.indirect_size), (layout.indirect_offset, layout.indirect_size));
                assert_eq!((info.aes_ctr_ex_offset, info.aes_ctr_ex_size), (layout.ctr_ex_offset, layout.ctr_ex_size));

                let mut base_src = VecNca(base_nca.bytes.clone());
                let mut up_src = VecNca(update_nca.bytes.clone());
                let mut original = NcaSection::new(&mut base_src, &base_header, base_key, 0).unwrap();
                let raw = RawSection::new(&mut up_src, &up_header, up_key, 0).unwrap();
                let mut ex = AesCtrExStorage::new(raw, &up_header, up_key, 0).unwrap();
                assert_eq!(ex.size(), layout.ctr_ex_offset, "{label}");
                let mut patched = IndirectStorage::new(&mut original, &mut ex, &up_header, 0).unwrap();
                assert_eq!(patched.size(), want.len() as u64, "{label}");
                assert_same(&label, &read_vec(&mut patched, 0, want.len()), &want);

                let mut rng = Rng(5);
                for _ in 0..50 {
                    let offset = rng.below(want.len() as u64);
                    let n = 1 + rng.below((want.len() as u64 - offset).min(40_000));
                    assert_same(
                        &label,
                        &read_vec(&mut patched, offset, n as usize),
                        &want[offset as usize..][..n as usize],
                    );
                }

                // The update's own IVFC header finds the new RomFS in it.
                let (offset, size) = nca::ivfc_data_level(&up_header, 0).unwrap();
                assert_eq!(size, new_image.len() as u64, "{label}");
                let mut data = SubStorage::new(&mut patched, offset, size).unwrap();
                assert_same(&label, &read_vec(&mut data, 0, new_image.len()), &new_image);
            }
        }
    }

    // -----------------------------------------------------------------------------------------------------
    // AesCtrEx regions that stop before the tables: the patch meta hash layer, and the hactool fallback
    // -----------------------------------------------------------------------------------------------------

    // A section with a patch meta hash layer (FS header byte 5 = 1, like the updates of Breath of the Wild) keeps both
    // of its tables under the section's ordinary counter (the upper IV from the FS header at 0x140, at the table's
    // absolute offset in the NCA), and its AesCtrEx regions cover only the update's own data: the tree ends at the
    // indirect table (Atmosphère's `CreatePatchMetaStorage`). With the flag that holds even if the regions say they
    // run on over the tables. Without the flag, bytes that no region covers are read with the ordinary counter too,
    // as hactool does. The fixtures write all of this from that description (`PatchSection::meta_hash_layer`,
    // `regions_cover_tables`, `regions_stop_at_indirect`), and the tests read them back through the layers.

    /// A base game, and the RomFS that an update turns its RomFS section into.
    struct Game {
        keys: Keys,
        base_nca: BuiltNca,
        base_plain: Vec<u8>,
        new_image: Vec<u8>,
        /// The patched section, which reading the update through the base game has to give.
        want: Vec<u8>,
    }

    impl Game {
        const BASE_ID: u64 = 0x0100_0000_0001_0000;
        const UPDATE_KEY: Key128 =
            [0x33, 0xC0, 0x9A, 0x71, 0x05, 0xE8, 0x4D, 0xB2, 0x6F, 0x19, 0xA4, 0x80, 0x3B, 0xD6, 0x5E, 0xF7];

        fn new(keys_dir: &Path) -> Self {
            let keys = TestKeys::keys(keys_dir);
            let keep = pattern(120_000, 1);
            let mut old = ImageBuilder::new();
            old.file("a/keep.bin", &keep);
            old.file("b/change.bin", &pattern(50_000, 2));
            old.file("gone.bin", &pattern(30_000, 3));
            old.file("c/tail.txt", b"unchanged tail");
            old.dir("empty");
            // A new first file moves everything after it, and one file changes.
            let mut new = ImageBuilder::new();
            new.file("fresh.bin", &pattern(20_000, 4));
            new.file("a/keep.bin", &keep);
            new.file("b/change.bin", &pattern(50_001, 5));
            new.file("c/tail.txt", b"unchanged tail");
            new.file("c/more/added.bin", &pattern(3_000, 6));
            new.dir("empty");

            let base_section = Section::romfs(old.build());
            let base_plain = base_section.plaintext();
            let base_nca = NcaBuilder::new(NcaContentType::Program, Self::BASE_ID).section(base_section).build(&keys);
            let new_image = new.build();
            let want = Section::romfs(new_image.clone()).plaintext();
            Self { keys, base_nca, base_plain, new_image, want }
        }

        /// A patch from the base game's section to the new one. Chunks of 0x10 find the big file again wherever it
        /// moved to.
        fn patch(&self) -> PatchSection {
            PatchSection::new(&self.base_plain, &self.new_image).chunk_size(0x10)
        }

        /// An update NCA whose only section is `patch`.
        fn update(&self, patch: PatchSection) -> BuiltNca {
            NcaBuilder::new(NcaContentType::Program, Self::BASE_ID | 0x800)
                .section_key(Self::UPDATE_KEY)
                .section(Section::patch(patch))
                .build(&self.keys)
        }

        /// Opens section 0 of `update`, as `header` describes it (which a test may have changed), over the base game's
        /// section. Layer 1 is handed to `on_layer1` before the indirect table is read from it, then the patched
        /// section to `on_patched`. Fails if either layer doesn't open.
        fn open(
            &self,
            update: &BuiltNca,
            header: &NcaHeader,
            on_layer1: impl FnOnce(&mut AesCtrExStorage<'_>),
            on_patched: impl FnOnce(&mut IndirectStorage<'_>),
        ) -> Result<()> {
            let base_header = NcaHeader::decrypt(&self.base_nca.bytes, &self.keys)?;
            let base_key = base_header.section_key(&self.keys, None)?;
            let key = header.section_key(&self.keys, None)?;
            let mut base_src = VecNca(self.base_nca.bytes.clone());
            let mut up_src = VecNca(update.bytes.clone());
            let mut original = NcaSection::new(&mut base_src, &base_header, base_key, 0)?;
            let raw = RawSection::new(&mut up_src, header, key, 0)?;
            let mut ex = AesCtrExStorage::new(raw, header, key, 0)?;
            on_layer1(&mut ex);
            let mut patched = IndirectStorage::new(&mut original, &mut ex, header, 0)?;
            on_patched(&mut patched);
            Ok(())
        }
    }

    /// What layer 1 has to return for `[0, ctr_ex_offset)`: the update's data (the pieces that the indirect entries of
    /// storage 1 read out of `want`, the patched section, and zeros in between), then the indirect table, then zero
    /// padding up to the AesCtrEx table.
    fn layer1_plaintext(layout: &PatchLayout, want: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; layout.ctr_ex_offset as usize];
        for e in layout.entries.iter().filter(|e| e.storage_index == 1) {
            let (virtual_offset, physical_offset, len) = (e.virtual_offset as usize, e.physical_offset as usize, e.len);
            out[physical_offset..][..len as usize].copy_from_slice(&want[virtual_offset..][..len as usize]);
        }
        let encoded: Vec<Vec<u8>> = layout
            .entries
            .iter()
            .map(|e| indirect_entry(e.virtual_offset, e.physical_offset, e.storage_index))
            .collect();
        let table = bucket_tree(&encoded, want.len() as u64);
        assert_eq!(table.len() as u64, layout.indirect_size);
        out[layout.indirect_offset as usize..][..table.len()].copy_from_slice(&table);
        out
    }

    /// How an update ends its AesCtrEx regions.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Ends {
        /// With a patch meta hash layer: at the indirect table.
        MetaHash,
        /// With a patch meta hash layer: at the AesCtrEx table, so over the indirect table.
        MetaHashOverTables,
        /// Without one: at the indirect table.
        NoFlag,
    }

    /// Builds an update from `patch`, checks that it is stored the way `ends` says, and that the layers read it back
    /// byte for byte: layer 1 (the update's data, the indirect table and the padding that follows it) and the patched
    /// section. Returns whether a region starts before the indirect table and runs on into it.
    fn check_patch(game: &Game, label: &str, patch: PatchSection, ends: Ends) -> bool {
        println!("checking {label}");
        let layout = patch.layout();
        let update = game.update(patch);
        let header = NcaHeader::decrypt(&update.bytes, &game.keys).unwrap();
        let (i, c) = (layout.indirect_offset, layout.ctr_ex_offset);
        let over_tables = ends == Ends::MetaHashOverTables;

        // The stored section, taken apart the way the format says rather than through the readers. `ordinary` reads
        // a range of it under the ordinary counter.
        let fs = header.fs_header(0);
        let section = header.section(0).unwrap();
        let section_len = section.end - section.start;
        let counter = Ctr::new(&Game::UPDATE_KEY, header.section_nonce(0));
        let ordinary = |offset: u64, len: u64| {
            let mut bytes = update.bytes[(section.start + offset) as usize..][..len as usize].to_vec();
            counter.apply(section.start + offset, &mut bytes);
            bytes
        };
        assert_eq!(header.section_crypto(0), CRYPT_BKTR, "{label}");
        assert_eq!(fs[5], u8::from(ends != Ends::NoFlag), "{label}: the meta data hash type");
        assert_eq!((u64le(fs, 0x100), u64le(fs, 0x108)), (i, layout.indirect_size), "{label}");
        assert_eq!((u64le(fs, 0x120), u64le(fs, 0x128)), (c, layout.ctr_ex_size), "{label}");
        let ctr_ex_end = c + layout.ctr_ex_size;
        assert!(i + layout.indirect_size <= c, "{label}");
        // Both tables are under the ordinary counter: the L1 node of each says where its tree ends.
        let indirect = ordinary(i, layout.indirect_size);
        assert_eq!((u32le(&indirect, 0), u64le(&indirect, 8)), (0, game.want.len() as u64), "{label}: indirect table");
        let ctr_ex = ordinary(c, layout.ctr_ex_size);
        let tree_end = if over_tables { c } else { i };
        assert_eq!((u32le(&ctr_ex, 0), u64le(&ctr_ex, 8)), (0, tree_end), "{label}: where the AesCtrEx tree ends");
        assert_eq!(layout.regions_end, tree_end, "{label}");
        assert_eq!(layout.ordinary_counter_from, i, "{label}");

        if ends == Ends::NoFlag {
            assert!(fs[0x1A0..0x1D0].iter().all(|&b| b == 0), "{label}: no meta data hash info");
            assert_eq!(layout.meta_hash_size, 0, "{label}");
            assert_eq!(section_len, ctr_ex_end.next_multiple_of(0x200), "{label}: the AesCtrEx table ends the section");
        } else {
            // A blob after the AesCtrEx table, which the section ends after; its info says where, and its hash.
            let (offset, size) = (u64le(fs, 0x1A0), u64le(fs, 0x1A8));
            assert_eq!((offset, size), (layout.meta_hash_offset, META_HASH_SIZE as u64), "{label}");
            assert!(ctr_ex_end <= offset, "{label}: the blob follows the AesCtrEx table");
            let blob_end = (offset + size).next_multiple_of(16);
            assert!(
                blob_end <= section_len && section_len < blob_end + 0x200,
                "{label}: the section ends after the blob"
            );
            let blob = ordinary(offset, size);
            assert!(blob.iter().any(|&b| b != 0), "{label}");
            assert_eq!(Sha256::digest(&blob).as_slice(), &fs[0x1B0..0x1D0], "{label}: the info's hash");
        }

        // The region in force at the indirect table: with the regions over the tables, one with a generation of its
        // own, which is what the table would be wrongly read with. Otherwise none reaches it.
        let at_indirect = layout.regions[layout.regions.partition_point(|r| r.offset <= i) - 1];
        if over_tables {
            let header_generation = u32le(fs, 0x140);
            assert!(at_indirect.encrypted && at_indirect.generation != header_generation, "{label}: {at_indirect:?}");
        } else {
            assert!(layout.regions.iter().all(|r| r.offset < i), "{label}: a region starts past the update's data");
        }

        // Layer 1, in whole, around every boundary and in short reads that start and end on either side of the
        // indirect table, then the patched section.
        let plain = layer1_plaintext(&layout, &game.want);
        let step = (layout.regions.len() / 200).max(1);
        let mut boundaries: Vec<u64> = layout.regions.iter().step_by(step).map(|r| r.offset).collect();
        boundaries.extend([i, i + layout.indirect_size, c]);
        let entry_offsets: Vec<u64> = layout.entries.iter().map(|e| e.virtual_offset).collect();
        game.open(
            &update,
            &header,
            |ex| {
                assert_eq!(ex.size(), c, "{label}");
                check_reads(ex, &plain, &boundaries, 31);
                for lo in i - 40..i + 40 {
                    for len in [1usize, 7, 16, 33, 100] {
                        assert_same(&format!("{len} at {lo:#x}"), &read_vec(ex, lo, len), &plain[lo as usize..][..len]);
                    }
                }
            },
            |patched| check_reads(patched, &game.want, &entry_offsets, 32),
        )
        .unwrap_or_else(|e| panic!("{label}: {e}"));
        over_tables && at_indirect.offset < i
    }

    #[test]
    fn a_meta_hash_layer_keeps_both_tables_under_the_ordinary_counter() {
        let tmp = TempDir::new("bktr-meta-hash");
        let game = Game::new(tmp.path());
        let layered = || game.patch().meta_hash_layer(true);
        let mixed: &[(u32, bool)] = &[(3, true), (1, true), (2, false), (0xFFFF_FFFF, true)];
        let variants: Vec<(&str, PatchSection)> = vec![
            ("defaults", layered()),
            ("a region per block, so several sets of AesCtrEx entries", layered().ctr_ex_regions(0x10, mixed)),
            ("generation 0, secure value 0, no gap", layered().generation(0).secure_value(0).table_gap(0)),
            (
                "largest generation and secure value, a large gap",
                layered().generation(u32::MAX).secure_value(u32::MAX).table_gap(0x1_0000),
            ),
            ("one region", layered().ctr_ex_regions(1 << 30, &[(5, true)])),
            ("nothing encrypted by regions", layered().ctr_ex_regions(0x3010, &[(1, false)])),
        ];
        for (label, patch) in variants {
            let layout = patch.layout();
            assert!(layout.indirect_offset > 0x10000 && layout.indirect_size > BUCKET_NODE_SIZE as u64, "{label}");
            assert!(!check_patch(&game, label, patch, Ends::MetaHash), "{label}: regions run on into the tables");
        }
    }

    #[test]
    fn a_meta_hash_layer_wins_over_regions_that_run_over_the_tables() {
        let tmp = TempDir::new("bktr-meta-hash-over");
        let game = Game::new(tmp.path());
        let over = || game.patch().meta_hash_layer(true).regions_cover_tables(true);
        // Every region is encrypted, with a generation other than the header's (4, unless a variant says otherwise).
        let own: &[(u32, bool)] = &[(1, true), (2, true), (6, true)];
        let indirect_offset = game.patch().layout().indirect_offset as usize;
        // Each variant, and whether a region starts before the indirect table and runs on into it (regions of 0x10
        // can't, and neither can one that starts where the table does).
        let variants: Vec<(&str, PatchSection, bool)> = vec![
            ("defaults, but encrypted", over().ctr_ex_regions(0x2A10, own), true),
            (
                "a region per block, so several sets of AesCtrEx entries",
                over().ctr_ex_regions(0x10, &[(3, true), (1, true)]),
                false,
            ),
            (
                "generation 0, secure value 0, no gap",
                over().generation(0).secure_value(0).table_gap(0).ctr_ex_regions(0x2A10, own),
                true,
            ),
            (
                "largest secure value, a large gap",
                over().generation(u32::MAX).secure_value(u32::MAX).table_gap(0x1_0000).ctr_ex_regions(0x2A10, own),
                true,
            ),
            ("one region over everything", over().ctr_ex_regions(1 << 30, &[(5, true)]), true),
            (
                "a region starts at the indirect table",
                over().ctr_ex_regions(indirect_offset, &[(1, true), (2, true)]),
                false,
            ),
        ];
        for (label, patch, straddles) in variants {
            let layout = patch.layout();
            assert_eq!(layout.regions_end, layout.ctr_ex_offset, "{label}");
            let got = check_patch(&game, label, patch, Ends::MetaHashOverTables);
            assert_eq!(got, straddles, "{label}: whether a region straddles the start of the indirect table");
        }
    }

    #[test]
    fn regions_that_stop_at_the_indirect_table_leave_the_rest_under_the_ordinary_counter() {
        let tmp = TempDir::new("bktr-stop-early");
        let game = Game::new(tmp.path());
        let early = || game.patch().regions_stop_at_indirect(true);
        let mixed: &[(u32, bool)] = &[(3, true), (1, true), (2, false), (0xFFFF_FFFF, true)];
        let variants: Vec<(&str, PatchSection)> = vec![
            ("defaults", early()),
            ("a region per block, so several sets of AesCtrEx entries", early().ctr_ex_regions(0x10, mixed)),
            ("generation 0, secure value 0, no gap", early().generation(0).secure_value(0).table_gap(0)),
            (
                "largest generation and secure value, a large gap",
                early().generation(u32::MAX).secure_value(u32::MAX).table_gap(0x1_0000),
            ),
            ("one region", early().ctr_ex_regions(1 << 30, &[(5, true)])),
            ("nothing encrypted by regions", early().ctr_ex_regions(0x3010, &[(1, false)])),
        ];
        for (label, patch) in variants {
            assert!(!check_patch(&game, label, patch, Ends::NoFlag), "{label}: regions run on into the tables");
        }
    }

    #[test]
    fn the_meta_hash_flag_decides_which_counter_the_indirect_table_is_read_with() {
        let tmp = TempDir::new("bktr-flag");
        let game = Game::new(tmp.path());
        // Every region is encrypted, with a generation other than the header's (4): an indirect table read with the
        // counter of the region that covers it can't come out right by chance.
        let own: &[(u32, bool)] = &[(1, true), (2, true), (6, true)];
        let garbage = "indirect table has a bad";
        let never = |_: &mut IndirectStorage<'_>| panic!("the indirect table was accepted");

        // The tables are stored under the ordinary counter, the regions run on over them, and the flag is set: this
        // reads back.
        let patch = game.patch().meta_hash_layer(true).regions_cover_tables(true).ctr_ex_regions(0x2A10, own);
        let layout = patch.layout();
        let flagged = game.update(patch);
        let mut header = NcaHeader::decrypt(&flagged.bytes, &game.keys).unwrap();
        assert_eq!(header.fs_header(0)[5], 1);
        game.open(&flagged, &header, |_| {}, |patched| check_reads(patched, &game.want, &[], 1)).unwrap();

        // The very same bytes with the flag cleared: layer 1 now decrypts the indirect table with the counter of the
        // region covering it, which gives garbage, and the table is refused.
        header.fs_header_mut(0)[5] = 0;
        let (i, len) = (layout.indirect_offset, layout.indirect_size as usize);
        let plain = layer1_plaintext(&layout, &game.want);
        let table_is_garbage = |ex: &mut AesCtrExStorage<'_>| {
            assert_ne!(read_vec(ex, i, len), plain[i as usize..][..len], "the table read with the regions' counters");
        };
        assert_fails(game.open(&flagged, &header, table_is_garbage, never), garbage);

        // And the other way round: an update that has the regions cover the indirect table and encrypts it with their
        // counters, with no flag, reads back; the same bytes with the flag set don't.
        let patch = game.patch().ctr_ex_regions(0x2A10, own);
        let layout = patch.layout();
        assert_eq!((layout.regions_end, layout.ordinary_counter_from), (layout.ctr_ex_offset, layout.ctr_ex_offset));
        let unflagged = game.update(patch);
        let mut header = NcaHeader::decrypt(&unflagged.bytes, &game.keys).unwrap();
        assert_eq!(header.fs_header(0)[5], 0);
        game.open(&unflagged, &header, |_| {}, |patched| check_reads(patched, &game.want, &[], 2)).unwrap();
        header.fs_header_mut(0)[5] = 1;
        let (i, len) = (layout.indirect_offset, layout.indirect_size as usize);
        let plain = layer1_plaintext(&layout, &game.want);
        let table_is_garbage = |ex: &mut AesCtrExStorage<'_>| {
            assert_ne!(read_vec(ex, i, len), plain[i as usize..][..len], "the table read with the ordinary counter");
        };
        assert_fails(game.open(&unflagged, &header, table_is_garbage, never), garbage);

        // Where the regions stop at the indirect table anyway, the flag makes no difference.
        let layered = game.update(game.patch().meta_hash_layer(true));
        let stopped = game.update(game.patch().regions_stop_at_indirect(true));
        for (what, update, flag) in
            [("a meta hash layer, flag cleared", &layered, 0), ("no layer, flag set", &stopped, 1)]
        {
            let mut header = NcaHeader::decrypt(&update.bytes, &game.keys).unwrap();
            header.fs_header_mut(0)[5] = flag;
            game.open(update, &header, |_| {}, |patched| check_reads(patched, &game.want, &[], 3))
                .unwrap_or_else(|e| panic!("{what}: {e}"));
        }
    }
}
