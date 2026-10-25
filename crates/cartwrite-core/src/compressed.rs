//! Compressed storage, used by many newer NCAs (`CompressedStorage` in Atmosphère).
//!
//! It sits on top of a section's data level (after the hash layer): the first
//! `table_offset` bytes of that level hold the compressed data, followed by a bucket tree
//! mapping virtual ranges to it. Each entry is stored as-is, implied zeros, or an LZ4 block
//! that decompresses to exactly the entry's virtual size.

use crate::bktr::{BucketEntry, BucketTree};
use crate::error::{fmt_err, Error, Result};
use crate::nca::NcaHeader;
use crate::storage::{Storage, SubStorage};
use crate::util::{u32le, u64le};

const TYPE_NONE: u8 = 0;
const TYPE_ZEROS: u8 = 1;
const TYPE_LZ4: u8 = 3;
/// LZ4 blocks start on this boundary.
const BLOCK_ALIGNMENT: u64 = 0x10;
/// Atmosphère reads at most 64 KiB per compressed block; allow headroom for odd content.
const MAX_BLOCK_SIZE: u64 = 4 << 20;

/// The compression fields of a section's FS header (`NcaCompressionInfo`, at 0x178).
#[derive(Clone, Copy, Debug)]
pub struct CompressionInfo {
    pub table_offset: u64,
    pub table_size: u64,
    pub header: [u8; 0x10],
}

impl CompressionInfo {
    /// `None` if section `i` isn't compressed (`ExistsCompressionLayer`).
    pub fn parse(header: &NcaHeader, i: usize) -> Option<Self> {
        let fs = header.fs_header(i);
        let info = Self {
            table_offset: u64le(fs, 0x178),
            table_size: u64le(fs, 0x180),
            header: fs[0x188..0x198].try_into().unwrap(),
        };
        (info.table_offset != 0 && info.table_size != 0).then_some(info)
    }
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    virt_offset: u64,
    phys_offset: u64,
    compression_type: u8,
    phys_size: u32,
}

impl BucketEntry for Entry {
    const SIZE: usize = 0x18;
    fn parse(b: &[u8]) -> Self {
        Self {
            virt_offset: u64le(b, 0),
            phys_offset: u64le(b, 8),
            compression_type: b[0x10],
            phys_size: u32le(b, 0x14),
        }
    }
    fn offset(&self) -> u64 {
        self.virt_offset
    }
}

/// The decompressed view of a compressed data level.
pub struct CompressedStorage<'a> {
    /// The compressed data: `[0, table_offset)` of the data level.
    data: SubStorage<'a>,
    table: BucketTree<Entry>,
    /// The most recently decompressed block (entry index, bytes), since reads usually walk
    /// forward through a block in several pieces.
    cached: Option<(usize, Vec<u8>)>,
}

impl<'a> CompressedStorage<'a> {
    /// `level` is the section's data level (what the hash layer verifies).
    pub fn new(level: &'a mut dyn Storage, info: &CompressionInfo) -> Result<Self> {
        let table: BucketTree<Entry> = {
            let mut meta = SubStorage::new(&mut *level, info.table_offset, info.table_size)?;
            BucketTree::read(&mut meta, &info.header, "compression")?
        };
        if table.start() != 0 {
            return fmt_err("compression table doesn't start at offset 0");
        }
        for (i, e) in table.entries.iter().enumerate() {
            let virt_size = table.entry_end(i) - e.virt_offset;
            let phys_size = match e.compression_type {
                TYPE_NONE => virt_size,
                // No stored data, so its physical offset means nothing.
                TYPE_ZEROS => continue,
                TYPE_LZ4 => {
                    if e.phys_offset % BLOCK_ALIGNMENT != 0 || e.phys_size as u64 > MAX_BLOCK_SIZE {
                        return fmt_err(format!("bad compressed block at {:#x}", e.virt_offset));
                    }
                    if virt_size > MAX_BLOCK_SIZE {
                        return fmt_err(format!("compressed block at {:#x} is implausibly large", e.virt_offset));
                    }
                    e.phys_size as u64
                }
                t => return Err(Error::Unsupported(format!("unsupported compression type {t}"))),
            };
            if e.phys_offset.checked_add(phys_size).is_none_or(|end| end > info.table_offset) {
                return fmt_err(format!("compressed block at {:#x} points outside the data", e.virt_offset));
            }
        }
        let data = SubStorage::new(level, 0, info.table_offset)?;
        Ok(Self { data, table, cached: None })
    }

    fn block(&mut self, i: usize) -> Result<&[u8]> {
        if self.cached.as_ref().is_none_or(|(c, _)| *c != i) {
            let e = self.table.entries[i];
            let virt_size = (self.table.entry_end(i) - e.virt_offset) as usize;
            let mut src = vec![0u8; e.phys_size as usize];
            self.data.read(e.phys_offset, &mut src)?;
            let mut out = vec![0u8; virt_size];
            match lz4_flex::block::decompress_into(&src, &mut out) {
                Ok(n) if n == virt_size => {}
                _ => return fmt_err(format!("compressed block at {:#x} is corrupt", e.virt_offset)),
            }
            self.cached = Some((i, out));
        }
        Ok(&self.cached.as_ref().unwrap().1)
    }
}

impl Storage for CompressedStorage<'_> {
    fn size(&self) -> u64 {
        self.table.end
    }

    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        self.table.check_range(offset, buf.len(), "compression")?;
        let end = offset + buf.len() as u64;
        let mut i = self.table.find(offset);
        let mut pos = offset;
        while pos < end {
            let e = self.table.entries[i];
            let piece_end = self.table.entry_end(i).min(end);
            let within = (pos - e.virt_offset) as usize;
            let out = &mut buf[(pos - offset) as usize..(piece_end - offset) as usize];
            match e.compression_type {
                TYPE_NONE => self.data.read(e.phys_offset + within as u64, out)?,
                TYPE_ZEROS => out.fill(0),
                _ => {
                    let len = out.len();
                    out.copy_from_slice(&self.block(i)?[within..within + len]);
                }
            }
            pos = piece_end;
            i += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;
    use crate::nca::HEADER_SIZE;
    use crate::testutil::{
        bucket_tree, bucket_tree_header, compression_entry, pattern, BUCKET_NODE_SIZE, CMP_LZ4, CMP_NONE, CMP_ZEROS,
    };

    // These tests describe compressed storage from the format (Atmosphere's `CompressedStorage`: a bucket tree of
    // 0x18-byte entries over stored, zero and LZ4-block ranges, behind the compression info at 0x178 of the FS
    // header) and check the reader against that. Their fixtures are written out here from the description, with the
    // bucket tree layout from `testutil`; nothing in them comes from the code under test.

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

    /// Fails with a short message (not a dump of kilobytes) if the two differ.
    fn assert_same(what: &str, got: &[u8], want: &[u8]) {
        if got != want {
            let first = got.iter().zip(want).position(|(a, b)| a != b);
            panic!("{what}: got {} bytes, want {}; first difference at {first:?}", got.len(), want.len());
        }
    }

    fn read_vec(s: &mut dyn Storage, offset: u64, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        s.read(offset, &mut buf).unwrap_or_else(|e| panic!("reading {len:#x} bytes at {offset:#x}: {e}"));
        buf
    }

    /// Highly compressible data: a short phrase over and over.
    fn text(len: usize) -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog; ".iter().copied().cycle().take(len).collect()
    }

    /// Half incompressible, half repetitive.
    fn mixed_data(len: usize, seed: u64) -> Vec<u8> {
        let mut v = pattern(len / 2, seed);
        v.extend(text(len - len / 2));
        v
    }

    /// A table entry as the format has it.
    #[derive(Clone, Copy)]
    struct Raw {
        virt: u64,
        phys: u64,
        ty: u8,
        size: u32,
    }

    /// The data level made of `data` followed by a table of `entries` that ends at `end`, and the compression info
    /// that describes it.
    fn assemble(data: &[u8], entries: &[Raw], end: u64) -> (Vec<u8>, CompressionInfo) {
        let encoded: Vec<Vec<u8>> = entries.iter().map(|e| compression_entry(e.virt, e.phys, e.ty, e.size)).collect();
        let table = bucket_tree(&encoded, end);
        let mut level = data.to_vec();
        level.extend_from_slice(&table);
        let info = CompressionInfo {
            table_offset: data.len() as u64,
            table_size: table.len() as u64,
            header: bucket_tree_header(entries.len()),
        };
        (level, info)
    }

    fn open<'a>(level: &'a mut Vec<u8>, info: &CompressionInfo) -> Result<CompressedStorage<'a>> {
        CompressedStorage::new(level, info)
    }

    /// A raw LZ4 block, as the format wants it.
    fn lz4(data: &[u8]) -> Vec<u8> {
        lz4_flex::block::compress(data)
    }

    // -----------------------------------------------------------------------------------------------------
    // The compression info in the FS header
    // -----------------------------------------------------------------------------------------------------

    /// An NCA header whose FS headers are full of junk, except for the compression info of `section`.
    fn header_with_info(section: usize, offset: u64, size: u64, tree: [u8; 0x10]) -> NcaHeader {
        let mut h = NcaHeader { raw: Box::new([0xEE; HEADER_SIZE]) };
        for i in 0..4 {
            let fs = h.fs_header_mut(i);
            // SparseInfo and everything after the compression info are junk, the compression info itself is empty.
            fs[0x178..0x1A0].fill(0);
            if i == section {
                fs[0x178..0x180].copy_from_slice(&offset.to_le_bytes());
                fs[0x180..0x188].copy_from_slice(&size.to_le_bytes());
                fs[0x188..0x198].copy_from_slice(&tree);
            }
        }
        h
    }

    #[test]
    fn compression_info_is_read_from_the_documented_offsets() {
        let tree = bucket_tree_header(77);
        // Neither half of either number is zero by itself, so a 32-bit read of them would be wrong.
        let (offset, size) = (0x1_2345_6000u64, 0x2_0000_4000u64);
        for section in 0..4 {
            let h = header_with_info(section, offset, size, tree);
            let info = CompressionInfo::parse(&h, section).expect("the section is compressed");
            assert_eq!((info.table_offset, info.table_size), (offset, size), "section {section}");
            assert_eq!(info.header, tree, "section {section}");
            assert_eq!(&info.header[..4], b"BKTR");
            // The other sections' FS headers say nothing about compression.
            for other in (0..4).filter(|&o| o != section) {
                assert!(CompressionInfo::parse(&h, other).is_none(), "section {other} next to section {section}");
            }
        }
    }

    #[test]
    fn a_section_is_compressed_only_with_both_a_table_offset_and_size() {
        let tree = bucket_tree_header(1);
        for (offset, size, compressed) in [
            (0x4000, 0x4000, true),
            (1, 1, true),
            (0x1_0000_0000, 0x1_0000_0000, true),
            (0, 0x4000, false),
            (0x4000, 0, false),
            (0, 0, false),
        ] {
            let h = header_with_info(1, offset, size, tree);
            assert_eq!(CompressionInfo::parse(&h, 1).is_some(), compressed, "offset {offset:#x}, size {size:#x}");
        }
        // A bucket tree header alone, without the table, doesn't make a compression layer either.
        let h = header_with_info(0, 0, 0, tree);
        assert!(CompressionInfo::parse(&h, 0).is_none());
    }

    // -----------------------------------------------------------------------------------------------------
    // Reading
    // -----------------------------------------------------------------------------------------------------

    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Kind {
        Stored,
        Zeros,
        Lz4,
    }

    /// A compressed data level and the image it decompresses to.
    struct Fixture {
        level: Vec<u8>,
        info: CompressionInfo,
        want: Vec<u8>,
        /// Where each entry starts in the image.
        starts: Vec<u64>,
        entries: Vec<Raw>,
    }

    /// Stores `ranges` (how, and the image bytes) one entry each. The stored data goes in a shuffled order with
    /// gaps of junk between the blocks (LZ4 blocks 16-byte aligned, stored ones anywhere), a zeros entry points
    /// anywhere in the data, a stored entry's `physical_size` is whatever, and the table follows at an odd offset.
    fn fixture(ranges: &[(Kind, Vec<u8>)], seed: u64) -> Fixture {
        let mut rng = Rng(seed);
        let mut order: Vec<usize> = (0..ranges.len()).collect();
        for i in (1..order.len()).rev() {
            order.swap(i, rng.below(i as u64 + 1) as usize);
        }
        let mut data = Vec::new();
        let mut stored = vec![(0u64, 0u32); ranges.len()];
        for &i in &order {
            let (kind, bytes) = &ranges[i];
            data.extend(pattern(rng.below(40) as usize, rng.draw()));
            match kind {
                Kind::Stored => {
                    stored[i] = (data.len() as u64, bytes.len() as u32);
                    data.extend_from_slice(bytes);
                }
                Kind::Lz4 => {
                    data.resize(data.len().next_multiple_of(16), 0xA7);
                    let block = lz4(bytes);
                    stored[i] = (data.len() as u64, block.len() as u32);
                    data.extend(block);
                }
                Kind::Zeros => assert!(bytes.iter().all(|&b| b == 0), "a zeros entry covers zeros"),
            }
        }
        data.extend(pattern(1 + rng.below(8) as usize, rng.draw()));

        let (mut entries, mut want, mut starts) = (Vec::new(), Vec::new(), Vec::new());
        for (i, (kind, bytes)) in ranges.iter().enumerate() {
            let virt = want.len() as u64;
            let entry = match kind {
                Kind::Zeros => Raw { virt, phys: rng.below(data.len() as u64 + 1), ty: CMP_ZEROS, size: 0 },
                Kind::Lz4 => Raw { virt, phys: stored[i].0, ty: CMP_LZ4, size: stored[i].1 },
                Kind::Stored => {
                    // The size isn't used for reading stored ranges.
                    let size = [stored[i].1, 0, stored[i].1 + 0x1000][i % 3];
                    Raw { virt, phys: stored[i].0, ty: CMP_NONE, size }
                }
            };
            entries.push(entry);
            starts.push(virt);
            want.extend_from_slice(bytes);
        }
        let (level, info) = assemble(&data, &entries, want.len() as u64);
        Fixture { level, info, want, starts, entries }
    }

    /// Reads all of `s`, every byte on its own, both sides of each of `starts` (and of the end), reads from the middle
    /// of each range to the middle of ones further on, and random ranges, and checks them against `want`.
    fn check_reads(s: &mut dyn Storage, want: &[u8], starts: &[u64], seed: u64) {
        let len = want.len() as u64;
        assert_eq!(s.size(), len);
        assert_same("all", &read_vec(s, 0, want.len()), want);
        for (i, expected) in want.iter().enumerate() {
            assert_eq!(read_vec(s, i as u64, 1)[0], *expected, "byte {i:#x}");
        }
        for &b in starts.iter().chain([&len]) {
            let around =
                [(b.saturating_sub(1), b + 1), (b.saturating_sub(5), b + 7), (b, b + 3), (b.saturating_sub(3), b)];
            for (lo, hi) in around {
                let (lo, hi) = (lo.min(len), hi.min(len));
                if lo < hi {
                    assert_same(
                        &format!("{lo:#x}..{hi:#x}"),
                        &read_vec(s, lo, (hi - lo) as usize),
                        &want[lo as usize..hi as usize],
                    );
                }
            }
        }
        let ends: Vec<u64> = starts.iter().skip(1).copied().chain([len]).collect();
        let mids: Vec<u64> = starts.iter().zip(&ends).map(|(a, b)| (a + b) / 2).collect();
        for from in 0..mids.len() {
            for ahead in [1, 2, 5, 11] {
                let Some(&to) = mids.get(from + ahead) else { continue };
                let lo = mids[from];
                assert_same(
                    &format!("{lo:#x}..{to:#x}"),
                    &read_vec(s, lo, (to - lo) as usize),
                    &want[lo as usize..to as usize],
                );
            }
        }
        let mut rng = Rng(seed);
        for i in 0..400 {
            let offset = rng.below(len);
            let cap = if i % 10 == 0 { 100_000 } else { 4000 };
            let n = 1 + rng.below((len - offset).min(cap));
            assert_same(
                &format!("{n} at {offset}"),
                &read_vec(s, offset, n as usize),
                &want[offset as usize..][..n as usize],
            );
        }
    }

    /// Ranges of every kind in every size that matters: one byte, a few, a block's worth, tens of KiB.
    fn mixed_ranges() -> Vec<(Kind, Vec<u8>)> {
        vec![
            (Kind::Lz4, text(0x10000)), // highly compressible: a few hundred bytes stored
            (Kind::Stored, pattern(0x1000, 1)),
            (Kind::Zeros, vec![0; 0x2345]),
            (Kind::Lz4, pattern(0x1000, 2)), // incompressible: more bytes stored than it covers
            (Kind::Lz4, pattern(1, 3)),
            (Kind::Stored, pattern(1, 4)),
            (Kind::Zeros, vec![0; 1]),
            (Kind::Lz4, mixed_data(0x3001, 5)),
            (Kind::Stored, pattern(0x7F, 6)),
            (Kind::Lz4, pattern(17, 7)),
            (Kind::Lz4, vec![0; 0x2000]),   // zeros, but stored as an LZ4 block
            (Kind::Stored, vec![0; 0x100]), // zeros, stored as is
            (Kind::Zeros, vec![0; 0x10000]),
            (Kind::Lz4, text(0x1235)),
            (Kind::Stored, mixed_data(0x2001, 8)),
            (Kind::Lz4, pattern(0x400, 9)),
            (Kind::Stored, pattern(33, 10)),
        ]
    }

    #[test]
    fn mixed_entries_read_back_byte_for_byte() {
        let ranges = mixed_ranges();
        let mut table_offsets = Vec::new();
        for seed in [1, 2, 3] {
            let mut fx = fixture(&ranges, seed);
            // The fixture is what it claims to be: the image is the ranges end to end, the compressible block is
            // small, the incompressible one is bigger than what it covers, and the data isn't in image order.
            assert_eq!(fx.want.len(), ranges.iter().map(|r| r.1.len()).sum::<usize>());
            assert!(fx.entries[0].size < 0x400 && fx.entries[3].size > 0x1000, "seed {seed}");
            let in_data: Vec<u64> = fx.entries.iter().filter(|e| e.ty != CMP_ZEROS).map(|e| e.phys).collect();
            assert!(!in_data.is_sorted(), "seed {seed}: the stored data is in the order of the image");
            table_offsets.push(fx.info.table_offset);

            let mut s = open(&mut fx.level, &fx.info).unwrap();
            check_reads(&mut s, &fx.want, &fx.starts, seed);
        }
        assert!(
            table_offsets.iter().any(|o| o % 16 != 0),
            "the table should start at an odd offset: {table_offsets:?}"
        );
    }

    #[test]
    fn the_level_may_run_on_past_the_table() {
        let mut fx = fixture(&mixed_ranges(), 4);
        fx.level.extend(pattern(1000, 99));
        let mut s = open(&mut fx.level, &fx.info).unwrap();
        check_reads(&mut s, &fx.want, &fx.starts, 4);
    }

    #[test]
    fn the_reserved_bytes_of_an_entry_are_ignored() {
        let mut fx = fixture(&mixed_ranges(), 9);
        // The entries all sit in the first entry set, after the L1 node and the set's 0x10-byte header.
        let first = fx.info.table_offset as usize + BUCKET_NODE_SIZE + 0x10;
        for i in 0..fx.entries.len() {
            let at = first + i * 0x18;
            assert_eq!(fx.level[at + 0x10], fx.entries[i].ty, "entry {i} is where it is meant to be");
            fx.level[at + 0x11..at + 0x14].fill(0xA5);
        }
        let mut s = open(&mut fx.level, &fx.info).unwrap();
        check_reads(&mut s, &fx.want, &fx.starts, 9);
    }

    #[test]
    fn a_table_with_several_entry_sets() {
        // 1500 entries of 0x18 bytes: 682 fit in a set, so three.
        let kinds = [Kind::Stored, Kind::Zeros, Kind::Lz4, Kind::Lz4, Kind::Stored];
        let ranges: Vec<(Kind, Vec<u8>)> = (0..1500usize)
            .map(|i| {
                let len = 1 + (i * 37) % 60;
                let kind = kinds[i % kinds.len()];
                (kind, if kind == Kind::Zeros { vec![0; len] } else { pattern(len, i as u64) })
            })
            .collect();
        let mut fx = fixture(&ranges, 5);
        assert_eq!(fx.info.table_size as usize, 4 * BUCKET_NODE_SIZE);
        assert_eq!(fx.info.header, bucket_tree_header(1500));
        let mut s = open(&mut fx.level, &fx.info).unwrap();
        // The seam between the first and second sets, and between the second and third.
        for first_of_set in [682usize, 1364] {
            let at = fx.starts[first_of_set];
            assert_same("seam", &read_vec(&mut s, at - 20, 40), &fx.want[at as usize - 20..at as usize + 20]);
        }
        check_reads(&mut s, &fx.want, &fx.starts, 6);
    }

    #[test]
    fn a_single_entry_covers_the_whole_image() {
        let cases = [
            (Kind::Stored, pattern(100, 1)),
            (Kind::Stored, pattern(1, 2)),
            (Kind::Zeros, vec![0; 100]),
            (Kind::Zeros, vec![0; 1]),
            (Kind::Lz4, pattern(100, 3)),
            (Kind::Lz4, text(5000)),
            (Kind::Lz4, vec![7; 1]),
        ];
        for (n, case) in cases.into_iter().enumerate() {
            let mut fx = fixture(std::slice::from_ref(&case), n as u64);
            assert_eq!(fx.entries.len(), 1);
            let mut s = open(&mut fx.level, &fx.info).unwrap();
            check_reads(&mut s, &case.1, &[0], 7);
        }
    }

    // -----------------------------------------------------------------------------------------------------
    // The block cache
    // -----------------------------------------------------------------------------------------------------

    /// A data level that counts the reads that reach the compressed data (not the table).
    struct Counting {
        level: Vec<u8>,
        data_len: u64,
        reads: Rc<Cell<u32>>,
    }

    impl Storage for Counting {
        fn size(&self) -> u64 {
            self.level.size()
        }

        fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
            if offset < self.data_len {
                self.reads.set(self.reads.get() + 1);
            }
            self.level.read(offset, buf)
        }
    }

    const A_LEN: usize = 0x3000;
    const MID_LEN: usize = 0x300;
    const B_LEN: usize = 0x2345;
    /// Where block B starts in the image of [`TwoBlocks`]; block A starts at 0.
    const B_START: usize = A_LEN + MID_LEN;

    /// An image of two LZ4 blocks with a stored range between them (so `A_LEN`, `MID_LEN` and `B_LEN` bytes).
    struct TwoBlocks {
        level: Counting,
        /// Reads that reached the compressed data so far.
        reads: Rc<Cell<u32>>,
        info: CompressionInfo,
        want: Vec<u8>,
    }

    fn two_blocks() -> TwoBlocks {
        let ranges = [
            (Kind::Lz4, mixed_data(A_LEN, 11)),
            (Kind::Stored, pattern(MID_LEN, 12)),
            (Kind::Lz4, mixed_data(B_LEN, 13)),
        ];
        let fx = fixture(&ranges, 8);
        let reads = Rc::new(Cell::new(0));
        let level = Counting { level: fx.level, data_len: fx.info.table_offset, reads: Rc::clone(&reads) };
        TwoBlocks { level, reads, info: fx.info, want: fx.want }
    }

    #[test]
    fn small_reads_within_one_lz4_block_return_the_right_bytes_and_fetch_it_once() {
        let mut fx = two_blocks();
        let mut s = CompressedStorage::new(&mut fx.level, &fx.info).unwrap();
        let before = fx.reads.get();
        // All of block A in pieces of 1 to 13 bytes.
        let mut pos = 0;
        let mut n = 1;
        while pos < A_LEN {
            let len = n.min(A_LEN - pos);
            assert_same(&format!("{len} at {pos}"), &read_vec(&mut s, pos as u64, len), &fx.want[pos..pos + len]);
            pos += len;
            n = n % 13 + 1;
        }
        assert_eq!(fx.reads.get() - before, 1, "block A should be fetched once for all those reads");

        // All of block B in pieces of 7 bytes, from the back.
        let before = fx.reads.get();
        let mut pos = B_START + B_LEN;
        while pos > B_START {
            let len = 7.min(pos - B_START);
            pos -= len;
            assert_same(&format!("{len} at {pos}"), &read_vec(&mut s, pos as u64, len), &fx.want[pos..pos + len]);
        }
        assert_eq!(fx.reads.get() - before, 1, "block B should be fetched once for all those reads");
    }

    #[test]
    fn reads_that_alternate_between_two_lz4_blocks_return_the_right_bytes() {
        let mut fx = two_blocks();
        let mut s = CompressedStorage::new(&mut fx.level, &fx.info).unwrap();
        let mut rng = Rng(21);
        for _ in 0..200 {
            let pa = rng.below(A_LEN as u64 - 40) as usize;
            let pb = B_START + rng.below(B_LEN as u64 - 40) as usize;
            let (la, lb) = (1 + rng.below(40) as usize, 1 + rng.below(40) as usize);
            assert_same("in A", &read_vec(&mut s, pa as u64, la), &fx.want[pa..pa + la]);
            assert_same("in B", &read_vec(&mut s, pb as u64, lb), &fx.want[pb..pb + lb]);
        }
        // A read from the end of A, across the stored range, to the start of B, between reads of each on its own.
        let (lo, hi) = (A_LEN - 100, B_START + 100);
        assert_same("A to B", &read_vec(&mut s, lo as u64, hi - lo), &fx.want[lo..hi]);
        assert_same("in A again", &read_vec(&mut s, 5, 50), &fx.want[5..55]);
        assert_same("A to B again", &read_vec(&mut s, lo as u64, hi - lo), &fx.want[lo..hi]);
        assert_same("in B again", &read_vec(&mut s, B_START as u64 + 5, 50), &fx.want[B_START + 5..B_START + 55]);
        assert_same("in A once more", &read_vec(&mut s, A_LEN as u64 - 50, 50), &fx.want[A_LEN - 50..A_LEN]);
    }

    // -----------------------------------------------------------------------------------------------------
    // Tables that can't be read
    // -----------------------------------------------------------------------------------------------------

    /// The way an LZ4 range of `data` is stored at `at` (16-byte aligned or not), with the table after it.
    fn lz4_at(at: usize, data: &[u8]) -> Result<()> {
        let block = lz4(data);
        let mut stored = vec![0xA5; at];
        stored.extend_from_slice(&block);
        let entry = Raw { virt: 0, phys: at as u64, ty: CMP_LZ4, size: block.len() as u32 };
        let (mut level, info) = assemble(&stored, &[entry], data.len() as u64);
        let mut s = open(&mut level, &info)?;
        assert_same("the range", &read_vec(&mut s, 0, data.len()), data);
        Ok(())
    }

    #[test]
    fn lz4_blocks_must_start_on_16_byte_boundaries() {
        let data = pattern(300, 1);
        for at in [0, 16, 32, 0x1000, 0x1230] {
            lz4_at(at, &data).unwrap_or_else(|e| panic!("block at {at:#x}: {e}"));
        }
        for at in [1, 4, 8, 15, 17, 24, 31, 0x1008, 0x1231] {
            assert_fails(lz4_at(at, &data), "bad compressed block at 0x0");
        }
    }

    #[test]
    fn the_stored_data_of_an_entry_must_lie_before_the_table() {
        let block = lz4(&pattern(100, 2));
        let stored = pattern(100, 3);
        let n = block.len() as u32;
        // `data` is all the stored data there is (so it ends where the table starts), `entries` end at `end`.
        let check = |data: &[u8], entries: &[Raw], end: u64, expected: Option<&str>| {
            let (mut level, info) = assemble(data, entries, end);
            match (open(&mut level, &info), expected) {
                (Ok(_), None) => {}
                (Ok(_), Some(msg)) => panic!("accepted, but should have failed with {msg:?}"),
                (Err(e), None) => panic!("rejected: {e}"),
                (Err(e), Some(msg)) => {
                    assert!(e.to_string().contains(msg), "expected an error mentioning {msg:?}, got {e}")
                }
            }
        };
        let outside = Some("points outside the data");
        let none = |phys, virt_len: u64| {
            [
                Raw { virt: 0, phys, ty: CMP_NONE, size: virt_len as u32 },
                Raw { virt: virt_len, phys: 0, ty: CMP_ZEROS, size: 0 },
            ]
        };

        // Stored ranges: up to the last stored byte is fine, one more is not.
        check(&stored, &none(0, 100), 150, None);
        check(&stored, &none(0, 101), 150, outside);
        check(&stored, &none(1, 100), 150, outside);
        check(&stored, &none(99, 1), 150, None);
        check(&stored, &none(100, 1), 150, outside);
        // The size field doesn't matter for them.
        check(&stored, &[Raw { virt: 0, phys: 0, ty: CMP_NONE, size: 0 }], 100, None);
        check(&stored, &[Raw { virt: 0, phys: 0, ty: CMP_NONE, size: 7 }], 101, outside);
        check(&stored, &[Raw { virt: 0, phys: 0, ty: CMP_NONE, size: 5000 }], 100, None);
        // What counts is how much of the image the range covers, whatever the size field says: this one would read
        // into the table.
        check(&stored, &[Raw { virt: 0, phys: 50, ty: CMP_NONE, size: 50 }], 1000, outside);

        // LZ4 blocks: the whole block has to be inside.
        let lz4_entry = |phys, size| [Raw { virt: 0, phys, ty: CMP_LZ4, size }];
        check(&block, &lz4_entry(0, n), 100, None);
        check(&block, &lz4_entry(0, n + 1), 100, outside);
        check(&block, &lz4_entry(16, n), 100, outside);
        let mut padded = vec![0u8; 16];
        padded.extend_from_slice(&block);
        check(&padded, &lz4_entry(16, n), 100, None);
        check(&padded, &lz4_entry(16, n + 1), 100, outside);
        check(&padded, &lz4_entry(32, n), 100, outside);

        // Offsets that would wrap around (a negative i64).
        check(&stored, &[Raw { virt: 0, phys: u64::MAX - 15, ty: CMP_NONE, size: 100 }], 100, outside);
        check(&stored, &[Raw { virt: 0, phys: u64::MAX - 15, ty: CMP_LZ4, size: n }], 100, outside);
        check(&stored, &[Raw { virt: 0, phys: 1 << 63, ty: CMP_NONE, size: 100 }], 100, outside);
        // A negative size (an i32 in the format) is nowhere near a block.
        check(&block, &lz4_entry(0, u32::MAX), 100, Some("compressed block"));
        check(&block, &lz4_entry(0, 1 << 31), 100, Some("compressed block"));
    }

    #[test]
    fn unsupported_compression_types_are_refused() {
        let stored = pattern(300, 4);
        for ty in [2u8, 4, 5, 7, 0x83, 0xFF] {
            // Wherever the entry is in the table, and whether anyone reads it.
            for position in 0..3 {
                let mut entries = vec![
                    Raw { virt: 0, phys: 0, ty: CMP_NONE, size: 100 },
                    Raw { virt: 100, phys: 100, ty: CMP_NONE, size: 100 },
                    Raw { virt: 200, phys: 200, ty: CMP_NONE, size: 100 },
                ];
                entries[position].ty = ty;
                let (mut level, info) = assemble(&stored, &entries, 300);
                match open(&mut level, &info) {
                    Ok(_) => panic!("type {ty} accepted"),
                    Err(Error::Unsupported(msg)) => {
                        assert_eq!(msg, format!("unsupported compression type {ty}"));
                    }
                    Err(e) => panic!("type {ty}: expected an Unsupported error, got {e:?}"),
                }
            }
        }
        // Types 0, 1 and 3 are fine (the zeros entry in the middle needs no data).
        let entries = [
            Raw { virt: 0, phys: 0, ty: CMP_NONE, size: 100 },
            Raw { virt: 100, phys: 0, ty: CMP_ZEROS, size: 0 },
            Raw { virt: 200, phys: 100, ty: CMP_NONE, size: 100 },
        ];
        let (mut level, info) = assemble(&stored, &entries, 300);
        open(&mut level, &info).unwrap();
    }

    #[test]
    fn the_first_entry_must_start_at_offset_zero() {
        let stored = pattern(300, 5);
        for first in [1u64, 0x10, 100, 299] {
            let entries = [
                Raw { virt: first, phys: 0, ty: CMP_NONE, size: 100 },
                Raw { virt: 300, phys: 100, ty: CMP_NONE, size: 100 },
            ];
            let (mut level, info) = assemble(&stored, &entries, 400);
            assert_fails(open(&mut level, &info), "doesn't start at offset 0");
        }
        // Starting at 0 is fine.
        let entries =
            [Raw { virt: 0, phys: 0, ty: CMP_NONE, size: 100 }, Raw { virt: 300, phys: 100, ty: CMP_NONE, size: 100 }];
        let (mut level, info) = assemble(&stored, &entries, 400);
        assert!(open(&mut level, &info).is_ok());
    }

    #[test]
    fn malformed_bucket_trees_are_refused_as_compression_tables() {
        let stored = pattern(300, 6);
        let entries =
            [Raw { virt: 0, phys: 0, ty: CMP_NONE, size: 100 }, Raw { virt: 100, phys: 100, ty: CMP_NONE, size: 100 }];
        type Mutate = fn(&mut Vec<u8>, &mut CompressionInfo);
        let cases: Vec<(&str, Mutate, &str)> = vec![
            ("no magic", |_, i| i.header[..4].copy_from_slice(b"BKTX"), "compression table has no BKTR header"),
            (
                "no entries",
                |_, i| i.header[8..12].copy_from_slice(&0u32.to_le_bytes()),
                "compression table has a bad entry count",
            ),
            (
                "more entries than the tree has",
                |_, i| i.header[8..12].copy_from_slice(&3u32.to_le_bytes()),
                "compression table has 2 entries, header says 3",
            ),
            ("table too small", |_, i| i.table_size -= 1, "compression table is truncated"),
            (
                "table cut to the L1 node",
                |_, i| i.table_size = BUCKET_NODE_SIZE as u64,
                "compression table is truncated",
            ),
            ("table past the data level", |_, i| i.table_size += 1, "sub-storage extends past its parent"),
            (
                "table starting past the data level",
                |l, i| i.table_offset = l.len() as u64 + 1,
                "read past end of storage",
            ),
            (
                "entries out of order",
                |l, i| {
                    // The second entry (in the first entry set, after the L1 node) starts where the first one does.
                    let at = i.table_offset as usize + BUCKET_NODE_SIZE + 0x10 + 0x18;
                    l[at..at + 8].copy_from_slice(&0u64.to_le_bytes());
                },
                "compression table entries are out of order",
            ),
        ];
        for (name, mutate, expected) in cases {
            let (mut level, mut info) = assemble(&stored, &entries, 200);
            mutate(&mut level, &mut info);
            match open(&mut level, &info) {
                Ok(_) => panic!("{name}: accepted, but should have failed with {expected:?}"),
                Err(e) => {
                    let msg = e.to_string();
                    assert!(msg.contains(expected), "{name}: expected an error mentioning {expected:?}, got {msg:?}");
                }
            }
        }
    }

    // -----------------------------------------------------------------------------------------------------
    // Blocks that can't be decompressed
    // -----------------------------------------------------------------------------------------------------

    /// A table whose entries are `(virtual length, how, stored bytes)` end to end, the stored bytes one after the
    /// other (each LZ4 block on a 16-byte boundary).
    fn blocks(parts: &[(u64, u8, &[u8])]) -> (Vec<u8>, CompressionInfo, Vec<u64>) {
        let (mut data, mut entries, mut virt, mut starts) = (Vec::new(), Vec::new(), 0u64, Vec::new());
        for &(len, ty, stored) in parts {
            data.resize(data.len().next_multiple_of(16), 0xA5);
            entries.push(Raw { virt, phys: data.len() as u64, ty, size: stored.len() as u32 });
            starts.push(virt);
            data.extend_from_slice(stored);
            virt += len;
        }
        let (level, info) = assemble(&data, &entries, virt);
        (level, info, starts)
    }

    #[test]
    fn an_lz4_block_must_decompress_to_exactly_the_size_of_its_range() {
        let data = pattern(100, 7);
        let block = lz4(&data);
        let neighbour = pattern(30, 8);
        // Control: the right size.
        let (mut level, info, _) =
            blocks(&[(30, CMP_NONE, &neighbour), (100, CMP_LZ4, &block), (30, CMP_NONE, &neighbour)]);
        let mut s = open(&mut level, &info).unwrap();
        assert_same("the block", &read_vec(&mut s, 30, 100), &data);

        // The block decompresses to 100 bytes. A range that wants fewer, or more, can't be read, but the ones next to
        // it can, before and after the failed attempt.
        for len in [1u64, 50, 99, 101, 102, 150, 1000] {
            let (mut level, info, _) =
                blocks(&[(30, CMP_NONE, &neighbour), (len, CMP_LZ4, &block), (30, CMP_NONE, &neighbour)]);
            let mut s = open(&mut level, &info).expect("the table is fine, the block is not");
            assert_same("before", &read_vec(&mut s, 0, 30), &neighbour);
            for (offset, n) in [(30, 1), (30 + len - 1, 1), (30, len as usize), (20, 20), (30 + len - 5, 10)] {
                let mut buf = vec![0u8; n];
                assert_fails(s.read(offset, &mut buf), "is corrupt");
            }
            assert_same("after", &read_vec(&mut s, 30 + len, 30), &neighbour);
            assert_same("before, again", &read_vec(&mut s, 0, 30), &neighbour);
        }
        // As the last range of the image.
        for len in [99u64, 101] {
            let (mut level, info, _) = blocks(&[(30, CMP_NONE, &neighbour), (len, CMP_LZ4, &block)]);
            let mut s = open(&mut level, &info).unwrap();
            let mut buf = [0u8; 1];
            assert_fails(s.read(30 + len - 1, &mut buf), "is corrupt");
        }
    }

    #[test]
    fn corrupt_lz4_data_is_an_error_when_the_block_is_read() {
        let data = pattern(100, 9);
        let block = lz4(&data);
        assert!(block.len() > 100, "random data makes one literal run");
        let truncated = block[..block.len() - 1].to_vec();
        let half = block[..block.len() / 2].to_vec();
        // One literal, then a match that reaches back 5 bytes before the start of the output.
        let bad_offset = [0x10u8, b'a', 0x05, 0x00];
        // A literal run that goes on for ever: 15, and then 0xFF over and over.
        let endless = vec![0xFFu8; 40];
        let cases: Vec<(&str, u64, Vec<u8>)> = vec![
            ("truncated by a byte", 100, truncated),
            ("cut in half", 100, half),
            ("a match before the start", 5, bad_offset.to_vec()),
            ("no bytes at all", 100, Vec::new()),
            ("a literal run that never ends", 1000, endless),
            ("one byte", 10, vec![0xF0]),
        ];
        let neighbour = pattern(30, 10);
        for (name, len, bad) in cases {
            let (mut level, info, starts) =
                blocks(&[(30, CMP_NONE, &neighbour), (len, CMP_LZ4, &bad), (30, CMP_NONE, &neighbour)]);
            let mut s = open(&mut level, &info).unwrap_or_else(|e| panic!("{name}: {e}"));
            let mut buf = vec![0u8; len as usize];
            assert_fails(s.read(starts[1], &mut buf), "is corrupt");
            assert_fails(s.read(starts[1] + len - 1, &mut buf[..1]), "is corrupt");
            // It stays broken, and doesn't take its neighbours down.
            assert_fails(s.read(starts[1], &mut buf[..1]), "is corrupt");
            assert_same(name, &read_vec(&mut s, 0, 30), &neighbour);
            assert_same(name, &read_vec(&mut s, starts[2], 30), &neighbour);
        }

        // A block read before the bad one stays readable after the failed attempt.
        let good_data = mixed_data(500, 11);
        let good = lz4(&good_data);
        let (mut level, info, starts) = blocks(&[(500, CMP_LZ4, &good), (100, CMP_LZ4, &block[..block.len() - 1])]);
        let mut s = open(&mut level, &info).unwrap();
        assert_same("good", &read_vec(&mut s, 0, 500), &good_data);
        let mut buf = [0u8; 10];
        assert_fails(s.read(starts[1], &mut buf), "is corrupt");
        assert_same("good, again", &read_vec(&mut s, 250, 100), &good_data[250..350]);
    }

    // -----------------------------------------------------------------------------------------------------
    // Reads outside the image
    // -----------------------------------------------------------------------------------------------------

    #[test]
    fn reads_must_stay_inside_the_image() {
        let mut fx = fixture(&mixed_ranges(), 12);
        let end = fx.want.len() as u64;
        let mut s = open(&mut fx.level, &fx.info).unwrap();
        assert_eq!(s.size(), end);
        let message = "read outside the compression table's range";
        let mut buf = vec![0u8; 100];
        let all_and_one = end as usize + 1;
        for (offset, n) in [
            (end - 99, 100),
            (end, 1),
            (end + 1, 1),
            (end - 1, 2),
            (0, all_and_one),
            (u64::MAX, 1),
            (u64::MAX - 5, 10),
            (end + 1000, 100),
        ] {
            assert_fails(s.read(offset, &mut vec![0u8; n]), message);
        }
        // The last bytes of the image are still there afterwards.
        assert_same("tail", &read_vec(&mut s, end - 100, 100), &fx.want[end as usize - 100..]);
        s.read(end - 100, &mut buf).unwrap();
        assert_same("tail", &buf, &fx.want[end as usize - 100..]);
        assert_same("whole", &read_vec(&mut s, 0, end as usize), &fx.want);
    }
}
