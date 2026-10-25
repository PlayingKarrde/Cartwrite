//! Synthetic Switch content for tests.
//!
//! Everything here is built from made-up keys ([`TestKeys`]); no real console key or game data is involved.
//! The pieces stack up the same way real content does:
//!
//! * [`build_pfs0`] and [`ImageBuilder`] make raw PFS0 and RomFS images.
//! * [`NcaBuilder`] wraps up to four such images ([`Section`]) in an encrypted NCA3 (standard crypto, AES-CTR
//!   sections, key generation 0).
//! * [`PatchSection`] makes the RomFS section of an update (an AesCtrEx bucket tree over an indirect bucket tree over
//!   pieces of the base game's section), written from the format description rather than from the reader in `bktr`.
//! * [`MetaBuilder`] makes the `.cnmt.nca` that describes a title and lists its other NCAs.
//! * [`NspBuilder`] packs NCAs (and any other files) into an NSP, which `scan::scan_file` reads back.
//!
//! The hash tables inside sections (SHA-256 blocks, IVFC levels), the NCA signatures and the cnmt digest are
//! zero-filled: the layout fields that locate the data are right, but nothing in the crate verifies the hashes.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use sha2::{Digest, Sha256};

use crate::cnmt::{META_ADD_ON_CONTENT, META_APPLICATION, META_DATA_PATCH, META_DELTA, META_PATCH};
use crate::crypto::{ecb_encrypt, Ctr, Key128};
use crate::keys::{master_key_index, Keys};
use crate::nca::{
    NcaContentType, NcaHeader, CRYPT_BKTR, CRYPT_CTR, FS_PFS0, FS_ROMFS, HASH_IVFC, HASH_SHA256, HEADER_SIZE,
};
use crate::util::hex;

fn put_u16(buf: &mut [u8], at: usize, v: u16) {
    buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// Zero-pads `buf` to a multiple of `align`.
fn pad_to(buf: &mut Vec<u8>, align: usize) {
    buf.resize(buf.len().next_multiple_of(align), 0);
}

/// `len` deterministic pseudo-random bytes (splitmix64 seeded with `seed`): never repeats within any realistic
/// length, so a copy that drops, duplicates or reorders a chunk can't go unnoticed.
pub fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        out.extend_from_slice(&z.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// A scratch directory under the system temp dir, removed (with everything in it) when dropped, also on panic.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates an empty directory named after `label`, the process id and a counter, so concurrent tests and
    /// test processes never share one.
    pub fn new(label: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("cartwrite-test-{label}-{}-{n}", std::process::id()));
        // Leftovers of an earlier crashed run that had the same process id.
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap_or_else(|e| panic!("creating {}: {e}", path.display()));
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// ---------------------------------------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------------------------------------

/// Made-up keys, enough for `Keys::load` and for building/reading standard-crypto NCAs of key generation 0.
/// They are arbitrary bytes, not real console keys.
pub struct TestKeys;

impl TestKeys {
    /// The 32-byte AES-XTS key that encrypts NCA headers.
    pub const HEADER_KEY: [u8; 32] = [
        0x5A, 0x13, 0xC8, 0x7E, 0x21, 0x94, 0xB0, 0x3D, 0xF6, 0x42, 0x0A, 0x8B, 0xD7, 0x69, 0x1E, 0xA5, //
        0x37, 0xCC, 0x80, 0x52, 0xE9, 0x0F, 0x74, 0xB1, 0x2D, 0x96, 0x4A, 0xDF, 0x63, 0x18, 0xFB, 0x85,
    ];

    /// `key_area_key_application_00`: encrypts the key area of NCAs with key generation 0 and key area key
    /// index 0 (application).
    pub const KEY_AREA_KEY_APPLICATION_00: Key128 =
        [0xC1, 0x7A, 0x3E, 0x90, 0x58, 0xD2, 0x0B, 0xF4, 0x66, 0x1D, 0xA9, 0x82, 0x2F, 0xE7, 0x4C, 0x35];

    /// Writes `prod.keys` into `dir` (created if missing) and returns its path.
    pub fn write(dir: &Path) -> PathBuf {
        fs::create_dir_all(dir).unwrap_or_else(|e| panic!("creating {}: {e}", dir.display()));
        let path = dir.join("prod.keys");
        let text = format!(
            "header_key = {}\nkey_area_key_application_00 = {}\n",
            hex(&Self::HEADER_KEY),
            hex(&Self::KEY_AREA_KEY_APPLICATION_00)
        );
        fs::write(&path, text).unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
        path
    }

    /// Writes `prod.keys` into `dir` (see [`write`](Self::write)) and loads it with `Keys::load`.
    pub fn keys(dir: &Path) -> Keys {
        Keys::load(&Self::write(dir)).expect("the test keys file loads")
    }
}

// ---------------------------------------------------------------------------------------------------------
// PFS0
// ---------------------------------------------------------------------------------------------------------

/// Builds a PFS0 image holding `files`, with the string table padded to a multiple of 0x20.
pub fn build_pfs0(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut strings = Vec::new();
    let mut name_offs = Vec::new();
    for (name, _) in files {
        name_offs.push(strings.len() as u32);
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
    }
    strings.resize(strings.len().div_ceil(0x20) * 0x20, 0);

    let mut out = b"PFS0".to_vec();
    out.extend_from_slice(&(files.len() as u32).to_le_bytes());
    out.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    let mut data_off = 0u64;
    for ((_, data), name_off) in files.iter().zip(&name_offs) {
        out.extend_from_slice(&data_off.to_le_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(&name_off.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        data_off += data.len() as u64;
    }
    out.extend_from_slice(&strings);
    for (_, data) in files {
        out.extend_from_slice(data);
    }
    out
}

// ---------------------------------------------------------------------------------------------------------
// RomFS
// ---------------------------------------------------------------------------------------------------------

// The RomFS layout constants are restated here instead of imported from `romfs.rs`, so the builder is an
// independent description of the format that the reader gets checked against.
const ROMFS_HEADER_SIZE: usize = 0x50;
const ROMFS_DIR_ENTRY_SIZE: usize = 0x18;
const ROMFS_FILE_ENTRY_SIZE: usize = 0x20;
/// "No such entry" in the sibling and child links.
const ROMFS_NONE: u32 = 0xFFFF_FFFF;

struct TestDir {
    name: String,
    parent: usize,
    dirs: Vec<usize>,
    files: Vec<usize>,
}

struct TestFile {
    name: String,
    parent: usize,
    data: Vec<u8>,
}

/// Builds a RomFS image (without hash tables) from a list of directories and files.
pub struct ImageBuilder {
    dirs: Vec<TestDir>,
    files: Vec<TestFile>,
}

impl ImageBuilder {
    pub fn new() -> Self {
        let root = TestDir { name: String::new(), parent: 0, dirs: Vec::new(), files: Vec::new() };
        Self { dirs: vec![root], files: Vec::new() }
    }

    /// Creates the directory `path` ("a/b/c") and any missing parents; returns its index.
    pub fn dir(&mut self, path: &str) -> usize {
        let mut cur = 0;
        for name in path.split('/').filter(|n| !n.is_empty()) {
            let existing = self.dirs[cur].dirs.iter().copied().find(|&d| self.dirs[d].name == name);
            cur = existing.unwrap_or_else(|| {
                let new = self.dirs.len();
                self.dirs.push(TestDir { name: name.into(), parent: cur, dirs: Vec::new(), files: Vec::new() });
                self.dirs[cur].dirs.push(new);
                new
            });
        }
        cur
    }

    /// Adds the file `path` ("a/b/c.bin"), creating its directories.
    pub fn file(&mut self, path: &str, data: &[u8]) {
        let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
        let parent = self.dir(dir);
        self.files.push(TestFile { name: name.into(), parent, data: data.to_vec() });
        self.dirs[parent].files.push(self.files.len() - 1);
    }

    pub fn build(&self) -> Vec<u8> {
        fn pad4(buf: &mut Vec<u8>) {
            while !buf.len().is_multiple_of(4) {
                buf.push(0);
            }
        }
        // Table offset of each entry, given its header size and name.
        fn offsets(entries: &[(usize, &str)]) -> Vec<u32> {
            let mut pos = 0u32;
            entries
                .iter()
                .map(|&(header, name)| {
                    let at = pos;
                    pos += (header + name.len().div_ceil(4) * 4) as u32;
                    at
                })
                .collect()
        }
        // The offset of the entry after `item` in `list`, if any.
        fn next_of(list: &[usize], offs: &[u32], item: usize) -> u32 {
            let at = list.iter().position(|&i| i == item).unwrap();
            list.get(at + 1).map_or(ROMFS_NONE, |&n| offs[n])
        }
        fn first_of(list: &[usize], offs: &[u32]) -> u32 {
            list.first().map_or(ROMFS_NONE, |&i| offs[i])
        }

        let dir_offs = offsets(&self.dirs.iter().map(|d| (ROMFS_DIR_ENTRY_SIZE, d.name.as_str())).collect::<Vec<_>>());
        let file_offs =
            offsets(&self.files.iter().map(|f| (ROMFS_FILE_ENTRY_SIZE, f.name.as_str())).collect::<Vec<_>>());

        let mut dir_table = Vec::new();
        for (i, d) in self.dirs.iter().enumerate() {
            let sibling = if i == 0 { ROMFS_NONE } else { next_of(&self.dirs[d.parent].dirs, &dir_offs, i) };
            let links = [
                dir_offs[d.parent],
                sibling,
                first_of(&d.dirs, &dir_offs),
                first_of(&d.files, &file_offs),
                ROMFS_NONE,
                d.name.len() as u32,
            ];
            links.iter().for_each(|v| dir_table.extend(v.to_le_bytes()));
            dir_table.extend(d.name.as_bytes());
            pad4(&mut dir_table);
        }

        let mut file_table = Vec::new();
        let mut data = Vec::new();
        for (i, f) in self.files.iter().enumerate() {
            while !data.len().is_multiple_of(0x10) {
                data.push(0);
            }
            let sibling = next_of(&self.dirs[f.parent].files, &file_offs, i);
            file_table.extend(dir_offs[f.parent].to_le_bytes());
            file_table.extend(sibling.to_le_bytes());
            file_table.extend((data.len() as u64).to_le_bytes());
            file_table.extend((f.data.len() as u64).to_le_bytes());
            file_table.extend(ROMFS_NONE.to_le_bytes());
            file_table.extend((f.name.len() as u32).to_le_bytes());
            file_table.extend(f.name.as_bytes());
            pad4(&mut file_table);
            data.extend(&f.data);
        }

        let dir_meta_off = ROMFS_HEADER_SIZE;
        let file_meta_off = dir_meta_off + dir_table.len();
        let data_start = (file_meta_off + file_table.len()).next_multiple_of(0x20);
        let header = [
            ROMFS_HEADER_SIZE,
            dir_meta_off, // directory hash table (empty)
            0,
            dir_meta_off,
            dir_table.len(),
            file_meta_off, // file hash table (empty)
            0,
            file_meta_off,
            file_table.len(),
            data_start,
        ];
        let mut img = Vec::new();
        header.iter().for_each(|&v| img.extend((v as u64).to_le_bytes()));
        img.extend(dir_table);
        img.extend(file_table);
        img.resize(data_start, 0);
        img.extend(data);
        img
    }
}

impl Default for ImageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------------------------------------
// NCA
// ---------------------------------------------------------------------------------------------------------

/// Sections start on, and are padded to, this boundary (the unit of the header's section table).
const SECTION_ALIGN: usize = 0x200;

/// The AES-CTR section key (key 2 of the key area) an [`NcaBuilder`] uses unless told otherwise.
pub const DEFAULT_SECTION_KEY: Key128 =
    [0x9D, 0x04, 0xB7, 0x6E, 0xF1, 0x28, 0xC5, 0x5B, 0x30, 0xEA, 0x73, 0x0C, 0xA6, 0x4F, 0xD8, 0x19];

/// One filesystem section of an NCA, holding a finished PFS0 or RomFS image.
#[derive(Clone)]
pub enum Section {
    /// A PFS0 behind a hierarchical-SHA256 hash table (FS header: fs_type 1, hash_type 2).
    Pfs0(Vec<u8>),
    /// A RomFS behind a six-level IVFC hash tree (FS header: fs_type 0, hash_type 3).
    RomFs(Vec<u8>),
    /// The RomFS of an update: only what changed since the base game, stored with AesCtrEx encryption
    /// (FS header: encryption type 4, patch info at 0x100).
    Patch(Box<PatchSection>),
}

impl Section {
    /// A PFS0 section with the given files.
    pub fn pfs0(files: &[(&str, &[u8])]) -> Self {
        Self::Pfs0(build_pfs0(files))
    }

    /// A RomFS section holding `image` (from [`ImageBuilder::build`]).
    pub fn romfs(image: Vec<u8>) -> Self {
        Self::RomFs(image)
    }

    /// An update's patched RomFS section.
    pub fn patch(patch: PatchSection) -> Self {
        Self::Patch(Box::new(patch))
    }

    /// The section's bytes as the NCA holds them before encryption (hash tables followed by the data, padded to
    /// [`SECTION_ALIGN`]): for a base game's RomFS section, what a patch is made against. Not for patch sections,
    /// whose stored bytes aren't a single plaintext.
    pub fn plaintext(&self) -> Vec<u8> {
        self.layout(&mut [0u8; 0x200])
    }

    /// Fills in the layout fields of the FS header `fs` for this section and returns the plaintext section
    /// bytes (hash tables followed by the data, padded to [`SECTION_ALIGN`]).
    fn layout(&self, fs: &mut [u8]) -> Vec<u8> {
        put_u16(fs, 0, 2); // version
        fs[4] = CRYPT_CTR;
        let mut out;
        match self {
            Self::Patch(_) => unreachable!("an update section is assembled by NcaBuilder::build, not laid out"),
            Self::Pfs0(image) => {
                const BLOCK_SIZE: usize = 0x1000;
                fs[2] = FS_PFS0;
                fs[3] = HASH_SHA256;
                let hash_table_size = image.len().div_ceil(BLOCK_SIZE).max(1) * 0x20;
                let data_offset = hash_table_size.next_multiple_of(SECTION_ALIGN);
                put_u32(fs, 0x28, BLOCK_SIZE as u32);
                put_u32(fs, 0x2C, 2); // layers
                put_u64(fs, 0x30, 0); // hash table offset
                put_u64(fs, 0x38, hash_table_size as u64);
                put_u64(fs, 0x40, data_offset as u64);
                put_u64(fs, 0x48, image.len() as u64);
                out = vec![0u8; data_offset];
                out.extend_from_slice(image);
            }
            Self::RomFs(image) => {
                const LEVELS: usize = 6; // five hash levels, then the data
                const BLOCK_LOG2: u32 = 14;
                let block = 1usize << BLOCK_LOG2;
                fs[2] = FS_ROMFS;
                fs[3] = HASH_IVFC;
                // Each hash level holds one 0x20-byte hash per block of the level below it.
                let mut sizes = [image.len(); LEVELS];
                for i in (0..LEVELS - 1).rev() {
                    sizes[i] = sizes[i + 1].div_ceil(block).max(1) * 0x20;
                }
                let mut offsets = [0usize; LEVELS];
                for i in 1..LEVELS {
                    offsets[i] = (offsets[i - 1] + sizes[i - 1]).next_multiple_of(block);
                }
                fs[8..12].copy_from_slice(b"IVFC");
                put_u32(fs, 0x0C, 0x20000); // magic number
                put_u32(fs, 0x10, 0x20); // master hash size
                put_u32(fs, 0x14, LEVELS as u32 + 1); // the count includes the master hash
                for i in 0..LEVELS {
                    let e = 0x18 + i * 0x18;
                    put_u64(fs, e, offsets[i] as u64);
                    put_u64(fs, e + 8, sizes[i] as u64);
                    put_u32(fs, e + 0x10, BLOCK_LOG2);
                }
                out = vec![0u8; offsets[LEVELS - 1]];
                out.extend_from_slice(image);
            }
        }
        pad_to(&mut out, SECTION_ALIGN);
        out
    }
}

/// Builds an encrypted NCA3: standard crypto (no rights ID), key generation 0 (so master key index 0), key area
/// key index 0 (application), AES-CTR sections (AesCtrEx for a [`Section::Patch`]).
#[derive(Clone)]
pub struct NcaBuilder {
    content_type: NcaContentType,
    title_id: u64,
    section_key: Key128,
    sections: Vec<Section>,
}

impl NcaBuilder {
    pub fn new(content_type: NcaContentType, title_id: u64) -> Self {
        Self { content_type, title_id, section_key: DEFAULT_SECTION_KEY, sections: Vec::new() }
    }

    /// Uses `key` as the AES-CTR section key (key 2 of the key area) instead of [`DEFAULT_SECTION_KEY`].
    pub fn section_key(mut self, key: Key128) -> Self {
        self.section_key = key;
        self
    }

    /// Appends a section (an NCA has at most four).
    pub fn section(mut self, section: Section) -> Self {
        assert!(self.sections.len() < 4, "an NCA has at most four sections");
        self.sections.push(section);
        self
    }

    /// Lays out, encrypts and returns the NCA. `keys` must hold the header key and the key area key for key
    /// generation 0 ([`TestKeys`]).
    pub fn build(&self, keys: &Keys) -> BuiltNca {
        const KEY_GENERATION: u8 = 0;
        const KAEK_INDEX: u8 = 0;
        assert!(!self.sections.is_empty(), "an NCA needs at least one section");
        let type_byte = match self.content_type {
            NcaContentType::Program => 0,
            NcaContentType::Meta => 1,
            NcaContentType::Control => 2,
            NcaContentType::Manual => 3,
            NcaContentType::Data => 4,
            NcaContentType::PublicData => 5,
            NcaContentType::Unknown(v) => v,
        };

        let mut header = NcaHeader { raw: Box::new([0u8; HEADER_SIZE]) };
        header.raw[0x200..0x204].copy_from_slice(b"NCA3");
        header.raw[0x205] = type_byte;
        header.raw[0x206] = KEY_GENERATION; // the old field; newer generations cap it at 2
        header.raw[0x207] = KAEK_INDEX;
        put_u64(&mut header.raw[..], 0x210, self.title_id);
        put_u32(&mut header.raw[..], 0x21C, 0x000C_1100); // SDK addon version
        header.raw[0x220] = KEY_GENERATION;

        // Key area: four keys under the key area key. Only key 2 (AES-CTR) is used for sections.
        let filler =
            |i: u8| -> Key128 { std::array::from_fn(|j| (j as u8).wrapping_mul(0x1D) ^ i.wrapping_mul(0x55) ^ 0x6C) };
        let mut area = [0u8; 0x40];
        for (i, key) in [filler(0), filler(1), self.section_key, filler(3)].iter().enumerate() {
            area[i * 16..i * 16 + 16].copy_from_slice(key);
        }
        let kaek = keys
            .key_area_key(master_key_index(KEY_GENERATION), KAEK_INDEX)
            .expect("the keys hold key_area_key_application_00");
        ecb_encrypt(&kaek, &mut area);
        header.raw[0x300..0x340].copy_from_slice(&area);

        let mut body = Vec::new();
        let mut pos = HEADER_SIZE;
        for (i, section) in self.sections.iter().enumerate() {
            let data = match section {
                Section::Patch(patch) => {
                    // Encrypted region by region, with the counters the patch's own tables describe.
                    let layout = patch.layout();
                    patch.write_fs_header(&layout, header.fs_header_mut(i));
                    patch.encrypt(&layout, pos as u64, &self.section_key)
                }
                _ => {
                    let mut data = section.layout(header.fs_header_mut(i));
                    let nonce = Sha256::new()
                        .chain_update(b"cartwrite-test-nonce")
                        .chain_update(self.title_id.to_le_bytes())
                        .chain_update([type_byte, i as u8])
                        .finalize();
                    header.fs_header_mut(i)[0x140..0x148].copy_from_slice(&nonce[..8]);
                    // CTR counters follow the absolute offset inside the NCA, like `nca::decrypt_in_place`.
                    Ctr::new(&self.section_key, header.section_nonce(i)).apply(pos as u64, &mut data);
                    data
                }
            };
            header.update_fs_header_hash(i);
            let end = pos + data.len();
            let entry = 0x240 + i * 0x10;
            put_u32(&mut header.raw[..], entry, (pos / 0x200) as u32);
            put_u32(&mut header.raw[..], entry + 4, (end / 0x200) as u32);
            put_u32(&mut header.raw[..], entry + 8, 1);
            body.extend_from_slice(&data);
            pos = end;
        }
        put_u64(&mut header.raw[..], 0x208, pos as u64);

        let mut bytes = header.encrypt(keys);
        bytes.extend_from_slice(&body);
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        BuiltNca { bytes, content_type: self.content_type, content_id: hash[..16].try_into().unwrap(), hash }
    }
}

/// An encrypted NCA file, plus what the cnmt and the NSP need to refer to it.
#[derive(Clone)]
pub struct BuiltNca {
    /// The whole NCA file, as stored in an NSP.
    pub bytes: Vec<u8>,
    pub content_type: NcaContentType,
    /// First 16 bytes of the SHA-256 of `bytes`, as for real content.
    pub content_id: [u8; 16],
    /// SHA-256 of `bytes` (the hash field of a cnmt content record).
    pub hash: [u8; 32],
}

impl BuiltNca {
    pub fn content_id_hex(&self) -> String {
        hex(&self.content_id)
    }

    /// `<content id>.nca`, or `<content id>.cnmt.nca` for a meta NCA.
    pub fn file_name(&self) -> String {
        let ext = if self.content_type == NcaContentType::Meta { "cnmt.nca" } else { "nca" };
        format!("{}.{ext}", self.content_id_hex())
    }
}

// ---------------------------------------------------------------------------------------------------------
// Update (BKTR) sections
// ---------------------------------------------------------------------------------------------------------

// The bucket tree and patch layouts are restated here instead of imported from `bktr.rs` (the format as
// Atmosphère's libstratosphere describes it), so these builders are an independent description that the reader
// gets checked against.

/// Size of every node of a bucket tree.
pub const BUCKET_NODE_SIZE: usize = 0x4000;
const BUCKET_NODE_HEADER_SIZE: usize = 0x10;

/// The 16-byte bucket tree header kept in the FS header: "BKTR", version 1, entry count, 0.
pub fn bucket_tree_header(entry_count: usize) -> [u8; 0x10] {
    let mut h = [0u8; 0x10];
    h[..4].copy_from_slice(b"BKTR");
    put_u32(&mut h, 4, 1);
    put_u32(&mut h, 8, entry_count as u32);
    h
}

/// An AesCtrEx entry (0x10 bytes): where the region starts, whether it is encrypted, and the generation that goes
/// into its counter.
pub fn ctr_ex_entry(offset: u64, encrypted: bool, generation: u32) -> Vec<u8> {
    let mut e = vec![0u8; 0x10];
    put_u64(&mut e, 0, offset);
    e[8] = if encrypted { 0 } else { 1 };
    put_u32(&mut e, 0xC, generation);
    e
}

/// An indirect entry (0x14 bytes): virtual range start, where it is read from in storage `storage_index`
/// (0 = the base game's section, 1 = the update's data), and which storage that is.
pub fn indirect_entry(virtual_offset: u64, physical_offset: u64, storage_index: u32) -> Vec<u8> {
    let mut e = vec![0u8; 0x14];
    put_u64(&mut e, 0, virtual_offset);
    put_u64(&mut e, 8, physical_offset);
    put_u32(&mut e, 0x10, storage_index);
    e
}

/// The "meta" region of a bucket tree holding `entries` (encoded entries of one size, each starting with its u64
/// offset, offsets increasing) that together cover `[entries[0].offset, end)`: an L1 node followed by one
/// 0x4000-byte entry set per `(0x4000 - 0x10) / entry size` entries. Trees big enough to need L2 nodes (more than
/// 2046 entry sets) aren't built.
pub fn bucket_tree(entries: &[Vec<u8>], end: u64) -> Vec<u8> {
    assert!(!entries.is_empty(), "a bucket tree has at least one entry");
    let entry_size = entries[0].len();
    assert!(entries.iter().all(|e| e.len() == entry_size), "entries of different sizes");
    let per_set = (BUCKET_NODE_SIZE - BUCKET_NODE_HEADER_SIZE) / entry_size;
    let sets: Vec<&[Vec<u8>]> = entries.chunks(per_set).collect();
    assert!(sets.len() <= (BUCKET_NODE_SIZE - BUCKET_NODE_HEADER_SIZE) / 8, "trees with L2 nodes aren't built");
    let first_offset = |e: &Vec<u8>| u64::from_le_bytes(e[..8].try_into().unwrap());

    let mut out = vec![0u8; BUCKET_NODE_SIZE * (1 + sets.len())];
    // L1 node: index 0, the number of entry sets, the tree's end offset, then each set's first offset.
    put_u32(&mut out, 4, sets.len() as u32);
    put_u64(&mut out, 8, end);
    for (i, set) in sets.iter().enumerate() {
        put_u64(&mut out, BUCKET_NODE_HEADER_SIZE + i * 8, first_offset(&set[0]));
        // Entry set `i`: its index, entry count, the offset where it ends, then the entries.
        let node = BUCKET_NODE_SIZE * (1 + i);
        put_u32(&mut out, node, i as u32);
        put_u32(&mut out, node + 4, set.len() as u32);
        put_u64(&mut out, node + 8, sets.get(i + 1).map_or(end, |next| first_offset(&next[0])));
        for (j, entry) in set.iter().enumerate() {
            let at = node + BUCKET_NODE_HEADER_SIZE + j * entry_size;
            out[at..at + entry_size].copy_from_slice(entry);
        }
    }
    out
}

/// One entry of a patch's indirect table, with the length of the range it covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PatchEntry {
    pub virtual_offset: u64,
    pub physical_offset: u64,
    /// 0 = the base game's section, 1 = the update's own data.
    pub storage_index: u32,
    /// Bytes covered: `[virtual_offset, virtual_offset + len)`. The table itself doesn't store this.
    pub len: u64,
}

/// One entry of a patch's AesCtrEx table: a region of the update's own data (up to the next entry's offset).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtrExRegion {
    pub offset: u64,
    pub encrypted: bool,
    pub generation: u32,
}

/// What a [`PatchSection`] boils down to once it is diffed and its tables are built.
pub struct PatchLayout {
    /// The indirect table's entries, in order.
    pub entries: Vec<PatchEntry>,
    /// The AesCtrEx table's entries, in order.
    pub regions: Vec<CtrExRegion>,
    /// Section-relative offset of the indirect table, which is also where the update data ends.
    pub indirect_offset: u64,
    pub indirect_size: u64,
    /// Section-relative offset of the AesCtrEx table, which is also where the AesCtrEx regions end.
    pub ctr_ex_offset: u64,
    pub ctr_ex_size: u64,
    /// Plaintext of `[0, ctr_ex_offset)`: the update data, the indirect table, then zero padding.
    head: Vec<u8>,
    /// The AesCtrEx table's plaintext.
    ctr_ex_table: Vec<u8>,
}

/// The RomFS section of an update, built from the format description: the patched section is cut into fixed-size
/// chunks, each either found again in the base game's section (read from there, through the indirect table) or
/// stored in the update's own data. The update's data and the indirect table are then encrypted region by region
/// as the AesCtrEx table says, with the AesCtrEx table itself after them under the section's ordinary counter.
///
/// ```text
/// [0, indirect_offset)                          update data (pieces for indirect entries of storage 1)
/// [indirect_offset, + indirect_size)            indirect bucket tree
/// ... zero padding ...
/// [ctr_ex_offset, + ctr_ex_size)                AesCtrEx bucket tree (its regions cover [0, ctr_ex_offset))
/// ```
///
/// Put into an NCA with [`Section::patch`]. The knobs have defaults that produce several differing AesCtrEx
/// generations and a not-encrypted region.
#[derive(Clone)]
pub struct PatchSection {
    /// The base game's section, as its NCA holds it (decrypted).
    base: Vec<u8>,
    /// The patched section: IVFC hash levels and the new RomFS image.
    target: Vec<u8>,
    /// The first 0x100 bytes of the FS header (version, types, IVFC levels), which locate the RomFS in `target`.
    fs_prefix: Vec<u8>,
    chunk: usize,
    merge: bool,
    generation: u32,
    secure_value: u32,
    region_size: usize,
    region_pattern: Vec<(u32, bool)>,
    gap: usize,
}

impl PatchSection {
    /// A patch that turns `base_section` (the base game's decrypted RomFS section, see [`Section::plaintext`]) into
    /// the section holding `new_romfs_image`. Chunks of 0x1000, regions of 0x2A10 bytes cycling through
    /// generations 1, 2, 3 (not encrypted) and 6, header generation 4, secure value 0x01020304.
    pub fn new(base_section: &[u8], new_romfs_image: &[u8]) -> Self {
        let mut fs = [0u8; 0x200];
        let target = Section::RomFs(new_romfs_image.to_vec()).layout(&mut fs);
        Self {
            base: base_section.to_vec(),
            target,
            fs_prefix: fs[..0x100].to_vec(),
            chunk: 0x1000,
            merge: true,
            generation: 4,
            secure_value: 0x0102_0304,
            region_size: 0x2A10,
            region_pattern: vec![(1, true), (2, true), (3, false), (6, true)],
            gap: 0x200,
        }
    }

    /// Diffs in chunks of `bytes`: a chunk is read from the base game if the base has the same bytes at a multiple
    /// of `bytes`. Smaller chunks find more of a shifted file, at the price of a bigger indirect table.
    pub fn chunk_size(mut self, bytes: usize) -> Self {
        assert!(bytes > 0);
        self.chunk = bytes;
        self
    }

    /// Whether consecutive chunks that continue the same storage share one indirect entry (the default) or each get
    /// their own.
    pub fn merge_chunks(mut self, merge: bool) -> Self {
        self.merge = merge;
        self
    }

    /// The generation in the FS header (offset 0x140), which the AesCtrEx table itself is encrypted with.
    pub fn generation(mut self, generation: u32) -> Self {
        self.generation = generation;
        self
    }

    /// The secure value in the FS header (offset 0x144), which every region's counter starts with.
    pub fn secure_value(mut self, secure_value: u32) -> Self {
        self.secure_value = secure_value;
        self
    }

    /// Cuts the AesCtrEx regions every `region_size` bytes (a multiple of 16), giving them `(generation,
    /// encrypted)` from `pattern` in turn.
    pub fn ctr_ex_regions(mut self, region_size: usize, pattern: &[(u32, bool)]) -> Self {
        assert!(region_size > 0 && region_size.is_multiple_of(16) && !pattern.is_empty());
        self.region_size = region_size;
        self.region_pattern = pattern.to_vec();
        self
    }

    /// Leaves `bytes` (a multiple of 0x200) of zeros between the indirect table and the AesCtrEx table.
    pub fn table_gap(mut self, bytes: usize) -> Self {
        assert!(bytes.is_multiple_of(SECTION_ALIGN));
        self.gap = bytes;
        self
    }

    /// Diffs, builds both tables and works out where everything goes.
    pub fn layout(&self) -> PatchLayout {
        assert!(!self.target.is_empty());
        let chunk = self.chunk;

        // Where each aligned chunk of the base game first appears.
        let mut in_base: HashMap<&[u8], u64> = HashMap::new();
        for (i, c) in self.base.chunks_exact(chunk).enumerate() {
            in_base.entry(c).or_insert((i * chunk) as u64);
        }

        let mut entries: Vec<PatchEntry> = Vec::new();
        let mut update_data = Vec::new();
        for (i, c) in self.target.chunks(chunk).enumerate() {
            let len = c.len() as u64;
            // The chunk that carries on from where the previous one left off in the base game.
            let continues_base = |e: &PatchEntry| {
                let next = (e.physical_offset + e.len) as usize;
                e.storage_index == 0 && self.base.get(next..next + c.len()) == Some(c)
            };
            if self.merge && entries.last().is_some_and(continues_base) {
                entries.last_mut().unwrap().len += len;
            } else if let Some(&physical_offset) = in_base.get(c) {
                let virtual_offset = (i * chunk) as u64;
                entries.push(PatchEntry { virtual_offset, physical_offset, storage_index: 0, len });
            } else {
                // New data goes on the end of the update data, so a run of it is contiguous there too.
                match entries.last_mut() {
                    Some(last) if self.merge && last.storage_index == 1 => last.len += len,
                    _ => {
                        let virtual_offset = (i * chunk) as u64;
                        let physical_offset = update_data.len() as u64;
                        entries.push(PatchEntry { virtual_offset, physical_offset, storage_index: 1, len });
                    }
                }
                update_data.extend_from_slice(c);
            }
        }

        // Update data, indirect table, padding; the AesCtrEx regions cover all of it.
        let indirect_offset = update_data.len().next_multiple_of(SECTION_ALIGN);
        update_data.resize(indirect_offset, 0);
        let indirect_entries: Vec<Vec<u8>> =
            entries.iter().map(|e| indirect_entry(e.virtual_offset, e.physical_offset, e.storage_index)).collect();
        let indirect_table = bucket_tree(&indirect_entries, self.target.len() as u64);
        let ctr_ex_offset = (indirect_offset + indirect_table.len() + self.gap).next_multiple_of(SECTION_ALIGN);
        let mut head = update_data;
        head.extend_from_slice(&indirect_table);
        head.resize(ctr_ex_offset, 0);

        let regions: Vec<CtrExRegion> = (0..ctr_ex_offset)
            .step_by(self.region_size)
            .enumerate()
            .map(|(i, offset)| {
                let (generation, encrypted) = self.region_pattern[i % self.region_pattern.len()];
                CtrExRegion { offset: offset as u64, encrypted, generation }
            })
            .collect();
        let ctr_ex_entries: Vec<Vec<u8>> =
            regions.iter().map(|r| ctr_ex_entry(r.offset, r.encrypted, r.generation)).collect();
        let mut ctr_ex_table = bucket_tree(&ctr_ex_entries, ctr_ex_offset as u64);
        let ctr_ex_size = ctr_ex_table.len() as u64;
        pad_to(&mut ctr_ex_table, SECTION_ALIGN);

        PatchLayout {
            entries,
            regions,
            indirect_offset: indirect_offset as u64,
            indirect_size: indirect_table.len() as u64,
            ctr_ex_offset: ctr_ex_offset as u64,
            ctr_ex_size,
            head,
            ctr_ex_table,
        }
    }

    /// Fills in the FS header `fs`: encryption type 4, the IVFC levels of the patched section, the patch info
    /// (0x100..0x140) and the generation and secure value (0x140, 0x144).
    fn write_fs_header(&self, layout: &PatchLayout, fs: &mut [u8]) {
        fs[..0x100].copy_from_slice(&self.fs_prefix);
        fs[4] = CRYPT_BKTR;
        put_u64(fs, 0x100, layout.indirect_offset);
        put_u64(fs, 0x108, layout.indirect_size);
        fs[0x110..0x120].copy_from_slice(&bucket_tree_header(layout.entries.len()));
        put_u64(fs, 0x120, layout.ctr_ex_offset);
        put_u64(fs, 0x128, layout.ctr_ex_size);
        fs[0x130..0x140].copy_from_slice(&bucket_tree_header(layout.regions.len()));
        put_u32(fs, 0x140, self.generation);
        put_u32(fs, 0x144, self.secure_value);
    }

    /// The section as stored in an NCA, where it starts at absolute offset `start`: every encrypted AesCtrEx
    /// region under AES-CTR with `key` and the upper counter `secure_value << 32 | region generation` (big-endian),
    /// the AesCtrEx table under the header's `secure_value << 32 | generation`; the low half of each counter is the
    /// absolute offset / 16.
    fn encrypt(&self, layout: &PatchLayout, start: u64, key: &Key128) -> Vec<u8> {
        let upper = |generation: u32| ((u64::from(self.secure_value) << 32) | u64::from(generation)).to_be_bytes();
        let mut stored = layout.head.clone();
        for (i, r) in layout.regions.iter().enumerate() {
            let end = layout.regions.get(i + 1).map_or(layout.ctr_ex_offset, |next| next.offset);
            if r.encrypted {
                Ctr::new(key, upper(r.generation))
                    .apply(start + r.offset, &mut stored[r.offset as usize..end as usize]);
            }
        }
        let mut table = layout.ctr_ex_table.clone();
        Ctr::new(key, upper(self.generation)).apply(start + layout.ctr_ex_offset, &mut table);
        stored.extend_from_slice(&table);
        stored
    }
}

// ---------------------------------------------------------------------------------------------------------
// Meta NCA / cnmt
// ---------------------------------------------------------------------------------------------------------

/// Builds the `.cnmt.nca` of a title: an NCA whose section 0 is a SHA-256 PFS0 holding one `.cnmt` file.
pub struct MetaBuilder {
    meta_type: u8,
    title_id: u64,
    version: u32,
    ext_header: Vec<u8>,
    records: Vec<[u8; 0x38]>,
}

impl MetaBuilder {
    /// The meta of a base game (`META_APPLICATION`, extended header of 0x10 bytes).
    pub fn application(title_id: u64, version: u32, required_system_version: u32) -> Self {
        let mut ext_header = vec![0u8; 0x10];
        put_u64(&mut ext_header, 0, title_id + 0x800); // the update's title id
        put_u32(&mut ext_header, 8, required_system_version);
        Self { meta_type: META_APPLICATION, title_id, version, ext_header, records: Vec::new() }
    }

    /// The meta of the update of `application_id` (`META_PATCH`, extended header of 0x18 bytes: the application id,
    /// the required system version, the size of the extended data (none), reserved). An update's title id is its
    /// application's with 0x800 added.
    pub fn patch(application_id: u64, version: u32, required_system_version: u32) -> Self {
        let mut ext_header = vec![0u8; 0x18];
        put_u64(&mut ext_header, 0, application_id);
        put_u32(&mut ext_header, 8, required_system_version);
        let title_id = application_id | 0x800;
        Self { meta_type: META_PATCH, title_id, version, ext_header, records: Vec::new() }
    }

    /// Lists `nca` as content of type `record_type` (`cnmt::CT_*`).
    pub fn content(mut self, nca: &BuiltNca, record_type: u8) -> Self {
        let mut r = [0u8; 0x38];
        r[..0x20].copy_from_slice(&nca.hash);
        r[0x20..0x30].copy_from_slice(&nca.content_id);
        r[0x30..0x36].copy_from_slice(&(nca.bytes.len() as u64).to_le_bytes()[..6]);
        r[0x36] = record_type;
        self.records.push(r);
        self
    }

    /// The `.cnmt` file: 0x20-byte header, extended header, content records, then a (zeroed) 0x20-byte digest.
    pub fn cnmt(&self) -> Vec<u8> {
        let mut d = vec![0u8; 0x20];
        put_u64(&mut d, 0, self.title_id);
        put_u32(&mut d, 8, self.version);
        d[0xC] = self.meta_type;
        put_u16(&mut d, 0xE, self.ext_header.len() as u16);
        put_u16(&mut d, 0x10, self.records.len() as u16);
        d.extend_from_slice(&self.ext_header);
        for r in &self.records {
            d.extend_from_slice(r);
        }
        d.extend_from_slice(&[0u8; 0x20]);
        d
    }

    /// The name of the `.cnmt` file inside the meta NCA, e.g. `Application_0100000000010000.cnmt`.
    pub fn cnmt_name(&self) -> String {
        let kind = match self.meta_type {
            META_APPLICATION => "Application",
            META_PATCH => "Patch",
            META_ADD_ON_CONTENT => "AddOnContent",
            META_DELTA => "Delta",
            META_DATA_PATCH => "DataPatch",
            _ => "Meta",
        };
        format!("{kind}_{:016x}.cnmt", self.title_id)
    }

    /// The meta NCA, encrypted like any other (default section key).
    pub fn build(&self, keys: &Keys) -> BuiltNca {
        let cnmt = self.cnmt();
        NcaBuilder::new(NcaContentType::Meta, self.title_id)
            .section(Section::pfs0(&[(&self.cnmt_name(), &cnmt)]))
            .build(keys)
    }
}

// ---------------------------------------------------------------------------------------------------------
// NACP
// ---------------------------------------------------------------------------------------------------------

/// A 0x4000-byte NACP with `title` and `publisher` in the first language (American English) and `display_version`.
pub fn build_nacp(title: &str, publisher: &str, display_version: &str) -> Vec<u8> {
    assert!(title.len() < 0x200 && publisher.len() < 0x100 && display_version.len() < 0x10);
    let mut d = vec![0u8; 0x4000];
    d[..title.len()].copy_from_slice(title.as_bytes());
    d[0x200..0x200 + publisher.len()].copy_from_slice(publisher.as_bytes());
    d[0x3060..0x3060 + display_version.len()].copy_from_slice(display_version.as_bytes());
    d
}

// ---------------------------------------------------------------------------------------------------------
// NSP
// ---------------------------------------------------------------------------------------------------------

/// Collects named files and packs them into an NSP (a PFS0 file).
#[derive(Default)]
pub struct NspBuilder {
    files: Vec<(String, Vec<u8>)>,
}

impl NspBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an arbitrary file (a ticket, say).
    pub fn file(mut self, name: &str, data: Vec<u8>) -> Self {
        self.files.push((name.to_owned(), data));
        self
    }

    /// Adds `nca` under its own `<content id>.nca` / `.cnmt.nca` name.
    pub fn nca(self, nca: &BuiltNca) -> Self {
        self.file(&nca.file_name(), nca.bytes.clone())
    }

    pub fn build(&self) -> Vec<u8> {
        let files: Vec<(&str, &[u8])> = self.files.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
        build_pfs0(&files)
    }

    /// Writes the NSP to `path`, creating its parent folder if needed.
    pub fn write(&self, path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|e| panic!("creating {}: {e}", parent.display()));
        }
        fs::write(path, self.build()).unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
    }
}
