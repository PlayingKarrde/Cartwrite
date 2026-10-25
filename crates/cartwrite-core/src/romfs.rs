//! RomFS reader: lists the whole directory tree of a RomFS image, or finds a file in its root directory.

use std::collections::HashSet;

use crate::error::{fmt_err, Result};
use crate::storage::Storage;
use crate::util::{u32le, u64le};

/// `read(offset, len)` reads from the start of the RomFS image.
/// Returns (offset, size) of `name` relative to the RomFS start, if present.
pub fn find_root_file(
    read: &mut dyn FnMut(u64, usize) -> Result<Vec<u8>>,
    names: &[&str],
) -> Result<Option<(String, u64, u64)>> {
    let hdr = read(0, 0x50)?;
    if u64le(&hdr, 0) != 0x50 {
        return fmt_err("bad RomFS header");
    }
    let file_meta_off = u64le(&hdr, 0x38);
    let file_meta_size = u64le(&hdr, 0x40);
    let data_off = u64le(&hdr, 0x48);
    if file_meta_size > 16 * 1024 * 1024 {
        return fmt_err("RomFS file table too large");
    }
    let table = read(file_meta_off, file_meta_size as usize)?;
    let mut found: Vec<(usize, String, u64, u64)> = Vec::new();
    let mut pos = 0usize;
    while pos + 0x20 <= table.len() {
        let parent = u32le(&table, pos);
        let offset = u64le(&table, pos + 8);
        let size = u64le(&table, pos + 0x10);
        let name_len = u32le(&table, pos + 0x1C) as usize;
        if pos + 0x20 + name_len > table.len() {
            break;
        }
        let name = String::from_utf8_lossy(&table[pos + 0x20..pos + 0x20 + name_len]).into_owned();
        if parent == 0 {
            if let Some(rank) = names.iter().position(|n| *n == name) {
                found.push((rank, name, data_off + offset, size));
            }
        }
        pos += 0x20 + name_len.div_ceil(4) * 4;
    }
    found.sort_by_key(|f| f.0);
    Ok(found.into_iter().next().map(|(_, n, o, s)| (n, o, s)))
}

/// Size of the RomFS header.
const HEADER_SIZE: usize = 0x50;
/// Largest directory or file meta table we are willing to load.
const MAX_TABLE_SIZE: u64 = 32 * 1024 * 1024;
/// Most directories plus files we accept in one image.
const MAX_ENTRIES: usize = 1_000_000;
/// Deepest path (in components) we accept. Far beyond anything real, and keeps hostile images from
/// making the output quadratic in the number of entries.
const MAX_DEPTH: usize = 256;
/// "No such entry" in the sibling and child links.
const NONE: u32 = 0xFFFF_FFFF;
/// Fixed part of a directory / file entry; the name follows, padded to 4 bytes. The last u32 is the name length.
const DIR_ENTRY_SIZE: usize = 0x18;
const FILE_ENTRY_SIZE: usize = 0x20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RomfsFile {
    /// Path components from the RomFS root, e.g. ["Data", "Model", "a.bin"].
    pub path: Vec<String>,
    /// Offset of the file's data from the start of the RomFS image.
    pub offset: u64,
    pub size: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RomfsTree {
    /// Every directory except the root, parents before children (so creating them in order works; keeps empty dirs).
    pub dirs: Vec<Vec<String>>,
    pub files: Vec<RomfsFile>,
}

/// Reads the whole directory tree of the RomFS image `romfs` (offset 0 = RomFS header).
pub fn read_tree(romfs: &mut dyn Storage) -> Result<RomfsTree> {
    let mut hdr = [0u8; HEADER_SIZE];
    romfs.read(0, &mut hdr)?;
    if u64le(&hdr, 0) != HEADER_SIZE as u64 {
        return fmt_err("bad RomFS header");
    }
    let dir_table = read_table(romfs, u64le(&hdr, 0x18), u64le(&hdr, 0x20), "directory")?;
    let file_table = read_table(romfs, u64le(&hdr, 0x38), u64le(&hdr, 0x40), "file")?;
    let data_start = u64le(&hdr, 0x48);
    let image_size = romfs.size();

    let mut tree = RomfsTree::default();
    // The root is the directory at offset 0; its own name is never used.
    let mut seen_dirs = HashSet::from([0u32]);
    let mut seen_files = HashSet::new();
    let mut count = 0usize;
    let mut stack: Vec<(u32, Vec<String>)> = vec![(0, Vec::new())];
    while let Some((dir_pos, path)) = stack.pop() {
        if !path.is_empty() {
            tree.dirs.push(path.clone());
        }
        let (head, _) = entry(&dir_table, dir_pos, DIR_ENTRY_SIZE)?;
        let (mut next_dir, mut next_file) = (u32le(head, 8), u32le(head, 0xC));

        while next_file != NONE {
            visit(&mut seen_files, &mut count, next_file)?;
            let (head, name) = entry(&file_table, next_file, FILE_ENTRY_SIZE)?;
            let size = u64le(head, 0x10);
            let offset = data_start.checked_add(u64le(head, 8));
            let Some(offset) = offset.filter(|o| o.checked_add(size).is_some_and(|end| end <= image_size)) else {
                return fmt_err("RomFS file extends past the end of the image");
            };
            tree.files.push(RomfsFile { path: child_path(&path, name)?, offset, size });
            next_file = u32le(head, 4);
        }

        let mut subdirs = Vec::new();
        while next_dir != NONE {
            visit(&mut seen_dirs, &mut count, next_dir)?;
            let (head, name) = entry(&dir_table, next_dir, DIR_ENTRY_SIZE)?;
            subdirs.push((next_dir, child_path(&path, name)?));
            next_dir = u32le(head, 4);
        }
        // Reversed so they are popped in table order.
        stack.extend(subdirs.into_iter().rev());
    }
    Ok(tree)
}

/// Loads a meta table (`kind` is "directory" or "file", for the error message).
fn read_table(romfs: &mut dyn Storage, offset: u64, size: u64, kind: &str) -> Result<Vec<u8>> {
    if size > MAX_TABLE_SIZE {
        return fmt_err(format!("RomFS {kind} table too large"));
    }
    let mut table = vec![0u8; size as usize];
    romfs.read(offset, &mut table)?;
    Ok(table)
}

/// The `size`-byte fixed header and the raw name of the entry at `pos` in a meta table.
fn entry(table: &[u8], pos: u32, size: usize) -> Result<(&[u8], &[u8])> {
    let truncated = || fmt_err("RomFS entry extends past its table");
    let Some(tail) = table.get(pos as usize..) else { return truncated() };
    let Some((head, rest)) = tail.split_at_checked(size) else { return truncated() };
    let Some(name) = rest.get(..u32le(head, size - 4) as usize) else { return truncated() };
    Ok((head, name))
}

/// Records that the entry at `pos` was reached; a second visit means the links form a loop.
fn visit(seen: &mut HashSet<u32>, count: &mut usize, pos: u32) -> Result<()> {
    *count += 1;
    if *count > MAX_ENTRIES {
        return fmt_err("RomFS has too many entries");
    }
    if !seen.insert(pos) {
        return fmt_err("RomFS directory tree contains a loop");
    }
    Ok(())
}

/// `parent` plus one more component, after checking that `name` is safe to create on disk.
fn child_path(parent: &[String], name: &[u8]) -> Result<Vec<String>> {
    let Ok(name) = std::str::from_utf8(name) else { return fmt_err("RomFS entry name is not valid UTF-8") };
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
        return fmt_err(format!("invalid RomFS entry name {name:?}"));
    }
    if parent.len() >= MAX_DEPTH {
        return fmt_err("RomFS directory tree is too deep");
    }
    let mut path = Vec::with_capacity(parent.len() + 1);
    path.extend_from_slice(parent);
    path.push(name.to_owned());
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ImageBuilder;

    fn put_u32(img: &mut [u8], at: usize, v: u32) {
        img[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put_u64(img: &mut [u8], at: usize, v: u64) {
        img[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// Offsets in `img` of the first directory entry after the root, and of the first file entry.
    fn first_dir(img: &[u8]) -> usize {
        u64le(img, 0x18) as usize + DIR_ENTRY_SIZE
    }

    fn first_file(img: &[u8]) -> usize {
        u64le(img, 0x38) as usize
    }

    fn path(p: &str) -> Vec<String> {
        p.split('/').map(String::from).collect()
    }

    /// An image with one top-level file `xxxx`, whose entry the tests then patch.
    fn one_file_image() -> Vec<u8> {
        let mut b = ImageBuilder::new();
        b.file("xxxx", b"data");
        b.build()
    }

    /// Asserts that reading `img` fails with an error mentioning `expected`.
    fn assert_fails(img: &mut Vec<u8>, expected: &str) {
        let msg = read_tree(img).expect_err("image was accepted").to_string();
        assert!(msg.contains(expected), "expected an error mentioning {expected:?}, got {msg:?}");
    }

    #[test]
    fn reads_nested_tree() {
        let contents: [(&str, &[u8]); 6] = [
            ("root.txt", b"root file"),
            ("Data/info.txt", b"info"),
            ("Data/Model/a.bin", b"\x01\x02\x03"),
            ("Data/Model/Deep/c.bin", b"deep file with a longer body"),
            ("Data/Model/b.bin", b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ("Data/zero.dat", b""),
        ];
        let mut b = ImageBuilder::new();
        for (p, data) in &contents {
            b.file(p, data);
        }
        b.dir("Data/EmptySub");
        b.dir("Empty");
        let mut img = b.build();

        let tree = read_tree(&mut img).unwrap();

        let mut dirs = tree.dirs.clone();
        dirs.sort();
        let mut expected: Vec<_> =
            ["Data", "Data/EmptySub", "Data/Model", "Data/Model/Deep", "Empty"].into_iter().map(path).collect();
        expected.sort();
        assert_eq!(dirs, expected);
        for (i, dir) in tree.dirs.iter().enumerate() {
            let parent = &dir[..dir.len() - 1];
            assert!(parent.is_empty() || tree.dirs[..i].iter().any(|d| d == parent), "{dir:?} before its parent");
        }

        assert_eq!(tree.files.len(), contents.len());
        for (p, data) in &contents {
            let file = tree.files.iter().find(|f| f.path == path(p)).unwrap_or_else(|| panic!("{p} missing"));
            assert_eq!(file.size, data.len() as u64);
            let mut buf = vec![0u8; data.len()];
            img.read(file.offset, &mut buf).unwrap();
            assert_eq!(&buf, data, "{p}");
        }
    }

    #[test]
    fn empty_romfs_has_an_empty_tree() {
        let mut img = ImageBuilder::new().build();
        assert_eq!(read_tree(&mut img).unwrap(), RomfsTree::default());
    }

    #[test]
    fn deep_trees_are_read_iteratively() {
        let chain = |depth: usize| vec!["d"; depth].join("/");
        let mut b = ImageBuilder::new();
        b.file(&format!("{}/leaf", chain(MAX_DEPTH - 1)), b"leaf");
        let tree = read_tree(&mut b.build()).unwrap();
        assert_eq!(tree.dirs.len(), MAX_DEPTH - 1);
        assert_eq!(tree.files[0].path.len(), MAX_DEPTH);

        let mut b = ImageBuilder::new();
        b.file(&format!("{}/leaf", chain(MAX_DEPTH)), b"leaf");
        assert_fails(&mut b.build(), "too deep");
    }

    #[test]
    fn directory_sibling_loop_is_rejected() {
        let mut b = ImageBuilder::new();
        b.dir("a");
        let mut img = b.build();
        let a = first_dir(&img);
        put_u32(&mut img, a + 4, DIR_ENTRY_SIZE as u32); // a.sibling = a
        assert_fails(&mut img, "loop");
    }

    #[test]
    fn directory_child_loop_is_rejected() {
        let mut b = ImageBuilder::new();
        b.dir("a");
        let mut img = b.build();
        let a = first_dir(&img);
        put_u32(&mut img, a + 8, 0); // a.first_child_dir = root
        assert_fails(&mut img, "loop");
    }

    #[test]
    fn file_sibling_loop_is_rejected() {
        let mut img = one_file_image();
        let f = first_file(&img);
        put_u32(&mut img, f + 4, 0); // file.sibling = file
        assert_fails(&mut img, "loop");
    }

    #[test]
    fn file_linked_from_two_directories_is_rejected() {
        let mut b = ImageBuilder::new();
        b.dir("a");
        b.file("xxxx", b"data");
        let mut img = b.build();
        let a = first_dir(&img);
        put_u32(&mut img, a + 0xC, 0); // a.first_child_file = the root's file
        assert_fails(&mut img, "loop");
    }

    #[test]
    fn dot_dot_name_is_rejected() {
        let mut b = ImageBuilder::new();
        b.file("..", b"x");
        assert_fails(&mut b.build(), "entry name");
    }

    #[test]
    fn unsafe_names_are_rejected() {
        let names: [&[u8]; 8] = [b"", b".", b"..", b"a/b", b"a\\b", b"a\0b", b"\xff\xfe", b"\xc3"];
        for name in names {
            let mut img = one_file_image();
            let f = first_file(&img);
            img[f + FILE_ENTRY_SIZE..f + FILE_ENTRY_SIZE + name.len()].copy_from_slice(name);
            put_u32(&mut img, f + 0x1C, name.len() as u32);
            let msg = read_tree(&mut img).expect_err(&format!("{name:?} accepted")).to_string();
            assert!(msg.contains("entry name"), "{name:?}: {msg}");
        }
        // Sanity check: the unpatched image is fine.
        assert_eq!(read_tree(&mut one_file_image()).unwrap().files[0].path, path("xxxx"));
    }

    #[test]
    fn file_past_end_of_image_is_rejected() {
        let mut img = one_file_image();
        let f = first_file(&img);
        let len = img.len() as u64;
        put_u64(&mut img, f + 0x10, len); // size
        assert_fails(&mut img, "past the end of the image");

        let mut img = one_file_image();
        put_u64(&mut img, f + 0x10, u64::MAX);
        assert_fails(&mut img, "past the end of the image");

        let mut img = one_file_image();
        put_u64(&mut img, f + 8, u64::MAX); // offset overflows when added to the data start
        assert_fails(&mut img, "past the end of the image");
    }

    #[test]
    fn file_ending_exactly_at_end_of_image_is_accepted() {
        let mut img = one_file_image();
        let tree = read_tree(&mut img).unwrap();
        assert_eq!(tree.files[0].offset + tree.files[0].size, img.len() as u64);
    }

    #[test]
    fn truncated_entries_are_rejected() {
        let mut img = one_file_image();
        let f = first_file(&img);
        put_u32(&mut img, f + 0x1C, 0x1000); // name_len beyond the table
        assert_fails(&mut img, "past its table");

        let mut img = one_file_image();
        put_u32(&mut img, f + 0x1C, u32::MAX);
        assert_fails(&mut img, "past its table");

        let mut img = one_file_image();
        put_u32(&mut img, 0x50 + 0xC, 0x10000); // root.first_child_file past the file table
        assert_fails(&mut img, "past its table");

        let mut img = one_file_image();
        put_u32(&mut img, 0x50 + 0xC, u32::MAX - 1);
        assert_fails(&mut img, "past its table");

        let mut img = one_file_image();
        put_u64(&mut img, 0x40, 0x10); // file table shorter than one entry header
        assert_fails(&mut img, "past its table");

        let mut img = one_file_image();
        put_u64(&mut img, 0x20, 0x10); // directory table shorter than the root entry
        assert_fails(&mut img, "past its table");
    }

    #[test]
    fn bad_header_is_rejected() {
        let mut img = one_file_image();
        put_u64(&mut img, 0, 0x51);
        assert_fails(&mut img, "bad RomFS header");

        let mut img = one_file_image();
        put_u64(&mut img, 0x20, MAX_TABLE_SIZE + 1);
        assert_fails(&mut img, "directory table too large");

        let mut img = one_file_image();
        put_u64(&mut img, 0x40, MAX_TABLE_SIZE + 1);
        assert_fails(&mut img, "file table too large");

        let mut img = one_file_image();
        put_u64(&mut img, 0x38, u64::MAX); // table offset is past the image
        assert_fails(&mut img, "read past end");

        assert_fails(&mut vec![0u8; 0x10], "read past end");
    }
}
