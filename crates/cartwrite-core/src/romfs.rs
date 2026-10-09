//! Minimal RomFS reader: finds a file in the root directory.

use crate::error::{fmt_err, Result};
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
