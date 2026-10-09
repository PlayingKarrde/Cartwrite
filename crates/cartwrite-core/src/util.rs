use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

pub fn read_at(f: &mut File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(buf)
}

pub fn read_vec_at(f: &mut File, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    let mut v = vec![0u8; len];
    read_at(f, offset, &mut v)?;
    Ok(v)
}

pub fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}

pub fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

pub fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Reads a NUL-terminated string from a byte table (empty if `o` is out of range).
pub fn cstr(b: &[u8], o: usize) -> String {
    let Some(tail) = b.get(o..) else { return String::new() };
    let end = tail.iter().position(|&c| c == 0).unwrap_or(tail.len());
    String::from_utf8_lossy(&tail[..end]).into_owned()
}

/// `data[offset..offset + len]`, or `None` if that range is out of bounds or overflows.
pub fn slice(data: &[u8], offset: u64, len: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::try_from(len).ok()?)?;
    data.get(start..end)
}

pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.2} {}", UNITS[u])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cstr_and_slice_are_bounds_safe() {
        assert_eq!(cstr(b"abc\0def", 0), "abc");
        assert_eq!(cstr(b"abc", 10), "");
        assert_eq!(slice(b"abcdef", 2, 3), Some(&b"cde"[..]));
        assert_eq!(slice(b"abcdef", 4, 3), None);
        assert_eq!(slice(b"abcdef", u64::MAX, 2), None);
    }
}
