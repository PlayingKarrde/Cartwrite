//! Random-access plaintext views (an NCA section, a RomFS image inside it, ...) used when
//! extracting files.

use crate::crypto::Key128;
use crate::error::{fmt_err, Error, Result};
use crate::nca::{NcaHeader, NcaSource};

pub trait Storage {
    fn size(&self) -> u64;
    /// Fills `buf` with the bytes at `offset`. Reading past `size()` is an error.
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()>;
}

fn check_range(offset: u64, len: usize, size: u64) -> Result<()> {
    match offset.checked_add(len as u64) {
        Some(end) if end <= size => Ok(()),
        _ => fmt_err(format!("read past end of storage ({offset:#x}+{len:#x} > {size:#x})")),
    }
}

impl Storage for Vec<u8> {
    fn size(&self) -> u64 {
        self.len() as u64
    }

    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size())?;
        let start = offset as usize;
        buf.copy_from_slice(&self[start..start + buf.len()]);
        Ok(())
    }
}

/// A window `[offset, offset + size)` of another storage.
pub struct SubStorage<'a> {
    inner: &'a mut dyn Storage,
    offset: u64,
    size: u64,
}

impl<'a> SubStorage<'a> {
    pub fn new(inner: &'a mut dyn Storage, offset: u64, size: u64) -> Result<Self> {
        check_range(offset, 0, inner.size())?;
        if offset.checked_add(size).is_none_or(|end| end > inner.size()) {
            return fmt_err("sub-storage extends past its parent");
        }
        Ok(Self { inner, offset, size })
    }
}

impl Storage for SubStorage<'_> {
    fn size(&self) -> u64 {
        self.size
    }

    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size)?;
        self.inner.read(self.offset + offset, buf)
    }
}

/// Plaintext of one NCA section (section-relative offsets). Only for sections whose crypto
/// `nca::decrypt_in_place` handles correctly, i.e. not BKTR patch sections.
pub struct NcaSection<'a> {
    src: &'a mut dyn NcaSource,
    header: &'a NcaHeader,
    key: Key128,
    start: u64,
    size: u64,
}

impl<'a> NcaSection<'a> {
    pub fn new(src: &'a mut dyn NcaSource, header: &'a NcaHeader, key: Key128, section: usize) -> Result<Self> {
        let s = header.section(section).ok_or_else(|| Error::Format(format!("NCA has no section {section}")))?;
        Ok(Self { src, header, key, start: s.start, size: s.end - s.start })
    }
}

impl Storage for NcaSection<'_> {
    fn size(&self) -> u64 {
        self.size
    }

    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size)?;
        self.src.read_plain(self.header, &self.key, self.start + offset, buf)
    }
}

/// One NCA section as stored, still encrypted (section-relative offsets). Used under the
/// update-section layers in [`crate::bktr`], which do their own decryption.
pub struct RawSection<'a> {
    src: &'a mut dyn NcaSource,
    header: &'a NcaHeader,
    key: Key128,
    start: u64,
    size: u64,
}

impl<'a> RawSection<'a> {
    pub fn new(src: &'a mut dyn NcaSource, header: &'a NcaHeader, key: Key128, section: usize) -> Result<Self> {
        let s = header.section(section).ok_or_else(|| Error::Format(format!("NCA has no section {section}")))?;
        Ok(Self { src, header, key, start: s.start, size: s.end - s.start })
    }
}

impl Storage for RawSection<'_> {
    fn size(&self) -> u64 {
        self.size
    }

    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size)?;
        self.src.read_raw(self.header, &self.key, self.start + offset, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_storage_is_bounds_checked() {
        let mut v: Vec<u8> = (0..16).collect();
        let mut sub = SubStorage::new(&mut v, 4, 8).unwrap();
        let mut buf = [0u8; 3];
        sub.read(5, &mut buf).unwrap();
        assert_eq!(buf, [9, 10, 11]);
        assert!(sub.read(6, &mut buf).is_err());
        assert!(SubStorage::new(&mut v, 10, 8).is_err());
    }
}
