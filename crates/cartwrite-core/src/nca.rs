//! NCA header handling and section decryption.

use std::fs::File;

use crate::crypto::{ecb_decrypt, ecb_encrypt, Ctr, Key128, Xts};
use crate::error::{fmt_err, Error, Result};
use crate::keys::{master_key_index, Keys};
use crate::util::{read_at, u32le, u64le};

pub const HEADER_SIZE: usize = 0xC00;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NcaContentType {
    Program,
    Meta,
    Control,
    Manual,
    Data,
    PublicData,
    Unknown(u8),
}

impl From<u8> for NcaContentType {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Program,
            1 => Self::Meta,
            2 => Self::Control,
            3 => Self::Manual,
            4 => Self::Data,
            5 => Self::PublicData,
            o => Self::Unknown(o),
        }
    }
}

/// Section encryption type from the FS header.
pub const CRYPT_NONE: u8 = 1;
pub const CRYPT_XTS: u8 = 2;
pub const CRYPT_CTR: u8 = 3;
pub const CRYPT_BKTR: u8 = 4;

#[derive(Clone)]
pub struct NcaHeader {
    /// Decrypted header bytes.
    pub raw: Box<[u8; HEADER_SIZE]>,
}

#[derive(Clone, Copy, Debug)]
pub struct SectionInfo {
    pub index: usize,
    pub start: u64,
    pub end: u64,
}

impl NcaHeader {
    pub fn decrypt(enc: &[u8], keys: &Keys) -> Result<Self> {
        if enc.len() < HEADER_SIZE {
            return fmt_err("NCA too small");
        }
        let mut raw = Box::new([0u8; HEADER_SIZE]);
        raw.copy_from_slice(&enc[..HEADER_SIZE]);
        Xts::new(keys.header_key()).decrypt(&mut raw[..], 0, 0x200);
        match &raw[0x200..0x204] {
            b"NCA3" => Ok(Self { raw }),
            b"NCA2" | b"NCA0" => Err(Error::Unsupported("legacy NCA2/NCA0 content is not supported".into())),
            _ => fmt_err("NCA header failed to decrypt (wrong header_key or corrupt file)"),
        }
    }

    pub fn encrypt(&self, keys: &Keys) -> Vec<u8> {
        let mut out = self.raw.to_vec();
        Xts::new(keys.header_key()).encrypt(&mut out, 0, 0x200);
        out
    }

    pub fn content_type(&self) -> NcaContentType {
        self.raw[0x205].into()
    }

    /// Effective key generation (the larger of the two header fields).
    pub fn key_generation(&self) -> u8 {
        self.raw[0x206].max(self.raw[0x220])
    }

    pub fn kaek_index(&self) -> u8 {
        self.raw[0x207]
    }

    pub fn nca_size(&self) -> u64 {
        u64le(&self.raw[..], 0x208)
    }

    pub fn rights_id(&self) -> [u8; 16] {
        self.raw[0x230..0x240].try_into().unwrap()
    }

    pub fn has_rights_id(&self) -> bool {
        self.raw[0x230..0x240].iter().any(|&b| b != 0)
    }

    pub fn section(&self, i: usize) -> Option<SectionInfo> {
        let e = 0x240 + i * 0x10;
        let start = u32le(&self.raw[..], e) as u64 * 0x200;
        let end = u32le(&self.raw[..], e + 4) as u64 * 0x200;
        (end > start).then_some(SectionInfo { index: i, start, end })
    }

    pub fn sections(&self) -> impl Iterator<Item = SectionInfo> + '_ {
        (0..4).filter_map(|i| self.section(i))
    }

    pub fn fs_header(&self, i: usize) -> &[u8] {
        &self.raw[0x400 + i * 0x200..0x600 + i * 0x200]
    }

    pub fn fs_header_mut(&mut self, i: usize) -> &mut [u8] {
        &mut self.raw[0x400 + i * 0x200..0x600 + i * 0x200]
    }

    pub fn section_crypto(&self, i: usize) -> u8 {
        self.fs_header(i)[4]
    }

    /// Upper 8 bytes of the AES-CTR counter for section `i`.
    pub fn section_nonce(&self, i: usize) -> [u8; 8] {
        let mut n: [u8; 8] = self.fs_header(i)[0x140..0x148].try_into().unwrap();
        n.reverse();
        n
    }

    pub fn master_key_index(&self) -> usize {
        master_key_index(self.key_generation())
    }

    /// Returns the decrypted key area (4 keys).
    pub fn decrypt_key_area(&self, keys: &Keys) -> Result<[Key128; 4]> {
        let kak = keys.key_area_key(self.master_key_index(), self.kaek_index())?;
        let mut area: [u8; 0x40] = self.raw[0x300..0x340].try_into().unwrap();
        ecb_decrypt(&kak, &mut area);
        Ok(std::array::from_fn(|i| area[i * 16..i * 16 + 16].try_into().unwrap()))
    }

    /// AES-CTR key for the sections. `title_key` is the *decrypted* title key for
    /// rights-ID (eShop) content.
    pub fn section_key(&self, keys: &Keys, title_key: Option<&Key128>) -> Result<Key128> {
        if self.has_rights_id() {
            title_key.copied().ok_or_else(|| {
                Error::Unsupported(format!(
                    "no ticket found for rights ID {} (NSP is missing its .tik)",
                    crate::util::hex(&self.rights_id())
                ))
            })
        } else {
            Ok(self.decrypt_key_area(keys)?[2])
        }
    }

    /// Converts rights-ID content to "standard crypto": writes the title key into the key
    /// area and clears the rights ID, so no ticket is needed to install it.
    pub fn remove_title_rights(&mut self, keys: &Keys, title_key: &Key128) -> Result<()> {
        let kak = keys.key_area_key(self.master_key_index(), self.kaek_index())?;
        let mut area = [0u8; 0x40];
        for i in 0..4 {
            area[i * 16..i * 16 + 16].copy_from_slice(title_key);
        }
        ecb_encrypt(&kak, &mut area);
        self.raw[0x300..0x340].copy_from_slice(&area);
        self.raw[0x230..0x240].fill(0);
        Ok(())
    }

    /// Recomputes the FS header hash stored in the main header for section `i`.
    pub fn update_fs_header_hash(&mut self, i: usize) {
        use sha2::{Digest, Sha256};
        let h = Sha256::digest(self.fs_header(i));
        self.raw[0x280 + i * 0x20..0x2A0 + i * 0x20].copy_from_slice(&h);
    }
}

/// Decrypts the title key from a ticket's title key block.
pub fn decrypt_title_key(keys: &Keys, enc: &Key128, key_generation: u8) -> Result<Key128> {
    let kek = keys.titlekek(master_key_index(key_generation))?;
    Ok(crate::crypto::ecb_decrypt_key(&kek, enc))
}

/// Something that can return plaintext bytes at an absolute offset inside an NCA.
pub trait NcaSource {
    fn read_plain(&mut self, header: &NcaHeader, key: &Key128, offset: u64, buf: &mut [u8]) -> Result<()>;
}

/// An encrypted NCA stored at `base` inside a file.
pub struct FileNca<'a> {
    pub file: &'a mut File,
    pub base: u64,
}

impl NcaSource for FileNca<'_> {
    fn read_plain(&mut self, header: &NcaHeader, key: &Key128, offset: u64, buf: &mut [u8]) -> Result<()> {
        let aligned = offset & !0xF;
        let pad = (offset - aligned) as usize;
        let mut tmp = vec![0u8; pad + buf.len()];
        read_at(self.file, self.base + aligned, &mut tmp)?;
        decrypt_in_place(header, key, aligned, &mut tmp)?;
        buf.copy_from_slice(&tmp[pad..]);
        Ok(())
    }
}

/// Decrypts `data` that starts at absolute NCA offset `offset` (must be 16-aligned),
/// applying each section's crypto to the bytes it covers.
pub fn decrypt_in_place(header: &NcaHeader, key: &Key128, offset: u64, data: &mut [u8]) -> Result<()> {
    let end = offset + data.len() as u64;
    for s in header.sections() {
        let lo = s.start.max(offset);
        let hi = s.end.min(end);
        if lo >= hi {
            continue;
        }
        let slice = &mut data[(lo - offset) as usize..(hi - offset) as usize];
        match header.section_crypto(s.index) {
            CRYPT_NONE => {}
            CRYPT_CTR | CRYPT_BKTR => Ctr::new(key, header.section_nonce(s.index)).apply(lo, slice),
            other => return Err(Error::Unsupported(format!("unsupported section crypto type {other}"))),
        }
    }
    Ok(())
}

/// Reads a section-relative range as plaintext.
pub fn read_section(
    src: &mut dyn NcaSource,
    header: &NcaHeader,
    key: &Key128,
    section: usize,
    rel: u64,
    len: usize,
) -> Result<Vec<u8>> {
    let s = header.section(section).ok_or_else(|| Error::Format(format!("NCA has no section {section}")))?;
    let in_range = s.start.checked_add(rel).and_then(|v| v.checked_add(len as u64)).is_some_and(|end| end <= s.end);
    if !in_range {
        return fmt_err("read past end of NCA section");
    }
    let mut buf = vec![0u8; len];
    src.read_plain(header, key, s.start + rel, &mut buf)?;
    Ok(buf)
}

/// Location of the PFS0 inside a hierarchical-SHA256 section (used by meta NCAs).
#[derive(Clone, Copy, Debug)]
pub struct Sha256Layout {
    pub block_size: u64,
    pub hash_table_offset: u64,
    pub hash_table_size: u64,
    pub data_offset: u64,
    pub data_size: u64,
}

pub fn sha256_layout(header: &NcaHeader, section: usize) -> Result<Sha256Layout> {
    let fs = header.fs_header(section);
    if fs[3] != 2 {
        return fmt_err("section is not hierarchical-SHA256 hashed");
    }
    Ok(Sha256Layout {
        block_size: u32le(fs, 0x28) as u64,
        hash_table_offset: u64le(fs, 0x30),
        hash_table_size: u64le(fs, 0x38),
        data_offset: u64le(fs, 0x40),
        data_size: u64le(fs, 0x48),
    })
}

/// Location of the RomFS data level inside an IVFC section.
pub fn ivfc_data_level(header: &NcaHeader, section: usize) -> Result<(u64, u64)> {
    let fs = header.fs_header(section);
    if fs[3] != 3 || &fs[8..12] != b"IVFC" {
        return fmt_err("section is not an IVFC RomFS");
    }
    let levels = (u32le(fs, 0x14) as usize).saturating_sub(1).clamp(1, 6);
    let lvl = 0x18 + (levels - 1) * 0x18;
    Ok((u64le(fs, lvl), u64le(fs, lvl + 8)))
}
