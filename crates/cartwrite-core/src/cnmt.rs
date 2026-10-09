//! Content meta (cnmt) parsing.

use crate::error::{fmt_err, Result};
use crate::util::{u16le, u32le, u64le};

pub const META_APPLICATION: u8 = 0x80;
pub const META_PATCH: u8 = 0x81;
pub const META_ADD_ON_CONTENT: u8 = 0x82;
pub const META_DELTA: u8 = 0x83;
pub const META_DATA_PATCH: u8 = 0x84;

/// Content record types.
pub const CT_META: u8 = 0;
pub const CT_PROGRAM: u8 = 1;
pub const CT_DATA: u8 = 2;
pub const CT_CONTROL: u8 = 3;
pub const CT_HTML_DOCUMENT: u8 = 4;
pub const CT_LEGAL_INFORMATION: u8 = 5;
pub const CT_DELTA_FRAGMENT: u8 = 6;

#[derive(Clone, Debug)]
pub struct ContentRecord {
    pub hash: [u8; 32],
    pub content_id: [u8; 16],
    pub size: u64,
    pub content_type: u8,
    pub id_offset: u8,
}

impl ContentRecord {
    pub fn content_id_hex(&self) -> String {
        crate::util::hex(&self.content_id)
    }
}

#[derive(Clone, Debug)]
pub struct Cnmt {
    pub title_id: u64,
    pub version: u32,
    pub meta_type: u8,
    /// The base application this content belongs to.
    pub application_id: u64,
    /// Present for applications and patches (absolute offset 0x28 in the cnmt).
    pub required_system_version: Option<u32>,
    pub contents: Vec<ContentRecord>,
}

/// Absolute offset of the RequiredSystemVersion field within a cnmt.
pub const RSV_OFFSET: usize = 0x28;

impl Cnmt {
    pub fn parse(d: &[u8]) -> Result<Self> {
        if d.len() < 0x20 {
            return fmt_err("cnmt too small");
        }
        let title_id = u64le(d, 0);
        let version = u32le(d, 8);
        let meta_type = d[0xC];
        let ext_size = u16le(d, 0xE) as usize;
        let count = u16le(d, 0x10) as usize;
        let ext = 0x20;
        if d.len() < ext + ext_size + count * 0x38 {
            return fmt_err("cnmt truncated");
        }
        // Bytes of extended header each meta type needs for the fields read below.
        let needed = match meta_type {
            META_APPLICATION | META_PATCH => 0xC,
            META_ADD_ON_CONTENT => 0x8,
            META_DATA_PATCH => 0x10,
            _ => 0,
        };
        if ext_size < needed {
            return fmt_err("cnmt extended header too small");
        }
        let (application_id, required_system_version) = match meta_type {
            META_APPLICATION => (title_id, Some(u32le(d, ext + 8))),
            META_PATCH => (u64le(d, ext), Some(u32le(d, ext + 8))),
            META_ADD_ON_CONTENT => (u64le(d, ext), None),
            META_DATA_PATCH => (u64le(d, ext + 8), None),
            _ => (title_id & !0x1FFF, None),
        };
        let contents = (0..count)
            .map(|i| {
                let r = ext + ext_size + i * 0x38;
                let mut size_bytes = [0u8; 8];
                size_bytes[..5].copy_from_slice(&d[r + 0x30..r + 0x35]);
                ContentRecord {
                    hash: d[r..r + 0x20].try_into().unwrap(),
                    content_id: d[r + 0x20..r + 0x30].try_into().unwrap(),
                    size: u64::from_le_bytes(size_bytes),
                    content_type: d[r + 0x36],
                    id_offset: d[r + 0x37],
                }
            })
            .collect();
        Ok(Self { title_id, version, meta_type, application_id, required_system_version, contents })
    }
}
