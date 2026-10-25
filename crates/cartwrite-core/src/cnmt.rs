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
    /// For a DLC update (data patch): the DLC title it updates (DataPatchMetaExtendedHeader DataId, at ext+0).
    pub data_id: Option<u64>,
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
        let data_id = (meta_type == META_DATA_PATCH).then(|| u64le(d, ext));
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
        Ok(Self { title_id, version, meta_type, application_id, data_id, required_system_version, contents })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u16(d: &mut [u8], at: usize, v: u16) {
        d[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn put_u32(d: &mut [u8], at: usize, v: u32) {
        d[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put_u64(d: &mut [u8], at: usize, v: u64) {
        d[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// A cnmt of `meta_type` with `ext` as extended header and one content record (a program with `id_offset`).
    fn cnmt_bytes(title_id: u64, version: u32, meta_type: u8, ext: &[u8], id_offset: u8) -> Vec<u8> {
        let mut d = vec![0u8; 0x20];
        put_u64(&mut d, 0, title_id);
        put_u32(&mut d, 8, version);
        d[0xC] = meta_type;
        put_u16(&mut d, 0xE, ext.len() as u16);
        put_u16(&mut d, 0x10, 1);
        d.extend_from_slice(ext);
        let mut record = [0u8; 0x38];
        record[0x20..0x30].copy_from_slice(&[0xAB; 16]);
        record[0x30] = 0x10;
        record[0x36] = CT_PROGRAM;
        record[0x37] = id_offset;
        d.extend_from_slice(&record);
        d.extend_from_slice(&[0u8; 0x20]);
        d
    }

    #[test]
    fn data_patch_names_the_dlc_it_updates() {
        // DataId, ApplicationId, RequiredApplicationVersion, ExtendedDataSize, reserved.
        const DATA_ID: u64 = 0x0100_0000_0001_1001;
        const APPLICATION_ID: u64 = 0x0100_0000_0001_0000;
        let mut ext = vec![0u8; 0x20];
        put_u64(&mut ext, 0, DATA_ID);
        put_u64(&mut ext, 8, APPLICATION_ID);
        put_u32(&mut ext, 0x10, 0x0001_0000);
        let c = Cnmt::parse(&cnmt_bytes(0x0100_0000_0001_1801, 0x2_0000, META_DATA_PATCH, &ext, 0)).unwrap();
        assert_eq!((c.title_id, c.version, c.meta_type), (0x0100_0000_0001_1801, 0x2_0000, META_DATA_PATCH));
        assert_eq!(c.data_id, Some(DATA_ID));
        assert_eq!(c.application_id, APPLICATION_ID);
        assert_eq!(c.required_system_version, None);
        assert_eq!(c.contents.len(), 1);
        assert_eq!((c.contents[0].content_type, c.contents[0].id_offset), (CT_PROGRAM, 0));
    }

    #[test]
    fn data_patch_needs_its_ids() {
        let err = Cnmt::parse(&cnmt_bytes(0x0100_0000_0001_1801, 0, META_DATA_PATCH, &[0u8; 8], 0)).unwrap_err();
        assert!(err.to_string().contains("extended header too small"), "{err}");
    }

    #[test]
    fn application_has_no_data_id() {
        const TITLE_ID: u64 = 0x0100_0000_0001_0000;
        let mut ext = vec![0u8; 0x10];
        put_u64(&mut ext, 0, TITLE_ID + 0x800);
        put_u32(&mut ext, 8, 0x0003_0000);
        let c = Cnmt::parse(&cnmt_bytes(TITLE_ID, 0, META_APPLICATION, &ext, 1)).unwrap();
        assert_eq!(c.data_id, None);
        assert_eq!(c.application_id, TITLE_ID);
        assert_eq!(c.required_system_version, Some(0x0003_0000));
        assert_eq!((c.contents[0].content_type, c.contents[0].id_offset), (CT_PROGRAM, 1));
    }
}
