//! eShop ticket parsing.

use crate::crypto::Key128;
use crate::error::{fmt_err, Result};

#[derive(Clone, Debug)]
pub struct Ticket {
    pub rights_id: [u8; 16],
    pub title_key_block: Key128,
    /// 0 = common, 1 = personalized (console-bound, can't be converted without console keys).
    pub key_type: u8,
    pub master_key_revision: u8,
}

impl Ticket {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return fmt_err("ticket too small");
        }
        let sig_type = u32::from_le_bytes(data[..4].try_into().unwrap());
        let sig_block = match sig_type {
            0x10000 | 0x10003 => 0x200 + 0x3C,
            0x10001 | 0x10004 => 0x100 + 0x3C,
            0x10002 | 0x10005 => 0x3C + 0x40,
            _ => return fmt_err(format!("unknown ticket signature type {sig_type:#x}")),
        };
        let b = 4 + sig_block;
        if data.len() < b + 0x180 {
            return fmt_err("ticket truncated");
        }
        Ok(Self {
            title_key_block: data[b + 0x40..b + 0x50].try_into().unwrap(),
            key_type: data[b + 0x141],
            master_key_revision: data[b + 0x145],
            rights_id: data[b + 0x160..b + 0x170].try_into().unwrap(),
        })
    }
}
