//! Required System Version helpers.
//!
//! A title's cnmt carries the minimum firmware ("required system version") the console must
//! run. Content can only actually be decrypted by firmware that has its master key, so the
//! lowest *useful* requirement is the first firmware that shipped that key. Patching the RSV
//! down to that value avoids pointless "system update required" prompts.

/// Encodes a firmware version the way cnmt RSV fields do (3.0.0 and later).
pub const fn fw(major: u32, minor: u32, patch: u32) -> u32 {
    (major << 26) | (minor << 20) | (patch << 16)
}

/// (key generation byte, lowest RSV for that key generation, firmware label)
const KEYGEN_TABLE: &[(u8, u32, &str)] = &[
    (0, 0, "1.0.0"),
    (1, 0, "1.0.0"),
    (2, fw(3, 0, 0), "3.0.0"),
    (3, fw(3, 0, 1), "3.0.1"),
    (4, fw(4, 0, 0), "4.0.0"),
    (5, fw(5, 0, 0), "5.0.0"),
    (6, fw(6, 0, 0), "6.0.0"),
    (7, fw(6, 2, 0), "6.2.0"),
    (8, fw(7, 0, 0), "7.0.0"),
    (9, fw(8, 1, 0), "8.1.0"),
    (10, fw(9, 0, 0), "9.0.0"),
    (11, fw(9, 1, 0), "9.1.0"),
    (12, fw(12, 1, 0), "12.1.0"),
    (13, fw(13, 0, 0), "13.0.0"),
    (14, fw(14, 0, 0), "14.0.0"),
    (15, fw(15, 0, 0), "15.0.0"),
    (16, fw(16, 0, 0), "16.0.0"),
    (17, fw(17, 0, 0), "17.0.0"),
    (18, fw(18, 0, 0), "18.0.0"),
    (19, fw(19, 0, 0), "19.0.0"),
    (20, fw(20, 0, 0), "20.0.0"),
    (21, fw(21, 0, 0), "21.0.0"),
];

/// Lowest RSV that still guarantees the console has the key for `key_generation`.
pub fn min_rsv_for_keygen(key_generation: u8) -> Option<u32> {
    KEYGEN_TABLE.iter().find(|e| e.0 == key_generation).map(|e| e.1)
}

pub fn firmware_for_keygen(key_generation: u8) -> Option<&'static str> {
    KEYGEN_TABLE.iter().find(|e| e.0 == key_generation).map(|e| e.2)
}

pub fn firmware_for_master_key(master_key_index: usize) -> Option<&'static str> {
    firmware_for_keygen(if master_key_index == 0 { 0 } else { master_key_index as u8 + 1 })
}

/// What the RSV should become, or `None` if it is already low enough / keygen unknown.
pub fn patched_rsv(current: u32, key_generation: u8) -> Option<u32> {
    let min = min_rsv_for_keygen(key_generation)?;
    (current > min).then_some(min)
}

/// Human readable form of an RSV value, e.g. "16.0.3".
pub fn format_rsv(rsv: u32) -> String {
    if rsv >= fw(3, 0, 0) {
        let s = format!("{}.{}.{}", rsv >> 26, (rsv >> 20) & 0x3F, (rsv >> 16) & 0xF);
        if rsv & 0xFFFF != 0 {
            format!("{s}-{}", rsv & 0xFFFF)
        } else {
            s
        }
    } else if rsv >= 0x10000 {
        format!("2.{}.0", rsv >> 16)
    } else {
        "1.0.0".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsv_format() {
        assert_eq!(format_rsv(fw(16, 0, 3)), "16.0.3");
        assert_eq!(format_rsv(805502976), "12.0.3");
        assert_eq!(patched_rsv(fw(16, 1, 0), 16), Some(fw(16, 0, 0)));
        assert_eq!(patched_rsv(fw(15, 0, 0), 16), None);
    }
}
