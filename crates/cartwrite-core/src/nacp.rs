//! Control data (NACP) parsing: game title, publisher and display version.

use crate::util::cstr;

pub const LANGUAGES: [&str; 16] = [
    "AmericanEnglish",
    "BritishEnglish",
    "Japanese",
    "French",
    "German",
    "LatinAmericanSpanish",
    "Spanish",
    "Italian",
    "Dutch",
    "CanadianFrench",
    "Portuguese",
    "Russian",
    "Korean",
    "TraditionalChinese",
    "SimplifiedChinese",
    "BrazilianPortuguese",
];

#[derive(Clone, Debug, Default)]
pub struct Nacp {
    pub title: String,
    pub publisher: String,
    pub display_version: String,
    /// Index into [`LANGUAGES`] of the entry `title` came from.
    pub language: usize,
}

impl Nacp {
    pub fn parse(d: &[u8]) -> Option<Self> {
        if d.len() < 0x3070 {
            return None;
        }
        let titles = title_table(d)?;
        let (language, title, publisher) = (0..titles.len() / 0x300).find_map(|i| {
            let t = cstr(&titles[i * 0x300..i * 0x300 + 0x200], 0);
            (!t.trim().is_empty()).then(|| (i, t, cstr(&titles[i * 0x300 + 0x200..i * 0x300 + 0x300], 0)))
        })?;
        Some(Self { title, publisher, display_version: cstr(&d[0x3060..0x3070], 0), language })
    }
}

/// Offset of the TitleCompression flag (newer SDKs).
const TITLE_COMPRESSION: usize = 0x3215;

/// Returns the per-language title entries (0x300 bytes each).
///
/// Newer SDKs can store up to 32 languages by compressing the table: the first 0x3000 bytes
/// then hold a u16 compressed length followed by raw-deflate data.
fn title_table(d: &[u8]) -> Option<std::borrow::Cow<'_, [u8]>> {
    if d.get(TITLE_COMPRESSION).copied().unwrap_or(0) == 0 {
        return Some(std::borrow::Cow::Borrowed(&d[..0x3000]));
    }
    let len = u16::from_le_bytes([d[0], d[1]]) as usize;
    let data = d.get(2..2 + len)?;
    let out = miniz_oxide::inflate::decompress_to_vec(data)
        .or_else(|_| miniz_oxide::inflate::decompress_to_vec_zlib(data))
        .ok()?;
    (out.len() >= 0x300).then_some(std::borrow::Cow::Owned(out))
}

/// RomFS file names to try for the icon, best first.
pub fn icon_names(preferred_language: usize) -> Vec<String> {
    let mut v = vec![format!("icon_{}.dat", LANGUAGES[preferred_language.min(15)])];
    v.extend(LANGUAGES.iter().map(|l| format!("icon_{l}.dat")));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(table: &mut [u8], lang: usize, title: &str, publisher: &str) {
        table[lang * 0x300..lang * 0x300 + title.len()].copy_from_slice(title.as_bytes());
        let p = lang * 0x300 + 0x200;
        table[p..p + publisher.len()].copy_from_slice(publisher.as_bytes());
    }

    #[test]
    fn plain_titles() {
        let mut d = vec![0u8; 0x4000];
        entry(&mut d, 0, "Game", "Pub");
        d[0x3060..0x3065].copy_from_slice(b"1.0.0");
        let n = Nacp::parse(&d).unwrap();
        assert_eq!((n.title.as_str(), n.publisher.as_str(), n.display_version.as_str()), ("Game", "Pub", "1.0.0"));
    }

    #[test]
    fn compressed_titles() {
        let mut table = vec![0u8; 0x6000];
        entry(&mut table, 1, "Compressed Game", "Big N");
        let packed = miniz_oxide::deflate::compress_to_vec(&table, 6);
        let mut d = vec![0u8; 0x4000];
        d[..2].copy_from_slice(&(packed.len() as u16).to_le_bytes());
        d[2..2 + packed.len()].copy_from_slice(&packed);
        d[TITLE_COMPRESSION] = 1;
        let n = Nacp::parse(&d).unwrap();
        assert_eq!((n.title.as_str(), n.publisher.as_str(), n.language), ("Compressed Game", "Big N", 1));
    }
}
