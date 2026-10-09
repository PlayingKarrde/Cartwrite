//! Loading of the user's `prod.keys` (Lockpick/hactool format).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::crypto::{ecb_decrypt_key, Key128};
use crate::error::{Error, Result};
use crate::util::parse_hex;

pub const MAX_KEY_GEN: usize = 0x20;

#[derive(Clone)]
pub struct Keys {
    pub path: PathBuf,
    header_key: [u8; 32],
    key_area_keys: [[Option<Key128>; 3]; MAX_KEY_GEN],
    titlekeks: [Option<Key128>; MAX_KEY_GEN],
    pub xci_header_key: Option<Key128>,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("path", &self.path)
            .field("max_master_key", &self.max_master_key())
            .finish_non_exhaustive()
    }
}

impl Keys {
    /// Locations searched when the user hasn't picked a keys file.
    pub fn default_locations() -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                out.push(dir.join("prod.keys"));
                out.push(dir.join("keys.txt"));
                out.push(dir.join("Keys").join("prod.keys"));
            }
        }
        if let Ok(cwd) = std::env::current_dir() {
            out.push(cwd.join("prod.keys"));
            out.push(cwd.join("Keys").join("prod.keys"));
        }
        if let Some(home) = dirs::home_dir() {
            out.push(home.join(".switch").join("prod.keys"));
            out.push(home.join(".switch").join("keys.txt"));
        }
        out
    }

    pub fn find_default() -> Option<PathBuf> {
        Self::default_locations().into_iter().find(|p| p.is_file())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::File { path: path.to_path_buf(), source: e })?;
        let mut raw: HashMap<String, Vec<u8>> = HashMap::new();
        for line in text.lines() {
            let Some((name, value)) = line.split_once('=') else { continue };
            let name = name.trim().to_ascii_lowercase();
            if let Some(bytes) = parse_hex(value.trim()) {
                raw.insert(name, bytes);
            }
        }
        Self::from_map(path.to_path_buf(), &raw)
    }

    fn from_map(path: PathBuf, raw: &HashMap<String, Vec<u8>>) -> Result<Self> {
        let k16 = |name: &str| -> Option<Key128> { raw.get(name).and_then(|v| v.as_slice().try_into().ok()) };

        let kek_src = k16("aes_kek_generation_source");
        let key_src = k16("aes_key_generation_source");
        let generate_kek = |src: &Key128, master: &Key128| -> Option<Key128> {
            let kek = ecb_decrypt_key(master, &kek_src?);
            let src_kek = ecb_decrypt_key(&kek, src);
            Some(ecb_decrypt_key(&src_kek, &key_src?))
        };

        let header_key: [u8; 32] = match raw.get("header_key").and_then(|v| v.as_slice().try_into().ok()) {
            Some(k) => k,
            None => {
                // Derive from master_key_00 like hactool does.
                let derived = (|| {
                    let mk0 = k16("master_key_00")?;
                    let header_kek = generate_kek(&k16("header_kek_source")?, &mk0)?;
                    let src = raw.get("header_key_source")?;
                    if src.len() != 32 {
                        return None;
                    }
                    let a = ecb_decrypt_key(&header_kek, src[..16].try_into().ok()?);
                    let b = ecb_decrypt_key(&header_kek, src[16..].try_into().ok()?);
                    let mut k = [0u8; 32];
                    k[..16].copy_from_slice(&a);
                    k[16..].copy_from_slice(&b);
                    Some(k)
                })();
                derived.ok_or_else(|| Error::MissingKey("header_key".into()))?
            }
        };

        let mut key_area_keys = [[None; 3]; MAX_KEY_GEN];
        let mut titlekeks = [None; MAX_KEY_GEN];
        let kinds = ["application", "ocean", "system"];
        for i in 0..MAX_KEY_GEN {
            let master = k16(&format!("master_key_{i:02x}"));
            for (k, kind) in kinds.iter().enumerate() {
                key_area_keys[i][k] = k16(&format!("key_area_key_{kind}_{i:02x}"))
                    .or_else(|| generate_kek(&k16(&format!("key_area_key_{kind}_source"))?, master.as_ref()?));
            }
            titlekeks[i] = k16(&format!("titlekek_{i:02x}"))
                .or_else(|| Some(ecb_decrypt_key(master.as_ref()?, &k16("titlekek_source")?)));
        }

        if key_area_keys.iter().all(|k| k[0].is_none()) {
            return Err(Error::InvalidKeys("no key_area_key_application_XX or master_key_XX entries found".into()));
        }

        Ok(Self { path, header_key, key_area_keys, titlekeks, xci_header_key: k16("xci_header_key") })
    }

    pub fn header_key(&self) -> &[u8; 32] {
        &self.header_key
    }

    /// Highest master key index available (e.g. 0x12 for firmware 19.x keys).
    pub fn max_master_key(&self) -> Option<usize> {
        (0..MAX_KEY_GEN).rev().find(|&i| self.key_area_keys[i][0].is_some())
    }

    pub fn key_area_key(&self, master_key_index: usize, kind: u8) -> Result<Key128> {
        self.key_area_keys
            .get(master_key_index)
            .and_then(|k| k.get(kind as usize).copied().flatten())
            .ok_or_else(|| missing_mk("key_area_key", master_key_index))
    }

    pub fn titlekek(&self, master_key_index: usize) -> Result<Key128> {
        self.titlekeks.get(master_key_index).copied().flatten().ok_or_else(|| missing_mk("titlekek", master_key_index))
    }
}

fn missing_mk(what: &str, idx: usize) -> Error {
    let fw = match crate::rsv::firmware_for_master_key(idx) {
        Some(v) => format!("firmware {v} or later"),
        None => "a newer firmware".into(),
    };
    Error::MissingKey(format!("{what}_{idx:02x} (this content needs newer keys; re-dump prod.keys on {fw})"))
}

/// Converts the key generation byte stored in NCA headers / tickets to a master key index.
pub fn master_key_index(key_generation: u8) -> usize {
    key_generation.saturating_sub(1) as usize
}
