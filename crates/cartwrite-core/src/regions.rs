//! Optional "which region is this release from" lookup.
//!
//! Switch title IDs don't encode a region, but titledb publishes the full catalogue of each
//! country's eShop (`US.en.json`, `JP.ja.json`, ...). A title ID that only appears in the
//! Japanese list is the Japanese release, one in every list is a worldwide release, and so on.
//!
//! Those lists are big (about 90 MB each, 15 to 26 MB compressed), so only the title IDs are
//! kept while parsing and the result is cached as a small index that's refreshed monthly.

use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::error::{Error, Result};
use crate::plan::Game;
use crate::titledb::{cache_dir, http_get, is_url};

/// Folder (URL or local directory) holding titledb's `<COUNTRY>.<lang>.json` files.
pub const DEFAULT_SOURCE: &str = "https://raw.githubusercontent.com/blawar/titledb/master/";

/// Region membership hardly ever changes, so the index is refreshed monthly.
pub const MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_DOWNLOAD: u64 = 512 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Region {
    Us,
    Eu,
    Jp,
    Asia,
    Kr,
}

impl Region {
    pub const ALL: [Region; 5] = [Region::Us, Region::Eu, Region::Jp, Region::Asia, Region::Kr];

    /// titledb file listing this region's eShop.
    pub fn file(self) -> &'static str {
        match self {
            Region::Us => "US.en.json",
            Region::Eu => "GB.en.json",
            Region::Jp => "JP.ja.json",
            Region::Asia => "HK.zh.json",
            Region::Kr => "KR.ko.json",
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Region::Us => "US",
            Region::Eu => "EU",
            Region::Jp => "JP",
            Region::Asia => "Asia",
            Region::Kr => "KR",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Region::Us => "Americas (US eShop)",
            Region::Eu => "Europe (UK eShop)",
            Region::Jp => "Japan",
            Region::Asia => "Asia (Hong Kong eShop)",
            Region::Kr => "Korea",
        }
    }

    fn bit(self) -> u8 {
        1 << Region::ALL.iter().position(|r| *r == self).unwrap()
    }
}

#[derive(Clone, Debug)]
pub struct RegionDb {
    /// Title ID -> bitmask of regions whose eShop lists it.
    map: HashMap<u64, u8>,
    pub fetched: SystemTime,
    pub source: String,
}

impl RegionDb {
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn regions(&self, title_id: u64) -> Vec<Region> {
        let mask = self.map.get(&title_id).copied().unwrap_or(0);
        Region::ALL.into_iter().filter(|r| mask & r.bit() != 0).collect()
    }

    /// Regions of a game's release: its application ID, or failing that (e.g. DLC-only
    /// entries) any of its titles.
    pub fn for_game(&self, game: &Game) -> Vec<Region> {
        let direct = self.regions(game.application_id);
        if !direct.is_empty() {
            return direct;
        }
        let mask = game.titles.iter().filter_map(|t| self.map.get(&t.title_id)).fold(0, |a, b| a | b);
        Region::ALL.into_iter().filter(|r| mask & r.bit() != 0).collect()
    }

    pub fn is_stale(&self) -> bool {
        self.fetched.elapsed().map_or(true, |age| age > MAX_AGE)
    }

    fn to_text(&self) -> String {
        let mut lines: Vec<String> = self.map.iter().map(|(id, m)| format!("{id:016X}|{m}")).collect();
        lines.sort();
        lines.join("\n")
    }

    fn from_text(text: &str, source: &str, fetched: SystemTime) -> Option<Self> {
        let map: HashMap<u64, u8> = text
            .lines()
            .filter_map(|l| {
                let (id, mask) = l.split_once('|')?;
                Some((u64::from_str_radix(id, 16).ok()?, mask.parse().ok()?))
            })
            .collect();
        (!map.is_empty()).then(|| Self { map, fetched, source: source.into() })
    }
}

/// Reads the title IDs out of one titledb region file (an object of nsuId -> title info).
pub fn parse_region_file(reader: impl Read) -> Result<Vec<u64>> {
    #[derive(serde::Deserialize)]
    struct Entry {
        #[serde(default)]
        id: Option<String>,
    }
    let entries: HashMap<String, Option<Entry>> = serde_json::from_reader(BufReader::with_capacity(1 << 20, reader))
        .map_err(|e| Error::Format(format!("not a titledb region file: {e}")))?;
    Ok(entries.into_values().flatten().filter_map(|e| u64::from_str_radix(e.id?.trim(), 16).ok()).collect())
}

fn open_region_file(source: &str, region: Region) -> Result<Box<dyn Read + Send>> {
    if is_url(source) {
        let base = if source.ends_with('/') { source.to_string() } else { format!("{source}/") };
        let reader = http_get(&format!("{base}{}", region.file()), DOWNLOAD_TIMEOUT)?;
        Ok(Box::new(reader.take(MAX_DOWNLOAD)))
    } else {
        let path = Path::new(source).join(region.file());
        let f = std::fs::File::open(&path).map_err(|e| Error::File { path, source: e })?;
        Ok(Box::new(f))
    }
}

/// Downloads (or reads from a local folder) every region list and refreshes the cache.
/// `progress` is called before each region. Blocking; call it from a background thread.
pub fn fetch(source: &str, progress: &mut dyn FnMut(usize, Region)) -> Result<RegionDb> {
    let source = source.trim();
    if source.is_empty() {
        return Err(Error::Unsupported("no region list source is set".into()));
    }
    let mut map: HashMap<u64, u8> = HashMap::new();
    for (i, region) in Region::ALL.into_iter().enumerate() {
        progress(i, region);
        let ids = open_region_file(source, region)
            .and_then(parse_region_file)
            .map_err(|e| Error::Network(format!("{} ({}): {e}", region.name(), region.file())))?;
        for id in ids {
            *map.entry(id).or_default() |= region.bit();
        }
    }
    let db = RegionDb { map, fetched: SystemTime::now(), source: source.into() };
    if let Some(dir) = cache_dir() {
        let _ = std::fs::create_dir_all(&dir);
        let tmp = dir.join("regions.txt.part");
        if std::fs::write(&tmp, db.to_text()).is_ok() && std::fs::rename(&tmp, dir.join("regions.txt")).is_ok() {
            let _ = std::fs::write(dir.join("regions.source"), source);
        }
    }
    Ok(db)
}

/// Loads the cached index if it was built from `source`.
pub fn load_cached(source: &str) -> Option<RegionDb> {
    let dir = cache_dir()?;
    let cached_source = std::fs::read_to_string(dir.join("regions.source")).ok()?;
    if cached_source.trim() != source.trim() {
        return None;
    }
    let path = dir.join("regions.txt");
    let fetched = std::fs::metadata(&path).and_then(|m| m.modified()).ok()?;
    let text = std::fs::read_to_string(&path).ok()?;
    RegionDb::from_text(&text, source.trim(), fetched)
}

/// Cached index if it's fresh, otherwise a new download, falling back to the stale cache if
/// that fails. Returns whatever is available plus the refresh error, if any.
pub fn load(
    source: &str,
    force_refresh: bool,
    progress: &mut dyn FnMut(usize, Region),
) -> (Option<RegionDb>, Option<Error>) {
    let cached = load_cached(source);
    if !force_refresh && cached.as_ref().is_some_and(|db| !db.is_stale()) {
        return (cached, None);
    }
    match fetch(source, progress) {
        Ok(db) => (Some(db), None),
        Err(e) => (cached, Some(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_region_file_ids() {
        let json = r#"{
            "70010000000001": {"id": "0100E0D01F224000", "name": "A", "region": "JP"},
            "70010000000002": {"id": null, "name": "No id"},
            "70010000000003": {"name": "Missing id"},
            "70010000000004": {"id": "0100E0D01F225001", "screenshots": [1, 2]}
        }"#;
        let mut ids = parse_region_file(json.as_bytes()).unwrap();
        ids.sort();
        assert_eq!(ids, vec![0x0100E0D01F224000, 0x0100E0D01F225001]);
    }

    #[test]
    fn cache_text_roundtrip() {
        let mut map = HashMap::new();
        map.insert(0x0100E0D01F224000, Region::Jp.bit());
        map.insert(0x0100B99019412000, Region::Us.bit() | Region::Eu.bit() | Region::Jp.bit());
        let db = RegionDb { map, fetched: SystemTime::now(), source: "x".into() };
        let back = RegionDb::from_text(&db.to_text(), "x", SystemTime::now()).unwrap();
        assert_eq!(back.regions(0x0100E0D01F224000), vec![Region::Jp]);
        assert_eq!(back.regions(0x0100B99019412000), vec![Region::Us, Region::Eu, Region::Jp]);
        assert!(back.regions(0x0100000000010000).is_empty());
    }
}
