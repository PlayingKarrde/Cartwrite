//! Optional update / missing-DLC check against a community title database.
//!
//! The database is a list of every title ID with its newest version, as published by
//! blawar's titledb (`versions.txt`, one `id|rightsId|version` line per title). titledb's
//! `versions.json` (base ID -> {update version: release date}) is also accepted, though it
//! only covers updates, not DLC.
//!
//! The source can be any URL or a local file. Downloads are cached on disk so checks work
//! offline and only refresh when the copy is older than [`MAX_AGE`].

use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::error::{Error, Result};
use crate::plan::Game;
use crate::scan::TitleKind;

pub const DEFAULT_SOURCE: &str = "https://raw.githubusercontent.com/blawar/titledb/master/versions.txt";

/// Cached copies older than this are refreshed in the background.
pub const MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_DOWNLOAD: u64 = 64 << 20;

/// DLC title IDs are the base ID + 0x1000 + an index of 1..=0xFFF.
const DLC_OFFSET: u64 = 0x1000;
const UPDATE_OFFSET: u64 = 0x800;

#[derive(Clone, Debug)]
pub struct TitleDb {
    /// Newest known version per title ID (base, update or DLC).
    latest: BTreeMap<u64, u32>,
    /// Whether the source lists DLC (`versions.json` doesn't).
    has_dlc: bool,
    /// When this copy was downloaded (or the local file was modified).
    pub fetched: SystemTime,
    pub source: String,
}

/// How a game compares with the database.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// (newest update you have, newest in the database), when the database is newer.
    pub newer_update: Option<(Option<u32>, u32)>,
    /// DLC title IDs in the database that none of your files contain.
    pub missing_dlc: Vec<u64>,
    /// (DLC title ID, your version, newest version).
    pub outdated_dlc: Vec<(u64, u32, u32)>,
}

impl Report {
    pub fn is_up_to_date(&self) -> bool {
        self.newer_update.is_none() && self.missing_dlc.is_empty() && self.outdated_dlc.is_empty()
    }
}

impl TitleDb {
    /// Parses `versions.txt` or `versions.json` content.
    pub fn parse(text: &str, source: impl Into<String>, fetched: SystemTime) -> Result<Self> {
        let trimmed = text.trim_start();
        let (latest, has_dlc) =
            if trimmed.starts_with('{') { (parse_json(trimmed)?, false) } else { (parse_txt(text), true) };
        if latest.is_empty() {
            return Err(Error::Format("this doesn't look like a titledb versions file".into()));
        }
        Ok(Self { latest, has_dlc, fetched, source: source.into() })
    }

    pub fn len(&self) -> usize {
        self.latest.len()
    }

    pub fn is_empty(&self) -> bool {
        self.latest.is_empty()
    }

    pub fn has_dlc_info(&self) -> bool {
        self.has_dlc
    }

    pub fn latest(&self, title_id: u64) -> Option<u32> {
        self.latest.get(&title_id).copied()
    }

    /// DLC the database lists for a base game, with their newest versions.
    pub fn dlcs(&self, application_id: u64) -> impl Iterator<Item = (u64, u32)> + '_ {
        let first = application_id + DLC_OFFSET + 1;
        self.latest.range(first..=first + 0xFFE).map(|(&id, &v)| (id, v))
    }

    pub fn is_stale(&self) -> bool {
        self.fetched.elapsed().map_or(true, |age| age > MAX_AGE)
    }

    /// Compares a game with the database. `None` if the database doesn't know the game.
    pub fn check(&self, game: &Game) -> Option<Report> {
        let app = game.application_id;
        let update_id = app + UPDATE_OFFSET;
        let known =
            self.latest.contains_key(&app) || self.latest.contains_key(&update_id) || self.dlcs(app).next().is_some();
        if !known {
            return None;
        }
        let mut report = Report::default();

        let have_update = game.titles.iter().filter(|t| t.kind == TitleKind::Update).map(|t| t.version).max();
        if let Some(latest) = self.latest(update_id) {
            if have_update.is_none_or(|v| v < latest) {
                report.newer_update = Some((have_update, latest));
            }
        }

        let have_dlc: HashSet<u64> =
            game.titles.iter().filter(|t| t.kind == TitleKind::Dlc).map(|t| t.title_id).collect();
        for (id, _) in self.dlcs(app) {
            if !have_dlc.contains(&id) {
                report.missing_dlc.push(id);
            }
        }
        for t in game.titles.iter().filter(|t| t.kind == TitleKind::Dlc) {
            if let Some(latest) = self.latest(t.title_id) {
                if t.version < latest {
                    report.outdated_dlc.push((t.title_id, t.version, latest));
                }
            }
        }
        Some(report)
    }
}

fn parse_txt(text: &str) -> BTreeMap<u64, u32> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.trim().split('|');
        let (Some(id), Some(version)) = (fields.next(), fields.next_back()) else { continue };
        let (Ok(id), Ok(version)) = (u64::from_str_radix(id.trim(), 16), version.trim().parse::<u32>()) else {
            continue; // header line, or a title with no known version
        };
        out.insert(id, version);
    }
    out
}

fn parse_json(text: &str) -> Result<BTreeMap<u64, u32>> {
    let map: BTreeMap<String, BTreeMap<String, serde_json::Value>> =
        serde_json::from_str(text).map_err(|e| Error::Format(format!("invalid versions.json: {e}")))?;
    let mut out = BTreeMap::new();
    for (id, versions) in map {
        let Ok(base) = u64::from_str_radix(&id, 16) else { continue };
        if let Some(latest) = versions.keys().filter_map(|v| v.parse::<u32>().ok()).max() {
            out.insert(base + UPDATE_OFFSET, latest);
        }
    }
    Ok(out)
}

pub(crate) fn is_url(source: &str) -> bool {
    let s = source.trim().to_ascii_lowercase();
    s.starts_with("http://") || s.starts_with("https://")
}

pub(crate) fn cache_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("Cartwrite"))
}

/// Loads the cached copy if it was downloaded from `source`.
pub fn load_cached(source: &str) -> Option<TitleDb> {
    let dir = cache_dir()?;
    let cached_source = std::fs::read_to_string(dir.join("titledb.source")).ok()?;
    if cached_source.trim() != source.trim() {
        return None;
    }
    let path = dir.join("titledb.txt");
    let fetched = std::fs::metadata(&path).and_then(|m| m.modified()).ok()?;
    let text = std::fs::read_to_string(&path).ok()?;
    TitleDb::parse(&text, source.trim(), fetched).ok()
}

/// Downloads (or reads, for a local path) the database and refreshes the cache.
/// Blocking; call it from a background thread.
pub fn fetch(source: &str) -> Result<TitleDb> {
    let source = source.trim();
    if source.is_empty() {
        return Err(Error::Unsupported("no title database source is set".into()));
    }
    if !is_url(source) {
        let path = Path::new(source);
        let text = std::fs::read_to_string(path).map_err(|e| Error::File { path: path.to_path_buf(), source: e })?;
        let fetched = std::fs::metadata(path).and_then(|m| m.modified()).unwrap_or_else(|_| SystemTime::now());
        return TitleDb::parse(&text, source, fetched);
    }

    let mut text = String::new();
    http_get(source, TOTAL_TIMEOUT)?
        .take(MAX_DOWNLOAD)
        .read_to_string(&mut text)
        .map_err(|e| Error::Network(format!("download interrupted: {e}")))?;
    let db = TitleDb::parse(&text, source, SystemTime::now())?;

    // Cache it; failing to write the cache isn't fatal.
    if let Some(dir) = cache_dir() {
        let _ = std::fs::create_dir_all(&dir);
        let tmp = dir.join("titledb.txt.part");
        if std::fs::write(&tmp, &text).is_ok() && std::fs::rename(&tmp, dir.join("titledb.txt")).is_ok() {
            let _ = std::fs::write(dir.join("titledb.source"), source);
        }
    }
    Ok(db)
}

/// Gets the database the way the app and CLI want it: the cached copy if it's fresh,
/// otherwise a new download, falling back to the stale cache if the download fails.
/// Returns whatever database is available plus the refresh error, if there was one.
/// Blocking; call it from a background thread.
pub fn load(source: &str, force_refresh: bool) -> (Option<TitleDb>, Option<Error>) {
    let cached = load_cached(source);
    if !force_refresh && cached.as_ref().is_some_and(|db| !db.is_stale()) {
        return (cached, None);
    }
    match fetch(source) {
        Ok(db) => (Some(db), None),
        Err(e) => (cached, Some(e)),
    }
}

/// Starts an HTTP GET with a short connect timeout and an overall `timeout`.
pub(crate) fn http_get(url: &str, timeout: Duration) -> Result<impl Read + Send> {
    let agent = ureq::AgentBuilder::new().timeout_connect(CONNECT_TIMEOUT).timeout(timeout).build();
    let resp = agent.get(url).call().map_err(|e| Error::Network(network_message(e)))?;
    Ok(resp.into_reader())
}

fn network_message(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, resp) => format!("the server returned {code} {}", resp.status_text()),
        ureq::Error::Transport(t) => match t.kind() {
            ureq::ErrorKind::Dns => "couldn't look up the server (are you offline?)".into(),
            ureq::ErrorKind::ConnectionFailed => "couldn't connect to the server".into(),
            ureq::ErrorKind::Io => format!("connection problem: {t}"),
            _ => t.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::group;
    use crate::scan::Title;

    const TXT: &str = "id|rightsId|version
0100000000010000|01000000000100000000000000000003|0
0100000000010800|00000000000000000000000000000000|393216
0100000000011001|01000000000110010000000000000000|65536
0100000000011002|01000000000110020000000000000000|0
0100000000011003|00000000000000000000000000000000|
0100000000020000|00000000000000000000000000000000|0
";

    fn db() -> TitleDb {
        TitleDb::parse(TXT, "test", SystemTime::now()).unwrap()
    }

    fn game(titles: Vec<Title>) -> Game {
        group(titles).remove(0)
    }

    #[test]
    fn parses_versions_txt() {
        let db = db();
        assert_eq!(db.len(), 5); // header and the blank-version row are skipped
        assert_eq!(db.latest(0x0100000000010800), Some(393216));
        let dlcs: Vec<u64> = db.dlcs(0x0100000000010000).map(|d| d.0).collect();
        assert_eq!(dlcs, vec![0x0100000000011001, 0x0100000000011002]);
        assert!(db.dlcs(0x0100000000020000).next().is_none());
    }

    #[test]
    fn parses_versions_json() {
        let json = r#"{"0100000000010000": {"65536": "2017-10-26", "393216": "2025-06-25"}}"#;
        let db = TitleDb::parse(json, "test", SystemTime::now()).unwrap();
        assert_eq!(db.latest(0x0100000000010800), Some(393216));
        assert!(!db.has_dlc_info());
    }

    #[test]
    fn rejects_garbage() {
        assert!(TitleDb::parse("<html>not found</html>", "x", SystemTime::now()).is_err());
    }

    #[test]
    fn reports_newer_update_and_missing_dlc() {
        let base = crate::plan::tests::title(TitleKind::Base, 0x0100000000010000, 0, None);
        let upd = crate::plan::tests::title(TitleKind::Update, 0x0100000000010800, 196608, None);
        let dlc = crate::plan::tests::title(TitleKind::Dlc, 0x0100000000011002, 0, None);
        let report = db().check(&game(vec![base, upd, dlc])).unwrap();
        assert_eq!(report.newer_update, Some((Some(196608), 393216)));
        assert_eq!(report.missing_dlc, vec![0x0100000000011001]);
        assert!(report.outdated_dlc.is_empty());
    }

    #[test]
    fn up_to_date_and_unknown_games() {
        let db = db();
        let base = crate::plan::tests::title(TitleKind::Base, 0x0100000000020000, 0, None);
        assert!(db.check(&game(vec![base])).unwrap().is_up_to_date());
        let unknown = crate::plan::tests::title(TitleKind::Base, 0x0100000000030000, 0, None);
        assert_eq!(db.check(&game(vec![unknown])), None);
    }

    #[test]
    fn outdated_dlc_is_reported() {
        let base = crate::plan::tests::title(TitleKind::Base, 0x0100000000010000, 0, None);
        let old_dlc = crate::plan::tests::title(TitleKind::Dlc, 0x0100000000011001, 0, None);
        let report = db().check(&game(vec![base, old_dlc])).unwrap();
        assert_eq!(report.outdated_dlc, vec![(0x0100000000011001, 0, 65536)]);
    }
}
