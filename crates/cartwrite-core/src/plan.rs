//! Groups scanned titles by game and picks the newest version of each.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use crate::scan::{Title, TitleKind};

#[derive(Clone, Debug)]
pub struct Game {
    pub application_id: u64,
    pub name: String,
    pub publisher: String,
    pub display_version: Option<String>,
    pub icon: Option<Arc<Vec<u8>>>,
    /// Newest version of each title ID, ordered base, update, DLCs.
    pub titles: Vec<Title>,
    /// Older versions / duplicates that will be left out.
    pub superseded: Vec<Title>,
    /// Problems that involve other games, e.g. DLC from a different release in the same file.
    pub notes: Vec<String>,
}

impl Game {
    pub fn base(&self) -> Option<&Title> {
        self.titles.iter().find(|t| t.kind == TitleKind::Base)
    }

    pub fn warnings(&self) -> Vec<String> {
        let mut w: Vec<String> = self.notes.clone();
        // A note already explains why DLC have no base game here.
        if self.base().is_none() && self.notes.is_empty() {
            w.push("No base game, so the XCI will only contain updates/DLC.".into());
        }
        for t in &self.titles {
            for msg in &t.warnings {
                w.push(format!("{} {:016X}: {msg}", t.kind.label(), t.title_id));
            }
        }
        w
    }
}

/// Builds the output file name (without extension) for a selection of titles, following
/// NSC_Builder's `Name [TitleID][vVersion] (1G+1U+2D)` convention, but using the version
/// players see (e.g. `v2.3.24.2`) instead of the internal number when it's known.
pub fn output_stem(name: &str, application_id: u64, titles: &[&Title]) -> String {
    let count = |k: &[TitleKind]| titles.iter().filter(|t| k.contains(&t.kind)).count();
    let (g, u, d) =
        (count(&[TitleKind::Base]), count(&[TitleKind::Update]), count(&[TitleKind::Dlc, TitleKind::DlcUpdate]));
    let version = titles
        .iter()
        .filter(|t| t.kind == TitleKind::Update)
        .chain(titles.iter().filter(|t| t.kind == TitleKind::Base))
        .map(|t| t.version_label())
        .next()
        .unwrap_or_else(|| "v0".into());
    let mut parts = Vec::new();
    for (n, tag) in [(g, "G"), (u, "U"), (d, "D")] {
        if n > 0 {
            parts.push(format!("{n}{tag}"));
        }
    }
    let tag = if g + u + d <= 1 { String::new() } else { format!(" ({})", parts.join("+")) };
    sanitize(&format!("{name} [{application_id:016X}][{version}]{tag}"))
}

pub fn sanitize(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .filter(|c| !matches!(c, '™' | '®' | '©'))
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => ' ',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect();
    let mut out = String::with_capacity(cleaned.len());
    for w in cleaned.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(w);
    }
    out.trim_end_matches(['.', ' ']).to_string()
}

/// Groups titles by base application ID, keeping only the newest version of each title ID.
pub fn group(titles: Vec<Title>) -> Vec<Game> {
    let mut by_app: BTreeMap<u64, Vec<Title>> = BTreeMap::new();
    for t in titles {
        by_app.entry(t.application_id).or_default().push(t);
    }
    let mut games = by_app
        .into_iter()
        .map(|(application_id, mut list)| {
            // Newest first so the first occurrence of each title ID wins.
            list.sort_by(|a, b| (a.kind, a.title_id, b.version).cmp(&(b.kind, b.title_id, a.version)));
            let mut titles: Vec<Title> = Vec::new();
            let mut superseded = Vec::new();
            for t in list {
                if titles.iter().any(|k| k.title_id == t.title_id) {
                    superseded.push(t);
                } else {
                    titles.push(t);
                }
            }
            let info_src = titles
                .iter()
                .filter(|t| t.kind == TitleKind::Update)
                .chain(titles.iter().filter(|t| t.kind == TitleKind::Base))
                .find(|t| t.nacp.is_some());
            let name = info_src
                .and_then(|t| t.nacp.as_ref())
                .map(|n| n.title.clone())
                .unwrap_or_else(|| name_from_file(&titles[0]));
            let publisher = info_src.and_then(|t| t.nacp.as_ref()).map(|n| n.publisher.clone()).unwrap_or_default();
            let display_version = info_src.and_then(|t| t.nacp.as_ref()).map(|n| n.display_version.clone());
            let icon = titles
                .iter()
                .filter(|t| t.kind == TitleKind::Update)
                .chain(titles.iter().filter(|t| t.kind == TitleKind::Base))
                .find_map(|t| t.icon.clone());
            Game { application_id, name, publisher, display_version, icon, titles, superseded, notes: Vec::new() }
        })
        .collect::<Vec<_>>();
    note_mismatched_dlc(&mut games);
    games
}

/// Finds DLC that sit in the same file as another game's base or update but belong to a
/// different application ID (typically another region's release). The game in the file
/// won't load them, which otherwise just looks like a confusing "no base game" entry.
fn note_mismatched_dlc(games: &mut [Game]) {
    let sources = |g: &Game| -> HashSet<PathBuf> { g.titles.iter().map(|t| t.source.as_ref().clone()).collect() };
    let has_game = |g: &Game| g.titles.iter().any(|t| matches!(t.kind, TitleKind::Base | TitleKind::Update));
    let dlc_only = |g: &Game| !has_game(g) && g.titles.iter().any(|t| t.kind == TitleKind::Dlc);

    let mut notes: Vec<(usize, String)> = Vec::new();
    for (i, orphan) in games.iter().enumerate().filter(|(_, g)| dlc_only(g)) {
        let orphan_sources = sources(orphan);
        let dlc_count = orphan.titles.iter().filter(|t| t.kind == TitleKind::Dlc).count();
        for (j, owner) in games.iter().enumerate().filter(|(j, g)| *j != i && has_game(g)) {
            let owner_sources = sources(owner);
            let Some(file) = owner_sources.iter().find(|p| orphan_sources.contains(*p)) else { continue };
            let file = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            notes.push((
                i,
                format!(
                    "These DLC belong to a different release ({:016X}) than {} ({:016X}) in the same file, so that game won't load them.",
                    orphan.application_id, owner.name, owner.application_id
                ),
            ));
            notes.push((
                j,
                format!(
                    "{file} also has {dlc_count} DLC for a different release ({:016X}). This game won't load them, so they're listed separately.",
                    orphan.application_id
                ),
            ));
        }
    }
    for (i, note) in notes {
        if !games[i].notes.contains(&note) {
            games[i].notes.push(note);
        }
    }
}

/// Strips `[..]` / `(..)` tags from a file name to guess a title.
fn name_from_file(t: &Title) -> String {
    let stem = t.source.file_stem().and_then(|s| s.to_str()).unwrap_or("Unknown");
    let mut out = String::new();
    let mut depth = 0i32;
    for c in stem.chars() {
        match c {
            '[' | '(' => depth += 1,
            ']' | ')' => depth = (depth - 1).max(0),
            c if depth == 0 => out.push(c),
            _ => {}
        }
    }
    let s = out.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.is_empty() {
        format!("{:016X}", t.application_id)
    } else {
        s
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::container::ContainerKind;
    use crate::nacp::Nacp;
    use crate::scan::NcaRef;
    use std::collections::HashMap;
    use std::path::PathBuf;

    pub(crate) fn title(kind: TitleKind, title_id: u64, version: u32, display: Option<&str>) -> Title {
        let source = Arc::new(PathBuf::from(format!("{title_id:016x}_v{version}.nsp")));
        let meta = NcaRef {
            source: source.clone(),
            offset: 0,
            stored_size: 100,
            nca_size: 100,
            is_ncz: false,
            out_name: format!("{title_id:x}{version}.cnmt.nca"),
            content_type: crate::cnmt::CT_META,
            id_offset: 0,
            key_generation: 0,
            rights_id: None,
        };
        Title {
            title_id,
            application_id: title_id & !0x1FFF,
            data_id: None,
            version,
            kind,
            required_system_version: None,
            meta,
            contents: Vec::new(),
            tickets: HashMap::new(),
            nacp: display.map(|v| Nacp { title: "Game".into(), display_version: v.into(), ..Default::default() }),
            icon: None,
            source,
            source_kind: ContainerKind::Nsp,
            source_complete: true,
            warnings: Vec::new(),
        }
    }

    const BASE: u64 = 0x0100_0000_0001_0000;

    #[test]
    fn newest_update_wins_and_duplicates_are_dropped() {
        let games = group(vec![
            title(TitleKind::Base, BASE, 0, Some("1.0.0")),
            title(TitleKind::Update, BASE | 0x800, 65536, Some("1.1.0")),
            title(TitleKind::Update, BASE | 0x800, 131072, Some("1.2.0")),
            title(TitleKind::Base, BASE, 0, Some("1.0.0")),
            title(TitleKind::Dlc, BASE + 0x1001, 0, None),
        ]);
        assert_eq!(games.len(), 1);
        let g = &games[0];
        let kept: Vec<(TitleKind, u32)> = g.titles.iter().map(|t| (t.kind, t.version)).collect();
        assert_eq!(kept, vec![(TitleKind::Base, 0), (TitleKind::Update, 131072), (TitleKind::Dlc, 0)]);
        assert_eq!(g.superseded.len(), 2);
        assert_eq!(g.display_version.as_deref(), Some("1.2.0"));
    }

    #[test]
    fn dlc_for_another_release_in_the_same_file_is_explained() {
        let other_app = 0x0100_0000_0005_0000;
        let file = Arc::new(PathBuf::from("mixed.xci"));
        let mut titles = vec![
            title(TitleKind::Base, BASE, 0, Some("1.0.0")),
            title(TitleKind::Update, BASE | 0x800, 65536, Some("1.0.1")),
            title(TitleKind::Dlc, other_app + 0x1001, 0, None),
        ];
        for t in &mut titles {
            t.source = file.clone();
        }
        let games = group(titles);
        assert_eq!(games.len(), 2);
        let main = games.iter().find(|g| g.application_id == BASE).unwrap();
        let orphan = games.iter().find(|g| g.application_id == other_app).unwrap();
        assert!(main.warnings()[0].contains("1 DLC for a different release (0100000000050000)"));
        let w = orphan.warnings();
        assert!(w[0].contains("different release (0100000000050000) than Game (0100000000010000)"), "{w:?}");
        assert!(!w.iter().any(|m| m.starts_with("No base game")), "{w:?}");
    }

    #[test]
    fn dlc_in_its_own_file_is_not_flagged() {
        let other_app = 0x0100_0000_0005_0000;
        let games = group(vec![
            title(TitleKind::Base, BASE, 0, Some("1.0.0")),
            title(TitleKind::Dlc, other_app + 0x1001, 0, None),
        ]);
        assert!(games.iter().all(|g| g.notes.is_empty()));
    }

    #[test]
    fn output_names_use_display_version() {
        let base = title(TitleKind::Base, BASE, 0, Some("1.0.0"));
        let upd = title(TitleKind::Update, BASE | 0x800, 131072, Some("1.2.0"));
        let dlc = title(TitleKind::Dlc, BASE + 0x1001, 0, None);
        assert_eq!(output_stem("Game", BASE, &[&base]), "Game [0100000000010000][v1.0.0]");
        assert_eq!(output_stem("Game", BASE, &[&base, &upd, &dlc]), "Game [0100000000010000][v1.2.0] (1G+1U+1D)");
        let numeric = title(TitleKind::Update, BASE | 0x800, 131072, None);
        assert_eq!(output_stem("Game", BASE, &[&base, &numeric]), "Game [0100000000010000][v131072] (1G+1U)");
    }

    #[test]
    fn sanitize_strips_reserved_characters() {
        assert_eq!(sanitize("Zelda\u{2122}: Tears / of the Kingdom?  "), "Zelda Tears of the Kingdom");
        assert_eq!(sanitize("Name..."), "Name");
    }
}
