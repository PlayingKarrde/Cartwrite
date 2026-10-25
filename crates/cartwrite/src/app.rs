use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::Arc;
use std::time::Instant;

use cartwrite_core::build::{BuildOptions, Progress};
use cartwrite_core::container::ContainerKind;
use cartwrite_core::extract::{dlc_path, ExtractOptions};
use cartwrite_core::plan::{group, output_stem, Game};
use cartwrite_core::regions::{self, Region, RegionDb};
use cartwrite_core::rsv::format_rsv;
use cartwrite_core::scan::{Title, TitleKind, EXTENSIONS};
use cartwrite_core::titledb::{self, Report, TitleDb};
use cartwrite_core::util::{format_age, format_size};
use cartwrite_core::Keys;
use eframe::egui::{self, Color32, RichText};

use crate::theme::{self, ThemeChoice, ThemeStyle};
use crate::worker::{
    spawn_build, spawn_extract, spawn_regions, spawn_scan, spawn_titledb, BuildJob, BuildMsg, ExtractJob, RegionMsg,
    ScanMsg, TitleDbResult,
};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct Settings {
    keys_path: Option<PathBuf>,
    /// `None` = write next to the first source file.
    output_dir: Option<PathBuf>,
    patch_rsv: bool,
    split_fat32: bool,
    include_deltas: bool,
    delete_source_xci: bool,
    last_dir: Option<PathBuf>,
    theme: ThemeChoice,
    style: ThemeStyle,
    /// Compare games with a title database to spot newer updates and missing DLC.
    check_updates: bool,
    /// URL or local file of a titledb `versions.txt`.
    titledb_source: String,
    /// Show which eShop region each release is from.
    show_regions: bool,
    /// URL or local folder of titledb's per-country lists.
    regions_source: String,
    /// Last folder a game was extracted into.
    extract_dir: Option<PathBuf>,
    /// Last "Game only" / "Game + DLC" choice for extracting.
    extract_dlc: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            keys_path: None,
            output_dir: None,
            patch_rsv: true,
            split_fat32: false,
            include_deltas: false,
            delete_source_xci: false,
            last_dir: None,
            theme: ThemeChoice::Dark,
            style: ThemeStyle::Nx,
            check_updates: false,
            titledb_source: titledb::DEFAULT_SOURCE.into(),
            show_regions: false,
            regions_source: regions::DEFAULT_SOURCE.into(),
            extract_dir: None,
            extract_dlc: false,
        }
    }
}

/// What a running job does with a game.
#[derive(Clone, Copy, PartialEq)]
enum JobKind {
    Build,
    Extract,
}

impl JobKind {
    fn doing(self) -> &'static str {
        match self {
            Self::Build => "Building",
            Self::Extract => "Extracting",
        }
    }

    fn done(self) -> &'static str {
        match self {
            Self::Build => "Built",
            Self::Extract => "Extracted",
        }
    }
}

#[derive(Clone, PartialEq)]
enum Status {
    Ready,
    Queued,
    Building { kind: JobKind, done: u64, total: u64 },
    Done(JobKind, Vec<PathBuf>),
    Failed(String),
}

struct GameView {
    game: Game,
    selected: bool,
    /// Title IDs the user unticked.
    excluded: HashSet<u64>,
    status: Status,
    icon: Option<egui::load::Bytes>,
}

impl GameView {
    fn chosen(&self) -> Vec<&Title> {
        self.game.titles.iter().filter(|t| !self.excluded.contains(&t.title_id)).collect()
    }

    fn file_stem(&self) -> String {
        output_stem(&self.game.name, self.game.application_id, &self.chosen())
    }

    /// Extraction needs a base game.
    fn has_base(&self) -> bool {
        self.chosen().iter().any(|t| t.kind == TitleKind::Base)
    }

    fn has_dlc(&self) -> bool {
        self.chosen().iter().any(|t| matches!(t.kind, TitleKind::Dlc | TitleKind::DlcUpdate))
    }

    /// The titles an extraction reads: DLC only when it was asked for.
    fn extract_titles(&self, with_dlc: bool) -> Vec<&Title> {
        self.chosen()
            .into_iter()
            .filter(|t| with_dlc || matches!(t.kind, TitleKind::Base | TitleKind::Update))
            .collect()
    }

    /// Name of the folder an extraction is written to (same as the command line's).
    fn extract_stem(&self, with_dlc: bool) -> String {
        output_stem(&self.game.name, self.game.application_id, &self.extract_titles(with_dlc))
    }
}

struct Job {
    kind: JobKind,
    rx: Receiver<BuildMsg>,
    cancel: Arc<AtomicBool>,
    started: Instant,
    current: Option<u64>,
    bytes_before: u64,
    bytes_total: u64,
    /// When the first byte count of an extraction arrived. Listing and decompressing come
    /// first, so speed and time left are measured from here rather than from `started`.
    bytes_started: Option<Instant>,
}

/// The "Extract to folder" dialog.
struct ExtractDialog {
    application_id: u64,
    /// Folder the game folder is created in.
    dir: PathBuf,
    with_dlc: bool,
}

pub struct App {
    settings: Settings,
    keys: Option<Arc<Keys>>,
    keys_error: Option<String>,
    inputs: Vec<PathBuf>,
    titles: Vec<Title>,
    scan_errors: Vec<(PathBuf, String)>,
    games: Vec<GameView>,
    scan_rx: Option<Receiver<ScanMsg>>,
    job: Option<Job>,
    log: Vec<(Instant, String, bool)>,
    show_settings: bool,
    extract_dialog: Option<ExtractDialog>,
    show_log: bool,
    pending_rescan: bool,
    scanned: HashSet<PathBuf>,
    logo: Option<(Color32, egui::TextureHandle)>,
    debug: DebugHooks,
    titledb: TitleDbState,
    regions: RegionState,
}

/// The optional region lookup's index and its loading state.
#[derive(Default)]
struct RegionState {
    db: Option<Arc<RegionDb>>,
    source: String,
    rx: Option<Receiver<RegionMsg>>,
    progress: Option<(usize, Region)>,
    error: Option<String>,
}

/// The optional update / DLC check's database and its loading state.
#[derive(Default)]
struct TitleDbState {
    db: Option<Arc<TitleDb>>,
    /// Source the current load was started for (to notice when the setting changes).
    source: String,
    rx: Option<Receiver<TitleDbResult>>,
    error: Option<String>,
}

/// Developer aids driven by environment variables (used to screenshot the UI headlessly).
#[derive(Default)]
struct DebugHooks {
    /// `CARTWRITE_SCREENSHOT=out.png`: save a screenshot after ~2 s and exit.
    screenshot: Option<PathBuf>,
    /// `CARTWRITE_DEBUG_BUILD`: start "Build all" shortly after launch.
    auto_build: bool,
    /// `CARTWRITE_DEBUG_SETTINGS`: open the settings dialog on launch
    /// (`=updates` also scrolls it to the update check section).
    open_settings: bool,
    scroll_to_updates: bool,
    /// `CARTWRITE_DEBUG_TITLEDB=<source>`: turn the update check on with this source.
    titledb: Option<String>,
    /// `CARTWRITE_DEBUG_REGIONS=1` turns the region lookup on; any other value is used as its source.
    regions: Option<String>,
    /// `CARTWRITE_DEBUG_EXTRACT`: open the extract dialog for the first game once the scan is done
    /// (`=<folder>` instead extracts that game, without DLC, into the folder).
    extract: bool,
    extract_to: Option<PathBuf>,
    // `CARTWRITE_DEBUG_THEME=light` is applied in `App::new` without touching saved settings.
}

impl DebugHooks {
    fn from_env() -> Self {
        Self {
            screenshot: std::env::var_os("CARTWRITE_SCREENSHOT").map(PathBuf::from),
            auto_build: std::env::var_os("CARTWRITE_DEBUG_BUILD").is_some(),
            open_settings: std::env::var_os("CARTWRITE_DEBUG_SETTINGS").is_some(),
            scroll_to_updates: std::env::var("CARTWRITE_DEBUG_SETTINGS").as_deref() == Ok("updates"),
            titledb: std::env::var("CARTWRITE_DEBUG_TITLEDB").ok(),
            regions: std::env::var("CARTWRITE_DEBUG_REGIONS").ok(),
            extract: std::env::var_os("CARTWRITE_DEBUG_EXTRACT").is_some(),
            extract_to: std::env::var_os("CARTWRITE_DEBUG_EXTRACT").filter(|v| v != "1").map(PathBuf::from),
        }
    }
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        egui_extras::install_image_loaders(&cc.egui_ctx);
        let settings: Settings = cc.storage.and_then(|s| eframe::get_value(s, eframe::APP_KEY)).unwrap_or_default();
        theme::install(&cc.egui_ctx, settings.style, settings.theme);
        if std::env::var("CARTWRITE_DEBUG_THEME").as_deref() == Ok("light") {
            cc.egui_ctx.set_theme(egui::ThemePreference::Light);
        }
        let mut app = Self {
            settings,
            keys: None,
            keys_error: None,
            inputs: Vec::new(),
            titles: Vec::new(),
            scan_errors: Vec::new(),
            games: Vec::new(),
            scan_rx: None,
            job: None,
            log: Vec::new(),
            show_settings: false,
            extract_dialog: None,
            show_log: false,
            pending_rescan: false,
            scanned: HashSet::new(),
            logo: None,
            debug: DebugHooks::from_env(),
            titledb: TitleDbState::default(),
            regions: RegionState::default(),
        };
        app.show_settings = app.debug.open_settings;
        if let Some(source) = app.debug.regions.clone() {
            app.settings.show_regions = true;
            if source != "1" {
                app.settings.regions_source = source;
            }
        }
        if let Some(source) = app.debug.titledb.clone() {
            app.settings.check_updates = true;
            app.settings.titledb_source = source;
        }
        if app.settings.check_updates {
            app.load_titledb(&cc.egui_ctx, false);
        }
        if app.settings.show_regions {
            app.load_regions(&cc.egui_ctx, false);
        }
        app.load_keys();
        // Files passed on the command line / dropped onto the exe.
        let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
        if !args.is_empty() {
            app.add_paths(&cc.egui_ctx, args);
        }
        app
    }

    fn load_keys(&mut self) {
        let path = self.settings.keys_path.clone().filter(|p| p.is_file()).or_else(Keys::find_default);
        match path {
            None => {
                self.keys = None;
                self.keys_error = Some("prod.keys not found".into());
            }
            Some(p) => match Keys::load(&p) {
                Ok(k) => {
                    self.keys = Some(Arc::new(k));
                    self.keys_error = None;
                }
                Err(e) => {
                    self.keys = None;
                    self.keys_error = Some(format!("{}: {e}", p.display()));
                }
            },
        }
    }

    /// Starts loading the title database in the background (cache first unless `force`).
    fn load_titledb(&mut self, ctx: &egui::Context, force: bool) {
        let source = self.settings.titledb_source.trim().to_string();
        if source != self.titledb.source {
            self.titledb.db = None;
        }
        self.titledb.source = source.clone();
        self.titledb.error = None;
        self.titledb.rx = Some(spawn_titledb(ctx.clone(), source, force));
    }

    /// Starts loading the region index in the background (cache first unless `force`).
    fn load_regions(&mut self, ctx: &egui::Context, force: bool) {
        let source = self.settings.regions_source.trim().to_string();
        if source != self.regions.source {
            self.regions.db = None;
        }
        self.regions.source = source.clone();
        self.regions.error = None;
        self.regions.progress = None;
        self.regions.rx = Some(spawn_regions(ctx.clone(), source, force));
    }

    fn poll_regions(&mut self) {
        let Some(rx) = &self.regions.rx else { return };
        loop {
            match rx.try_recv() {
                Ok(RegionMsg::Progress(i, r)) => self.regions.progress = Some((i, r)),
                Ok(RegionMsg::Done(db, err)) => {
                    self.regions.rx = None;
                    self.regions.progress = None;
                    if let Some(db) = db {
                        self.regions.db = Some(Arc::new(db));
                    }
                    if let Some(e) = &err {
                        self.log(format!("Region lists: {e}"), false);
                    }
                    self.regions.error = err;
                    return;
                }
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    self.regions.rx = None;
                    self.regions.progress = None;
                    self.regions.error = Some("the download stopped unexpectedly".into());
                    return;
                }
            }
        }
    }

    fn active_regions(&self) -> Option<Arc<RegionDb>> {
        if self.settings.show_regions {
            self.regions.db.clone()
        } else {
            None
        }
    }

    fn poll_titledb(&mut self) {
        let Some(rx) = &self.titledb.rx else { return };
        let result = match rx.try_recv() {
            Ok(r) => r,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => (None, Some("the download stopped unexpectedly".into())),
        };
        self.titledb.rx = None;
        let (db, err) = result;
        if let Some(db) = db {
            self.titledb.db = Some(Arc::new(db));
        }
        if let Some(e) = &err {
            self.log(format!("Title database: {e}"), false);
        }
        self.titledb.error = err;
    }

    /// The database to check games against, if the feature is on and a copy is loaded.
    fn active_titledb(&self) -> Option<Arc<TitleDb>> {
        if self.settings.check_updates {
            self.titledb.db.clone()
        } else {
            None
        }
    }

    fn log(&mut self, msg: impl Into<String>, error: bool) {
        self.log.push((Instant::now(), msg.into(), error));
        if error {
            self.show_log = true;
        }
    }

    fn busy(&self) -> bool {
        self.scan_rx.is_some() || self.job.is_some()
    }

    fn add_paths(&mut self, ctx: &egui::Context, paths: Vec<PathBuf>) {
        let new: Vec<PathBuf> = paths
            .into_iter()
            .map(|p| std::path::absolute(&p).unwrap_or(p))
            .filter(|p| !self.inputs.contains(p))
            .collect();
        if new.is_empty() {
            return;
        }
        self.inputs.extend(new.iter().cloned());
        if let Some(keys) = self.keys.clone() {
            if self.scan_rx.is_none() {
                self.scan_rx = Some(spawn_scan(ctx.clone(), keys, new));
            } else {
                // A scan is running: queue by rescanning everything when it ends.
                self.pending_rescan = true;
            }
        }
    }

    fn rescan_all(&mut self, ctx: &egui::Context) {
        self.titles.clear();
        self.scanned.clear();
        self.scan_errors.clear();
        self.regroup();
        if let Some(keys) = self.keys.clone() {
            self.scan_rx = Some(spawn_scan(ctx.clone(), keys, self.inputs.clone()));
        }
    }

    fn clear(&mut self) {
        self.inputs.clear();
        self.scanned.clear();
        self.titles.clear();
        self.scan_errors.clear();
        self.games.clear();
    }

    /// Rebuilds the game list, keeping per-game UI state.
    fn regroup(&mut self) {
        let old: HashMap<u64, GameView> = self.games.drain(..).map(|g| (g.game.application_id, g)).collect();
        let mut old = old;
        self.games = group(self.titles.clone())
            .into_iter()
            .map(|game| {
                let icon = game.icon.as_ref().map(|v| egui::load::Bytes::from(v.as_slice().to_vec()));
                match old.remove(&game.application_id) {
                    Some(prev) => GameView {
                        game,
                        selected: prev.selected,
                        excluded: prev.excluded,
                        status: if matches!(prev.status, Status::Done(..) | Status::Failed(_)) {
                            Status::Ready
                        } else {
                            prev.status
                        },
                        icon,
                    },
                    None => {
                        // DLC for another release than the game in the same file: building them on
                        // their own is rarely wanted, so don't include them in "build all" by default.
                        let mismatched = !game.notes.is_empty()
                            && !game.titles.iter().any(|t| matches!(t.kind, TitleKind::Base | TitleKind::Update));
                        GameView { game, selected: !mismatched, excluded: HashSet::new(), status: Status::Ready, icon }
                    }
                }
            })
            .collect();
        self.games.sort_by_key(|g| g.game.name.to_lowercase());
    }

    fn poll(&mut self, ctx: &egui::Context) {
        self.poll_titledb();
        self.poll_regions();
        if let Some(rx) = &self.scan_rx {
            let mut changed = false;
            let mut done = false;
            let mut msgs = Vec::new();
            loop {
                match rx.try_recv() {
                    Ok(ScanMsg::File(p, r)) => msgs.push((p, r)),
                    Ok(ScanMsg::Done) | Err(TryRecvError::Disconnected) => {
                        done = true;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                }
            }
            for (p, r) in msgs {
                if !self.scanned.insert(p.clone()) {
                    continue;
                }
                changed = true;
                match r {
                    Ok(t) => self.titles.extend(t),
                    Err(e) => {
                        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                        self.log(format!("✖ {name}: {e}"), true);
                        self.scan_errors.push((p, e));
                    }
                }
            }
            if changed {
                self.regroup();
            }
            if done {
                self.scan_rx = None;
                if std::mem::take(&mut self.pending_rescan) {
                    self.rescan_all(ctx);
                }
            }
        }

        let Some(job) = &mut self.job else { return };
        let kind = job.kind;
        let mut msgs = Vec::new();
        loop {
            match job.rx.try_recv() {
                Ok(m) => msgs.push(m),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    msgs.push(BuildMsg::AllDone);
                    break;
                }
            }
        }
        for m in msgs {
            match m {
                BuildMsg::Started(id) => {
                    if let Some(job) = &mut self.job {
                        job.current = Some(id);
                    }
                    let name = self.game_name(id);
                    self.log(format!("{} {name}", kind.doing()), false);
                    self.set_status(id, Status::Building { kind, done: 0, total: 1 });
                }
                BuildMsg::Progress(id, Progress::Bytes { done, total }) => {
                    if let Some(job) = &mut self.job {
                        // An extraction has exactly one game, and its real size is only known now.
                        if kind == JobKind::Extract {
                            job.bytes_total = total;
                            job.bytes_started.get_or_insert_with(Instant::now);
                        }
                    }
                    self.set_status(id, Status::Building { kind, done, total })
                }
                BuildMsg::Progress(_, Progress::Log(msg)) => self.log(msg, false),
                BuildMsg::Finished(id, r) => {
                    if let Some(job) = &mut self.job {
                        if let Some(g) = self.games.iter().find(|g| g.game.application_id == id) {
                            if let Status::Building { total, .. } = g.status {
                                job.bytes_before += total;
                            }
                        }
                    }
                    match r {
                        Ok(paths) => {
                            for p in &paths {
                                self.log(format!("✔ Wrote {}", p.display()), false);
                            }
                            self.set_status(id, Status::Done(kind, paths));
                        }
                        Err(e) => {
                            let name = self.game_name(id);
                            self.log(format!("✖ {name}: {e}"), true);
                            self.set_status(id, Status::Failed(e));
                        }
                    }
                }
                BuildMsg::Cancelled(id) => {
                    let name = self.game_name(id);
                    self.log(format!("Cancelled {name}"), false);
                    self.set_status(id, Status::Ready);
                }
                BuildMsg::AllDone => {
                    for g in &mut self.games {
                        if g.status == Status::Queued {
                            g.status = Status::Ready;
                        }
                    }
                    self.job = None;
                    return;
                }
            }
        }
    }

    fn game_name(&self, id: u64) -> String {
        self.games.iter().find(|g| g.game.application_id == id).map(|g| g.game.name.clone()).unwrap_or_default()
    }

    fn set_status(&mut self, id: u64, s: Status) {
        if let Some(g) = self.games.iter_mut().find(|g| g.game.application_id == id) {
            g.status = s;
        }
    }

    fn output_dir_for(&self, g: &GameView) -> PathBuf {
        if let Some(d) = &self.settings.output_dir {
            return d.clone();
        }
        g.chosen().first().and_then(|t| t.source.parent().map(Path::to_path_buf)).unwrap_or_else(|| PathBuf::from("."))
    }

    fn start_build(&mut self, ctx: &egui::Context, only: Option<u64>) {
        let Some(keys) = self.keys.clone() else { return };
        let mut jobs = Vec::new();
        for g in &self.games {
            let wanted = match only {
                Some(id) => g.game.application_id == id,
                None => g.selected,
            };
            if !wanted || g.chosen().is_empty() {
                continue;
            }
            let output = self.output_dir_for(g).join(format!("{}.xci", g.file_stem()));
            let delete_after = if self.settings.delete_source_xci { self.deletable_sources(g) } else { Vec::new() };
            jobs.push(BuildJob {
                application_id: g.game.application_id,
                titles: g.chosen().into_iter().cloned().collect(),
                output,
                delete_after,
            });
        }
        if jobs.is_empty() {
            return;
        }
        let ids: HashSet<u64> = jobs.iter().map(|j| j.application_id).collect();
        let bytes_total = self
            .games
            .iter()
            .filter(|g| ids.contains(&g.game.application_id))
            .map(|g| g.chosen().iter().map(|t| t.size(self.settings.include_deltas)).sum::<u64>())
            .sum();
        for g in &mut self.games {
            if ids.contains(&g.game.application_id) {
                g.status = Status::Queued;
            }
        }
        let opts = BuildOptions {
            patch_rsv: self.settings.patch_rsv,
            include_deltas: self.settings.include_deltas,
            split_fat32: self.settings.split_fat32,
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let rx = spawn_build(ctx.clone(), keys, jobs, opts, cancel.clone());
        self.job = Some(Job {
            kind: JobKind::Build,
            rx,
            cancel,
            started: Instant::now(),
            current: None,
            bytes_before: 0,
            bytes_total,
            bytes_started: None,
        });
    }

    /// Opens the extract dialog for a game, starting from the last choices.
    fn open_extract_dialog(&mut self, id: u64) {
        let Some(g) = self.games.iter().find(|g| g.game.application_id == id) else { return };
        let dir = self.settings.extract_dir.clone().unwrap_or_else(|| self.output_dir_for(g));
        let with_dlc = self.settings.extract_dlc && g.has_dlc();
        self.extract_dialog = Some(ExtractDialog { application_id: id, dir, with_dlc });
    }

    /// Extracts one game to the folder `output`.
    fn start_extract(&mut self, ctx: &egui::Context, id: u64, output: PathBuf, opts: ExtractOptions) {
        let Some(keys) = self.keys.clone() else { return };
        let Some(g) = self.games.iter_mut().find(|g| g.game.application_id == id) else { return };
        let titles: Vec<Title> = g.chosen().into_iter().cloned().collect();
        if titles.is_empty() {
            return;
        }
        g.status = Status::Queued;
        let cancel = Arc::new(AtomicBool::new(false));
        let job = ExtractJob { application_id: id, titles, output, opts };
        let rx = spawn_extract(ctx.clone(), keys, job, cancel.clone());
        self.job = Some(Job {
            kind: JobKind::Extract,
            rx,
            cancel,
            started: Instant::now(),
            current: None,
            bytes_before: 0,
            bytes_total: 0,
            bytes_started: None,
        });
    }

    /// Source XCIs that are safe to delete after rebuilding `g`: every title they hold must
    /// end up in the new XCI (or be an older version of one that does), they must not hold
    /// other games, and nothing in them may have been skipped while reading.
    fn deletable_sources(&self, g: &GameView) -> Vec<PathBuf> {
        let chosen = g.chosen();
        let carried_over = |o: &Title| chosen.iter().any(|c| c.title_id == o.title_id && c.version >= o.version);
        let mut out: Vec<PathBuf> = Vec::new();
        let srcs = g.game.titles.iter().chain(&g.game.superseded).filter(|t| t.source_kind == ContainerKind::Xci);
        for t in srcs {
            let p = t.source.as_ref();
            if out.contains(p) {
                continue;
            }
            let safe = self
                .titles
                .iter()
                .filter(|o| o.source.as_ref() == p)
                .all(|o| o.application_id == g.game.application_id && o.source_complete && carried_over(o));
            if safe {
                out.push(p.clone());
            }
        }
        out
    }

    // ---------------------------------------------------------------- UI

    fn header(&mut self, ui: &mut egui::Ui) {
        let p = theme::palette(ui);
        let logo = self.logo_texture(ui.ctx(), p.accent);
        ui.horizontal(|ui| {
            ui.add(egui::Image::new((logo.id(), egui::vec2(34.0, 34.0))));
            ui.add_space(2.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                ui.label(RichText::new("Cartwrite").font(theme::semibold(17.0)).color(p.text));
                ui.label(RichText::new("Base game + update + DLC → one XCI").size(12.0).color(p.text_dim));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::icon_button(ui, true, "⚙", "Settings").clicked() {
                    self.show_settings = true;
                }
                let (icon, tip, next) = match self.settings.theme {
                    ThemeChoice::Dark => ("☀", "Switch to light mode", ThemeChoice::Light),
                    ThemeChoice::Light => ("🌙", "Switch to dark mode", ThemeChoice::Dark),
                    ThemeChoice::System => ("◐", "Following system theme. Click for dark mode.", ThemeChoice::Dark),
                };
                if theme::icon_button(ui, true, icon, tip).clicked() {
                    self.settings.theme = next;
                    ui.ctx().set_theme(next.preference());
                }
                ui.add_space(6.0);
                match self.keys.clone() {
                    Some(k) => {
                        let mk = k.max_master_key().unwrap_or(0);
                        status_pill(ui, p.ok, &format!("Keys ready · {mk:#04x}"))
                            .on_hover_text(format!("{}\nNewest master key: {mk:#04x}", k.path.display()));
                    }
                    None => {
                        let r = status_pill(ui, p.err, "prod.keys missing. Click to locate.")
                            .interact(egui::Sense::click())
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .on_hover_text(self.keys_error.clone().unwrap_or_default());
                        if r.clicked() {
                            self.pick_keys(ui.ctx());
                        }
                    }
                }
            });
        });
    }

    /// The app icon rendered in the current accent colour (cached per colour).
    fn logo_texture(&mut self, ctx: &egui::Context, accent: Color32) -> egui::TextureHandle {
        if let Some((c, tex)) = &self.logo {
            if *c == accent {
                return tex.clone();
            }
        }
        let rgba = crate::icon::render(128, [accent.r(), accent.g(), accent.b()]);
        let img = egui::ColorImage::from_rgba_unmultiplied([128, 128], &rgba);
        let tex = ctx.load_texture("logo", img, egui::TextureOptions::LINEAR);
        self.logo = Some((accent, tex.clone()));
        tex
    }

    fn pick_keys(&mut self, ctx: &egui::Context) {
        if let Some(p) = rfd::FileDialog::new().add_filter("Keys", &["keys", "txt"]).pick_file() {
            self.settings.keys_path = Some(p);
            self.load_keys();
            if self.keys.is_some() {
                self.rescan_all(ctx);
            }
        }
    }

    fn add_files_dialog(&mut self, ctx: &egui::Context) {
        let mut d = rfd::FileDialog::new().add_filter("Switch content", &EXTENSIONS);
        if let Some(dir) = &self.settings.last_dir {
            d = d.set_directory(dir);
        }
        if let Some(files) = d.pick_files() {
            self.settings.last_dir = files.first().and_then(|f| f.parent().map(Path::to_path_buf));
            self.add_paths(ctx, files);
        }
    }

    fn add_folder_dialog(&mut self, ctx: &egui::Context) {
        let mut d = rfd::FileDialog::new();
        if let Some(dir) = &self.settings.last_dir {
            d = d.set_directory(dir);
        }
        if let Some(dir) = d.pick_folder() {
            self.settings.last_dir = Some(dir.clone());
            self.add_paths(ctx, vec![dir]);
        }
    }

    fn bottom_bar(&mut self, ui: &mut egui::Ui) {
        let p = theme::palette(ui);
        if let Some(job) = &self.job {
            let current = job.current.and_then(|id| self.games.iter().find(|g| g.game.application_id == id));
            let cur_done = match current.map(|g| &g.status) {
                Some(Status::Building { done, .. }) => *done,
                _ => 0,
            };
            // An extraction only knows its size once it starts writing.
            let preparing = job.kind == JobKind::Extract && job.bytes_total == 0;
            let total = job.bytes_total.max(1);
            let done = (job.bytes_before + cur_done).min(total);
            let since = job.bytes_started.unwrap_or(job.started);
            let secs = since.elapsed().as_secs_f64().max(0.001);
            let speed = done as f64 / secs;
            let eta = if speed > 0.0 { total.saturating_sub(done) as f64 / speed } else { 0.0 };
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new(job.kind.doing()).color(p.text_dim));
                ui.label(
                    RichText::new(current.map(|g| g.game.name.as_str()).unwrap_or("…")).font(theme::semibold(14.0)),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::ghost_button(ui, true, "Cancel").clicked() {
                        job.cancel.store(true, Ordering::Relaxed);
                    }
                    let text = if preparing {
                        "Preparing…".to_string()
                    } else {
                        format!(
                            "{} of {}  ·  {}/s  ·  {} left",
                            format_size(done),
                            format_size(total),
                            format_size(speed as u64),
                            fmt_secs(eta)
                        )
                    };
                    ui.label(RichText::new(text).color(p.text_dim));
                });
            });
            let w = ui.available_width();
            let fraction = if preparing { 0.0 } else { done as f32 / total as f32 };
            theme::progress_bar(ui, egui::Id::new("overall"), fraction, w);
            ui.add_space(10.0);
        }

        ui.horizontal(|ui| {
            ui.label(RichText::new("Output").color(p.text_dim));
            let label = match &self.settings.output_dir {
                Some(d) => short_path(d, 42),
                None => "Same folder as source".into(),
            };
            let hover = match &self.settings.output_dir {
                Some(d) => d.display().to_string(),
                None => "Each XCI is written next to its source files. Click to pick a folder.".into(),
            };
            if theme::secondary_button(ui, true, format!("{label}  ⏷")).on_hover_text(hover).clicked() {
                if let Some(d) = rfd::FileDialog::new().pick_folder() {
                    self.settings.output_dir = Some(d);
                }
            }
            if self.settings.output_dir.is_some() && theme::icon_button(ui, true, "✕", "Use source folder").clicked() {
                self.settings.output_dir = None;
            }
            ui.add_space(14.0);
            theme::toggle(
                ui,
                &mut self.settings.patch_rsv,
                "Lower required firmware",
                "Patch RequiredSystemVersion down to the first firmware that can decrypt the game,\nso consoles on older firmware aren't asked to update.",
            );
            ui.add_space(6.0);
            theme::toggle(ui, &mut self.settings.split_fat32, "Split for FAT32", "Split files larger than 4 GB into .xc0, .xc1, … parts");

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let n = self.games.iter().filter(|g| g.selected && !g.chosen().is_empty()).count();
                let can = self.keys.is_some() && !self.busy() && n > 0;
                let text = match n {
                    0 => "Build".to_string(),
                    1 => "Build 1 XCI".to_string(),
                    n => format!("Build {n} XCIs"),
                };
                if theme::primary_button(ui, can, &format!("   {text}   ")).clicked() {
                    self.start_build(ui.ctx(), None);
                }
                let errors = self.log.iter().filter(|l| l.2).count();
                let icon = if errors > 0 { format!("☰ {errors}") } else { "☰".into() };
                let tip = if self.show_log { "Hide activity log" } else { "Show activity log" };
                if theme::icon_button(ui, true, &icon, tip).clicked() {
                    self.show_log = !self.show_log;
                }
            });
        });
    }

    fn log_panel(&mut self, ui: &mut egui::Ui) {
        let p = theme::palette(ui);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Activity").font(theme::semibold(13.0)));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::ghost_button(ui, true, "Clear").clicked() {
                    self.log.clear();
                }
            });
        });
        egui::ScrollArea::vertical().stick_to_bottom(true).auto_shrink([false, false]).show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 3.0;
            if self.log.is_empty() {
                ui.label(RichText::new("Nothing yet.").color(p.text_faint));
            }
            for (_, msg, err) in &self.log {
                let c = if *err { p.err } else { p.text_dim };
                ui.label(RichText::new(msg).monospace().color(c));
            }
        });
    }

    fn drop_zone(&mut self, ui: &mut egui::Ui, hovering: bool) {
        let p = theme::palette(ui);
        let avail = ui.available_rect_before_wrap();
        let size = egui::vec2(avail.width().min(640.0), 320.0);
        let rect = egui::Rect::from_center_size(avail.center() - egui::vec2(0.0, 24.0), size);
        let zone = ui.allocate_rect(rect, egui::Sense::click());
        let hot = hovering || zone.hovered();
        let t = ui.ctx().animate_bool_with_time(egui::Id::new("dz-hot"), hot, 0.15);
        let painter = ui.painter();
        painter.rect_filled(rect, 20.0, theme::lerp_color(p.card, p.accent.gamma_multiply(0.10), t));
        theme::dashed_rect(
            painter,
            rect.shrink(1.0),
            egui::Stroke::new(1.5, theme::lerp_color(p.border_strong, p.accent, t)),
        );
        if zone.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
            self.add_files_dialog(ui.ctx());
        }

        let inner = rect.shrink2(egui::vec2(40.0, 34.0));
        ui.scope_builder(egui::UiBuilder::new().max_rect(inner).layout(egui::Layout::top_down(egui::Align::Center)), |ui| {
            let (r, _) = ui.allocate_exact_size(egui::vec2(64.0, 64.0), egui::Sense::hover());
            ui.painter().circle_filled(r.center(), 32.0, p.accent.gamma_multiply(0.16));
            ui.painter().text(r.center(), egui::Align2::CENTER_CENTER, "⬇", egui::FontId::proportional(28.0), p.accent);
            ui.add_space(6.0);
            ui.label(RichText::new("Drop your games here").font(theme::semibold(22.0)).color(p.text));
            ui.label(
                RichText::new("Add a game with its update and DLC, or an XCI you built earlier plus a newer update, and get one XCI back.")
                    .color(p.text_dim),
            );
            ui.add_space(12.0);
            let bw = 136.0;
            ui.allocate_ui_with_layout(egui::vec2(bw * 2.0 + 10.0, 36.0), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 10.0;
                if theme::primary_button_sized(ui, true, "Add files", egui::vec2(bw, 36.0)).clicked() {
                    self.add_files_dialog(ui.ctx());
                }
                if ui.add_sized([bw, 36.0], egui::Button::new("Add folder").corner_radius(p.button_radius)).clicked() {
                    self.add_folder_dialog(ui.ctx());
                }
            });
            ui.add_space(10.0);
            ui.label(RichText::new("NSP  ·  NSZ  ·  XCI  ·  XCZ").size(12.0).color(p.text_faint));
        });

        if self.keys.is_none() {
            let below = egui::Rect::from_min_size(
                egui::pos2(rect.left(), rect.bottom() + 16.0),
                egui::vec2(rect.width(), 40.0),
            );
            ui.scope_builder(egui::UiBuilder::new().max_rect(below).layout(egui::Layout::top_down(egui::Align::Center)), |ui| {
                ui.label(
                    RichText::new("prod.keys is required. Put it in %USERPROFILE%\\.switch\\, next to the app, or click the red badge above.")
                        .color(p.warn),
                );
            });
        }
        if !self.scan_errors.is_empty() {
            let top = rect.bottom() + if self.keys.is_none() { 56.0 } else { 16.0 };
            let area = egui::Rect::from_min_size(egui::pos2(rect.left(), top), egui::vec2(rect.width(), 140.0));
            ui.scope_builder(
                egui::UiBuilder::new().max_rect(area).layout(egui::Layout::top_down(egui::Align::Min)),
                |ui| {
                    ui.spacing_mut().item_spacing.y = 4.0;
                    ui.label(
                        RichText::new(format!("Couldn't read {} file(s)", self.scan_errors.len()))
                            .font(theme::semibold(13.0))
                            .color(p.err),
                    );
                    for (path, e) in self.scan_errors.iter().take(4) {
                        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                        ui.add(
                            egui::Label::new(RichText::new(format!("{name}: {e}")).size(12.5).color(p.text_dim))
                                .truncate(),
                        )
                        .on_hover_text(format!("{}\n{e}", path.display()));
                    }
                    if self.scan_errors.len() > 4 {
                        ui.label(
                            RichText::new(format!("…and {} more (see the activity log)", self.scan_errors.len() - 4))
                                .size(12.5)
                                .color(p.text_faint),
                        );
                    }
                },
            );
        }
    }

    fn game_list(&mut self, ui: &mut egui::Ui) {
        let p = theme::palette(ui);
        let busy = self.busy();
        ui.horizontal(|ui| {
            ui.label(RichText::new("Games").font(theme::semibold(20.0)));
            theme::pill(ui, self.games.len().to_string(), p.text_dim);
            if self.scan_rx.is_some() {
                ui.add_space(4.0);
                ui.spinner();
                ui.label(RichText::new("Reading files…").color(p.text_dim));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::ghost_button(ui, !busy, "Clear all").clicked() {
                    self.clear();
                }
                if theme::secondary_button(ui, !busy, "Add folder").clicked() {
                    self.add_folder_dialog(ui.ctx());
                }
                if theme::secondary_button(ui, !busy, "Add files").clicked() {
                    self.add_files_dialog(ui.ctx());
                }
            });
        });
        ui.add_space(10.0);

        let job_running = self.job.is_some();
        let out_dir = self.settings.output_dir.clone();
        let deltas = self.settings.include_deltas;
        let titledb = self.active_titledb();
        let region_db = self.active_regions();
        let mut build_one = None;
        let mut extract_one = None;
        let mut remove = None;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for (i, g) in self.games.iter_mut().enumerate() {
                let dir = match &out_dir {
                    Some(d) => d.clone(),
                    None => {
                        g.chosen().first().and_then(|t| t.source.parent().map(Path::to_path_buf)).unwrap_or_default()
                    }
                };
                match game_card(ui, g, job_running, &dir, deltas, titledb.as_deref(), region_db.as_deref()) {
                    CardAction::None => {}
                    CardAction::Build => build_one = Some(g.game.application_id),
                    CardAction::Extract => extract_one = Some(g.game.application_id),
                    CardAction::Remove => remove = Some(i),
                }
                ui.add_space(10.0);
            }
            for (path, e) in &self.scan_errors {
                let name = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
                ui.label(RichText::new(format!("✖ {name}: {e}")).color(p.err));
            }
        });
        if let Some(id) = build_one {
            self.start_build(ui.ctx(), Some(id));
        }
        if let Some(id) = extract_one {
            self.open_extract_dialog(id);
        }
        if let Some(i) = remove {
            let g = self.games.remove(i);
            let srcs: HashSet<PathBuf> =
                g.game.titles.iter().chain(&g.game.superseded).map(|t| t.source.as_ref().clone()).collect();
            self.titles.retain(|t| t.application_id != g.game.application_id);
            let still_used: HashSet<PathBuf> = self.titles.iter().map(|t| t.source.as_ref().clone()).collect();
            self.inputs.retain(|p| !srcs.contains(p) || still_used.contains(p));
            self.scanned.retain(|p| !srcs.contains(p) || still_used.contains(p));
        }
    }

    /// Source field, refresh button and status for the update check (inside Settings).
    fn titledb_settings(&mut self, ui: &mut egui::Ui, p: &theme::Palette, action: &mut Option<bool>) {
        ui.add_space(2.0);
        ui.label(RichText::new("Title database source").color(p.text_dim));
        let field = ui.add(
            egui::TextEdit::singleline(&mut self.settings.titledb_source)
                .hint_text(titledb::DEFAULT_SOURCE)
                .desired_width(ui.available_width()),
        );
        let changed = self.settings.titledb_source.trim() != self.titledb.source;
        if field.lost_focus() && changed {
            *action = Some(false);
        }
        ui.label(
            RichText::new(
                "A URL or a local file in titledb's versions.txt format (one id|rightsId|version line per title). \
                 versions.json also works but has no DLC list.",
            )
            .size(12.0)
            .color(p.text_faint),
        );
        ui.add_space(4.0);
        let loading = self.titledb.rx.is_some();
        ui.horizontal(|ui| {
            if theme::secondary_button(ui, !loading, "Refresh now").clicked() {
                *action = Some(true);
            }
            if self.settings.titledb_source.trim() != titledb::DEFAULT_SOURCE
                && theme::ghost_button(ui, !loading, "Use default source").clicked()
            {
                self.settings.titledb_source = titledb::DEFAULT_SOURCE.into();
                *action = Some(false);
            }
        });
        ui.add_space(2.0);
        ui.horizontal_wrapped(|ui| {
            if loading {
                ui.spinner();
                ui.label(RichText::new("Loading the title database…").color(p.text_dim));
                return;
            }
            if let Some(db) = &self.titledb.db {
                status_pill(ui, p.ok, "Ready");
                let dlc = if db.has_dlc_info() { "" } else { " (no DLC info in this source)" };
                ui.label(
                    RichText::new(format!("{} titles, updated {}{dlc}", db.len(), format_age(db.fetched)))
                        .color(p.text_dim),
                );
            }
            if let Some(e) = &self.titledb.error {
                let msg = if self.titledb.db.is_some() {
                    format!("Couldn't refresh ({e}), so the copy above is being used.")
                } else {
                    format!("Couldn't load the title database: {e}")
                };
                ui.label(RichText::new(msg).color(p.err));
            }
        });
    }

    /// Source field, refresh button and status for the region lookup (inside Settings).
    fn region_settings(&mut self, ui: &mut egui::Ui, p: &theme::Palette, action: &mut Option<bool>) {
        ui.add_space(2.0);
        ui.label(RichText::new("Region lists source").color(p.text_dim));
        let field = ui.add(
            egui::TextEdit::singleline(&mut self.settings.regions_source)
                .hint_text(regions::DEFAULT_SOURCE)
                .desired_width(ui.available_width()),
        );
        if field.lost_focus() && self.settings.regions_source.trim() != self.regions.source {
            *action = Some(false);
        }
        ui.label(
            RichText::new(
                "A URL or local folder containing titledb's US.en.json, GB.en.json, JP.ja.json, HK.zh.json and \
                 KR.ko.json.",
            )
            .size(12.0)
            .color(p.text_faint),
        );
        ui.add_space(4.0);
        let loading = self.regions.rx.is_some();
        ui.horizontal(|ui| {
            if theme::secondary_button(ui, !loading, "Refresh now").clicked() {
                *action = Some(true);
            }
            if self.settings.regions_source.trim() != regions::DEFAULT_SOURCE
                && theme::ghost_button(ui, !loading, "Use default source").clicked()
            {
                self.settings.regions_source = regions::DEFAULT_SOURCE.into();
                *action = Some(false);
            }
        });
        ui.add_space(2.0);
        ui.horizontal_wrapped(|ui| {
            if loading {
                ui.spinner();
                let msg = match self.regions.progress {
                    Some((i, r)) => {
                        format!("Downloading region lists: {} of {}, {}", i + 1, Region::ALL.len(), r.name())
                    }
                    None => "Loading region lists…".into(),
                };
                ui.label(RichText::new(msg).color(p.text_dim));
                return;
            }
            if let Some(db) = &self.regions.db {
                status_pill(ui, p.ok, "Ready");
                ui.label(
                    RichText::new(format!("{} titles, updated {}", db.len(), format_age(db.fetched))).color(p.text_dim),
                );
            }
            if let Some(e) = &self.regions.error {
                let msg = if self.regions.db.is_some() {
                    format!("Couldn't refresh ({e}), so the copy above is being used.")
                } else {
                    format!("Couldn't load the region lists: {e}")
                };
                ui.label(RichText::new(msg).color(p.err));
            }
        });
    }

    fn settings_modal(&mut self, ctx: &egui::Context) {
        let p = theme::palette_for(theme::style(), ctx.theme() == egui::Theme::Dark);
        let mut close = false;
        let mut reload = false;
        let mut titledb_action: Option<bool> = None; // Some(force) to (re)load the database
        let mut regions_action: Option<bool> = None;
        let max_h = (ctx.content_rect().height() - 120.0).max(200.0);
        let modal = egui::Modal::new(egui::Id::new("settings")).frame(modal_frame(&p)).show(ctx, |ui| {
            ui.set_width(520.0);
            ui.set_max_width(520.0);
            egui::ScrollArea::vertical().max_height(max_h).auto_shrink([false, true]).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Settings").font(theme::semibold(20.0)));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::icon_button(ui, true, "✕", "Close").clicked() {
                            close = true;
                        }
                    });
                });

                section(ui, "APPEARANCE");
                let mut choice = self.settings.theme;
                if theme::segmented(
                    ui,
                    &mut choice,
                    &[(ThemeChoice::Dark, "Dark"), (ThemeChoice::Light, "Light"), (ThemeChoice::System, "System")],
                ) {
                    self.settings.theme = choice;
                    ui.ctx().set_theme(choice.preference());
                }
                ui.add_space(4.0);
                let mut style = self.settings.style;
                if theme::segmented(ui, &mut style, &[(ThemeStyle::Nx, "NX"), (ThemeStyle::Violet, "Violet")]) {
                    self.settings.style = style;
                    theme::apply_style(ui.ctx(), style);
                }

                section(ui, "KEYS");
                egui::Frame::new().fill(p.input).corner_radius(10).inner_margin(12).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| match &self.keys {
                        Some(k) => {
                            status_pill(ui, p.ok, "Loaded");
                            ui.add(
                                egui::Label::new(RichText::new(k.path.display().to_string()).color(p.text_dim))
                                    .truncate(),
                            );
                        }
                        None => {
                            status_pill(ui, p.err, "Not loaded");
                            ui.label(RichText::new(self.keys_error.clone().unwrap_or_default()).color(p.err));
                        }
                    });
                });
                ui.add_space(4.0);
                if theme::secondary_button(ui, self.job.is_none(), "Choose prod.keys…").clicked() {
                    if let Some(path) = rfd::FileDialog::new().add_filter("Keys", &["keys", "txt"]).pick_file() {
                        self.settings.keys_path = Some(path);
                        reload = true;
                    }
                }
                ui.label(
                    RichText::new("Also found automatically next to the app, in .\\Keys\\ or %USERPROFILE%\\.switch\\")
                        .size(12.0)
                        .color(p.text_faint),
                );

                section(ui, "BUILDING");
                setting_toggle(
                    ui,
                    &mut self.settings.patch_rsv,
                    "Lower required firmware",
                    "Patch RequiredSystemVersion to the first firmware that has the game's key.",
                );
                setting_toggle(
                    ui,
                    &mut self.settings.split_fat32,
                    "Split for FAT32",
                    "Write 4 GB parts (.xc0, .xc1, …) for FAT32 SD cards.",
                );
                setting_toggle(
                    ui,
                    &mut self.settings.include_deltas,
                    "Keep update delta fragments",
                    "Only used for eShop patching, so they are useless inside an XCI.",
                );
                setting_toggle(
                    ui,
                    &mut self.settings.delete_source_xci,
                    "Delete the old XCI after rebuilding it",
                    "When updating an existing XCI, remove the old file once the new one is written.",
                );

                section(ui, "TITLE DATABASE");
                if self.debug.scroll_to_updates {
                    ui.scroll_to_cursor(Some(egui::Align::TOP));
                }
                let was_on = self.settings.check_updates;
                setting_toggle(
                    ui,
                    &mut self.settings.check_updates,
                    "Check for newer updates and missing DLC",
                    "Compares your games with a community title database. Nothing is downloaded while this is off.",
                );
                if self.settings.check_updates && !was_on {
                    titledb_action = Some(false);
                }
                if self.settings.check_updates {
                    self.titledb_settings(ui, &p, &mut titledb_action);
                }

                ui.add_space(8.0);
                let was_on = self.settings.show_regions;
                setting_toggle(
                    ui,
                    &mut self.settings.show_regions,
                    "Show which region each release is from",
                    "Downloads titledb's eShop lists for the US, Europe, Japan, Asia and Korea once (about 100 MB), \
                     keeps a small summary and refreshes it monthly.",
                );
                if self.settings.show_regions && !was_on {
                    regions_action = Some(false);
                }
                if self.settings.show_regions {
                    self.region_settings(ui, &p, &mut regions_action);
                }
            });
            ui.add_space(14.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::primary_button(ui, true, "   Done   ").clicked() {
                    close = true;
                }
            });
        });
        if close || modal.should_close() {
            self.show_settings = false;
        }
        if let Some(force) = regions_action {
            self.load_regions(ctx, force);
        }
        if let Some(force) = titledb_action {
            self.load_titledb(ctx, force);
        }
        if reload {
            self.load_keys();
            if self.keys.is_some() {
                self.rescan_all(ctx);
            }
        }
    }

    fn extract_modal(&mut self, ctx: &egui::Context) {
        let Some(mut dlg) = self.extract_dialog.take() else { return };
        // The game was removed or regrouped away while the dialog was open: close it.
        let Some(g) = self.games.iter().find(|g| g.game.application_id == dlg.application_id) else { return };
        let p = theme::palette_for(theme::style(), ctx.theme() == egui::Theme::Dark);
        let can_start = self.keys.is_some() && !self.busy();
        let has_dlc = g.has_dlc();
        if !has_dlc {
            dlg.with_dlc = false;
        }
        let mut close = false;
        let mut start = false;
        let modal = egui::Modal::new(egui::Id::new("extract")).frame(modal_frame(&p)).show(ctx, |ui| {
            ui.set_width(460.0);
            ui.set_max_width(460.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Extract to folder").font(theme::semibold(20.0)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::icon_button(ui, true, "✕", "Close").clicked() {
                        close = true;
                    }
                });
            });
            ui.add_space(8.0);
            ui.label(RichText::new(&g.game.name).font(theme::semibold(15.0)));
            ui.label(
                RichText::new("Writes the game's files with its update applied: exefs, romfs, control and logo.")
                    .size(12.0)
                    .color(p.text_dim),
            );

            section(ui, "CONTENT");
            if has_dlc {
                theme::segmented(ui, &mut dlg.with_dlc, &[(false, "Game only"), (true, "Game + DLC")]);
                if dlg.with_dlc {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(
                            "DLC goes to a separate folder next to the game's, as <title id>/romfs, with its DLC                              update applied.",
                        )
                        .size(12.0)
                        .color(p.text_dim),
                    );
                }
            } else {
                ui.label(RichText::new("No DLC selected for this game.").size(12.0).color(p.text_dim));
            }

            section(ui, "DESTINATION");
            let label = format!("{}  ⏷", short_path(&dlg.dir, 40));
            if theme::secondary_button(ui, true, label).on_hover_text(dlg.dir.display().to_string()).clicked() {
                if let Some(d) = rfd::FileDialog::new().set_directory(&dlg.dir).pick_folder() {
                    dlg.dir = d;
                }
            }
            let stem = g.extract_stem(dlg.with_dlc);
            let target = dlg.dir.join(&stem);
            ui.add_space(4.0);
            ui.add(egui::Label::new(RichText::new(format!("→  {stem}")).size(12.5).color(p.text_dim)).truncate())
                .on_hover_text(target.display().to_string());
            let dlc_target = dlc_path(&target);
            if dlg.with_dlc {
                let name = dlc_target.file_name().unwrap_or_default().to_string_lossy().into_owned();
                ui.add(egui::Label::new(RichText::new(format!("→  {name}")).size(12.5).color(p.text_dim)).truncate())
                    .on_hover_text(dlc_target.display().to_string());
            }

            let exists = target.exists() || (dlg.with_dlc && dlc_target.exists());
            if exists {
                ui.add_space(8.0);
                let msg = if dlg.with_dlc {
                    "An earlier extraction is already there. Extracting replaces it."
                } else {
                    "This folder already exists. Extracting replaces it."
                };
                ui.label(RichText::new(msg).color(p.warn));
            }
            let compressed = g.extract_titles(dlg.with_dlc).iter().any(|t| {
                let ext = t.source.extension().map(|e| e.to_string_lossy().to_ascii_lowercase());
                matches!(ext.as_deref(), Some("nsz" | "xcz"))
            });
            if compressed {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(
                        "Compressed input is decompressed to a temporary folder next to the output first, \
                         so it needs extra free space.",
                    )
                    .size(12.0)
                    .color(p.text_dim),
                );
            }

            ui.add_space(14.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let text = if exists { "   Replace   " } else { "   Extract   " };
                if theme::primary_button(ui, can_start, text).clicked() {
                    start = true;
                }
                if theme::ghost_button(ui, true, "Cancel").clicked() {
                    close = true;
                }
            });
        });
        if start {
            let output = dlg.dir.join(g.extract_stem(dlg.with_dlc));
            let exists = output.exists() || (dlg.with_dlc && dlc_path(&output).exists());
            let opts = ExtractOptions { include_dlc: dlg.with_dlc, overwrite: exists };
            self.settings.extract_dir = Some(dlg.dir.clone());
            if has_dlc {
                self.settings.extract_dlc = dlg.with_dlc;
            }
            self.start_extract(ctx, dlg.application_id, output, opts);
        } else if !(close || modal.should_close()) {
            self.extract_dialog = Some(dlg);
        }
    }
}

/// Frame shared by the modal dialogs.
fn modal_frame(p: &theme::Palette) -> egui::Frame {
    egui::Frame::new()
        .fill(p.panel)
        .stroke(egui::Stroke::new(1.0, p.border))
        .corner_radius(16)
        .inner_margin(24)
        .shadow(egui::epaint::Shadow { offset: [0, 16], blur: 48, spread: 0, color: p.shadow })
}

fn section(ui: &mut egui::Ui, title: &str) {
    let p = theme::palette(ui);
    ui.add_space(14.0);
    ui.label(RichText::new(title).font(theme::semibold(11.5)).color(p.text_faint));
    ui.add_space(2.0);
}

fn setting_toggle(ui: &mut egui::Ui, value: &mut bool, label: &str, hint: &str) {
    let p = theme::palette(ui);
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 0.0;
        theme::toggle(ui, value, label, "");
        ui.horizontal(|ui| {
            ui.add_space(42.0);
            ui.add(egui::Label::new(RichText::new(hint).size(12.0).color(p.text_dim)).wrap());
        });
    });
    ui.add_space(6.0);
}

fn status_pill(ui: &mut egui::Ui, color: Color32, text: &str) -> egui::Response {
    let dark = ui.visuals().dark_mode;
    // Own row so it sizes to its content inside right-aligned layouts; the dot is painted
    // in the left padding so it stays on the left whatever the layout direction.
    let resp = ui
        .horizontal(|ui| {
            egui::Frame::new()
                .fill(color.gamma_multiply(if dark { 0.14 } else { 0.10 }))
                .corner_radius(20)
                .inner_margin(egui::Margin { left: 23, right: 11, top: 4, bottom: 4 })
                .show(ui, |ui| {
                    ui.label(RichText::new(text).font(theme::semibold(12.5)).color(color));
                })
                .response
        })
        .inner;
    ui.painter().circle_filled(egui::pos2(resp.rect.left() + 13.0, resp.rect.center().y), 4.0, color);
    resp
}

fn short_path(p: &Path, max: usize) -> String {
    let s = p.display().to_string();
    if s.chars().count() <= max {
        return s;
    }
    let tail: String = s.chars().rev().take(max - 1).collect::<Vec<_>>().into_iter().rev().collect();
    format!("…{tail}")
}

enum CardAction {
    None,
    Build,
    Extract,
    Remove,
}

fn kind_color(p: &theme::Palette, kind: TitleKind) -> Color32 {
    match kind {
        TitleKind::Base => p.ok,
        TitleKind::Update => p.info,
        TitleKind::Dlc | TitleKind::DlcUpdate => p.dlc,
    }
}

/// The "Extract…" button on a game card. Returns true when clicked.
fn extract_button(ui: &mut egui::Ui, busy: bool, has_base: bool) -> bool {
    let tip = if has_base { "Extract the game, with its update applied, to a folder" } else { "Needs the base game" };
    theme::secondary_button(ui, !busy && has_base, "Extract…").on_hover_text(tip).on_disabled_hover_text(tip).clicked()
}

fn game_card(
    ui: &mut egui::Ui,
    g: &mut GameView,
    busy: bool,
    out_dir: &Path,
    deltas: bool,
    titledb: Option<&TitleDb>,
    region_db: Option<&RegionDb>,
) -> CardAction {
    let p = theme::palette(ui);
    let mut action = CardAction::None;
    let id = egui::Id::new(("card", g.game.application_id));
    let hovered = ui.ctx().data(|d| d.get_temp::<bool>(id)).unwrap_or(false);
    let t = ui.ctx().animate_bool_with_time(id.with("h"), hovered, 0.12);
    let selected_t = ui.ctx().animate_bool_with_time(id.with("s"), g.selected, 0.12);
    let border = theme::lerp_color(p.border, p.border_strong, t);
    let frame = egui::Frame::new()
        .fill(p.card)
        .stroke(egui::Stroke::new(1.0, border))
        .corner_radius(14)
        .inner_margin(16)
        .shadow(egui::epaint::Shadow { offset: [0, 2], blur: 12, spread: 0, color: p.shadow.gamma_multiply(0.6) });

    let resp = frame.show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            check_circle(ui, &mut g.selected, !busy, 22.0).on_hover_text("Include when building all selected games");
            ui.add_space(2.0);
            let size = egui::vec2(84.0, 84.0);
            let alpha = 0.45 + 0.55 * selected_t;
            match &g.icon {
                Some(bytes) => {
                    ui.add(
                        egui::Image::from_bytes(
                            format!("bytes://icon/{:016x}.jpg", g.game.application_id),
                            bytes.clone(),
                        )
                        .fit_to_exact_size(size)
                        .corner_radius(12)
                        .tint(Color32::WHITE.gamma_multiply(alpha)),
                    );
                }
                None => {
                    let (r, _) = ui.allocate_exact_size(size, egui::Sense::hover());
                    ui.painter().rect_filled(r, 12.0, p.control);
                    ui.painter().text(
                        r.center(),
                        egui::Align2::CENTER_CENTER,
                        "🎮",
                        egui::FontId::proportional(30.0),
                        p.text_faint,
                    );
                }
            }
            ui.add_space(6.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 5.0;
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    ui.add(
                        egui::Label::new(RichText::new(&g.game.name).font(theme::semibold(18.0)).color(p.text))
                            .truncate(),
                    );
                });
                let mut sub = Vec::new();
                if !g.game.publisher.is_empty() {
                    sub.push(g.game.publisher.clone());
                }
                if let Some(v) = &g.game.display_version {
                    sub.push(format!("v{v}"));
                }
                sub.push(format!("{:016X}", g.game.application_id));
                ui.horizontal(|ui| {
                    ui.label(RichText::new(sub.join("  ·  ")).size(12.5).color(p.text_dim));
                    if let Some(rdb) = region_db {
                        region_badges(ui, &p, &rdb.for_game(&g.game));
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    let chosen = g.chosen();
                    let base = chosen.iter().any(|t| t.kind == TitleKind::Base);
                    let upd = chosen.iter().find(|t| t.kind == TitleKind::Update);
                    let dlc = chosen.iter().filter(|t| matches!(t.kind, TitleKind::Dlc | TitleKind::DlcUpdate)).count();
                    if base {
                        theme::pill(ui, "Base", p.ok);
                    } else {
                        theme::pill(ui, "No base", p.warn);
                    }
                    if let Some(u) = upd {
                        theme::pill(ui, format!("Update {}", u.version_label()), p.info)
                            .on_hover_text(format!("Internal version {}", u.version));
                    }
                    if dlc > 0 {
                        theme::pill(ui, format!("{dlc} DLC"), p.dlc);
                    }
                    if !g.game.superseded.is_empty() {
                        theme::pill(ui, format!("{} left out", g.game.superseded.len()), p.text_dim)
                            .on_hover_text("Older versions or duplicates that won't be included");
                    }
                    let size: u64 = chosen.iter().map(|t| t.size(deltas)).sum();
                    ui.add_space(4.0);
                    ui.label(RichText::new(format_size(size)).color(p.text_dim));
                });
                if let Some(db) = titledb {
                    update_check_pills(ui, &p, db, db.check(&g.game));
                }
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::icon_button(ui, !busy, "✕", "Remove from list").clicked() {
                    action = CardAction::Remove;
                }
                let can_build = !busy && !g.chosen().is_empty();
                let has_base = g.has_base();
                match &g.status {
                    Status::Done(kind, paths) => {
                        if let Some(path) = paths.first() {
                            if theme::secondary_button(ui, true, "Show in folder")
                                .on_hover_text(path.display().to_string())
                                .clicked()
                            {
                                reveal(path);
                            }
                        }
                        if extract_button(ui, busy, has_base) {
                            action = CardAction::Extract;
                        }
                        status_pill(ui, p.ok, kind.done());
                    }
                    Status::Building { kind, done, total } => {
                        let pct = *done as f32 / (*total).max(1) as f32 * 100.0;
                        status_pill(ui, p.accent, &format!("{} {pct:.0}%", kind.doing()));
                    }
                    Status::Queued => {
                        status_pill(ui, p.text_dim, "Queued");
                    }
                    Status::Failed(e) => {
                        if theme::secondary_button(ui, can_build, "Retry").clicked() {
                            action = CardAction::Build;
                        }
                        if extract_button(ui, busy, has_base) {
                            action = CardAction::Extract;
                        }
                        status_pill(ui, p.err, "Failed").on_hover_text(e);
                    }
                    Status::Ready => {
                        if theme::secondary_button(ui, can_build, "Build").clicked() {
                            action = CardAction::Build;
                        }
                        if extract_button(ui, busy, has_base) {
                            action = CardAction::Extract;
                        }
                    }
                }
            });
        });

        if let Status::Building { done, total, .. } = g.status {
            ui.add_space(10.0);
            let w = ui.available_width();
            theme::progress_bar(ui, id.with("bar"), done as f32 / total.max(1) as f32, w);
        }
        if let Status::Failed(e) = &g.status {
            ui.add_space(6.0);
            ui.label(RichText::new(format!("✖ {e}")).size(12.5).color(p.err));
        }
        for w in g.game.warnings() {
            ui.label(RichText::new(format!("⚠  {w}")).size(12.5).color(p.warn));
        }

        ui.add_space(10.0);
        let rect = ui.available_rect_before_wrap();
        ui.painter().hline(rect.x_range(), rect.top(), egui::Stroke::new(1.0, p.border));
        ui.add_space(8.0);

        let state_id = id.with(("contents", g.game.superseded.len()));
        let mut state = egui::collapsing_header::CollapsingState::load_with_default_open(
            ui.ctx(),
            state_id,
            !g.game.superseded.is_empty(),
        );
        ui.horizontal(|ui| {
            let open = state.openness(ui.ctx());
            let n = g.game.titles.len() + g.game.superseded.len();
            let arrow = if open > 0.5 { "⏷" } else { "⏵" };
            let label = format!("{arrow}  Contents  ·  {n} item{}", if n == 1 { "" } else { "s" });
            if theme::ghost_button(ui, true, RichText::new(label).color(p.text_dim)).clicked() {
                state.toggle(ui);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let out = out_dir.join(format!("{}.xci", g.file_stem()));
                ui.add(
                    egui::Label::new(
                        RichText::new(format!("→  {}", out.file_name().unwrap_or_default().to_string_lossy()))
                            .size(12.5)
                            .color(p.text_dim),
                    )
                    .truncate(),
                )
                .on_hover_text(out.display().to_string());
            });
        });
        state.show_body_unindented(ui, |ui| {
            ui.add_space(4.0);
            egui::Frame::new().fill(p.input).corner_radius(10).inner_margin(egui::Margin::symmetric(10, 6)).show(
                ui,
                |ui| {
                    ui.set_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 2.0;
                    for t in &g.game.titles {
                        let mut on = !g.excluded.contains(&t.title_id);
                        let changed = content_row(ui, &p, t, deltas, None, !on, |ui| {
                            check_circle(ui, &mut on, !busy, 18.0).changed()
                        });
                        if changed {
                            if on {
                                g.excluded.remove(&t.title_id);
                            } else {
                                g.excluded.insert(t.title_id);
                            }
                        }
                    }
                    for t in &g.game.superseded {
                        let dup = g.game.titles.iter().any(|k| k.title_id == t.title_id && k.version == t.version);
                        content_row(ui, &p, t, deltas, Some(if dup { "duplicate" } else { "older" }), true, |_| false);
                    }
                },
            );
        });
    });
    let hovered_now = ui.rect_contains_pointer(resp.response.rect);
    if hovered_now != hovered {
        ui.ctx().data_mut(|d| d.insert_temp(id, hovered_now));
    }
    action
}

/// Small flag + code badges for the regions a release is listed in.
fn region_badges(ui: &mut egui::Ui, p: &theme::Palette, regions: &[Region]) {
    if regions.is_empty() {
        return;
    }
    ui.add_space(4.0);
    for &r in regions {
        egui::Frame::new()
            .fill(p.control)
            .corner_radius(6)
            .inner_margin(egui::Margin { left: 4, right: 6, top: 2, bottom: 2 })
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                let (rect, _) = ui.allocate_exact_size(egui::vec2(18.0, 12.0), egui::Sense::hover());
                theme::paint_flag(ui.painter(), rect, r);
                ui.label(RichText::new(r.code()).font(theme::semibold(11.5)).color(p.text_dim));
            })
            .response
            .on_hover_text(format!("Listed in the {} eShop", r.name()));
    }
}

/// Result of the optional update / DLC check on a game card.
fn update_check_pills(ui: &mut egui::Ui, p: &theme::Palette, db: &TitleDb, report: Option<Report>) {
    let updated = format!("Title database updated {}.", format_age(db.fetched));
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        let Some(r) = report else {
            theme::pill(ui, "Not in title database", p.text_faint).on_hover_text(format!(
                "The title database doesn't list this game, so it can't be checked.\n{updated}"
            ));
            return;
        };
        if r.is_up_to_date() {
            theme::pill(ui, "Up to date", p.ok).on_hover_text(format!(
                "You have the newest update and every DLC the title database lists.\n{updated}"
            ));
            return;
        }
        if let Some((have, latest)) = r.newer_update {
            let have = match have {
                Some(v) => format!("Your newest update is v{v}."),
                None => "You don't have an update for this game.".into(),
            };
            theme::pill(ui, "Newer update available", p.warn).on_hover_text(format!(
                "The title database lists update v{latest} (update #{}). {have}\n{updated}",
                latest >> 16
            ));
        }
        if !r.missing_dlc.is_empty() {
            let n = r.missing_dlc.len();
            let mut list: Vec<String> = r.missing_dlc.iter().take(12).map(|id| format!("{id:016X}")).collect();
            if n > 12 {
                list.push(format!("and {} more", n - 12));
            }
            theme::pill(ui, format!("{n} DLC missing"), p.warn).on_hover_text(format!(
                "DLC the title database lists that none of your files contain:\n{}\n{updated}",
                list.join("\n")
            ));
        }
        if !r.outdated_dlc.is_empty() {
            let list: Vec<String> = r
                .outdated_dlc
                .iter()
                .map(|(id, have, latest)| format!("{id:016X}: v{have}, newest v{latest}"))
                .collect();
            theme::pill(ui, format!("{} DLC outdated", r.outdated_dlc.len()), p.warn)
                .on_hover_text(format!("{}\n{updated}", list.join("\n")));
        }
    });
}

/// One row of the contents table with fixed-width columns.
fn content_row(
    ui: &mut egui::Ui,
    p: &theme::Palette,
    t: &Title,
    deltas: bool,
    note: Option<&str>,
    faded: bool,
    lead: impl FnOnce(&mut egui::Ui) -> bool,
) -> bool {
    let strike = note.is_some();
    let text_c = if faded { p.text_faint } else { p.text };
    let dim_c = if faded { p.text_faint } else { p.text_dim };
    let rt = |s: String, c: Color32| {
        let r = RichText::new(s).color(c);
        if strike {
            r.strikethrough()
        } else {
            r
        }
    };
    let bg = ui.painter().add(egui::Shape::Noop);
    let mut changed = false;
    let row = ui.horizontal(|ui| {
        ui.set_min_height(32.0);
        ui.spacing_mut().item_spacing.x = 0.0;
        let cell = |ui: &mut egui::Ui, w: f32, add: &mut dyn FnMut(&mut egui::Ui)| {
            ui.allocate_ui_with_layout(egui::vec2(w, 28.0), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                ui.set_min_width(w);
                add(ui);
            });
        };
        let mut lead = Some(lead);
        cell(ui, 32.0, &mut |ui| {
            ui.add_space(4.0);
            if let Some(f) = lead.take() {
                changed = f(ui);
            }
        });
        let kc = if faded { p.text_faint } else { kind_color(p, t.kind) };
        cell(ui, 92.0, &mut |ui| {
            theme::pill(ui, t.kind.label(), kc);
        });
        cell(ui, 150.0, &mut |ui| {
            ui.label(rt(format!("{:016X}", t.title_id), dim_c).monospace());
        });
        cell(ui, 100.0, &mut |ui| {
            ui.label(rt(t.version_label(), text_c)).on_hover_text(format!("Internal version {}", t.version));
        });
        cell(ui, 92.0, &mut |ui| {
            ui.label(rt(format_size(t.size(deltas)), text_c));
        });
        cell(ui, 88.0, &mut |ui| {
            let fw = t.required_system_version.map(|r| format!("FW {}", format_rsv(r))).unwrap_or_default();
            ui.label(rt(fw, dim_c));
        });
        cell(ui, 90.0, &mut |ui| {
            if let Some(n) = note {
                theme::pill(ui, n, p.text_faint);
            }
        });
        let file = t.source.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        ui.add(egui::Label::new(rt(file, dim_c)).truncate()).on_hover_text(t.source.display().to_string());
    });
    let rect = row.response.rect.expand2(egui::vec2(4.0, 0.0));
    if ui.rect_contains_pointer(rect) {
        ui.painter().set(bg, egui::Shape::rect_filled(rect, 6.0, p.control.gamma_multiply(0.6)));
    }
    changed
}

/// Round checkbox.
fn check_circle(ui: &mut egui::Ui, on: &mut bool, enabled: bool, size: f32) -> egui::Response {
    let p = theme::palette(ui);
    let sense = if enabled { egui::Sense::click() } else { egui::Sense::hover() };
    let (rect, mut resp) = ui.allocate_exact_size(egui::vec2(size, size), sense);
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    let t = ui.ctx().animate_bool_with_time(resp.id, *on, 0.12);
    let painter = ui.painter();
    let c = rect.center();
    let r = size / 2.0 - 1.0;
    let ring = if resp.hovered() { p.text_dim } else { p.border_strong };
    painter.circle_stroke(c, r, egui::Stroke::new(1.5, theme::lerp_color(ring, p.accent, t)));
    if t > 0.0 {
        painter.circle_filled(c, r * t, p.accent);
        let s = size / 22.0;
        let pts = vec![c + egui::vec2(-5.0, 0.0) * s, c + egui::vec2(-1.5, 3.5) * s, c + egui::vec2(5.0, -4.0) * s];
        painter.add(egui::Shape::line(pts, egui::Stroke::new(2.0 * s, Color32::WHITE.gamma_multiply(t))));
    }
    if !enabled {
        return resp;
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn fmt_secs(s: f64) -> String {
    let s = s.round() as u64;
    if s >= 3600 {
        format!("{}h {:02}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m {:02}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

/// Opens the system file manager with `p` selected.
fn reveal(p: &Path) {
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("explorer").arg("/select,").arg(p).spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg("-R").arg(p).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    if let Some(dir) = p.parent() {
        let _ = std::process::Command::new("xdg-open").arg(dir).spawn();
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = &ui.ctx().clone();
        self.poll(ctx);
        if let Some(path) = &self.debug.screenshot {
            debug_screenshot(ctx, path);
        }
        if self.debug.auto_build && ctx.cumulative_frame_nr() == 40 && !self.busy() {
            self.start_build(ctx, None);
        }
        if self.debug.extract && !self.games.is_empty() && self.scan_rx.is_none() {
            self.debug.extract = false;
            let id = self.games[0].game.application_id;
            match self.debug.extract_to.take() {
                Some(dir) => {
                    let output = dir.join(self.games[0].extract_stem(false));
                    self.start_extract(ctx, id, output, ExtractOptions::default());
                }
                None => self.open_extract_dialog(id),
            }
        }

        // Drag & drop.
        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).collect());
        if !dropped.is_empty() {
            if self.job.is_some() {
                self.log("Can't add files while building. Wait for it to finish.", true);
            } else {
                self.add_paths(ctx, dropped);
            }
        }
        let hovering = ctx.input(|i| !i.raw.hovered_files.is_empty());
        let p = theme::palette(ui);

        egui::Panel::top("top")
            .frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::symmetric(18, 12)))
            .show(ui, |ui| self.header(ui));
        egui::Panel::bottom("bottom")
            .frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::symmetric(20, 14)))
            .show(ui, |ui| self.bottom_bar(ui));
        if self.show_log {
            egui::Panel::bottom("log")
                .resizable(true)
                .default_size(150.0)
                .frame(egui::Frame::new().fill(p.bg).inner_margin(egui::Margin::symmetric(20, 10)))
                .show(ui, |ui| self.log_panel(ui));
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(p.bg).inner_margin(egui::Margin { left: 20, right: 20, top: 18, bottom: 8 }))
            .show(ui, |ui| {
                if self.games.is_empty() && self.scan_rx.is_none() {
                    self.drop_zone(ui, hovering);
                } else {
                    self.game_list(ui);
                }
            });

        if self.show_settings {
            self.settings_modal(ctx);
        }
        if self.extract_dialog.is_some() {
            self.extract_modal(ctx);
        }

        if hovering && !self.games.is_empty() {
            let painter = ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new("drop")));
            let rect = ctx.content_rect();
            painter.rect_filled(rect, 0.0, p.bg.gamma_multiply(0.85));
            let inner = rect.shrink(18.0);
            painter.rect_filled(inner, 18.0, p.accent.gamma_multiply(0.08));
            theme::dashed_rect(&painter, inner, egui::Stroke::new(2.0, p.accent));
            painter.text(
                inner.center() - egui::vec2(0.0, 14.0),
                egui::Align2::CENTER_CENTER,
                "Drop to add",
                theme::semibold(28.0),
                p.text,
            );
            painter.text(
                inner.center() + egui::vec2(0.0, 20.0),
                egui::Align2::CENTER_CENTER,
                "Files are grouped by game automatically",
                egui::FontId::proportional(14.0),
                p.text_dim,
            );
        }
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        if self.debug.screenshot.is_some() {
            return; // debug runs mustn't change the user's saved settings
        }
        eframe::set_value(storage, eframe::APP_KEY, &self.settings);
    }

    /// Cancels a running build or extraction and gives it a moment to remove its partial output
    /// (and the temporary files of compressed input), which would otherwise be left on disk.
    fn on_exit(&mut self) {
        let Some(job) = self.job.take() else { return };
        job.cancel.store(true, Ordering::Relaxed);
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match job.rx.recv_timeout(left) {
                Ok(BuildMsg::AllDone) | Err(_) => break,
                Ok(_) => {}
            }
        }
    }
}

/// Saves a screenshot of the window to `path` after ~2 s and exits (see [`DebugHooks`]).
fn debug_screenshot(ctx: &egui::Context, path: &Path) {
    if ctx.cumulative_frame_nr() == 120 {
        ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));
    }
    let shot = ctx.input(|i| {
        i.raw.events.iter().find_map(|e| match e {
            egui::Event::Screenshot { image, .. } => Some(image.clone()),
            _ => None,
        })
    });
    if let Some(image) = shot {
        let [w, h] = image.size;
        let raw: Vec<u8> = image.pixels.iter().flat_map(|p| p.to_array()).collect();
        if let Some(img) = image::RgbaImage::from_raw(w as u32, h as u32, raw) {
            let _ = img.save(path);
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }
    ctx.request_repaint();
}
