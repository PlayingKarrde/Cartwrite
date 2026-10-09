//! Background threads for scanning inputs and building XCIs.
//!
//! Each file / job runs under `catch_unwind`, so a parser panic on a corrupt file is
//! reported as an error instead of killing the thread and leaving the UI waiting forever.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::Instant;

use cartwrite_core::build::{build_xci, BuildOptions, Progress};
use cartwrite_core::scan::{collect_files, scan_file, Title};
use cartwrite_core::titledb::{self, TitleDb};
use cartwrite_core::{Error, Keys};

pub enum ScanMsg {
    File(PathBuf, Result<Vec<Title>, String>),
    Done,
}

pub fn spawn_scan(ctx: eframe::egui::Context, keys: Arc<Keys>, paths: Vec<PathBuf>) -> Receiver<ScanMsg> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        for f in collect_files(&paths) {
            let r = guarded(|| scan_file(&f, &keys).map_err(|e| e.to_string()));
            if tx.send(ScanMsg::File(f, r)).is_err() {
                return;
            }
            ctx.request_repaint();
        }
        let _ = tx.send(ScanMsg::Done);
        ctx.request_repaint();
    });
    rx
}

/// Result of loading the title database: what's available, and the refresh error if any.
pub type TitleDbResult = (Option<TitleDb>, Option<String>);

/// Loads the title database in the background (cache first, download if stale or forced).
pub fn spawn_titledb(ctx: eframe::egui::Context, source: String, force: bool) -> Receiver<TitleDbResult> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let result: Result<TitleDbResult, String> = guarded(|| {
            let (db, err) = titledb::load(&source, force);
            Ok((db, err.map(|e| e.to_string())))
        });
        let _ = tx.send(result.unwrap_or_else(|e| (None, Some(e))));
        ctx.request_repaint();
    });
    rx
}

pub struct BuildJob {
    pub application_id: u64,
    pub titles: Vec<Title>,
    pub output: PathBuf,
    /// Source XCIs to delete once this job succeeds.
    pub delete_after: Vec<PathBuf>,
}

pub enum BuildMsg {
    Started(u64),
    Progress(u64, Progress),
    Finished(u64, Result<Vec<PathBuf>, String>),
    Cancelled(u64),
    AllDone,
}

pub fn spawn_build(
    ctx: eframe::egui::Context,
    keys: Arc<Keys>,
    jobs: Vec<BuildJob>,
    opts: BuildOptions,
    cancel: Arc<AtomicBool>,
) -> Receiver<BuildMsg> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        for job in jobs {
            let id = job.application_id;
            let _ = tx.send(BuildMsg::Started(id));
            let refs: Vec<&Title> = job.titles.iter().collect();
            let mut last = Instant::now();
            let result = guarded(|| {
                build_xci(&keys, &refs, &job.output, &opts, &cancel, &mut |p| {
                    let throttle = matches!(p, Progress::Bytes { done, total } if done != total);
                    if throttle && last.elapsed().as_millis() < 100 {
                        return;
                    }
                    last = Instant::now();
                    let _ = tx.send(BuildMsg::Progress(id, p));
                    ctx.request_repaint();
                })
            });
            let msg = match result {
                Ok(written) => {
                    for p in &job.delete_after {
                        if !written.contains(p) {
                            let _ = std::fs::remove_file(p);
                        }
                    }
                    BuildMsg::Finished(id, Ok(written))
                }
                Err(Error::Cancelled) => BuildMsg::Cancelled(id),
                Err(e) => BuildMsg::Finished(id, Err(e.to_string())),
            };
            let cancelled = matches!(msg, BuildMsg::Cancelled(_));
            let _ = tx.send(msg);
            ctx.request_repaint();
            if cancelled {
                break;
            }
        }
        let _ = tx.send(BuildMsg::AllDone);
        ctx.request_repaint();
    });
    rx
}

/// Runs `f`, turning a panic into an error value.
fn guarded<T, E: FromPanic>(f: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(panic) => {
            let msg = panic
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".into());
            Err(E::from_panic(msg))
        }
    }
}

trait FromPanic {
    fn from_panic(msg: String) -> Self;
}

impl FromPanic for String {
    fn from_panic(msg: String) -> Self {
        format!("internal error while reading this file: {msg}")
    }
}

impl FromPanic for Error {
    fn from_panic(msg: String) -> Self {
        Error::Unsupported(format!("internal error while building: {msg}"))
    }
}
