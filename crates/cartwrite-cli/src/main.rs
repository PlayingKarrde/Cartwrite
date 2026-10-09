//! Command-line front end, mainly for scripting and testing.
//!
//!   cartwrite-cli info  <files/folders...>
//!   cartwrite-cli check [--titledb URL|FILE] [--refresh] <files/folders...>
//!   cartwrite-cli build [-o DIR] [--no-rsv] [--fat32] [--deltas] [--keys FILE] <files/folders...>

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use cartwrite_core::build::{build_xci, BuildOptions, Progress};
use cartwrite_core::plan::{group, output_stem};
use cartwrite_core::rsv::format_rsv;
use cartwrite_core::scan::{collect_files, scan_file, Title};
use cartwrite_core::titledb::{self, Report, DEFAULT_SOURCE};
use cartwrite_core::util::{format_age as age, format_size};
use cartwrite_core::Keys;

const USAGE: &str = "usage: cartwrite-cli info <files...>
       cartwrite-cli check [--titledb URL|FILE] [--refresh] <files...>
       cartwrite-cli build [-o DIR] [--no-rsv] [--fat32] [--deltas] [--keys FILE] <files...>";

fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

/// Returns `Ok(false)` if some games failed to build.
fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let mut out_dir: Option<PathBuf> = None;
    let mut keys_path: Option<PathBuf> = None;
    let mut opts = BuildOptions::default();
    let mut titledb_source = DEFAULT_SOURCE.to_string();
    let mut refresh = false;
    let mut inputs = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "-o" => out_dir = Some(args.next().ok_or("-o needs a directory")?.into()),
            "--keys" => keys_path = Some(args.next().ok_or("--keys needs a file")?.into()),
            "--no-rsv" => opts.patch_rsv = false,
            "--fat32" => opts.split_fat32 = true,
            "--deltas" => opts.include_deltas = true,
            "--titledb" => titledb_source = args.next().ok_or("--titledb needs a URL or file")?,
            "--refresh" => refresh = true,
            flag if flag.starts_with('-') => return Err(format!("unknown option {flag}\n{USAGE}").into()),
            _ => inputs.push(PathBuf::from(a)),
        }
    }
    if !matches!(cmd.as_str(), "info" | "check" | "build") || inputs.is_empty() {
        eprintln!("{USAGE}");
        std::process::exit(2);
    }

    let keys_path = keys_path.or_else(Keys::find_default).ok_or("prod.keys not found (use --keys)")?;
    let keys = Keys::load(&keys_path)?;

    let mut titles = Vec::new();
    for f in collect_files(&inputs) {
        match scan_file(&f, &keys) {
            Ok(t) => titles.extend(t),
            Err(e) => eprintln!("skipping {}: {e}", f.display()),
        }
    }
    let games = group(titles);

    let db = if cmd == "check" {
        let (db, err) = titledb::load(&titledb_source, refresh);
        match (&db, err) {
            (Some(db), Some(e)) => eprintln!(
                "warning: couldn't refresh the title database ({e}); using the cached copy from {}",
                age(db.fetched)
            ),
            (None, Some(e)) => return Err(format!("couldn't get the title database from {titledb_source}: {e}").into()),
            _ => {}
        }
        let db = db.ok_or("no title database")?;
        println!("Title database: {} titles, updated {} ({})", db.len(), age(db.fetched), db.source);
        Some(db)
    } else {
        None
    };

    for g in &games {
        println!("\n{} [{:016X}] {}", g.name, g.application_id, g.display_version.as_deref().unwrap_or(""));
        for t in &g.titles {
            print_title("  +", t);
        }
        for t in &g.superseded {
            print_title("  - (superseded)", t);
        }
        for w in g.warnings() {
            println!("  ! {w}");
        }
        if let Some(db) = &db {
            match db.check(g) {
                None => println!("  ? not in the title database"),
                Some(r) => print_report(&r),
            }
        }
    }

    let mut all_ok = true;
    if cmd == "build" {
        let cancel = AtomicBool::new(false);
        for g in &games {
            let sel: Vec<&Title> = g.titles.iter().collect();
            let dir = out_dir.clone().unwrap_or_else(|| PathBuf::from("output"));
            let path = dir.join(format!("{}.xci", output_stem(&g.name, g.application_id, &sel)));
            println!("\nBuilding {}", path.display());
            let start = Instant::now();
            let mut last = Instant::now();
            let result = build_xci(&keys, &sel, &path, &opts, &cancel, &mut |p| match p {
                Progress::Log(m) => println!("  {m}"),
                Progress::Bytes { done, total } => {
                    if last.elapsed().as_millis() > 500 || done == total {
                        last = Instant::now();
                        eprint!(
                            "\r  {:5.1}%  {} / {}   ",
                            done as f64 * 100.0 / total as f64,
                            format_size(done),
                            format_size(total)
                        );
                    }
                }
            });
            eprintln!();
            match result {
                Ok(written) => println!("  done in {:.1}s: {:?}", start.elapsed().as_secs_f64(), written),
                Err(e) => {
                    eprintln!("  failed: {e}");
                    all_ok = false;
                }
            }
        }
    }
    Ok(all_ok)
}

fn print_report(r: &Report) {
    if r.is_up_to_date() {
        println!("  = up to date");
    }
    if let Some((have, latest)) = r.newer_update {
        match have {
            Some(v) => println!("  > newer update available: v{latest} (you have v{v})"),
            None => println!("  > update available: v{latest} (you have none)"),
        }
    }
    for id in &r.missing_dlc {
        println!("  > missing DLC {id:016X}");
    }
    for (id, have, latest) in &r.outdated_dlc {
        println!("  > newer DLC {id:016X}: v{latest} (you have v{have})");
    }
}

fn print_title(prefix: &str, t: &Title) {
    println!(
        "{prefix} {:<10} {:016X} {:<16} {:>10}  RSV {:<8} kg {:<2} {}",
        t.kind.label(),
        t.title_id,
        t.version_label(),
        format_size(t.size(false)),
        t.required_system_version.map(format_rsv).unwrap_or_else(|| "-".into()),
        t.key_generation(),
        t.source.file_name().map(|n| n.to_string_lossy()).unwrap_or_default(),
    );
}
