//! Extracts a game's files to a folder:
//!
//! ```text
//! <out>/exefs/          main, main.npdm, rtld, sdk, subsdk*
//! <out>/romfs/          game data
//! <out>/logo/           boot logo (when present)
//! <out>/control/        control.nacp and icons
//! <out>/dlc/<id>/romfs/ each DLC's data (optional)
//! ```
//!
//! Files are written into `<out>.partial` and the folder is renamed once everything is done,
//! so a cancelled or failed extraction never leaves a half-written game behind.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::bktr::{AesCtrExStorage, IndirectStorage, PatchInfo};
use crate::build::Progress;
use crate::cnmt;
use crate::compressed::{CompressedStorage, CompressionInfo};
use crate::container::{self, Entry};
use crate::crypto::Key128;
use crate::error::{fmt_err, Error, Result};
use crate::keys::Keys;
use crate::nca::{
    self, FileNca, NcaHeader, NcaSource, CRYPT_BKTR, FS_PFS0, FS_ROMFS, HASH_IVFC, HASH_SHA256, HEADER_SIZE,
};
use crate::ncz::MemNcz;
use crate::romfs::{self, RomfsTree};
use crate::scan::{NcaRef, Title, TitleKind};
use crate::storage::{NcaSection, RawSection, Storage, SubStorage};
use crate::util::read_vec_at;

const COPY_BUF: usize = 8 << 20;
/// NCZ content up to this size is decompressed in memory (control data, small DLC).
const NCZ_MEMORY_LIMIT: u64 = 256 << 20;

#[derive(Clone, Debug, Default)]
pub struct ExtractOptions {
    /// Also extract each DLC's data into `dlc/<title id>/romfs`.
    pub include_dlc: bool,
    /// Replace `out` if it already holds an earlier extraction.
    pub overwrite: bool,
}

/// One section of one NCA.
#[derive(Clone, Copy)]
struct SectionRef<'a> {
    title: &'a Title,
    nca: &'a NcaRef,
    section: usize,
}

/// Where a part's files are read from.
#[derive(Clone, Copy)]
enum Source<'a> {
    /// One NCA section, read as it is.
    Plain(SectionRef<'a>),
    /// An update's RomFS section applied to the base game's section with the same index
    /// (`None` if the base has no such section, so everything comes from the update).
    Patched { base: Option<SectionRef<'a>>, update: SectionRef<'a> },
}

impl Source<'_> {
    fn label(&self) -> String {
        match self {
            Self::Plain(r) => r.nca.out_name.clone(),
            Self::Patched { base: Some(b), update } => format!("{} + update {}", b.nca.out_name, update.nca.out_name),
            Self::Patched { base: None, update } => update.nca.out_name.clone(),
        }
    }
}

/// One section to extract and where its files go (relative to the output folder).
struct Part<'a> {
    source: Source<'a>,
    /// [`FS_PFS0`] or [`FS_ROMFS`].
    fs_type: u8,
    dest: PathBuf,
}

/// What a part contains, found in the listing pass.
enum Listing {
    Pfs0(Vec<Entry>),
    Romfs(RomfsTree),
}

impl Listing {
    fn bytes(&self) -> u64 {
        match self {
            Self::Pfs0(entries) => entries.iter().map(|e| e.size).sum(),
            Self::Romfs(tree) => tree.files.iter().map(|f| f.size).sum(),
        }
    }
}

/// Extracts the selected titles of one game into the folder `out`. Returns `out`.
pub fn extract_game(
    keys: &Keys,
    titles: &[&Title],
    out: &Path,
    opts: &ExtractOptions,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(Progress),
) -> Result<PathBuf> {
    let parts = plan_parts(keys, titles, opts)?;
    if out.exists() {
        if !opts.overwrite {
            return Err(Error::Unsupported(format!("{} already exists", out.display())));
        }
        if !looks_like_extraction(out) {
            return Err(Error::Unsupported(format!(
                "{} already exists and doesn't look like an extracted game, so it won't be replaced",
                out.display()
            )));
        }
    }
    let partial = partial_path(out);
    if partial.exists() {
        fs::remove_dir_all(&partial)?;
    }

    let result = (|| {
        let mut listings = Vec::with_capacity(parts.len());
        for p in &parts {
            check_cancel(cancel)?;
            listings.push(with_part_data(keys, &p.source, |s| list(s, p.fs_type))?);
        }
        let total: u64 = listings.iter().map(Listing::bytes).sum();
        let mut done = 0u64;
        progress(Progress::Bytes { done, total });

        let mut buf = vec![0u8; COPY_BUF];
        for (p, listing) in parts.iter().zip(&listings) {
            progress(Progress::Log(format!("Extracting {} ({})", p.dest.display(), p.source.label())));
            let dest = partial.join(&p.dest);
            fs::create_dir_all(&dest)?;
            with_part_data(keys, &p.source, |s| {
                let mut copy = |rel: &Path, offset: u64, size: u64| -> Result<()> {
                    let path = dest.join(rel);
                    let mut f = File::create(&path).map_err(|e| Error::File { path: path.clone(), source: e })?;
                    let mut pos = 0u64;
                    while pos < size {
                        check_cancel(cancel)?;
                        let n = ((size - pos) as usize).min(buf.len());
                        s.read(offset + pos, &mut buf[..n])?;
                        f.write_all(&buf[..n]).map_err(|e| Error::File { path: path.clone(), source: e })?;
                        pos += n as u64;
                        done += n as u64;
                        progress(Progress::Bytes { done, total });
                    }
                    Ok(())
                };
                match listing {
                    Listing::Pfs0(entries) => {
                        for e in entries {
                            copy(Path::new(&e.name), e.offset, e.size)?;
                        }
                    }
                    Listing::Romfs(tree) => {
                        for d in &tree.dirs {
                            fs::create_dir_all(dest.join(d.iter().collect::<PathBuf>()))?;
                        }
                        for f in &tree.files {
                            copy(&f.path.iter().collect::<PathBuf>(), f.offset, f.size)?;
                        }
                    }
                }
                Ok(())
            })?;
        }
        Ok(())
    })();

    if let Err(e) = result {
        let _ = fs::remove_dir_all(&partial);
        return Err(e);
    }
    if out.exists() {
        fs::remove_dir_all(out)?;
    }
    fs::rename(&partial, out)?;
    Ok(out.to_path_buf())
}

/// Works out which NCA sections go where, checking up front for anything unsupported so
/// nothing is written for a game that can't be extracted.
fn plan_parts<'a>(keys: &Keys, titles: &[&'a Title], opts: &ExtractOptions) -> Result<Vec<Part<'a>>> {
    let Some(base) = titles.iter().copied().find(|t| t.kind == TitleKind::Base) else {
        return Err(Error::Unsupported("no base game selected, so there's nothing to extract".into()));
    };
    let update = titles.iter().copied().find(|t| t.kind == TitleKind::Update);
    let program = single_program(base)?;
    let base_header = OpenNca::header(keys, program)?;
    let plain = |title, nca, section| Source::Plain(SectionRef { title, nca, section });

    let mut parts: Vec<Part> = Vec::new();
    if let Some(update) = update {
        // The update's program replaces the base's exefs (and logo), and patches its RomFS.
        let up_program = single_program(update)?;
        let up_header = OpenNca::header(keys, up_program)?;
        for s in up_header.sections() {
            let fs_type = up_header.section_fs_type(s.index);
            let dest = section_dest(fs_type, s.index, up_program)?;
            check_section(&up_header, s.index, up_program)?;
            let up_ref = SectionRef { title: update, nca: up_program, section: s.index };
            let source = if fs_type == FS_ROMFS && is_patch_section(&up_header, s.index) {
                let base_ref = base_header
                    .section(s.index)
                    .filter(|_| base_header.section_fs_type(s.index) == FS_ROMFS)
                    .map(|_| SectionRef { title: base, nca: program, section: s.index });
                if base_ref.is_some() {
                    check_section(&base_header, s.index, program)?;
                }
                Source::Patched { base: base_ref, update: up_ref }
            } else {
                Source::Plain(up_ref)
            };
            parts.push(Part { source, fs_type, dest: dest.into() });
        }
    }
    // Base sections the update didn't provide (all of them when there's no update).
    for s in base_header.sections() {
        let fs_type = base_header.section_fs_type(s.index);
        let dest = section_dest(fs_type, s.index, program)?;
        if parts.iter().any(|p| p.dest == Path::new(dest)) {
            continue;
        }
        check_section(&base_header, s.index, program)?;
        parts.push(Part { source: plain(base, program, s.index), fs_type, dest: dest.into() });
    }

    let control_owner =
        update.filter(|u| u.contents.iter().any(|n| n.content_type == cnmt::CT_CONTROL)).unwrap_or(base);
    if let Some(control) = control_owner.contents.iter().find(|n| n.content_type == cnmt::CT_CONTROL) {
        let header = OpenNca::header(keys, control)?;
        check_section(&header, 0, control)?;
        parts.push(Part { source: plain(control_owner, control, 0), fs_type: FS_ROMFS, dest: "control".into() });
    }

    if opts.include_dlc {
        if titles.iter().any(|t| t.kind == TitleKind::DlcUpdate) {
            return Err(Error::Unsupported("DLC updates aren't supported when extracting yet".into()));
        }
        for dlc in titles.iter().filter(|t| t.kind == TitleKind::Dlc) {
            let Some(data) = dlc.contents.iter().find(|n| n.content_type == cnmt::CT_DATA) else {
                return fmt_err(format!("DLC {:016X} has no data content", dlc.title_id));
            };
            let header = OpenNca::header(keys, data)?;
            check_section(&header, 0, data)?;
            let dest = Path::new("dlc").join(format!("{:016X}", dlc.title_id)).join("romfs");
            parts.push(Part { source: plain(dlc, data, 0), fs_type: FS_ROMFS, dest });
        }
    }
    Ok(parts)
}

fn single_program(title: &Title) -> Result<&NcaRef> {
    let programs: Vec<&NcaRef> = title.contents.iter().filter(|n| n.content_type == cnmt::CT_PROGRAM).collect();
    match programs[..] {
        [p] => Ok(p),
        [] => Err(Error::Unsupported(format!(
            "{}: {} has no program content",
            title.source.display(),
            title.kind.label().to_lowercase()
        ))),
        _ => Err(Error::Unsupported("games with several programs aren't supported yet".into())),
    }
}

/// Output folder for a program NCA section.
fn section_dest(fs_type: u8, index: usize, nca: &NcaRef) -> Result<&'static str> {
    match (fs_type, index) {
        (FS_PFS0, 0) => Ok("exefs"),
        (FS_PFS0, _) => Ok("logo"),
        (FS_ROMFS, _) => Ok("romfs"),
        (t, i) => fmt_err(format!("{}: section {i} has unknown filesystem type {t}", nca.out_name)),
    }
}

/// True for an update section that only holds changes against the base game.
fn is_patch_section(header: &NcaHeader, i: usize) -> bool {
    header.section_crypto(i) == CRYPT_BKTR && PatchInfo::parse(header, i).has_indirect_table()
}

/// Runs `f` on a part's data: the PFS0 or RomFS image, patched with the update if needed.
fn with_part_data<T>(keys: &Keys, source: &Source, f: impl FnOnce(&mut dyn Storage) -> Result<T>) -> Result<T> {
    let (base, update) = match *source {
        Source::Plain(r) => return OpenNca::open(keys, r.title, r.nca)?.with_data(r.section, f),
        Source::Patched { base, update } => (base, update),
    };
    let mut up = OpenNca::open(keys, update.title, update.nca)?;
    let mut base_open = base.map(|b| OpenNca::open(keys, b.title, b.nca)).transpose()?;

    let mut empty = Vec::new();
    let mut base_section;
    let original: &mut dyn Storage = match (&mut base_open, base) {
        (Some(o), Some(b)) => {
            base_section = NcaSection::new(&mut *o.src, &o.header, o.key, b.section)?;
            &mut base_section
        }
        _ => &mut empty,
    };
    let raw = RawSection::new(&mut *up.src, &up.header, up.key, update.section)?;
    let mut ex = AesCtrExStorage::new(raw, &up.header, up.key, update.section)?;
    let mut patched = IndirectStorage::new(original, &mut ex, &up.header, update.section)?;
    // The update's own IVFC header describes the patched section.
    let (offset, size) = nca::ivfc_data_level(&up.header, update.section)?;
    let mut data = SubStorage::new(&mut patched, offset, size)?;
    decompressed(&mut data, &up.header, update.section, f)
}

/// Runs `f` on a section's data level, decompressed if the section uses compressed storage.
/// For an update, the update's header decides (the base is read below this layer).
fn decompressed<T>(
    level: &mut dyn Storage,
    header: &NcaHeader,
    section: usize,
    f: impl FnOnce(&mut dyn Storage) -> Result<T>,
) -> Result<T> {
    match CompressionInfo::parse(header, section) {
        Some(info) => f(&mut CompressedStorage::new(level, &info)?),
        None => f(level),
    }
}

fn check_section(header: &NcaHeader, i: usize, n: &NcaRef) -> Result<()> {
    if header.section(i).is_none() {
        return fmt_err(format!("{} has no section {i}", n.out_name));
    }
    if let Some(layer) = header.unsupported_layer(i) {
        return Err(Error::Unsupported(format!("{} uses {layer}, which extracting doesn't support yet", n.out_name)));
    }
    if n.is_ncz && n.nca_size > NCZ_MEMORY_LIMIT {
        return Err(Error::Unsupported("extracting from NSZ/XCZ files isn't supported yet".into()));
    }
    Ok(())
}

/// Lists the files in a section's data region.
fn list(s: &mut dyn Storage, fs_type: u8) -> Result<Listing> {
    if fs_type == FS_ROMFS {
        return Ok(Listing::Romfs(romfs::read_tree(s)?));
    }
    let entries = container::parse_pfs0_storage(s)?;
    for e in &entries {
        if e.name.is_empty() || e.name == "." || e.name == ".." || e.name.contains(['/', '\\', '\0']) {
            return fmt_err(format!("bad file name {:?} in a PFS0 section", e.name));
        }
    }
    Ok(Listing::Pfs0(entries))
}

/// An NCA opened for reading, with its section key.
struct OpenNca {
    header: NcaHeader,
    key: Key128,
    src: Box<dyn NcaSource>,
}

impl OpenNca {
    fn header(keys: &Keys, n: &NcaRef) -> Result<NcaHeader> {
        let mut f = open_source(&n.source)?;
        NcaHeader::decrypt(&read_vec_at(&mut f, n.offset, HEADER_SIZE)?, keys)
    }

    fn open(keys: &Keys, title: &Title, n: &NcaRef) -> Result<Self> {
        let mut file = open_source(&n.source)?;
        let header = NcaHeader::decrypt(&read_vec_at(&mut file, n.offset, HEADER_SIZE)?, keys)?;
        let key = header.section_key(keys, title.title_key(keys, &header)?.as_ref())?;
        let src: Box<dyn NcaSource> = if n.is_ncz {
            Box::new(MemNcz::load(&mut file, n.offset, n.stored_size, n.nca_size, NCZ_MEMORY_LIMIT)?)
        } else {
            Box::new(OwnedFileNca { file, base: n.offset })
        };
        Ok(Self { header, key, src })
    }

    /// Runs `f` on the data region of section `i`: the PFS0 inside a SHA-256 hashed section,
    /// or the RomFS image inside an IVFC one.
    fn with_data<T>(&mut self, i: usize, f: impl FnOnce(&mut dyn Storage) -> Result<T>) -> Result<T> {
        let (offset, size) = match self.header.section_hash_type(i) {
            HASH_SHA256 => {
                let l = nca::sha256_layout(&self.header, i)?;
                (l.data_offset, l.data_size)
            }
            HASH_IVFC => nca::ivfc_data_level(&self.header, i)?,
            t => return Err(Error::Unsupported(format!("section {i} uses hash type {t}, which isn't supported"))),
        };
        let mut section = NcaSection::new(&mut *self.src, &self.header, self.key, i)?;
        let mut data = SubStorage::new(&mut section, offset, size)?;
        decompressed(&mut data, &self.header, i, f)
    }
}

/// `FileNca` that owns its file, so an `OpenNca` can outlive the call that opened it.
struct OwnedFileNca {
    file: File,
    base: u64,
}

impl NcaSource for OwnedFileNca {
    fn read_plain(&mut self, header: &NcaHeader, key: &Key128, offset: u64, buf: &mut [u8]) -> Result<()> {
        FileNca { file: &mut self.file, base: self.base }.read_plain(header, key, offset, buf)
    }

    fn read_raw(&mut self, header: &NcaHeader, key: &Key128, offset: u64, buf: &mut [u8]) -> Result<()> {
        FileNca { file: &mut self.file, base: self.base }.read_raw(header, key, offset, buf)
    }
}

fn open_source(path: &Path) -> Result<File> {
    File::open(path).map_err(|e| Error::File { path: path.to_path_buf(), source: e })
}

fn partial_path(out: &Path) -> PathBuf {
    let mut name = out.file_name().unwrap_or_default().to_os_string();
    name.push(".partial");
    out.with_file_name(name)
}

/// True if `dir` holds the folders an earlier extraction would have made, so replacing it
/// can't wipe an unrelated folder the user pointed at by mistake.
fn looks_like_extraction(dir: &Path) -> bool {
    ["exefs", "romfs", "control"].iter().any(|d| dir.join(d).is_dir())
}

fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::nca::NcaContentType;
    use crate::testutil::{
        build_nacp, build_pfs0, pattern, BuiltNca, Compress, CompressedLevel, ImageBuilder, MetaBuilder, NcaBuilder,
        NspBuilder, PatchSection, Section, TempDir, TestKeys, CMP_LZ4, CMP_NONE, CMP_ZEROS,
    };
    use crate::util::u64le;
    use crate::{plan, scan};

    #[test]
    fn partial_folder_sits_next_to_the_output() {
        let out = Path::new("games").join("Game [0100000000010000][v1.0.0]");
        assert_eq!(partial_path(&out), Path::new("games").join("Game [0100000000010000][v1.0.0].partial"));
    }

    /// `(name, data)` pairs as `build_pfs0` takes them.
    fn as_refs<'a>(files: &'a [(&'a str, Vec<u8>)]) -> Vec<(&'a str, &'a [u8])> {
        files.iter().map(|(name, data)| (*name, data.as_slice())).collect()
    }

    /// Everything under `root`: files by path relative to it ('/'-separated), and directories.
    fn snapshot(root: &Path) -> (BTreeMap<String, Vec<u8>>, BTreeSet<String>) {
        fn walk(dir: &Path, prefix: &str, files: &mut BTreeMap<String, Vec<u8>>, dirs: &mut BTreeSet<String>) {
            for entry in fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let rel = format!("{prefix}{}", entry.file_name().to_string_lossy());
                if entry.file_type().unwrap().is_dir() {
                    dirs.insert(rel.clone());
                    walk(&entry.path(), &format!("{rel}/"), files, dirs);
                } else {
                    files.insert(rel, fs::read(entry.path()).unwrap());
                }
            }
        }
        let (mut files, mut dirs) = (BTreeMap::new(), BTreeSet::new());
        walk(root, "", &mut files, &mut dirs);
        (files, dirs)
    }

    /// Fails with a short message (not a dump of megabytes) if the two differ.
    fn assert_same_bytes(what: &str, got: &[u8], want: &[u8]) {
        if got != want {
            let first = got.iter().zip(want).position(|(a, b)| a != b);
            panic!("{what}: got {} bytes, want {}; first difference at {first:?}", got.len(), want.len());
        }
    }

    fn assert_extraction(out: &Path, files: &BTreeMap<String, Vec<u8>>, dirs: &BTreeSet<String>) {
        let (got_files, got_dirs) = snapshot(out);
        assert_eq!(got_dirs, *dirs, "directories under {}", out.display());
        assert_eq!(got_files.keys().collect::<Vec<_>>(), files.keys().collect::<Vec<_>>(), "files");
        for (path, want) in files {
            assert_same_bytes(path, &got_files[path], want);
        }
    }

    /// Builds a small encrypted base-game NSP with made-up keys, then scans, groups and extracts it.
    #[test]
    fn extract_base_game_end_to_end() {
        const TITLE_ID: u64 = 0x0100_0000_0001_0000;
        const CONTROL_KEY: Key128 =
            [0x42, 0xE1, 0x07, 0xBA, 0x93, 0x5D, 0x28, 0xFC, 0x71, 0x0E, 0xC4, 0x36, 0xA9, 0x8D, 0x1F, 0x60];

        let tmp = TempDir::new("extract");
        let keys = TestKeys::keys(&tmp.path().join("keys"));

        // What the game holds. Odd sizes put files at unaligned offsets inside their sections.
        let exefs = [("main", pattern(300, 1)), ("main.npdm", pattern(77, 2))];
        let logo = [("NintendoLogo.png", pattern(1013, 3))];
        let big = pattern(9 * 1024 * 1024 + 12_345, 4); // more than one COPY_BUF chunk
        assert!(big.len() > COPY_BUF);
        let romfs = [
            ("top.txt", b"a file in the root".to_vec()),
            ("data/big.bin", big),
            ("data/sub/nested.txt", b"nested".to_vec()),
            ("data/sub/deeper/leaf.bin", pattern(5000, 5)),
            ("data/zero.dat", Vec::new()),
        ];
        let empty_dirs = ["empty", "data/empty_sub"];
        let nacp = build_nacp("Test Game", "Test Publisher", "1.0.0");
        let icon = pattern(2048, 6);
        let control = [("control.nacp", nacp), ("icon_AmericanEnglish.dat", icon.clone())];

        let mut romfs_image = ImageBuilder::new();
        for (path, data) in &romfs {
            romfs_image.file(path, data);
        }
        for dir in empty_dirs {
            romfs_image.dir(dir);
        }
        let mut control_image = ImageBuilder::new();
        for (path, data) in &control {
            control_image.file(path, data);
        }

        let program = NcaBuilder::new(NcaContentType::Program, TITLE_ID)
            .section(Section::pfs0(&as_refs(&exefs)))
            .section(Section::romfs(romfs_image.build()))
            .section(Section::pfs0(&as_refs(&logo)))
            .build(&keys);
        let control_nca = NcaBuilder::new(NcaContentType::Control, TITLE_ID)
            .section_key(CONTROL_KEY)
            .section(Section::romfs(control_image.build()))
            .build(&keys);
        let meta = MetaBuilder::application(TITLE_ID, 0, 0x0001_0000)
            .content(&program, cnmt::CT_PROGRAM)
            .content(&control_nca, cnmt::CT_CONTROL)
            .build(&keys);
        let nsp = tmp.path().join("in").join("Test Game.nsp");
        NspBuilder::new().nca(&program).nca(&control_nca).nca(&meta).write(&nsp);

        // Scan and group.
        let titles = scan::scan_file(&nsp, &keys).expect("scanning the NSP");
        assert_eq!(titles.len(), 1);
        let title = &titles[0];
        assert_eq!(title.kind, TitleKind::Base);
        assert_eq!((title.title_id, title.application_id, title.version), (TITLE_ID, TITLE_ID, 0));
        assert_eq!(title.required_system_version, Some(0x0001_0000));
        assert_eq!(title.contents.len(), 2);
        assert!(title.source_complete);
        assert!(title.warnings.is_empty(), "{:?}", title.warnings);
        assert_eq!(title.nacp.as_ref().map(|n| n.title.as_str()), Some("Test Game"));
        assert_eq!(title.icon.as_deref(), Some(&icon));
        let games = plan::group(titles);
        assert_eq!(games.len(), 1);
        let game = &games[0];
        assert_eq!(game.name, "Test Game");
        assert!(game.warnings().is_empty(), "{:?}", game.warnings());
        let selected: Vec<&Title> = game.titles.iter().collect();

        // What extraction must produce.
        let mut files = BTreeMap::new();
        for (prefix, group) in
            [("exefs", &exefs[..]), ("logo", &logo[..]), ("romfs", &romfs[..]), ("control", &control[..])]
        {
            for (path, data) in group {
                files.insert(format!("{prefix}/{path}"), data.clone());
            }
        }
        let dirs: BTreeSet<String> = [
            "exefs",
            "logo",
            "control",
            "romfs",
            "romfs/empty",
            "romfs/data",
            "romfs/data/empty_sub",
            "romfs/data/sub",
            "romfs/data/sub/deeper",
        ]
        .map(String::from)
        .into();
        let total: u64 = files.values().map(|d| d.len() as u64).sum();

        // Extract.
        let out_root = tmp.path().join("out");
        let out = out_root.join(&game.name);
        let partial = partial_path(&out);
        let opts = ExtractOptions::default();
        let never = AtomicBool::new(false);
        let mut last_bytes = None;
        let mut progress = |p: Progress| {
            if let Progress::Bytes { done, total } = p {
                last_bytes = Some((done, total));
            }
        };
        let result = extract_game(&keys, &selected, &out, &opts, &never, &mut progress).expect("extracting");
        assert_eq!(result, out);
        assert_extraction(&out, &files, &dirs);
        assert!(!partial.exists(), "{} was left behind", partial.display());
        assert_eq!(last_bytes, Some((total, total)));

        // An existing extraction is only replaced on request.
        let stale = out.join("exefs").join("stale.bin");
        fs::write(&stale, b"left over from an earlier run").unwrap();
        let err =
            extract_game(&keys, &selected, &out, &opts, &never, &mut |_| {}).expect_err("overwrote without asking");
        assert!(matches!(&err, Error::Unsupported(m) if m.contains("already exists")), "{err}");
        assert!(stale.exists(), "the existing extraction was touched");
        assert!(!partial.exists());

        let overwrite = ExtractOptions { overwrite: true, ..Default::default() };
        extract_game(&keys, &selected, &out, &overwrite, &never, &mut |_| {}).expect("overwriting");
        assert_extraction(&out, &files, &dirs);
        assert!(!partial.exists());

        // Cancelled before it starts: nothing is created.
        let cancelled = out_root.join("Cancelled Game");
        let cancel = AtomicBool::new(true);
        let err = extract_game(&keys, &selected, &cancelled, &opts, &cancel, &mut |_| {}).expect_err("not cancelled");
        assert!(matches!(err, Error::Cancelled), "{err}");
        assert!(!cancelled.exists());
        assert!(!partial_path(&cancelled).exists());

        // Cancelled part-way through the large file: the half-written folder is removed.
        let interrupted = out_root.join("Interrupted Game");
        let cancel = AtomicBool::new(false);
        let mut cancel_midway = |p: Progress| {
            if matches!(p, Progress::Bytes { done, .. } if done > COPY_BUF as u64) {
                cancel.store(true, Ordering::Relaxed);
            }
        };
        let err = extract_game(&keys, &selected, &interrupted, &opts, &cancel, &mut cancel_midway)
            .expect_err("not cancelled");
        assert!(matches!(err, Error::Cancelled), "{err}");
        assert!(cancel.load(Ordering::Relaxed));
        assert!(!interrupted.exists());
        assert!(!partial_path(&interrupted).exists());
    }

    /// A RomFS image holding `files` ("a/b.bin", data) and the empty directories `dirs`.
    fn romfs_image(files: &[(&str, Vec<u8>)], dirs: &[&str]) -> Vec<u8> {
        let mut image = ImageBuilder::new();
        for (path, data) in files {
            image.file(path, data);
        }
        for dir in dirs {
            image.dir(dir);
        }
        image.build()
    }

    /// Builds a base game and its update (in separate NSPs, with their own keys) from made-up keys, then scans,
    /// groups and extracts them together. The update's executables and control data replace the base's, its RomFS
    /// is the base's patched, and the base's boot logo stays.
    #[test]
    fn extract_base_plus_update_end_to_end() {
        const APP_ID: u64 = 0x0100_0000_0001_0000;
        const UPDATE_ID: u64 = APP_ID | 0x800;
        const UPDATE_VERSION: u32 = 65536;
        const UPDATE_RSV: u32 = 0x0002_0000;
        const BASE_CONTROL_KEY: Key128 =
            [0x42, 0xE1, 0x07, 0xBA, 0x93, 0x5D, 0x28, 0xFC, 0x71, 0x0E, 0xC4, 0x36, 0xA9, 0x8D, 0x1F, 0x60];
        const UPDATE_KEY: Key128 =
            [0x1B, 0x77, 0xD2, 0x04, 0xE9, 0x5A, 0x3F, 0xC8, 0x80, 0x26, 0xBD, 0x91, 0x4E, 0xF3, 0x6A, 0x0D];
        const UPDATE_CONTROL_KEY: Key128 =
            [0xA3, 0x5C, 0x18, 0xEF, 0x62, 0xB9, 0x0A, 0x74, 0xD1, 0x3E, 0x87, 0x2B, 0xC6, 0x59, 0xF0, 0x93];

        let tmp = TempDir::new("extract-update");
        let keys = TestKeys::keys(&tmp.path().join("keys"));

        // The base game. The big file is in both versions of the RomFS and moves when the files before it change
        // size; the update must take it from the base game, not carry it.
        let big = pattern(9 * 1024 * 1024 + 12_345, 4);
        assert!(big.len() > COPY_BUF);
        let base_exefs = [("main", pattern(300, 1)), ("main.npdm", pattern(77, 2))];
        let logo = [("NintendoLogo.png", pattern(1013, 3))];
        let base_romfs = [
            ("top.txt", b"a file in the root".to_vec()),
            ("data/changes.bin", pattern(70_000, 7)),
            ("data/big.bin", big.clone()),
            ("data/sub/nested.txt", b"nested".to_vec()),
            ("data/sub/removed.bin", pattern(20_000, 8)),
            ("data/sub/deeper/leaf.bin", pattern(5000, 5)),
            ("data/zero.dat", Vec::new()),
        ];
        let base_control = [
            ("control.nacp", build_nacp("Test Game", "Test Publisher", "1.0.0")),
            ("icon_AmericanEnglish.dat", pattern(2048, 6)),
        ];
        let base_section = Section::romfs(romfs_image(&base_romfs, &["empty", "data/empty_sub"]));
        let base_program = NcaBuilder::new(NcaContentType::Program, APP_ID)
            .section(Section::pfs0(&as_refs(&base_exefs)))
            .section(base_section.clone())
            .section(Section::pfs0(&as_refs(&logo)))
            .build(&keys);
        let base_control_nca = NcaBuilder::new(NcaContentType::Control, APP_ID)
            .section_key(BASE_CONTROL_KEY)
            .section(Section::romfs(romfs_image(&base_control, &[])))
            .build(&keys);
        let base_meta = MetaBuilder::application(APP_ID, 0, 0x0001_0000)
            .content(&base_program, cnmt::CT_PROGRAM)
            .content(&base_control_nca, cnmt::CT_CONTROL)
            .build(&keys);
        let base_nsp = tmp.path().join("in").join("Test Game.nsp");
        NspBuilder::new().nca(&base_program).nca(&base_control_nca).nca(&base_meta).write(&base_nsp);

        // The update: new executables, no logo, and a RomFS with a file changed, one removed, two added (one in a
        // new directory) and a new empty directory.
        let up_exefs = [("main", pattern(412, 11)), ("main.npdm", pattern(95, 12))];
        let new_romfs = [
            ("top.txt", b"a file in the root, patched".to_vec()),
            ("data/changes.bin", pattern(75_000, 17)),
            ("data/big.bin", big),
            ("data/sub/nested.txt", b"nested".to_vec()),
            ("data/sub/added.txt", b"a file the update adds".to_vec()),
            ("data/sub/deeper/leaf.bin", pattern(5000, 5)),
            ("data/zero.dat", Vec::new()),
            ("fresh/inner/new_file.bin", pattern(41_000, 18)),
        ];
        let new_empty_dirs = ["empty", "data/empty_sub", "data/new_empty"];
        let up_control = [
            ("control.nacp", build_nacp("Test Game", "Test Publisher", "1.1.0")),
            ("icon_AmericanEnglish.dat", pattern(3000, 16)),
        ];

        // The patch is made against the base game's section as its NCA stores it. Chunks of 0x10 find the big file
        // again whatever the shift, which the new files in front of it and the bigger tables cause.
        let patch = PatchSection::new(&base_section.plaintext(), &romfs_image(&new_romfs, &new_empty_dirs));
        let patch = patch.chunk_size(0x10);
        let layout = patch.layout();
        // Not a trivial patch: both storages are used, the base game's data is read from other places than it
        // stands in the new section, and the 9 MiB file is not carried by the update.
        let used = |storage| layout.entries.iter().filter(|e| e.storage_index == storage).count();
        assert!(used(0) > 1 && used(1) > 1, "{} from the base game, {} from the update", used(0), used(1));
        assert!(layout.entries.iter().any(|e| e.storage_index == 0 && e.physical_offset != e.virtual_offset));
        let moved_big = layout
            .entries
            .iter()
            .filter(|e| e.storage_index == 0 && e.physical_offset != e.virtual_offset && e.len >= 9 * 1024 * 1024)
            .count();
        assert_eq!(moved_big, 1, "{:x?}", layout.entries);
        assert!(layout.indirect_offset < 1 << 20, "the update carries {:#x} bytes", layout.indirect_offset);
        // Its AesCtrEx regions have several generations and one of them is not encrypted; one runs from the update
        // data into the indirect table.
        let generations: BTreeSet<u32> = layout.regions.iter().map(|r| r.generation).collect();
        assert!(generations.len() >= 3 && layout.regions.iter().any(|r| !r.encrypted), "{:?}", layout.regions);
        let ends = layout.regions.iter().skip(1).map(|r| r.offset).chain([layout.ctr_ex_offset]);
        let straddles = layout
            .regions
            .iter()
            .zip(ends)
            .any(|(r, end)| r.offset < layout.indirect_offset && end > layout.indirect_offset);
        assert!(straddles, "no region covers both the update data and the indirect table");

        let up_program = NcaBuilder::new(NcaContentType::Program, UPDATE_ID)
            .section_key(UPDATE_KEY)
            .section(Section::pfs0(&as_refs(&up_exefs)))
            .section(Section::patch(patch))
            .build(&keys);
        let up_control_nca = NcaBuilder::new(NcaContentType::Control, UPDATE_ID)
            .section_key(UPDATE_CONTROL_KEY)
            .section(Section::romfs(romfs_image(&up_control, &[])))
            .build(&keys);
        let up_meta = MetaBuilder::patch(APP_ID, UPDATE_VERSION, UPDATE_RSV)
            .content(&up_program, cnmt::CT_PROGRAM)
            .content(&up_control_nca, cnmt::CT_CONTROL)
            .build(&keys);
        let update_nsp = tmp.path().join("in").join("Test Game [Update].nsp");
        NspBuilder::new().nca(&up_program).nca(&up_control_nca).nca(&up_meta).write(&update_nsp);

        // Scan both files and group them into one game.
        let mut titles = scan::scan_file(&base_nsp, &keys).expect("scanning the base NSP");
        titles.extend(scan::scan_file(&update_nsp, &keys).expect("scanning the update NSP"));
        assert_eq!(titles.len(), 2);
        let games = plan::group(titles);
        assert_eq!(games.len(), 1);
        let game = &games[0];
        let kinds: Vec<_> = game.titles.iter().map(|t| (t.kind, t.title_id, t.application_id, t.version)).collect();
        assert_eq!(
            kinds,
            [(TitleKind::Base, APP_ID, APP_ID, 0), (TitleKind::Update, UPDATE_ID, APP_ID, UPDATE_VERSION)]
        );
        let update = &game.titles[1];
        assert_eq!(update.required_system_version, Some(UPDATE_RSV));
        assert_eq!(update.contents.len(), 2);
        assert!(update.source_complete);
        assert!(update.warnings.is_empty(), "{:?}", update.warnings);
        assert_eq!(game.titles[0].display_version(), Some("1.0.0"));
        assert_eq!(update.display_version(), Some("1.1.0"));
        assert_eq!(game.name, "Test Game");
        assert_eq!(game.display_version.as_deref(), Some("1.1.0"));
        assert_eq!(game.icon.as_deref(), Some(&up_control[1].1));
        assert!(game.warnings().is_empty(), "{:?}", game.warnings());
        let selected: Vec<&Title> = game.titles.iter().collect();

        // What extraction must produce: the update's exefs and control data, the new RomFS, the base game's logo.
        let mut files = BTreeMap::new();
        for (prefix, group) in
            [("exefs", &up_exefs[..]), ("logo", &logo[..]), ("romfs", &new_romfs[..]), ("control", &up_control[..])]
        {
            for (path, data) in group {
                files.insert(format!("{prefix}/{path}"), data.clone());
            }
        }
        let dirs: BTreeSet<String> = [
            "exefs",
            "logo",
            "control",
            "romfs",
            "romfs/empty",
            "romfs/data",
            "romfs/data/empty_sub",
            "romfs/data/new_empty",
            "romfs/data/sub",
            "romfs/data/sub/deeper",
            "romfs/fresh",
            "romfs/fresh/inner",
        ]
        .map(String::from)
        .into();
        let total: u64 = files.values().map(|d| d.len() as u64).sum();
        assert!(!files.contains_key("romfs/data/sub/removed.bin"));

        let out = tmp.path().join("out").join(&game.name);
        let never = AtomicBool::new(false);
        let mut last_bytes = None;
        let mut progress = |p: Progress| {
            if let Progress::Bytes { done, total } = p {
                last_bytes = Some((done, total));
            }
        };
        let opts = ExtractOptions::default();
        let result = extract_game(&keys, &selected, &out, &opts, &never, &mut progress).expect("extracting");
        assert_eq!(result, out);
        assert_extraction(&out, &files, &dirs);
        assert!(!partial_path(&out).exists());
        assert_eq!(last_bytes, Some((total, total)));
    }

    // -----------------------------------------------------------------------------------------------------
    // Compressed sections
    // -----------------------------------------------------------------------------------------------------

    /// Compressible data: a phrase over and over.
    fn text(len: usize) -> Vec<u8> {
        b"All work and no play makes Jack a dull boy. ".iter().copied().cycle().take(len).collect()
    }

    /// Every directory that `files` and the empty directories `empty` (all '/'-separated paths) imply.
    fn implied_dirs(files: &BTreeMap<String, Vec<u8>>, empty: &[&str]) -> BTreeSet<String> {
        fn add_parents(dirs: &mut BTreeSet<String>, path: &str) {
            for (i, _) in path.match_indices('/') {
                dirs.insert(path[..i].to_string());
            }
        }
        let mut dirs = BTreeSet::new();
        for path in files.keys() {
            add_parents(&mut dirs, path);
        }
        for dir in empty {
            add_parents(&mut dirs, dir);
            dirs.insert(dir.to_string());
        }
        dirs
    }

    /// Scans the NSPs of one game, groups them and extracts all of it into `out_root/<game name>`. Returns that
    /// folder and the last byte count the progress reported.
    fn extract_nsps(keys: &Keys, nsps: &[&Path], out_root: &Path) -> (PathBuf, Option<(u64, u64)>) {
        let mut titles = Vec::new();
        for nsp in nsps {
            titles.extend(scan::scan_file(nsp, keys).expect("scanning an NSP"));
        }
        let games = plan::group(titles);
        assert_eq!(games.len(), 1);
        let game = &games[0];
        assert!(game.warnings().is_empty(), "{:?}", game.warnings());
        let selected: Vec<&Title> = game.titles.iter().collect();

        let out = out_root.join(&game.name);
        let never = AtomicBool::new(false);
        let mut last_bytes = None;
        let mut progress = |p: Progress| {
            if let Progress::Bytes { done, total } = p {
                last_bytes = Some((done, total));
            }
        };
        let opts = ExtractOptions::default();
        let result = extract_game(keys, &selected, &out, &opts, &never, &mut progress).expect("extracting");
        assert_eq!(result, out);
        assert!(!partial_path(&out).exists());
        (out, last_bytes)
    }

    /// The table offset and size in the compression info of section `section` of `nca`'s FS header, read straight
    /// from the bytes (0 and 0 if the section isn't compressed).
    fn compression_info_of(nca: &BuiltNca, keys: &Keys, section: usize) -> (u64, u64) {
        let header = NcaHeader::decrypt(&nca.bytes, keys).unwrap();
        let fs = header.fs_header(section);
        (u64le(fs, 0x178), u64le(fs, 0x180))
    }

    /// Checks that `section` stores `image` compressed with entries of every type, and returns how.
    fn check_compressed(section: &Section, image: &[u8]) -> CompressedLevel {
        let c = section.compression().expect("a compressed section");
        assert_eq!(c.decompress(), image, "the fixture decompresses to the image");
        let types: BTreeSet<u8> = c.entries.iter().map(|e| e.compression_type).collect();
        assert_eq!(types, BTreeSet::from([CMP_NONE, CMP_ZEROS, CMP_LZ4]), "entry types in {:?}", c.entries);
        assert_ne!(c.level, image);
        c
    }

    /// A base game with compressed storage under its executables and its RomFS (but not under its boot logo).
    /// Compression is built on top of the hash layer's data level: the data is stored as is, as zeros and as LZ4
    /// blocks, in a RomFS that has a zero-filled file and in a PFS0 that has one too.
    #[test]
    fn extract_compressed_base_end_to_end() {
        const TITLE_ID: u64 = 0x0100_0000_0002_0000;
        const CONTROL_KEY: Key128 =
            [0x7C, 0x19, 0xE2, 0xB5, 0x08, 0x4D, 0xA3, 0x66, 0xF0, 0x2B, 0x91, 0xCE, 0x35, 0xD8, 0x7A, 0x14];

        let tmp = TempDir::new("extract-compressed");
        let keys = TestKeys::keys(&tmp.path().join("keys"));

        // Odd sizes put files at unaligned offsets, and the content is a mix of what compresses and what doesn't.
        let exefs = [
            ("main", [pattern(20_000, 1), text(20_000)].concat()),
            ("main.npdm", pattern(77, 2)),
            ("rtld", text(9_000)),
            ("sdk", vec![0; 12_000]),
            ("subsdk0", pattern(3_001, 3)),
        ];
        let logo = [("NintendoLogo.png", pattern(1013, 4))];
        let romfs = [
            ("top.txt", b"a file in the root".to_vec()),
            ("data/random.bin", pattern(150_000, 5)),
            ("data/zeros.bin", vec![0; 100_000]),
            ("data/story.txt", text(120_000)),
            ("data/mixed.bin", [pattern(20_000, 6), vec![0; 20_000], text(20_000)].concat()),
            ("data/sub/nested.txt", b"nested".to_vec()),
            ("data/sub/deeper/leaf.bin", pattern(5000, 7)),
            ("data/empty.dat", Vec::new()),
        ];
        let empty_dirs = ["empty", "data/empty_sub"];
        let control = [
            ("control.nacp", build_nacp("Compressed Game", "Test Publisher", "1.0.0")),
            ("icon_AmericanEnglish.dat", pattern(2048, 8)),
        ];

        let exefs_image = build_pfs0(&as_refs(&exefs));
        let romfs_data = romfs_image(&romfs, &empty_dirs);
        use Compress::{Lz4, Stored, Zeros};
        let exefs_section = Section::Pfs0(exefs_image.clone()).compressed(0x1000, &[Lz4, Zeros, Stored, Zeros, Lz4]);
        let romfs_section =
            Section::romfs(romfs_data.clone()).compressed(0x2000, &[Lz4, Stored, Lz4, Zeros, Lz4, Zeros, Stored, Lz4]);
        let exefs_stored = check_compressed(&exefs_section, &exefs_image);
        let romfs_stored = check_compressed(&romfs_section, &romfs_data);

        let program = NcaBuilder::new(NcaContentType::Program, TITLE_ID)
            .section(exefs_section)
            .section(romfs_section)
            .section(Section::pfs0(&as_refs(&logo)))
            .build(&keys);
        // The FS headers say which sections are compressed.
        assert_eq!(compression_info_of(&program, &keys, 0), (exefs_stored.table_offset, exefs_stored.table_size));
        assert_eq!(compression_info_of(&program, &keys, 1), (romfs_stored.table_offset, romfs_stored.table_size));
        assert_eq!(compression_info_of(&program, &keys, 2), (0, 0));

        let control_nca = NcaBuilder::new(NcaContentType::Control, TITLE_ID)
            .section_key(CONTROL_KEY)
            .section(Section::romfs(romfs_image(&control, &[])))
            .build(&keys);
        let meta = MetaBuilder::application(TITLE_ID, 0, 0x0001_0000)
            .content(&program, cnmt::CT_PROGRAM)
            .content(&control_nca, cnmt::CT_CONTROL)
            .build(&keys);
        let nsp = tmp.path().join("in").join("Compressed Game.nsp");
        NspBuilder::new().nca(&program).nca(&control_nca).nca(&meta).write(&nsp);

        let mut files = BTreeMap::new();
        for (prefix, group) in
            [("exefs", &exefs[..]), ("logo", &logo[..]), ("romfs", &romfs[..]), ("control", &control[..])]
        {
            for (path, data) in group {
                files.insert(format!("{prefix}/{path}"), data.clone());
            }
        }
        let romfs_empty_dirs = empty_dirs.map(|d| format!("romfs/{d}"));
        let dirs = implied_dirs(&files, &romfs_empty_dirs.iter().map(String::as_str).collect::<Vec<_>>());
        let total: u64 = files.values().map(|d| d.len() as u64).sum();

        let (out, last_bytes) = extract_nsps(&keys, &[&nsp], &tmp.path().join("out"));
        assert_extraction(&out, &files, &dirs);
        assert_eq!(last_bytes, Some((total, total)));
        // The zero-filled files and the compressible ones really came back as what they are, not as stored bytes.
        assert_eq!(fs::read(out.join("romfs/data/zeros.bin")).unwrap(), vec![0; 100_000]);
        assert_eq!(fs::read(out.join("exefs/sdk")).unwrap(), vec![0; 12_000]);
    }

    /// A base game and an update (in separate NSPs) whose patched RomFS is compressed storage, in three ways: the
    /// update's compression is applied to the patched section whatever the base game's section looks like, and the
    /// base game's own compression info is never applied to what the update patches.
    #[test]
    fn extract_compressed_update_end_to_end() {
        const APP_ID: u64 = 0x0100_0000_0003_0000;
        const UPDATE_ID: u64 = APP_ID | 0x800;
        const UPDATE_VERSION: u32 = 65536;
        const BASE_CONTROL_KEY: Key128 =
            [0x15, 0xA8, 0x6E, 0xD3, 0x40, 0xB7, 0x9C, 0x21, 0xFE, 0x03, 0x58, 0xC4, 0x8B, 0x72, 0x1D, 0xE6];
        const UPDATE_KEY: Key128 =
            [0xD2, 0x4B, 0x07, 0x9F, 0x61, 0xEA, 0x38, 0xC5, 0x1A, 0x84, 0xF3, 0x5E, 0x90, 0x2D, 0xB6, 0x7F];
        const UPDATE_CONTROL_KEY: Key128 =
            [0x68, 0xF1, 0x3A, 0x97, 0xCC, 0x05, 0xDE, 0x42, 0xB9, 0x76, 0x1F, 0xA0, 0x83, 0xE5, 0x2C, 0x5B];

        let tmp = TempDir::new("extract-compressed-update");
        let keys = TestKeys::keys(&tmp.path().join("keys"));

        // The big files that stay are in both versions of the RomFS; the update must take them from the base game.
        let stay = pattern(160_000, 1);
        let zeros = vec![0; 60_000];
        let base_exefs = [("main", pattern(300, 2)), ("main.npdm", pattern(77, 3))];
        let logo = [("NintendoLogo.png", pattern(1013, 4))];
        let base_romfs = [
            ("top.txt", b"a file in the root".to_vec()),
            ("data/stay.bin", stay.clone()),
            ("data/changes.txt", text(70_000)),
            ("data/zeros.bin", zeros.clone()),
            ("data/sub/removed.bin", pattern(20_000, 5)),
            ("data/sub/nested.txt", b"nested".to_vec()),
        ];
        let base_empty = ["empty"];
        let base_control = [
            ("control.nacp", build_nacp("Updated Game", "Test Publisher", "1.0.0")),
            ("icon_AmericanEnglish.dat", pattern(2048, 6)),
        ];
        // The update changes one file, removes one, adds two (one in a new directory, one with zeros in it) and
        // shifts everything after the first.
        let up_exefs = [("main", pattern(412, 7)), ("main.npdm", pattern(95, 8))];
        let new_romfs = [
            ("top.txt", b"a file in the root, patched".to_vec()),
            ("data/stay.bin", stay),
            ("data/changes.txt", [text(40_000), pattern(20_000, 9), text(9_000)].concat()),
            ("data/zeros.bin", zeros),
            ("data/sub/nested.txt", b"nested".to_vec()),
            ("fresh/inner/new.bin", [vec![0; 30_000], pattern(10_000, 10)].concat()),
            ("fresh/empty.dat", Vec::new()),
        ];
        let new_empty = ["empty", "data/new_empty"];
        let up_control = [
            ("control.nacp", build_nacp("Updated Game", "Test Publisher", "1.1.0")),
            ("icon_AmericanEnglish.dat", pattern(3000, 11)),
        ];
        let old_image = romfs_image(&base_romfs, &base_empty);
        let new_image = romfs_image(&new_romfs, &new_empty);

        // What extraction must produce: the update's executables and control data, the new RomFS, the base's logo.
        let mut files = BTreeMap::new();
        for (prefix, group) in
            [("exefs", &up_exefs[..]), ("logo", &logo[..]), ("romfs", &new_romfs[..]), ("control", &up_control[..])]
        {
            for (path, data) in group {
                files.insert(format!("{prefix}/{path}"), data.clone());
            }
        }
        let new_empty_dirs = new_empty.map(|d| format!("romfs/{d}"));
        let dirs = implied_dirs(&files, &new_empty_dirs.iter().map(String::as_str).collect::<Vec<_>>());
        let total: u64 = files.values().map(|d| d.len() as u64).sum();

        use Compress::{Lz4, Stored, Zeros};
        type Compression<'a> = Option<(usize, &'a [Compress])>;
        let update_kinds = [Lz4, Stored, Lz4, Zeros, Lz4, Zeros, Stored, Lz4];
        let base_kinds = [Stored, Lz4, Zeros, Lz4];
        let variants: [(&str, Compression, Compression); 3] = [
            ("update compressed, base plain", None, Some((0x2000, &update_kinds))),
            ("update and base compressed, differently", Some((0x1000, &base_kinds)), Some((0x2000, &update_kinds))),
            ("base compressed, update plain", Some((0x1000, &base_kinds)), None),
        ];
        for (n, (label, base_how, update_how)) in variants.into_iter().enumerate() {
            let dir = tmp.path().join(format!("variant{n}"));
            let compress = |section: Section, how: Compression| match how {
                Some((block_size, kinds)) => section.compressed(block_size, kinds),
                None => section,
            };

            // The base game. The patch is made against the base's RomFS section exactly as its NCA stores it.
            let base_section = compress(Section::romfs(old_image.clone()), base_how);
            let base_plain = base_section.plaintext();
            let base_program = NcaBuilder::new(NcaContentType::Program, APP_ID)
                .section(Section::pfs0(&as_refs(&base_exefs)))
                .section(base_section.clone())
                .section(Section::pfs0(&as_refs(&logo)))
                .build(&keys);
            let base_info = compression_info_of(&base_program, &keys, 1);
            match base_how {
                None => assert_eq!(base_info, (0, 0), "{label}: the base game's RomFS section is not compressed"),
                Some(_) => {
                    let c = check_compressed(&base_section, &old_image);
                    assert_eq!(base_info, (c.table_offset, c.table_size), "{label}");
                }
            }
            let base_control_nca = NcaBuilder::new(NcaContentType::Control, APP_ID)
                .section_key(BASE_CONTROL_KEY)
                .section(Section::romfs(romfs_image(&base_control, &[])))
                .build(&keys);
            let base_meta = MetaBuilder::application(APP_ID, 0, 0x0001_0000)
                .content(&base_program, cnmt::CT_PROGRAM)
                .content(&base_control_nca, cnmt::CT_CONTROL)
                .build(&keys);
            let base_nsp = dir.join("in").join("Updated Game.nsp");
            NspBuilder::new().nca(&base_program).nca(&base_control_nca).nca(&base_meta).write(&base_nsp);

            // The update. Chunks of 0x10 find the base game's data wherever the compressed storage put it.
            let mut patch = PatchSection::new(&base_plain, &new_image).chunk_size(0x10);
            let mut update_stored = None;
            if let Some((block_size, kinds)) = update_how {
                patch = patch.compressed(block_size, kinds);
                let section = Section::romfs(new_image.clone()).compressed(block_size, kinds);
                update_stored = Some(check_compressed(&section, &new_image));
            }
            let layout = patch.layout();
            let used = |storage| layout.entries.iter().filter(|e| e.storage_index == storage).count();
            assert!(used(0) > 1 && used(1) > 1, "{label}: {} from the base game, {} from the update", used(0), used(1));
            let up_program = NcaBuilder::new(NcaContentType::Program, UPDATE_ID)
                .section_key(UPDATE_KEY)
                .section(Section::pfs0(&as_refs(&up_exefs)))
                .section(Section::patch(patch))
                .build(&keys);
            let up_info = compression_info_of(&up_program, &keys, 1);
            match &update_stored {
                None => assert_eq!(up_info, (0, 0), "{label}: the update's RomFS section is not compressed"),
                Some(c) => assert_eq!(up_info, (c.table_offset, c.table_size), "{label}"),
            }
            assert_ne!(up_info, base_info, "{label}");

            // The update's data level, where its IVFC header puts it, holds the compressed data and table (or the
            // image) and much of that comes from the base game, not from the update.
            let up_header = NcaHeader::decrypt(&up_program.bytes, &keys).unwrap();
            let (data_offset, data_size) = nca::ivfc_data_level(&up_header, 1).unwrap();
            let (level, data_end) = match &update_stored {
                Some(c) => (c.level.clone(), c.table_offset),
                None => (new_image.clone(), new_image.len() as u64),
            };
            assert_eq!(data_size, level.len() as u64, "{label}");
            let from_base: usize = layout
                .entries
                .iter()
                .filter(|e| e.storage_index == 0)
                .map(|e| {
                    // The part of the entry inside the stored data, as offsets into it.
                    let lo = e.virtual_offset.max(data_offset);
                    let hi = (e.virtual_offset + e.len).min(data_offset + data_end);
                    let part =
                        if lo < hi { &level[(lo - data_offset) as usize..(hi - data_offset) as usize] } else { &[] };
                    part.chunks(0x10).filter(|c| c.iter().any(|&b| b != 0)).count() * 0x10
                })
                .sum();
            assert!(
                from_base > 0x4000,
                "{label}: only {from_base:#x} bytes of the stored data come from the base game"
            );

            let up_control_nca = NcaBuilder::new(NcaContentType::Control, UPDATE_ID)
                .section_key(UPDATE_CONTROL_KEY)
                .section(Section::romfs(romfs_image(&up_control, &[])))
                .build(&keys);
            let up_meta = MetaBuilder::patch(APP_ID, UPDATE_VERSION, 0x0002_0000)
                .content(&up_program, cnmt::CT_PROGRAM)
                .content(&up_control_nca, cnmt::CT_CONTROL)
                .build(&keys);
            let update_nsp = dir.join("in").join("Updated Game [Update].nsp");
            NspBuilder::new().nca(&up_program).nca(&up_control_nca).nca(&up_meta).write(&update_nsp);

            let (out, last_bytes) = extract_nsps(&keys, &[&base_nsp, &update_nsp], &dir.join("out"));
            assert_extraction(&out, &files, &dirs);
            assert_eq!(last_bytes, Some((total, total)), "{label}");
        }
    }
}
