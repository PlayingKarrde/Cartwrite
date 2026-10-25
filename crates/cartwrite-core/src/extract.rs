//! Extracts a game's files to a folder:
//!
//! ```text
//! <out>/exefs/          main, main.npdm, rtld, sdk, subsdk*
//! <out>/romfs/          game data
//! <out>/logo/           boot logo (when present)
//! <out>/control/        control.nacp and icons
//! <out>/program<N>/...  the same for each further program of a multi-program title
//! <out>/dlc/<id>/romfs/ each DLC's data, with its DLC update applied (optional)
//! ```
//!
//! An update (or DLC update) replaces the sections it carries and patches the RomFS of the
//! NCA it updates; sections it doesn't carry come from the base.
//!
//! Files are written into `<out>.partial` and the folder is renamed once everything is done,
//! so a cancelled or failed extraction never leaves a half-written game behind.
//!
//! NSZ/XCZ content works too: each NCZ is first restored to a whole encrypted NCA in
//! `<out>.cartwrite-tmp` (once, however often it's read), and that folder is removed when the
//! extraction ends, however it ends.

use std::collections::{BTreeMap, BTreeSet, HashMap};
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
use crate::ncz::{NczInfo, UNCOMPRESSED_HEADER};
use crate::romfs::{self, RomfsTree};
use crate::scan::{NcaRef, Title, TitleKind};
use crate::storage::{NcaSection, RawSection, Storage, SubStorage};
use crate::util::read_vec_at;

const COPY_BUF: usize = 8 << 20;

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

impl<'a> Source<'a> {
    fn label(&self) -> String {
        match self {
            Self::Plain(r) => r.nca.out_name.clone(),
            Self::Patched { base: Some(b), update } => format!("{} + update {}", b.nca.out_name, update.nca.out_name),
            Self::Patched { base: None, update } => update.nca.out_name.clone(),
        }
    }

    /// The NCAs this source reads.
    fn ncas(&self) -> Vec<&'a NcaRef> {
        match *self {
            Self::Plain(r) => vec![r.nca],
            Self::Patched { base, update } => base.map(|b| b.nca).into_iter().chain([update.nca]).collect(),
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
    let temp = temp_path(out);
    if temp.exists() {
        fs::remove_dir_all(&temp)?;
    }
    let mut cache = NczCache::new(temp.clone());

    let result = (|| {
        // The listing pass restores every NCZ the parts read; the writing pass finds them in the cache.
        let mut listings = Vec::with_capacity(parts.len());
        for p in &parts {
            check_cancel(cancel)?;
            cache.restore_all(p.source.ncas(), cancel, &mut *progress).map_err(|e| in_part(e, p))?;
            let listing = with_part_data(keys, &cache, &p.source, |s| list(s, p.fs_type));
            listings.push(listing.map_err(|e| in_part(e, p))?);
        }
        let total: u64 = listings.iter().map(Listing::bytes).sum();
        let mut done = 0u64;
        progress(Progress::Bytes { done, total });

        let mut buf = vec![0u8; COPY_BUF];
        for (p, listing) in parts.iter().zip(&listings) {
            progress(Progress::Log(format!("Extracting {} ({})", p.dest.display(), p.source.label())));
            let dest = partial.join(&p.dest);
            fs::create_dir_all(&dest)?;
            with_part_data(keys, &cache, &p.source, |s| {
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
            })
            .map_err(|e| in_part(e, p))?;
        }
        Ok(())
    })();

    // The restored NCAs are only needed while extracting.
    let _ = fs::remove_dir_all(&temp);
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
    let mut parts: Vec<Part> = Vec::new();

    // Each program (multi-program titles have several, told apart by id_offset) with the
    // update's program of the same id_offset applied over it. Program 0 goes at the root.
    let programs = |t: &'a Title| by_id_offset(t, cnmt::CT_PROGRAM);
    let base_programs = programs(base);
    if base_programs.is_empty() {
        return Err(Error::Unsupported(format!("{}: base game has no program content", base.source.display())));
    }
    let up_programs = update.map(programs).unwrap_or_default();
    let ids: BTreeSet<u8> = base_programs.keys().chain(up_programs.keys()).copied().collect();
    for &id in &ids {
        let prefix = program_folder(id);
        let base_nca = base_programs.get(&id).map(|&n| (base, n));
        let up_nca = up_programs.get(&id).map(|&n| (update.unwrap(), n));
        add_nca_parts(keys, &mut parts, base_nca, up_nca, &prefix)?;

        // Control data: the update's when it has its own, else the base's.
        let control =
            |t: Option<&'a Title>| t.and_then(|t| by_id_offset(t, cnmt::CT_CONTROL).get(&id).map(|&n| (t, n)));
        if let Some((owner, nca)) = control(update).or_else(|| control(Some(base))) {
            let header = OpenNca::header(keys, nca)?;
            check_section(&header, 0, nca)?;
            let source = Source::Plain(SectionRef { title: owner, nca, section: 0 });
            parts.push(Part { source, fs_type: FS_ROMFS, dest: prefix.join("control") });
        }
    }

    if opts.include_dlc {
        for dlc_update in titles.iter().filter(|t| t.kind == TitleKind::DlcUpdate) {
            if !titles.iter().any(|t| t.kind == TitleKind::Dlc && Some(t.title_id) == dlc_update.data_id) {
                return Err(Error::Unsupported(format!(
                    "DLC update {:016X} is selected without the DLC it updates ({})",
                    dlc_update.title_id,
                    dlc_update.data_id.map_or("unknown".into(), |id| format!("{id:016X}"))
                )));
            }
        }
        for dlc in titles.iter().copied().filter(|t| t.kind == TitleKind::Dlc) {
            let data = |t: &'a Title| t.contents.iter().find(|n| n.content_type == cnmt::CT_DATA);
            let Some(base_data) = data(dlc) else {
                return fmt_err(format!("DLC {:016X} has no data content", dlc.title_id));
            };
            let dlc_update =
                titles.iter().copied().find(|t| t.kind == TitleKind::DlcUpdate && t.data_id == Some(dlc.title_id));
            let up_data = match dlc_update {
                Some(u) => Some((
                    u,
                    data(u)
                        .ok_or_else(|| Error::Format(format!("DLC update {:016X} has no data content", u.title_id)))?,
                )),
                None => None,
            };
            let prefix = Path::new("dlc").join(format!("{:016X}", dlc.title_id));
            add_nca_parts(keys, &mut parts, Some((dlc, base_data)), up_data, &prefix)?;
        }
    }
    Ok(parts)
}

/// A title's contents of one type, keyed by id_offset.
fn by_id_offset(title: &Title, content_type: u8) -> BTreeMap<u8, &NcaRef> {
    title.contents.iter().filter(|n| n.content_type == content_type).map(|n| (n.id_offset, n)).collect()
}

/// Folder for program `id_offset` of a title: the root for program 0, `program<N>` for others.
fn program_folder(id_offset: u8) -> PathBuf {
    if id_offset == 0 {
        PathBuf::new()
    } else {
        PathBuf::from(format!("program{id_offset}"))
    }
}

/// Adds the parts of one NCA (`base`) with `update` applied over it, under `prefix`: each of
/// the update's sections replaces the base's, or patches it if it's a patch section, and base
/// sections the update doesn't have are kept. Either NCA may be missing.
fn add_nca_parts<'a>(
    keys: &Keys,
    parts: &mut Vec<Part<'a>>,
    base: Option<(&'a Title, &'a NcaRef)>,
    update: Option<(&'a Title, &'a NcaRef)>,
    prefix: &Path,
) -> Result<()> {
    let base_header = base.map(|(_, n)| OpenNca::header(keys, n)).transpose()?;
    let mut done: Vec<&'static str> = Vec::new();
    if let Some((up_title, up_nca)) = update {
        let up_header = OpenNca::header(keys, up_nca)?;
        for s in up_header.sections() {
            let fs_type = up_header.section_fs_type(s.index);
            let dest = section_dest(fs_type, s.index, up_nca)?;
            check_section(&up_header, s.index, up_nca)?;
            let up_ref = SectionRef { title: up_title, nca: up_nca, section: s.index };
            let source = if fs_type == FS_ROMFS && is_patch_section(&up_header, s.index) {
                let base_ref = match (base, &base_header) {
                    (Some((t, n)), Some(h))
                        if h.section(s.index).is_some() && h.section_fs_type(s.index) == FS_ROMFS =>
                    {
                        check_section(h, s.index, n)?;
                        Some(SectionRef { title: t, nca: n, section: s.index })
                    }
                    _ => None,
                };
                Source::Patched { base: base_ref, update: up_ref }
            } else {
                Source::Plain(up_ref)
            };
            parts.push(Part { source, fs_type, dest: prefix.join(dest) });
            done.push(dest);
        }
    }
    if let (Some((title, nca)), Some(header)) = (base, &base_header) {
        for s in header.sections() {
            let fs_type = header.section_fs_type(s.index);
            let dest = section_dest(fs_type, s.index, nca)?;
            if done.contains(&dest) {
                continue;
            }
            check_section(header, s.index, nca)?;
            let source = Source::Plain(SectionRef { title, nca, section: s.index });
            parts.push(Part { source, fs_type, dest: prefix.join(dest) });
        }
    }
    Ok(())
}

/// Says which part a format error came from (e.g. "romfs (… + update …): …").
fn in_part(e: Error, p: &Part) -> Error {
    let at = || format!("{} ({})", p.dest.display(), p.source.label());
    match e {
        Error::Format(m) => Error::Format(format!("{}: {m}", at())),
        Error::Unsupported(m) => Error::Unsupported(format!("{}: {m}", at())),
        other => other,
    }
}

/// Output folder for a section of a program NCA (or of a DLC's data NCA, which only has a RomFS).
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

/// Runs `f` on a part's data: the PFS0 or RomFS image, patched with the update if needed. Any NCZ it reads must
/// already be restored in `cache`.
fn with_part_data<T>(
    keys: &Keys,
    cache: &NczCache,
    source: &Source,
    f: impl FnOnce(&mut dyn Storage) -> Result<T>,
) -> Result<T> {
    let (base, update) = match *source {
        Source::Plain(r) => return OpenNca::open(keys, cache, r.title, r.nca)?.with_data(r.section, f),
        Source::Patched { base, update } => (base, update),
    };
    let mut up = OpenNca::open(keys, cache, update.title, update.nca)?;
    let mut base_open = base.map(|b| OpenNca::open(keys, cache, b.title, b.nca)).transpose()?;

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

    /// Opens `n`; an NCZ is read from its restored copy in `cache`, which is a whole NCA from offset 0.
    fn open(keys: &Keys, cache: &NczCache, title: &Title, n: &NcaRef) -> Result<Self> {
        let (mut file, base) =
            if n.is_ncz { (open_source(cache.path(n)?)?, 0) } else { (open_source(&n.source)?, n.offset) };
        let header = NcaHeader::decrypt(&read_vec_at(&mut file, base, HEADER_SIZE)?, keys)?;
        let key = header.section_key(keys, title.title_key(keys, &header)?.as_ref())?;
        Ok(Self { header, key, src: Box::new(OwnedFileNca { file, base }) })
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

/// Where the extraction is written until it is done: `<out>.partial`.
fn partial_path(out: &Path) -> PathBuf {
    sibling_path(out, ".partial")
}

/// Where NCZ content is restored to while extracting: `<out>.cartwrite-tmp`.
fn temp_path(out: &Path) -> PathBuf {
    sibling_path(out, ".cartwrite-tmp")
}

fn sibling_path(out: &Path, suffix: &str) -> PathBuf {
    let mut name = out.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    out.with_file_name(name)
}

/// NCZ content restored to temporary NCA files, so it reads like any other NCA. An NCZ is restored once, however
/// many parts read it: the cache is keyed by source file and offset.
struct NczCache {
    /// The folder the NCAs are restored into (created when the first one is).
    dir: PathBuf,
    files: HashMap<(PathBuf, u64), PathBuf>,
}

impl NczCache {
    fn new(dir: PathBuf) -> Self {
        Self { dir, files: HashMap::new() }
    }

    /// Restores those of `ncas` that are NCZ and not restored yet.
    fn restore_all<'a>(
        &mut self,
        ncas: impl IntoIterator<Item = &'a NcaRef>,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<()> {
        for n in ncas.into_iter().filter(|n| n.is_ncz) {
            let key = (n.source.as_ref().clone(), n.offset);
            if self.files.contains_key(&key) {
                continue;
            }
            progress(Progress::Log(format!("Decompressing {}", n.out_name)));
            fs::create_dir_all(&self.dir).map_err(|e| Error::File { path: self.dir.clone(), source: e })?;
            let mut path = self.dir.join(&n.out_name);
            if self.files.values().any(|p| *p == path) {
                // The same content id in another file.
                path = self.dir.join(format!("{}-{}", self.files.len(), n.out_name));
            }
            restore_ncz(n, &path, cancel)?;
            self.files.insert(key, path);
        }
        Ok(())
    }

    /// The restored NCA of `n`.
    fn path(&self, n: &NcaRef) -> Result<&Path> {
        match self.files.get(&(n.source.as_ref().clone(), n.offset)) {
            Some(path) => Ok(path),
            None => fmt_err(format!("internal error: {} wasn't restored before it was read", n.out_name)),
        }
    }
}

/// Writes the NCA that the NCZ `n` holds to `path`, the way `build` restores it: the uncompressed head as it is,
/// then the decompressed rest, encrypted again section by section. Re-encrypting is what makes update sections
/// readable again, since NSZ stores their bytes decrypted with a plain counter, not as the NCA holds them.
fn restore_ncz(n: &NcaRef, path: &Path, cancel: &AtomicBool) -> Result<()> {
    let mut src = open_source(&n.source)?;
    let head_len = UNCOMPRESSED_HEADER.min(n.nca_size) as usize;
    let head = read_vec_at(&mut src, n.offset, head_len)
        .map_err(|e| Error::File { path: n.source.to_path_buf(), source: e })?;
    let info = NczInfo::parse(&mut src, n.offset, n.stored_size)?;

    let write_err = |e| Error::File { path: path.to_path_buf(), source: e };
    let mut out = File::create(path).map_err(write_err)?;
    out.write_all(&head).map_err(write_err)?;
    let mut pos = UNCOMPRESSED_HEADER;
    let mut buf = Vec::new();
    info.decompress(&src, n.nca_size, &mut |chunk| {
        check_cancel(cancel)?;
        let take = chunk.len().min(n.nca_size.saturating_sub(pos) as usize);
        buf.clear();
        buf.extend_from_slice(&chunk[..take]);
        info.reencrypt(pos, &mut buf);
        out.write_all(&buf).map_err(write_err)?;
        pos += take as u64;
        Ok(())
    })
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
        NczMode, NspBuilder, PatchSection, Section, TempDir, TestKeys, CMP_LZ4, CMP_NONE, CMP_ZEROS,
    };
    use crate::util::u64le;
    use crate::{plan, scan};

    #[test]
    fn partial_folder_sits_next_to_the_output() {
        let out = Path::new("games").join("Game [0100000000010000][v1.0.0]");
        assert_eq!(partial_path(&out), Path::new("games").join("Game [0100000000010000][v1.0.0].partial"));
    }

    #[test]
    fn temp_folder_sits_next_to_the_output() {
        let out = Path::new("games").join("Game [0100000000010000][v1.0.0]");
        assert_eq!(temp_path(&out), Path::new("games").join("Game [0100000000010000][v1.0.0].cartwrite-tmp"));
    }

    /// How a test NSP stores an NCA: as it is (`None`), or compressed into an NCZ the given way.
    type Stored = Option<NczMode>;

    /// Adds `nca` to `nsp` the way `how` says.
    fn add_nca(nsp: NspBuilder, nca: &BuiltNca, keys: &Keys, how: Stored) -> NspBuilder {
        match how {
            Some(mode) => nsp.ncz(nca, keys, mode),
            None => nsp.nca(nca),
        }
    }

    /// The names of the NCAs that the progress reports say were decompressed, sorted.
    fn decompressed_names(logs: &[String]) -> Vec<String> {
        let mut names: Vec<String> =
            logs.iter().filter_map(|m| m.strip_prefix("Decompressing ")).map(String::from).collect();
        names.sort();
        names
    }

    /// The sorted `<content id>.nca` names of `ncas`.
    fn names_of(ncas: &[&BuiltNca]) -> Vec<String> {
        let mut names: Vec<String> = ncas.iter().map(|n| n.file_name()).collect();
        names.sort();
        names
    }

    /// Checks that every NCZ among the contents of `titles` restores to the very bytes of the NCA it was made from
    /// (found by name among `built`), so the temporary file is a whole, encrypted NCA.
    fn assert_ncz_contents_restore(titles: &[Title], built: &[&BuiltNca], dir: &Path) {
        let mut restored = 0;
        for n in titles.iter().flat_map(|t| &t.contents).filter(|n| n.is_ncz) {
            let nca = built.iter().find(|b| b.file_name() == n.out_name).unwrap_or_else(|| panic!("{}", n.out_name));
            assert_eq!(n.nca_size, nca.bytes.len() as u64, "{}", n.out_name);
            let path = dir.join(&n.out_name);
            restore_ncz(n, &path, &AtomicBool::new(false)).expect("restoring");
            assert!(fs::read(&path).unwrap() == nca.bytes, "{} restores to the NCA it was made from", n.out_name);
            restored += 1;
        }
        assert!(restored > 0, "no NCZ among the contents");
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
        base_game_end_to_end(false);
    }

    /// The same game as an NSZ: the program is an NCZ with one zstd stream, the control data an NCZ with blocks.
    /// It comes out byte for byte as the plain one does, each NCZ is decompressed once however many passes read it,
    /// and the temporary folder is gone afterwards, also after a stale one, a refused overwrite and a cancel.
    #[test]
    fn extract_nsz_base_end_to_end() {
        base_game_end_to_end(true);
    }

    fn base_game_end_to_end(ncz: bool) {
        const TITLE_ID: u64 = 0x0100_0000_0001_0000;
        const CONTROL_KEY: Key128 =
            [0x42, 0xE1, 0x07, 0xBA, 0x93, 0x5D, 0x28, 0xFC, 0x71, 0x0E, 0xC4, 0x36, 0xA9, 0x8D, 0x1F, 0x60];

        let tmp = TempDir::new(if ncz { "extract-nsz" } else { "extract" });
        let keys = TestKeys::keys(&tmp.path().join("keys"));
        let (program_stored, control_stored) =
            if ncz { (Some(NczMode::Stream), Some(NczMode::Block(14))) } else { (None, None) };

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
        let nsp_builder = add_nca(NspBuilder::new(), &program, &keys, program_stored);
        add_nca(nsp_builder, &control_nca, &keys, control_stored).nca(&meta).write(&nsp);

        // Scan and group.
        let titles = scan::scan_file(&nsp, &keys).expect("scanning the NSP");
        assert_eq!(titles.len(), 1);
        let title = &titles[0];
        assert_eq!(title.kind, TitleKind::Base);
        assert_eq!((title.title_id, title.application_id, title.version), (TITLE_ID, TITLE_ID, 0));
        assert_eq!(title.required_system_version, Some(0x0001_0000));
        assert_eq!(title.contents.len(), 2);
        assert!(title.contents.iter().all(|n| n.is_ncz == ncz));
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
        let temp = temp_path(&out);
        let opts = ExtractOptions::default();
        let never = AtomicBool::new(false);
        // A temporary folder that an earlier run left behind, with a file that is named like the program NCA.
        fs::create_dir_all(&temp).unwrap();
        fs::write(temp.join(program.file_name()), b"left over from an earlier run").unwrap();
        let mut last_bytes = None;
        let mut logs = Vec::new();
        let mut progress = |p: Progress| match p {
            Progress::Bytes { done, total } => last_bytes = Some((done, total)),
            Progress::Log(message) => logs.push(message),
        };
        let result = extract_game(&keys, &selected, &out, &opts, &never, &mut progress).expect("extracting");
        assert_eq!(result, out);
        assert_extraction(&out, &files, &dirs);
        assert!(!partial.exists(), "{} was left behind", partial.display());
        assert!(!temp.exists(), "{} was left behind", temp.display());
        assert_eq!(last_bytes, Some((total, total)));
        // Both passes read both NCAs, but each is decompressed once.
        let want = if ncz { names_of(&[&program, &control_nca]) } else { Vec::new() };
        assert_eq!(decompressed_names(&logs), want);
        if ncz {
            assert_ncz_contents_restore(&game.titles, &[&program, &control_nca], tmp.path());
        }

        // An existing extraction is only replaced on request.
        let stale = out.join("exefs").join("stale.bin");
        fs::write(&stale, b"left over from an earlier run").unwrap();
        let err =
            extract_game(&keys, &selected, &out, &opts, &never, &mut |_| {}).expect_err("overwrote without asking");
        assert!(matches!(&err, Error::Unsupported(m) if m.contains("already exists")), "{err}");
        assert!(stale.exists(), "the existing extraction was touched");
        assert!(!partial.exists());
        assert!(!temp.exists());

        let overwrite = ExtractOptions { overwrite: true, ..Default::default() };
        extract_game(&keys, &selected, &out, &overwrite, &never, &mut |_| {}).expect("overwriting");
        assert_extraction(&out, &files, &dirs);
        assert!(!partial.exists());
        assert!(!temp.exists());

        // Cancelled before it starts: nothing is created.
        let cancelled = out_root.join("Cancelled Game");
        let cancel = AtomicBool::new(true);
        let err = extract_game(&keys, &selected, &cancelled, &opts, &cancel, &mut |_| {}).expect_err("not cancelled");
        assert!(matches!(err, Error::Cancelled), "{err}");
        assert!(!cancelled.exists());
        assert!(!partial_path(&cancelled).exists());
        assert!(!temp_path(&cancelled).exists());

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
        assert!(!temp_path(&interrupted).exists());
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
        base_plus_update_end_to_end(false, false);
    }

    /// The same, with an update whose RomFS section has a patch meta hash layer, as Breath of the Wild's updates
    /// do: both tables are under the section's ordinary counter, and the AesCtrEx regions cover only the update's
    /// data.
    #[test]
    fn extract_update_with_patch_meta_hash_layer_end_to_end() {
        base_plus_update_end_to_end(true, false);
    }

    /// The same, with the program and control NCAs of both the base game and the update stored as NCZ (a stream and
    /// blocks each). NSZ holds the update's patch section decrypted with its plain counter, which isn't its real
    /// plaintext, so this only comes out right if the NCZ is restored by encrypting it again.
    #[test]
    fn extract_nsz_base_plus_update_end_to_end() {
        base_plus_update_end_to_end(false, true);
    }

    fn base_plus_update_end_to_end(meta_hash_layer: bool, ncz: bool) {
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

        let tmp = TempDir::new(match (meta_hash_layer, ncz) {
            (_, true) => "extract-nsz-update",
            (true, false) => "extract-update-meta-hash",
            (false, false) => "extract-update",
        });
        let keys = TestKeys::keys(&tmp.path().join("keys"));
        // How each NCA is stored: the base game's program as a stream and its control data as blocks, the update's
        // the other way round and with another block size.
        let (base_program_stored, base_control_stored, up_program_stored, up_control_stored) = if ncz {
            (Some(NczMode::Stream), Some(NczMode::Block(14)), Some(NczMode::Block(15)), Some(NczMode::Stream))
        } else {
            (None, None, None, None)
        };

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
        let nsp = add_nca(NspBuilder::new(), &base_program, &keys, base_program_stored);
        add_nca(nsp, &base_control_nca, &keys, base_control_stored).nca(&base_meta).write(&base_nsp);

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
        let patch = patch.chunk_size(0x10).meta_hash_layer(meta_hash_layer);
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
        // Its AesCtrEx regions have several generations and one of them is not encrypted. Normally one runs from the
        // update data into the indirect table. With a meta hash layer the regions end at the indirect table, and the
        // layer's blob follows the AesCtrEx table.
        let generations: BTreeSet<u32> = layout.regions.iter().map(|r| r.generation).collect();
        assert!(generations.len() >= 3 && layout.regions.iter().any(|r| !r.encrypted), "{:?}", layout.regions);
        let ends = layout.regions.iter().skip(1).map(|r| r.offset).chain([layout.regions_end]);
        let straddles = layout
            .regions
            .iter()
            .zip(ends)
            .any(|(r, end)| r.offset < layout.indirect_offset && end > layout.indirect_offset);
        if meta_hash_layer {
            assert_eq!(layout.regions_end, layout.indirect_offset);
            assert!(!straddles && layout.meta_hash_offset >= layout.ctr_ex_offset + layout.ctr_ex_size);
            assert!(layout.meta_hash_size > 0);
        } else {
            assert!(straddles, "no region covers both the update data and the indirect table");
            assert_eq!((layout.regions_end, layout.meta_hash_size), (layout.ctr_ex_offset, 0));
        }

        let up_program = NcaBuilder::new(NcaContentType::Program, UPDATE_ID)
            .section_key(UPDATE_KEY)
            .section(Section::pfs0(&as_refs(&up_exefs)))
            .section(Section::patch(patch))
            .build(&keys);
        // The FS header of the patch section (section 1) says whether it has the layer.
        let up_header = NcaHeader::decrypt(&up_program.bytes, &keys).unwrap();
        let fs = up_header.fs_header(1);
        assert_eq!(fs[5], u8::from(meta_hash_layer));
        assert_eq!(u64le(fs, 0x1A0) != 0 && u64le(fs, 0x1A8) != 0, meta_hash_layer);
        let up_control_nca = NcaBuilder::new(NcaContentType::Control, UPDATE_ID)
            .section_key(UPDATE_CONTROL_KEY)
            .section(Section::romfs(romfs_image(&up_control, &[])))
            .build(&keys);
        let up_meta = MetaBuilder::patch(APP_ID, UPDATE_VERSION, UPDATE_RSV)
            .content(&up_program, cnmt::CT_PROGRAM)
            .content(&up_control_nca, cnmt::CT_CONTROL)
            .build(&keys);
        let update_nsp = tmp.path().join("in").join("Test Game [Update].nsp");
        let nsp = add_nca(NspBuilder::new(), &up_program, &keys, up_program_stored);
        add_nca(nsp, &up_control_nca, &keys, up_control_stored).nca(&up_meta).write(&update_nsp);

        // Scan both files and group them into one game.
        let mut titles = scan::scan_file(&base_nsp, &keys).expect("scanning the base NSP");
        titles.extend(scan::scan_file(&update_nsp, &keys).expect("scanning the update NSP"));
        assert_eq!(titles.len(), 2);
        assert!(titles.iter().flat_map(|t| &t.contents).all(|n| n.is_ncz == ncz));
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
        let mut logs = Vec::new();
        let mut progress = |p: Progress| match p {
            Progress::Bytes { done, total } => last_bytes = Some((done, total)),
            Progress::Log(message) => logs.push(message),
        };
        let opts = ExtractOptions::default();
        let result = extract_game(&keys, &selected, &out, &opts, &never, &mut progress).expect("extracting");
        assert_eq!(result, out);
        assert_extraction(&out, &files, &dirs);
        assert!(!partial_path(&out).exists());
        assert!(!temp_path(&out).exists());
        assert_eq!(last_bytes, Some((total, total)));
        // The base game's program (logo and the base for the patch), the update's program and its control data are
        // read, in both passes; the base game's control data is not (the update has its own). Each is decompressed
        // once.
        let want = if ncz { names_of(&[&base_program, &up_program, &up_control_nca]) } else { Vec::new() };
        assert_eq!(decompressed_names(&logs), want);
        if ncz {
            let all = [&base_program, &base_control_nca, &up_program, &up_control_nca];
            assert_ncz_contents_restore(&game.titles, &all, tmp.path());
        }
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

    // -----------------------------------------------------------------------------------------------------
    // NSZ, multi-program titles, DLC and DLC updates
    // -----------------------------------------------------------------------------------------------------

    /// Test files: ("a/b.bin", data).
    type FileList<'a> = [(&'a str, Vec<u8>)];

    /// Expected output files: each `(folder, files)` group's files, as "<folder>/<path>".
    fn expected(groups: &[(&str, &FileList)]) -> BTreeMap<String, Vec<u8>> {
        let mut files = BTreeMap::new();
        for (folder, group) in groups {
            for (path, data) in *group {
                assert!(files.insert(format!("{folder}/{path}"), data.clone()).is_none(), "{folder}/{path} twice");
            }
        }
        files
    }

    /// The titles of the NSPs, scanned.
    fn scan_all(keys: &Keys, nsps: &[&Path]) -> Vec<Title> {
        nsps.iter().flat_map(|nsp| scan::scan_file(nsp, keys).expect("scanning an NSP")).collect()
    }

    /// A small base game, `app_id`'s: executables, a RomFS and control data, written to `nsp` with the program and
    /// control NCAs stored the way `stored` says.
    struct SmallBase {
        program: BuiltNca,
        control: BuiltNca,
        /// What extracting the game produces.
        files: BTreeMap<String, Vec<u8>>,
    }

    fn write_small_base(keys: &Keys, nsp: &Path, app_id: u64, stored: (Stored, Stored)) -> SmallBase {
        const CONTROL_KEY: Key128 =
            [0x29, 0xB4, 0xE0, 0x71, 0x5C, 0x1A, 0xD6, 0x83, 0x4F, 0xA8, 0x0B, 0xF2, 0x97, 0x3D, 0xC5, 0x6E];
        let exefs = [("main", pattern(300, 1)), ("main.npdm", pattern(77, 2))];
        let romfs = [("top.txt", b"a file in the root".to_vec()), ("data/big.bin", pattern(70_000, 3))];
        let control = [
            ("control.nacp", build_nacp("Small Game", "Test Publisher", "1.0.0")),
            ("icon_AmericanEnglish.dat", pattern(2048, 4)),
        ];
        let program = NcaBuilder::new(NcaContentType::Program, app_id)
            .section(Section::pfs0(&as_refs(&exefs)))
            .section(Section::romfs(romfs_image(&romfs, &[])))
            .build(keys);
        let control_nca = NcaBuilder::new(NcaContentType::Control, app_id)
            .section_key(CONTROL_KEY)
            .section(Section::romfs(romfs_image(&control, &[])))
            .build(keys);
        let meta = MetaBuilder::application(app_id, 0, 0x0001_0000)
            .content(&program, cnmt::CT_PROGRAM)
            .content(&control_nca, cnmt::CT_CONTROL)
            .build(keys);
        let builder = add_nca(NspBuilder::new(), &program, keys, stored.0);
        add_nca(builder, &control_nca, keys, stored.1).nca(&meta).write(nsp);
        let files = expected(&[("exefs", &exefs), ("romfs", &romfs), ("control", &control)]);
        SmallBase { program, control: control_nca, files }
    }

    /// Cancelling as soon as an NCZ is about to be decompressed stops there: the extraction fails as cancelled, and
    /// neither the output, `.partial` nor `.cartwrite-tmp` is left behind. Decompressing itself checks the flag for every
    /// chunk it writes.
    #[test]
    fn extract_nsz_cancelled_while_decompressing_leaves_nothing_behind() {
        const APP_ID: u64 = 0x0100_0000_0006_0000;
        let tmp = TempDir::new("extract-nsz-cancel");
        let keys = TestKeys::keys(&tmp.path().join("keys"));
        let nsp = tmp.path().join("in").join("Small Game.nsp");
        let base = write_small_base(&keys, &nsp, APP_ID, (Some(NczMode::Stream), Some(NczMode::Block(14))));

        let games = plan::group(scan_all(&keys, &[&nsp]));
        assert_eq!(games.len(), 1);
        let selected: Vec<&Title> = games[0].titles.iter().collect();
        assert!(selected[0].contents.iter().all(|n| n.is_ncz));

        let out = tmp.path().join("out").join(&games[0].name);
        let cancel = AtomicBool::new(false);
        let mut logs = Vec::new();
        let mut progress = |p: Progress| {
            if let Progress::Log(message) = p {
                if message.starts_with("Decompressing ") {
                    cancel.store(true, Ordering::Relaxed);
                }
                logs.push(message);
            }
        };
        let opts = ExtractOptions::default();
        let err = extract_game(&keys, &selected, &out, &opts, &cancel, &mut progress).expect_err("not cancelled");
        assert!(matches!(err, Error::Cancelled), "{err}");
        // It stopped at the first NCZ: no other NCA was decompressed and nothing was extracted.
        assert_eq!(logs, [format!("Decompressing {}", base.program.file_name())]);
        assert!(!out.exists());
        assert!(!partial_path(&out).exists());
        assert!(!temp_path(&out).exists());

        // The flag is checked for every chunk: with it set, restoring writes the head and then stops at the first
        // chunk of the rest.
        let program_ref = selected[0].contents.iter().find(|n| n.content_type == cnmt::CT_PROGRAM).unwrap();
        let restored = tmp.path().join("restored.nca");
        let err = restore_ncz(program_ref, &restored, &AtomicBool::new(true)).expect_err("not cancelled");
        assert!(matches!(err, Error::Cancelled), "{err}");
        assert_eq!(fs::metadata(&restored).unwrap().len(), UNCOMPRESSED_HEADER);
        restore_ncz(program_ref, &restored, &AtomicBool::new(false)).expect("restoring");
        assert!(fs::read(&restored).unwrap() == base.program.bytes);
        assert_ne!(base.program.bytes, base.control.bytes);
    }

    /// An NCZ is restored once however often it is asked for, but the cache tells NCZs apart by file and offset,
    /// not by name: the same content in two files (so with the same name) is restored twice, to two files.
    #[test]
    fn ncz_cache_keys_are_source_file_and_offset() {
        const APP_ID: u64 = 0x0100_0000_0009_0000;
        let tmp = TempDir::new("extract-ncz-cache");
        let keys = TestKeys::keys(&tmp.path().join("keys"));
        let stored = (Some(NczMode::Stream), Some(NczMode::Block(14)));
        let (first, second) =
            (tmp.path().join("one").join("Small Game.nsp"), tmp.path().join("two").join("Small Game.nsp"));
        let base = write_small_base(&keys, &first, APP_ID, stored);
        write_small_base(&keys, &second, APP_ID, stored);
        let program_of = |nsp: &Path| {
            let titles = scan_all(&keys, &[nsp]);
            titles[0].contents.iter().find(|n| n.content_type == cnmt::CT_PROGRAM).cloned().unwrap()
        };
        let (a, b) = (program_of(&first), program_of(&second));
        assert_eq!(a.out_name, b.out_name);

        let mut cache = NczCache::new(tmp.path().join("cache"));
        assert!(cache.path(&a).is_err(), "found an NCZ that was never restored");
        let mut logs = Vec::new();
        let mut progress = |p: Progress| {
            if let Progress::Log(message) = p {
                logs.push(message);
            }
        };
        for _ in 0..2 {
            cache.restore_all([&a, &b, &a], &AtomicBool::new(false), &mut progress).expect("restoring");
        }
        assert_eq!(logs, vec![format!("Decompressing {}", a.out_name); 2]);
        let (path_a, path_b) = (cache.path(&a).unwrap(), cache.path(&b).unwrap());
        assert_ne!(path_a, path_b);
        for path in [path_a, path_b] {
            assert!(fs::read(path).unwrap() == base.program.bytes, "{}", path.display());
        }
    }

    /// A base game of two programs, `id_offset` 0 and 1, each with its own control data, and an update that has a
    /// program for both: it patches program 0's RomFS, and for program 1 only replaces the executables, so that
    /// program's RomFS and boot logo come from the base game unpatched. The update has control data for program 0
    /// only. Program 0 is extracted at the root and program 1 into `program1`.
    #[test]
    fn extract_multi_program_game_with_update_end_to_end() {
        const APP_ID: u64 = 0x0100_0000_0007_0000;
        const UPDATE_ID: u64 = APP_ID | 0x800;
        const CONTROL_KEY_0: Key128 =
            [0x12, 0x8E, 0xC3, 0x5A, 0x77, 0xD0, 0x31, 0xBB, 0x04, 0xE9, 0x6F, 0xA2, 0x58, 0x1C, 0x93, 0xF7];
        const CONTROL_KEY_1: Key128 =
            [0xE4, 0x39, 0x80, 0xDB, 0x16, 0x6A, 0xCF, 0x52, 0xA7, 0x0D, 0x3B, 0x91, 0xF8, 0x45, 0x2E, 0xB0];
        const UPDATE_KEY_0: Key128 =
            [0x5F, 0xA1, 0x08, 0xD7, 0x6C, 0xE3, 0x94, 0x2B, 0xB6, 0x70, 0x1D, 0xC8, 0x43, 0xFA, 0x85, 0x0E];
        const UPDATE_KEY_1: Key128 =
            [0xC9, 0x62, 0xB5, 0x1E, 0xF0, 0x37, 0x8A, 0x4D, 0x91, 0xDC, 0x26, 0x7B, 0xE8, 0x03, 0xAF, 0x54];
        const UPDATE_CONTROL_KEY: Key128 =
            [0x7A, 0x15, 0xE6, 0xCB, 0x30, 0x9D, 0x42, 0xF1, 0x68, 0xB3, 0x0C, 0x95, 0xDE, 0x27, 0x81, 0x4A];

        let tmp = TempDir::new("extract-multi-program");
        let keys = TestKeys::keys(&tmp.path().join("keys"));

        // The base game's programs. Every file differs, so that mixing up programs shows.
        let stay = pattern(60_000, 4);
        let exefs0 = [("main", pattern(300, 1)), ("main.npdm", pattern(77, 2))];
        let logo0 = [("NintendoLogo.png", pattern(1013, 3))];
        let romfs0 = [
            ("top.txt", b"program zero".to_vec()),
            ("data/stay.bin", stay.clone()),
            ("data/changes.bin", pattern(30_000, 5)),
            ("data/removed.bin", pattern(10_000, 6)),
        ];
        let control0 = [
            ("control.nacp", build_nacp("Two Programs", "Test Publisher", "1.0.0")),
            ("icon_AmericanEnglish.dat", pattern(2048, 7)),
        ];
        let exefs1 = [("main", pattern(222, 8)), ("main.npdm", pattern(66, 9))];
        let logo1 = [("NintendoLogo.png", pattern(900, 10))];
        let romfs1 = [("only_in_one.txt", b"program one".to_vec()), ("data/p1.bin", pattern(25_000, 11))];
        let control1 = [
            ("control.nacp", build_nacp("The Other Program", "Test Publisher", "1.0.0")),
            ("icon_AmericanEnglish.dat", pattern(1500, 12)),
        ];
        let base_romfs0 = Section::romfs(romfs_image(&romfs0, &[]));
        let base_p0 = NcaBuilder::new(NcaContentType::Program, APP_ID)
            .section(Section::pfs0(&as_refs(&exefs0)))
            .section(base_romfs0.clone())
            .section(Section::pfs0(&as_refs(&logo0)))
            .build(&keys);
        let base_p1 = NcaBuilder::new(NcaContentType::Program, APP_ID + 1)
            .section(Section::pfs0(&as_refs(&exefs1)))
            .section(Section::romfs(romfs_image(&romfs1, &["empty1"])))
            .section(Section::pfs0(&as_refs(&logo1)))
            .build(&keys);
        let base_c0 = NcaBuilder::new(NcaContentType::Control, APP_ID)
            .section_key(CONTROL_KEY_0)
            .section(Section::romfs(romfs_image(&control0, &[])))
            .build(&keys);
        let base_c1 = NcaBuilder::new(NcaContentType::Control, APP_ID + 1)
            .section_key(CONTROL_KEY_1)
            .section(Section::romfs(romfs_image(&control1, &[])))
            .build(&keys);
        let base_meta = MetaBuilder::application(APP_ID, 0, 0x0001_0000)
            .content(&base_p0, cnmt::CT_PROGRAM)
            .content_at(&base_p1, cnmt::CT_PROGRAM, 1)
            .content(&base_c0, cnmt::CT_CONTROL)
            .content_at(&base_c1, cnmt::CT_CONTROL, 1)
            .build(&keys);
        let base_nsp = tmp.path().join("in").join("Two Programs.nsp");
        NspBuilder::new().nca(&base_p0).nca(&base_p1).nca(&base_c0).nca(&base_c1).nca(&base_meta).write(&base_nsp);

        // The update. Program 0 gets new executables and a patched RomFS (it keeps the base's logo); program 1 only
        // gets new executables.
        let up_exefs0 = [("main", pattern(410, 13)), ("main.npdm", pattern(91, 14))];
        let new_romfs0 = [
            ("top.txt", b"program zero, patched".to_vec()),
            ("data/stay.bin", stay),
            ("data/changes.bin", pattern(33_000, 15)),
            ("data/added.bin", pattern(12_000, 16)),
        ];
        let up_control0 = [
            ("control.nacp", build_nacp("Two Programs", "Test Publisher", "1.1.0")),
            ("icon_AmericanEnglish.dat", pattern(3000, 17)),
        ];
        let up_exefs1 = [("main", pattern(500, 18)), ("main.npdm", pattern(70, 19))];
        let patch = PatchSection::new(&base_romfs0.plaintext(), &romfs_image(&new_romfs0, &[])).chunk_size(0x10);
        let layout = patch.layout();
        let used = |storage| layout.entries.iter().filter(|e| e.storage_index == storage).count();
        assert!(used(0) > 0 && used(1) > 0, "{} from the base game, {} from the update", used(0), used(1));
        let up_p0 = NcaBuilder::new(NcaContentType::Program, UPDATE_ID)
            .section_key(UPDATE_KEY_0)
            .section(Section::pfs0(&as_refs(&up_exefs0)))
            .section(Section::patch(patch))
            .build(&keys);
        let up_p1 = NcaBuilder::new(NcaContentType::Program, UPDATE_ID + 1)
            .section_key(UPDATE_KEY_1)
            .section(Section::pfs0(&as_refs(&up_exefs1)))
            .build(&keys);
        let up_c0 = NcaBuilder::new(NcaContentType::Control, UPDATE_ID)
            .section_key(UPDATE_CONTROL_KEY)
            .section(Section::romfs(romfs_image(&up_control0, &[])))
            .build(&keys);
        let up_meta = MetaBuilder::patch(APP_ID, 65536, 0x0002_0000)
            .content(&up_p0, cnmt::CT_PROGRAM)
            .content_at(&up_p1, cnmt::CT_PROGRAM, 1)
            .content(&up_c0, cnmt::CT_CONTROL)
            .build(&keys);
        let update_nsp = tmp.path().join("in").join("Two Programs [Update].nsp");
        NspBuilder::new().nca(&up_p0).nca(&up_p1).nca(&up_c0).nca(&up_meta).write(&update_nsp);

        // The scan tells the programs and control data apart by id_offset.
        let titles = scan_all(&keys, &[&base_nsp, &update_nsp]);
        let id_offsets = |kind| -> Vec<(u8, u8)> {
            let title = titles.iter().find(|t| t.kind == kind).unwrap();
            title.contents.iter().map(|n| (n.content_type, n.id_offset)).collect()
        };
        let (program, control) = (cnmt::CT_PROGRAM, cnmt::CT_CONTROL);
        assert_eq!(id_offsets(TitleKind::Base), [(program, 0), (program, 1), (control, 0), (control, 1)]);
        assert_eq!(id_offsets(TitleKind::Update), [(program, 0), (program, 1), (control, 0)]);

        // Program 0: the update's executables, patched RomFS and control data, the base game's logo. Program 1: the
        // update's executables; everything else is the base game's, and not patched.
        let files = expected(&[
            ("exefs", &up_exefs0),
            ("logo", &logo0),
            ("romfs", &new_romfs0),
            ("control", &up_control0),
            ("program1/exefs", &up_exefs1),
            ("program1/logo", &logo1),
            ("program1/romfs", &romfs1),
            ("program1/control", &control1),
        ]);
        let dirs = implied_dirs(&files, &["program1/romfs/empty1"]);
        let total: u64 = files.values().map(|d| d.len() as u64).sum();
        let (out, last_bytes) = extract_nsps(&keys, &[&base_nsp, &update_nsp], &tmp.path().join("out"));
        assert_extraction(&out, &files, &dirs);
        assert_eq!(last_bytes, Some((total, total)));
    }

    const DLC_APP_ID: u64 = 0x0100_0000_0008_0000;
    const DLC_ID: u64 = DLC_APP_ID + 0x1001;
    const DLC_UPDATE_ID: u64 = DLC_APP_ID + 0x1801;

    /// A base game with a DLC and an update of that DLC, in three NSPs.
    struct DlcGame {
        base_nsp: PathBuf,
        dlc_nsp: PathBuf,
        update_nsp: PathBuf,
        /// What extracting the base game alone produces.
        base_files: BTreeMap<String, Vec<u8>>,
        /// The DLC's RomFS, and the DLC's RomFS once its update is applied.
        dlc_romfs: Vec<(&'static str, Vec<u8>)>,
        new_dlc_romfs: Vec<(&'static str, Vec<u8>)>,
    }

    /// Writes a DLC game into `dir`. The DLC update's data NCA has a RomFS section that is a patch of the DLC's
    /// (`patch`) or a whole RomFS of its own.
    fn write_dlc_game(keys: &Keys, dir: &Path, patch: bool) -> DlcGame {
        const UPDATE_KEY: Key128 =
            [0x83, 0x2C, 0xF9, 0x56, 0x0B, 0xD4, 0x7E, 0xA1, 0x35, 0xC0, 0x68, 0x9A, 0xE7, 0x1F, 0x42, 0xBD];
        let (base_nsp, dlc_nsp, update_nsp) =
            (dir.join("Small Game.nsp"), dir.join("Small Game [DLC].nsp"), dir.join("Small Game [DLC Update].nsp"));
        let base = write_small_base(keys, &base_nsp, DLC_APP_ID, (None, None));

        let stay = pattern(50_000, 20);
        let dlc_romfs = vec![
            ("music/theme.bin", pattern(80_000, 21)),
            ("music/stay.bin", stay.clone()),
            ("levels/one.txt", b"level one".to_vec()),
            ("levels/two.txt", pattern(3000, 22)),
        ];
        let new_dlc_romfs = vec![
            ("music/theme.bin", pattern(85_000, 23)),
            ("music/stay.bin", stay),
            ("levels/one.txt", b"level one, fixed".to_vec()),
            ("levels/three.txt", pattern(5000, 24)),
        ];
        let dlc_section = Section::romfs(romfs_image(&dlc_romfs, &[]));
        let dlc_data = NcaBuilder::new(NcaContentType::Data, DLC_ID).section(dlc_section.clone()).build(keys);
        let dlc_meta = MetaBuilder::add_on_content(DLC_ID, DLC_APP_ID, 0).content(&dlc_data, cnmt::CT_DATA).build(keys);
        NspBuilder::new().nca(&dlc_data).nca(&dlc_meta).write(&dlc_nsp);

        let new_image = romfs_image(&new_dlc_romfs, &[]);
        let update_section = if patch {
            let patch = PatchSection::new(&dlc_section.plaintext(), &new_image).chunk_size(0x10);
            let layout = patch.layout();
            let used = |storage| layout.entries.iter().filter(|e| e.storage_index == storage).count();
            assert!(used(0) > 0 && used(1) > 0, "{} from the DLC, {} from the update", used(0), used(1));
            Section::patch(patch)
        } else {
            Section::romfs(new_image)
        };
        let update_data = NcaBuilder::new(NcaContentType::Data, DLC_UPDATE_ID)
            .section_key(UPDATE_KEY)
            .section(update_section)
            .build(keys);
        let update_meta = MetaBuilder::data_patch(DLC_UPDATE_ID, DLC_ID, DLC_APP_ID, 0x2_0000)
            .content(&update_data, cnmt::CT_DATA)
            .build(keys);
        NspBuilder::new().nca(&update_data).nca(&update_meta).write(&update_nsp);
        DlcGame { base_nsp, dlc_nsp, update_nsp, base_files: base.files, dlc_romfs, new_dlc_romfs }
    }

    /// The files extraction must produce: the base game's, and a DLC's RomFS under `dlc/<DLC id>/romfs`.
    fn with_dlc_romfs(
        base_files: &BTreeMap<String, Vec<u8>>,
        dlc_romfs: &[(&str, Vec<u8>)],
    ) -> BTreeMap<String, Vec<u8>> {
        let mut files = base_files.clone();
        files.extend(expected(&[(&format!("dlc/{DLC_ID:016X}/romfs"), dlc_romfs)]));
        files
    }

    /// The game made of the NSPs of `g`, as the scan and grouping find it: one game of a base, a DLC and a DLC update.
    fn group_dlc_game(keys: &Keys, g: &DlcGame) -> plan::Game {
        let mut games = plan::group(scan_all(keys, &[&g.base_nsp, &g.dlc_nsp, &g.update_nsp]));
        assert_eq!(games.len(), 1);
        let game = games.remove(0);
        let kinds: Vec<_> = game.titles.iter().map(|t| (t.kind, t.title_id, t.data_id)).collect();
        assert_eq!(
            kinds,
            [
                (TitleKind::Base, DLC_APP_ID, None),
                (TitleKind::Dlc, DLC_ID, None),
                (TitleKind::DlcUpdate, DLC_UPDATE_ID, Some(DLC_ID)),
            ]
        );
        assert!(game.warnings().is_empty(), "{:?}", game.warnings());
        game
    }

    /// Extracts the titles of `game` of the given `kinds` into `out`.
    fn extract_kinds(
        keys: &Keys,
        game: &plan::Game,
        kinds: &[TitleKind],
        include_dlc: bool,
        out: &Path,
    ) -> Result<PathBuf> {
        let selected: Vec<&Title> = game.titles.iter().filter(|t| kinds.contains(&t.kind)).collect();
        let opts = ExtractOptions { include_dlc, ..Default::default() };
        extract_game(keys, &selected, out, &opts, &AtomicBool::new(false), &mut |_| {})
    }

    /// A DLC update that patches the DLC's RomFS: with DLC extraction on, `dlc/<DLC id>/romfs` is the patched tree.
    /// Without its DLC the update can't be applied, which is an error; with DLC extraction off, the DLC titles,
    /// updates included, are left out.
    #[test]
    fn extract_dlc_with_its_patching_update_end_to_end() {
        let tmp = TempDir::new("extract-dlc-update");
        let keys = TestKeys::keys(&tmp.path().join("keys"));
        let g = write_dlc_game(&keys, &tmp.path().join("in"), true);
        let game = group_dlc_game(&keys, &g);
        let out_root = tmp.path().join("out");
        let (all, base_and_dlc, base_and_update) = (
            [TitleKind::Base, TitleKind::Dlc, TitleKind::DlcUpdate],
            [TitleKind::Base, TitleKind::Dlc],
            [TitleKind::Base, TitleKind::DlcUpdate],
        );

        // The DLC with its update: the patched tree, and nothing of the DLC's own that the update dropped.
        let files = with_dlc_romfs(&g.base_files, &g.new_dlc_romfs);
        let out = extract_kinds(&keys, &game, &all, true, &out_root.join("patched")).expect("extracting");
        assert_extraction(&out, &files, &implied_dirs(&files, &[]));
        assert!(!out.join("dlc").join(format!("{DLC_ID:016X}")).join("romfs/levels/two.txt").exists());

        // The DLC alone: its RomFS as it is.
        let files = with_dlc_romfs(&g.base_files, &g.dlc_romfs);
        let out = extract_kinds(&keys, &game, &base_and_dlc, true, &out_root.join("unpatched")).expect("extracting");
        assert_extraction(&out, &files, &implied_dirs(&files, &[]));

        // The update without its DLC.
        let out = out_root.join("orphan");
        let err = extract_kinds(&keys, &game, &base_and_update, true, &out).expect_err("applied an update to nothing");
        assert!(matches!(&err, Error::Unsupported(m) if m.contains("without the DLC it updates")), "{err}");
        assert!(err.to_string().contains(&format!("{DLC_ID:016X}")), "{err}");
        assert!(!out.exists() && !partial_path(&out).exists() && !temp_path(&out).exists());

        // DLC extraction off: no DLC folder, whatever DLC titles are selected, and no complaint about the update.
        for (name, kinds) in [("all", &all[..]), ("update only", &base_and_update[..]), ("dlc only", &base_and_dlc[..])]
        {
            let out = extract_kinds(&keys, &game, kinds, false, &out_root.join(format!("no dlc, {name}"))).expect(name);
            assert_extraction(&out, &g.base_files, &implied_dirs(&g.base_files, &[]));
        }
    }

    /// A DLC update whose RomFS section is a plain one, not a patch, replaces the DLC's RomFS.
    #[test]
    fn extract_dlc_update_with_a_whole_romfs_replaces_the_dlc_romfs() {
        let tmp = TempDir::new("extract-dlc-replace");
        let keys = TestKeys::keys(&tmp.path().join("keys"));
        let g = write_dlc_game(&keys, &tmp.path().join("in"), false);
        let game = group_dlc_game(&keys, &g);

        let files = with_dlc_romfs(&g.base_files, &g.new_dlc_romfs);
        let all = [TitleKind::Base, TitleKind::Dlc, TitleKind::DlcUpdate];
        let out = extract_kinds(&keys, &game, &all, true, &tmp.path().join("out")).expect("extracting");
        assert_extraction(&out, &files, &implied_dirs(&files, &[]));
        assert!(!out.join("dlc").join(format!("{DLC_ID:016X}")).join("romfs/levels/two.txt").exists());
    }
}
