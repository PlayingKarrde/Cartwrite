//! Reads input files and describes the titles (base / update / DLC) they contain.

use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::cnmt::{self, Cnmt};
use crate::container::{self, ContainerKind, Entry};
use crate::crypto::Key128;
use crate::error::{fmt_err, Error, Result};
use crate::keys::Keys;
use crate::nacp::{self, Nacp};
use crate::nca::{self, FileNca, NcaContentType, NcaHeader, NcaSource, HEADER_SIZE};
use crate::ncz::MemNcz;
use crate::ticket::Ticket;
use crate::util::{hex, read_vec_at};

pub const EXTENSIONS: [&str; 4] = ["nsp", "nsz", "xci", "xcz"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TitleKind {
    Base,
    Update,
    Dlc,
    DlcUpdate,
}

impl TitleKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Base => "Base",
            Self::Update => "Update",
            Self::Dlc => "DLC",
            Self::DlcUpdate => "DLC update",
        }
    }
}

/// One NCA inside a source container.
#[derive(Clone, Debug)]
pub struct NcaRef {
    pub source: Arc<PathBuf>,
    /// Absolute offset in the source file.
    pub offset: u64,
    pub stored_size: u64,
    /// Size once decompressed (equals `stored_size` unless `is_ncz`).
    pub nca_size: u64,
    pub is_ncz: bool,
    /// Name inside the output (always `.nca` / `.cnmt.nca`).
    pub out_name: String,
    /// cnmt content type (`cnmt::CT_*`).
    pub content_type: u8,
    pub key_generation: u8,
    pub rights_id: Option<[u8; 16]>,
}

#[derive(Clone, Debug)]
pub struct Title {
    pub title_id: u64,
    pub application_id: u64,
    pub version: u32,
    pub kind: TitleKind,
    pub required_system_version: Option<u32>,
    pub meta: NcaRef,
    pub contents: Vec<NcaRef>,
    pub tickets: HashMap<[u8; 16], Ticket>,
    pub nacp: Option<Nacp>,
    pub icon: Option<Arc<Vec<u8>>>,
    pub source: Arc<PathBuf>,
    pub source_kind: ContainerKind,
    /// False if other titles in the same source file couldn't be read (so the file holds
    /// content that isn't represented here).
    pub source_complete: bool,
    pub warnings: Vec<String>,
}

impl Title {
    /// Highest key generation used by any of this title's NCAs.
    pub fn key_generation(&self) -> u8 {
        self.contents.iter().chain([&self.meta]).map(|n| n.key_generation).max().unwrap_or(0)
    }

    pub fn ncas(&self, include_deltas: bool) -> impl Iterator<Item = &NcaRef> {
        self.contents
            .iter()
            .filter(move |n| include_deltas || n.content_type != cnmt::CT_DELTA_FRAGMENT)
            .chain([&self.meta])
    }

    pub fn size(&self, include_deltas: bool) -> u64 {
        self.ncas(include_deltas).map(|n| n.nca_size).sum()
    }

    /// Decrypted title key for an NCA with a rights ID.
    pub fn title_key(&self, keys: &Keys, header: &NcaHeader) -> Result<Option<Key128>> {
        if !header.has_rights_id() {
            return Ok(None);
        }
        let rid = header.rights_id();
        let Some(t) = self.tickets.get(&rid) else {
            return Err(Error::Unsupported(format!(
                "{}: no ticket for rights ID {} (the NSP is missing its .tik file)",
                self.source.display(),
                hex(&rid)
            )));
        };
        if t.key_type != 0 {
            return Err(Error::Unsupported(format!(
                "{}: personalized (console-bound) ticket, which can't be converted",
                self.source.display()
            )));
        }
        nca::decrypt_title_key(keys, &t.title_key_block, header.key_generation()).map(Some)
    }

    /// The version players see (e.g. "2.3.24.2"), from the title's own control data.
    /// DLC and titles whose control data couldn't be read have none.
    pub fn display_version(&self) -> Option<&str> {
        self.nacp.as_ref().map(|n| n.display_version.trim()).filter(|v| !v.is_empty())
    }

    /// Display version when known (`v2.3.24.2`), otherwise the internal number (`v196608`).
    pub fn version_label(&self) -> String {
        match self.display_version() {
            Some(v) => format!("v{v}"),
            None => format!("v{}", self.version),
        }
    }
}

/// Expands folders (recursively) into the list of supported files.
pub fn collect_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_dir() {
            let mut children: Vec<PathBuf> = std::fs::read_dir(p)
                .map(|rd| rd.filter_map(|e| e.ok().map(|e| e.path())).collect())
                .unwrap_or_default();
            children.sort();
            out.extend(collect_files(&children));
        } else if is_supported(p) {
            out.push(p.clone());
        }
    }
    out
}

pub fn is_supported(p: &Path) -> bool {
    p.extension().and_then(|e| e.to_str()).is_some_and(|e| EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
}

/// Parses one NSP/NSZ/XCI/XCZ.
pub fn scan_file(path: &Path, keys: &Keys) -> Result<Vec<Title>> {
    let (mut f, kind, entries) = container::open(path)?;
    let source = Arc::new(path.to_path_buf());
    let by_name: HashMap<String, &Entry> = entries.iter().map(|e| (e.name.to_ascii_lowercase(), e)).collect();

    let mut tickets = HashMap::new();
    for e in entries.iter().filter(|e| e.name.to_ascii_lowercase().ends_with(".tik")) {
        let data = read_vec_at(&mut f, e.offset, e.size.min(0x1000) as usize)?;
        if let Ok(t) = Ticket::parse(&data) {
            tickets.insert(t.rights_id, t);
        }
    }

    let mut titles = Vec::new();
    let mut failures = Vec::new();
    for meta_entry in entries.iter().filter(|e| e.name.to_ascii_lowercase().ends_with(".cnmt.nca")) {
        match read_title(&mut f, meta_entry, &by_name, &tickets, &source, kind, keys) {
            Ok(Some(t)) => titles.push(t),
            Ok(None) => {}
            Err(e) => failures.push((meta_entry.name.clone(), e)),
        }
    }
    if titles.is_empty() {
        return match failures.into_iter().next() {
            Some((_, e)) => Err(e),
            None => fmt_err("no titles found (no .cnmt.nca)"),
        };
    }
    // Keep what we could read, but make sure skipped content isn't silently dropped.
    for (name, e) in &failures {
        for t in &mut titles {
            t.source_complete = false;
            t.warnings.push(format!("skipped {name} in this file: {e}"));
        }
    }
    Ok(titles)
}

/// Reads one title from its meta NCA. `Ok(None)` for meta types we don't handle (e.g. deltas).
fn read_title(
    f: &mut File,
    meta_entry: &Entry,
    by_name: &HashMap<String, &Entry>,
    tickets: &HashMap<[u8; 16], Ticket>,
    source: &Arc<PathBuf>,
    kind: ContainerKind,
    keys: &Keys,
) -> Result<Option<Title>> {
    let (header, cnmt) = read_cnmt(f, meta_entry, keys)?;
    let kind_t = match cnmt.meta_type {
        cnmt::META_APPLICATION => TitleKind::Base,
        cnmt::META_PATCH => TitleKind::Update,
        cnmt::META_ADD_ON_CONTENT => TitleKind::Dlc,
        cnmt::META_DATA_PATCH => TitleKind::DlcUpdate,
        _ => return Ok(None),
    };
    let meta = NcaRef {
        source: source.clone(),
        offset: meta_entry.offset,
        stored_size: meta_entry.size,
        nca_size: meta_entry.size,
        is_ncz: false,
        out_name: meta_entry.name.clone(),
        content_type: cnmt::CT_META,
        key_generation: header.key_generation(),
        rights_id: None,
    };

    let mut warnings = Vec::new();
    let mut contents = Vec::new();
    for rec in &cnmt.contents {
        let id = rec.content_id_hex();
        let found = by_name
            .get(&format!("{id}.nca"))
            .map(|e| (*e, false))
            .or_else(|| by_name.get(&format!("{id}.ncz")).map(|e| (*e, true)));
        let Some((e, is_ncz)) = found else {
            if rec.content_type != cnmt::CT_DELTA_FRAGMENT {
                warnings.push(format!("missing content {id}.nca"));
            }
            continue;
        };
        let enc = read_vec_at(f, e.offset, HEADER_SIZE)?;
        let h = NcaHeader::decrypt(&enc, keys)?;
        contents.push(NcaRef {
            source: source.clone(),
            offset: e.offset,
            stored_size: e.size,
            nca_size: if is_ncz { h.nca_size() } else { e.size },
            is_ncz,
            out_name: format!("{id}.nca"),
            content_type: rec.content_type,
            key_generation: h.key_generation(),
            rights_id: h.has_rights_id().then(|| h.rights_id()),
        });
    }

    let mut title = Title {
        title_id: cnmt.title_id,
        application_id: cnmt.application_id,
        version: cnmt.version,
        kind: kind_t,
        required_system_version: cnmt.required_system_version,
        meta,
        contents,
        tickets: tickets.clone(),
        nacp: None,
        icon: None,
        source: source.clone(),
        source_kind: kind,
        source_complete: true,
        warnings,
    };
    for n in &title.contents {
        if let Some(rid) = n.rights_id {
            if !title.tickets.contains_key(&rid) {
                title.warnings.push(format!("no ticket for {}, so it can't be converted", n.out_name));
            }
        }
    }
    if let Some(ctrl) = title.contents.iter().find(|n| n.content_type == cnmt::CT_CONTROL).cloned() {
        match read_control(f, &ctrl, &title, keys) {
            Ok((nacp, icon)) => {
                title.nacp = Some(nacp);
                title.icon = icon.map(Arc::new);
            }
            Err(e) => title.warnings.push(format!("couldn't read game info: {e}")),
        }
    }
    Ok(Some(title))
}

fn read_cnmt(f: &mut File, e: &Entry, keys: &Keys) -> Result<(NcaHeader, Cnmt)> {
    let enc = read_vec_at(f, e.offset, HEADER_SIZE)?;
    let header = NcaHeader::decrypt(&enc, keys)?;
    if header.content_type() != NcaContentType::Meta {
        return fmt_err(format!("{} is not a meta NCA", e.name));
    }
    let key = header.section_key(keys, None)?;
    let layout = nca::sha256_layout(&header, 0)?;
    if layout.data_size > 16 << 20 {
        return fmt_err("meta NCA is implausibly large");
    }
    let mut src = FileNca { file: f, base: e.offset };
    let pfs0 = nca::read_section(&mut src, &header, &key, 0, layout.data_offset, layout.data_size as usize)?;
    let files = container::parse_pfs0_bytes(&pfs0)?;
    let Some(c) = files.iter().find(|x| x.name.ends_with(".cnmt")) else {
        return fmt_err("meta NCA contains no .cnmt");
    };
    let data = crate::util::slice(&pfs0, c.offset, c.size).ok_or_else(|| Error::Format("cnmt out of range".into()))?;
    let cnmt = Cnmt::parse(data)?;
    Ok((header, cnmt))
}

fn read_control(f: &mut File, n: &NcaRef, title: &Title, keys: &Keys) -> Result<(Nacp, Option<Vec<u8>>)> {
    let enc = read_vec_at(f, n.offset, HEADER_SIZE)?;
    let header = NcaHeader::decrypt(&enc, keys)?;
    let key = header.section_key(keys, title.title_key(keys, &header)?.as_ref())?;
    let mut mem;
    let mut file_src;
    let src: &mut dyn NcaSource = if n.is_ncz {
        mem = MemNcz::load(f, n.offset, n.stored_size, n.nca_size, 256 << 20)?;
        &mut mem
    } else {
        file_src = FileNca { file: f, base: n.offset };
        &mut file_src
    };
    let (romfs_off, _) = nca::ivfc_data_level(&header, 0)?;
    let mut read = |off: u64, len: usize| nca::read_section(src, &header, &key, 0, romfs_off + off, len);

    let Some((_, off, size)) = crate::romfs::find_root_file(&mut read, &["control.nacp"])? else {
        return fmt_err("control.nacp not found");
    };
    if size > 1 << 20 {
        return fmt_err("control.nacp is implausibly large");
    }
    let nacp = Nacp::parse(&read(off, size as usize)?).ok_or_else(|| Error::Format("bad NACP".into()))?;

    let names = nacp::icon_names(nacp.language);
    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let icon = match crate::romfs::find_root_file(&mut read, &name_refs)? {
        Some((_, off, size)) if size < 1 << 20 => Some(read(off, size as usize)?),
        _ => None,
    };
    Ok((nacp, icon))
}
