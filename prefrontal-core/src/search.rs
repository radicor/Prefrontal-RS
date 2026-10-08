//! Recall: tantivy full-text over code, docs, and commit messages.
//!
//! One index for everything, one document per file or commit. Projects are
//! the unit of (re)indexing — the watcher's per-project rescan maps 1:1 to
//! `delete_term(project) + re-add`. Snippets and line numbers come from the
//! file on disk at query time, so file content is indexed but never stored.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use prefrontal_protocol::SearchHit;
use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::{Field, Schema, Value, STORED, STRING, TEXT};
use tantivy::{doc, Index, IndexWriter, TantivyDocument, Term};

use crate::scan::SKIP_DIRS;
use crate::symbols;

const CODE_EXTENSIONS: &[&str] = &[
    "rs", "py", "js", "ts", "jsx", "tsx", "gd", "c", "h", "cpp", "hpp", "cc", "go", "java",
    "rb", "sh", "bash", "toml", "yaml", "yml", "css", "html", "slint", "sql", "proto", "json",
];
const DOC_EXTENSIONS: &[&str] = &["md", "markdown", "txt"];
const MAX_FILE_BYTES: u64 = 256 * 1024;
const MAX_COMMITS: usize = 1000;
const MAX_DEPTH: u32 = 8;
const SNIPPET_CHARS: usize = 160;

#[derive(Clone, Copy)]
pub struct Fields {
    pub project: Field,
    pub path: Field,
    pub kind: Field,
    pub content: Field,
    pub stored_text: Field,
    /// 1-based declaration line — set on symbol documents only.
    pub line: Field,
}
/// Owns the index *and* its writer behind one lock.
///
/// A panic mid-`add_document` used to poison a `Mutex<IndexWriter>` that every
/// later `.expect("index writer poisoned")` re-panicked on — after which
/// search silently answered from a frozen index forever, with no signal
/// anywhere. The charter already calls the index a rebuildable cache, so a
/// poison is repaired by wiping and reopening it; `is_healthy` then tells the
/// daemon it has an empty index to refill.
pub struct SearchIndex {
    dir: PathBuf,
    state: Mutex<State>,
    healthy: std::sync::atomic::AtomicBool,
}

struct State {
    index: Index,
    writer: IndexWriter,
    fields: Fields,
}

/// Default index home: `~/.local/share/prefrontal/index` — never inside projects.
pub fn default_index_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("prefrontal").join("index"))
}

fn schema() -> (Schema, Fields) {
    let mut b = Schema::builder();
    let fields = Fields {
        project: b.add_text_field("project", STRING | STORED),
        path: b.add_text_field("path", STRING | STORED),
        kind: b.add_text_field("kind", STRING | STORED),
        content: b.add_text_field("content", TEXT),
        stored_text: b.add_text_field("stored_text", STORED),
        line: b.add_u64_field("line", STORED),
    };
    (b.build(), fields)
}

/// Open (or create) the index for writing. A schema mismatch from an older
/// build wipes and recreates — the index is a cache, never the source of truth.
pub fn open(dir: &Path) -> Result<SearchIndex> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let (sch, fields) = schema();
    let mmap = || tantivy::directory::MmapDirectory::open(dir);
    let index = match Index::open_or_create(mmap()?, sch.clone()) {
        Ok(i) => i,
        Err(_) => {
            std::fs::remove_dir_all(dir).ok();
            std::fs::create_dir_all(dir)?;
            Index::open_or_create(mmap()?, sch)?
        }
    };
    let writer = index.writer(50_000_000)?;
    Ok(SearchIndex {
        dir: dir.to_path_buf(),
        state: Mutex::new(State { index, writer, fields }),
        healthy: std::sync::atomic::AtomicBool::new(true),
    })
}

impl SearchIndex {
    /// False once the writer has been recovered — the index is then empty and
    /// the caller should reindex every project.
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Run `f` against the index, repairing a poisoned writer first. A panic
    /// inside `f` poisons us again and the next call repairs — the caller
    /// sees the error, not a permanently broken subsystem.
    fn with_state<T>(&self, f: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                self.reopen(&mut state)?;
                state
            }
        };
        f(&mut state)
    }

    /// Wipe and reopen. The index is derived data; keeping a half-written one
    /// is worse than rebuilding it.
    fn reopen(&self, state: &mut State) -> Result<()> {
        // No logging in this crate — the daemon reports the rebuild.
        std::fs::remove_dir_all(&self.dir).ok();
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("recreating {}", self.dir.display()))?;
        let (sch, fields) = schema();
        let index = Index::open_or_create(tantivy::directory::MmapDirectory::open(&self.dir)?, sch)?;
        state.index = index;
        state.writer = state.index.writer(50_000_000)?;
        state.fields = fields;
        self.healthy.store(false, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

/// Read-only open for the CLI; fails politely if the daemon never built one.
pub fn open_readonly(dir: &Path) -> Result<(Index, Fields)> {
    let index = Index::open_in_dir(dir)
        .context("no search index — run prefrontald once to build it")?;
    let (_, fields) = schema();
    Ok((index, fields))
}

impl SearchIndex {
    /// Drop and re-add everything for one project. Returns documents indexed.
    pub fn reindex_project(&self, name: &str, project_dir: &Path) -> Result<usize> {
        let mut files = Vec::new();
        walk_files(project_dir, project_dir, 0, &mut files);
        let commits = commit_log(project_dir);

        self.with_state(|state| {
            let fields = state.fields;
            state
                .writer
                .delete_term(Term::from_field_text(fields.project, name));
            let mut added = 0usize;
            for (rel, kind) in &files {
                let Some(content) = read_indexable(&project_dir.join(rel)) else { continue };
                if kind == "code" {
                    let ext = rel.rsplit('.').next().unwrap_or_default().to_lowercase();
                    for sym in symbols::extract(&ext, &content) {
                        // tiny doc per declaration: a name query ranks it far above
                        // the file it lives in, and the signature ships in-index
                        state.writer.add_document(doc!(
                            fields.project => name,
                            fields.path => rel.as_str(),
                            fields.kind => "symbol",
                            fields.content => format!("{} {}", sym.kind, sym.name),
                            fields.stored_text => sym.signature,
                            fields.line => sym.line as u64,
                        ))?;
                        added += 1;
                    }
                }
                state.writer.add_document(doc!(
                    fields.project => name,
                    fields.path => rel.as_str(),
                    fields.kind => kind.as_str(),
                    fields.content => content,
                ))?;
                added += 1;
            }
            for (id, summary) in &commits {
                state.writer.add_document(doc!(
                    fields.project => name,
                    fields.path => id.as_str(),
                    fields.kind => "commit",
                    fields.content => summary.as_str(),
                    fields.stored_text => summary.as_str(),
                ))?;
                added += 1;
            }
            state.writer.commit()?;
            Ok(added)
        })
    }

    pub fn remove_project(&self, name: &str) -> Result<()> {
        self.with_state(|state| {
            state
                .writer
                .delete_term(Term::from_field_text(state.fields.project, name));
            state.writer.commit()?;
            Ok(())
        })
    }

    /// Query the index. Enriches hits with snippets from disk, so the hit
    /// list stays honest about what is on the filesystem right now.
    pub fn search_hits(
        &self,
        query: &str,
        limit: usize,
        project_dirs: &HashMap<String, PathBuf>,
    ) -> Result<Vec<SearchHit>> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        search(&state.index, state.fields, query, limit, project_dirs)
    }

    /// The index has been refilled after a rebuild.
    pub fn mark_healthy(&self) {
        self.healthy.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

fn walk_files(root: &Path, dir: &Path, depth: u32, out: &mut Vec<(String, String)>) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.filter_map(|e| e.ok()) {
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        if ft.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk_files(root, &path, depth + 1, out);
            }
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .unwrap_or_default();
        let kind = if DOC_EXTENSIONS.contains(&ext.as_str()) {
            "doc"
        } else if CODE_EXTENSIONS.contains(&ext.as_str()) {
            "code"
        } else {
            continue;
        };
        if let Ok(rel) = path.strip_prefix(root) {
            out.push((rel.to_string_lossy().to_string(), kind.to_string()));
        }
    }
}

/// Size-capped, binary-sniffed read.
fn read_indexable(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_FILE_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    if bytes.iter().take(1024).any(|&b| b == 0) {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Newest-first commit summaries, capped — recall reaches further back than
/// the 14-day timeline window.
fn commit_log(project_dir: &Path) -> Vec<(String, String)> {
    let Ok(repo) = gix::open(project_dir) else { return Vec::new() };
    let Ok(head) = repo.head_commit() else { return Vec::new() };
    let Ok(walk) = head.id().ancestors().all() else { return Vec::new() };
    walk.filter_map(Result::ok)
        .take(MAX_COMMITS)
        .filter_map(|info| {
            let commit = info.object().ok()?;
            let summary = commit.message().ok()?.summary().to_string();
            let id: String = info.id.to_string().chars().take(8).collect();
            Some((id, summary))
        })
        .collect()
}

/// Query the index; enrich hits with snippets and line numbers from disk.
/// `project_dirs` maps project name → absolute path (from the scan).
pub fn search(
    index: &Index,
    fields: Fields,
    query: &str,
    limit: usize,
    project_dirs: &HashMap<String, PathBuf>,
) -> Result<Vec<SearchHit>> {
    let reader = index.reader()?;
    let searcher = reader.searcher();
    let parser = QueryParser::for_index(index, vec![fields.content]);
    let (parsed, _errors) = parser.parse_query_lenient(query);
    let top = searcher.search(&parsed, &TopDocs::with_limit(limit).order_by_score())?;

    let terms: Vec<String> = query
        .split_whitespace()
        .map(|t| t.trim_matches('"').to_lowercase())
        .filter(|t| !t.is_empty())
        .collect();

    let mut hits = Vec::new();
    for (score, addr) in top {
        let doc: TantivyDocument = searcher.doc(addr)?;
        let get = |f: Field| {
            doc.get_first(f)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        let project = get(fields.project);
        let path = get(fields.path);
        let kind = get(fields.kind);
        let (line, snippet) = match kind.as_str() {
            "commit" => (None, get(fields.stored_text)),
            "symbol" => {
                let line = doc
                    .get_first(fields.line)
                    .and_then(|v| v.as_u64())
                    .map(|l| l as u32);
                (line, get(fields.stored_text))
            }
            _ => match project_dirs.get(&project) {
                Some(dir) => locate_snippet(&dir.join(&path), &terms),
                None => (None, String::new()),
            },
        };
        hits.push(SearchHit { project, path, kind, line, snippet, score });
    }
    Ok(hits)
}

/// First line containing any query term (1-based), else the first non-empty line.
fn locate_snippet(path: &Path, terms: &[String]) -> (Option<u32>, String) {
    let Some(content) = read_indexable(path) else { return (None, String::new()) };
    let mut first_nonempty: Option<(u32, &str)> = None;
    for (i, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if first_nonempty.is_none() {
            first_nonempty = Some((i as u32 + 1, line));
        }
        let lower = line.to_lowercase();
        if terms.iter().any(|t| lower.contains(t)) {
            return (Some(i as u32 + 1), truncate(line));
        }
    }
    match first_nonempty {
        Some((n, line)) => (Some(n), truncate(line)),
        None => (None, String::new()),
    }
}

fn truncate(s: &str) -> String {
    if s.chars().count() <= SNIPPET_CHARS {
        s.to_string()
    } else {
        let cut: String = s.chars().take(SNIPPET_CHARS - 1).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
impl SearchIndex {
    /// Reproduces the failure mode M11 is about: a panic while the writer lock
    /// is held leaves the mutex poisoned. Test-only — this never exists in a
    /// production build.
    pub fn poison_for_test(&self) {
        let _guard = self.state.lock();
        panic!("simulated tantivy panic under the writer lock");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pf-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// M11: a poisoned writer used to be fatal — every later reindex panicked
    /// on `.expect("index writer poisoned")` and search silently froze with no
    /// signal anywhere. Recovery must return `Err`/repair, never a second
    /// panic, and the index must be usable afterwards.
    #[test]
    fn poisoned_writer_is_repaired_not_fatal() {
        let index_dir = scratch("idx");
        let project = scratch("proj");
        std::fs::write(project.join("readme.md"), "some distinctive text to find").unwrap();

        let idx = open(&index_dir).expect("open index");
        assert_eq!(idx.reindex_project("alpha", &project).unwrap(), 1);
        assert!(idx.is_healthy(), "a fresh index is healthy");

        // Panic under the lock: the mutex is now poisoned.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            idx.poison_for_test()
        }));
        assert!(panicked.is_err(), "the poison helper must panic");

        // The very next reindex must repair it — no second panic, no Err that
        // leaves a permanently poisoned slot behind.
        let recovered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            idx.reindex_project("alpha", &project)
        }));
        assert!(recovered.is_ok(), "reindex must not panic again: {recovered:?}");
        assert!(recovered.unwrap().is_ok(), "reindex must repair, not error out");
        assert!(!idx.is_healthy(), "a repaired index is empty until it is refilled");

        // Refilling is what the daemon does when `is_healthy()` goes false.
        assert_eq!(idx.reindex_project("alpha", &project).unwrap(), 1);
        idx.mark_healthy();
        assert!(idx.is_healthy());

        // …and querying works over the recovered writer.
        let mut dirs = HashMap::new();
        dirs.insert("alpha".to_string(), project.clone());
        let hits = idx.search_hits("distinctive", 5, &dirs).expect("query after recovery");
        assert!(!hits.is_empty(), "the refilled index must be searchable");

        let _ = std::fs::remove_dir_all(&index_dir);
        let _ = std::fs::remove_dir_all(&project);
    }
}
