//! Filesystem watcher → debounced per-project rescans → WS deltas.
//!
//! Watches are added per-directory (never blanket-recursive) so build output
//! can be skipped — `target/` alone would eat thousands of inotify watches
//! and drown the debouncer during a compile. `.git` gets targeted watches
//! (the dir itself + `refs/`) so commits, staging, and branch switches
//! register without the object-store noise.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use prefrontal_core::{is_ignored, scan_project, SKIP_DIRS};
use prefrontal_protocol::Event as WireEvent;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::AppState;

/// Rescan a project this long after its *last* event — a git checkout or a
/// save-storm collapses into one rescan.
const QUIET: Duration = Duration::from_millis(600);
const MAX_DEPTH: u32 = 8;

struct Raw {
    path: PathBuf,
    created_dir: bool,
}

/// Watcher coverage. A `watch()` that fails (inotify limits, permissions)
/// used to be swallowed with `.is_ok()`, so a project silently stopped
/// updating and the dashboard still claimed to be live.
#[derive(Debug, Default)]
pub struct Stats {
    watched: std::sync::atomic::AtomicU64,
    failed: std::sync::atomic::AtomicU64,
}

impl Stats {
    pub fn watched(&self) -> u64 {
        self.watched.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn failed(&self) -> u64 {
        self.failed.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn record(&self, dir: &Path, ok: bool) {
        let counter = if ok { &self.watched } else { &self.failed };
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if !ok {
            // Without the path a warning is just noise: the whole point is to
            // tell someone *which* project stopped updating live.
            warn!("watch failed on {} — it will not update live", dir.display());
        }
    }
}

pub fn spawn(state: Arc<AppState>) -> Result<()> {
    let (tx, rx) = mpsc::unbounded_channel::<Raw>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res {
            let created = matches!(ev.kind, notify::EventKind::Create(_));
            for path in ev.paths {
                let created_dir = created && path.is_dir();
                let _ = tx.send(Raw { path, created_dir });
            }
        }
    })?;

    let roots = state.cfg.root_paths();
    for root in &roots {
        let result = watcher.watch(root, RecursiveMode::NonRecursive);
        state.watcher.record(root, result.is_ok());
        result.with_context(|| format!("watching root {}", root.display()))?;
        let Ok(entries) = std::fs::read_dir(root) else { continue };
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            if !entry.path().is_dir() || is_ignored(&name, &state.cfg) {
                continue;
            }
            add_watches(&mut watcher, &entry.path(), 0, &state.watcher);
        }
    }
    let watched = state.watcher.watched();
    let failed = state.watcher.failed();
    if failed > 0 {
        warn!(
            "watching {watched} directories under {} root(s) — {failed} could NOT be watched \
             (inotify limit? see /proc/sys/fs/inotify/max_user_watches): those projects are static \
             until a rescan",
            roots.len()
        );
    } else {
        info!("watching {watched} directories under {} root(s)", roots.len());
    }


    tokio::spawn(debounce_loop(state, rx, watcher, roots));
    Ok(())
}

fn add_watches(w: &mut RecommendedWatcher, dir: &Path, depth: u32, stats: &Stats) {
    if depth > MAX_DEPTH {
        return;
    }
    stats.record(dir, w.watch(dir, RecursiveMode::NonRecursive).is_ok());
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.filter_map(|e| e.ok()) {
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_dir() || ft.is_symlink() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name == ".git" {
            stats.record(&path, w.watch(&path, RecursiveMode::NonRecursive).is_ok());
            let refs = path.join("refs");
            if refs.is_dir() {
                stats.record(&refs, w.watch(&refs, RecursiveMode::Recursive).is_ok());
            }
            continue;
        }
        if name.starts_with('.') || SKIP_DIRS.contains(&name.as_str()) {
            continue;
        }
        add_watches(w, &path, depth + 1, stats);
    }
}

/// Map an event path to the project directory (root's immediate child) it lives in.
fn project_of(path: &Path, roots: &[PathBuf]) -> Option<PathBuf> {
    for root in roots {
        if let Ok(rest) = path.strip_prefix(root) {
            let first = rest.components().next()?;
            return Some(root.join(first.as_os_str()));
        }
    }
    None
}

async fn debounce_loop(
    state: Arc<AppState>,
    mut rx: mpsc::UnboundedReceiver<Raw>,
    mut watcher: RecommendedWatcher,
    roots: Vec<PathBuf>,
) {
    let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            raw = rx.recv() => {
                let Some(raw) = raw else { break };
                if raw.created_dir {
                    // brand-new project or fresh subtree — cover it going forward
                    let name = raw.path.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if !name.starts_with('.') && !SKIP_DIRS.contains(&name.as_str()) {
                        add_watches(&mut watcher, &raw.path, 0, &state.watcher);
                    }
                }
                if let Some(proj) = project_of(&raw.path, &roots) {
                    let name = proj.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if !is_ignored(&name, &state.cfg) {
                        pending.insert(proj, Instant::now());
                    }
                }
            }
            _ = tick.tick() => {
                let due: Vec<PathBuf> = pending
                    .iter()
                    .filter(|(_, seen)| seen.elapsed() >= QUIET)
                    .map(|(p, _)| p.clone())
                    .collect();
                for dir in due {
                    pending.remove(&dir);
                    rescan_one(&state, dir).await;
                }
            }
        }
    }
}

async fn rescan_one(state: &Arc<AppState>, dir: PathBuf) {
    let Some(name) = dir.file_name().map(|n| n.to_string_lossy().to_string()) else {
        return;
    };
    let cfg = state.cfg.clone();
    let d = dir.clone();
    let scanned = tokio::task::spawn_blocking(move || {
        d.is_dir().then(|| scan_project(&d, name, &cfg))
    })
    .await
    .ok()
    .flatten();

    match scanned {
        Some(project) => {
            let mut projects = state.projects.write().await;
            match projects.iter_mut().find(|p| p.path == project.path) {
                Some(slot) => {
                    if *slot == project {
                        return; // touched, but nothing the dashboard shows changed
                    }
                    *slot = project.clone();
                }
                None => projects.push(project.clone()),
            }
            projects.sort_by_key(|p| std::cmp::Reverse(p.last_touched_unix));
            drop(projects);
            debug!("project changed: {}", project.name);
            if let Some(search) = state.search.clone() {
                let name = project.name.clone();
                let pdir = dir.clone();
                let unhealthy = !search.is_healthy();
                if unhealthy {
                    // A repaired writer means an empty index; one project's
                    // reindex would leave the other 46 unsearchable.
                    warn!("index was rebuilt — refilling every project");
                    tokio::spawn(crate::build_index(state.clone()));
                }
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = search.reindex_project(&name, &pdir) {
                        debug!("reindex {name} failed: {e:#}");
                    }
                });
                crate::publish_index_health(state);
            }
            let _ = state.tx.send(WireEvent::ProjectChanged { project: Box::new(project) });
        }
        None => {
            let path = dir.to_string_lossy().to_string();
            let mut projects = state.projects.write().await;
            let before = projects.len();
            projects.retain(|p| p.path != path);
            if projects.len() != before {
                drop(projects);
                info!("project removed: {path}");
                if let Some(search) = state.search.clone() {
                    if let Some(name) = dir.file_name().map(|n| n.to_string_lossy().to_string()) {
                        tokio::task::spawn_blocking(move || search.remove_project(&name).ok());
                    }
                }
                let _ = state.tx.send(WireEvent::ProjectRemoved { path });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pf-watch-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The counters behind `GET /api/health`: a `watch()` that fails must be
    /// counted, not swallowed, or a project silently stops updating while the
    /// dashboard still claims to be live.
    #[test]
    fn counts_successes_and_failures_separately() {
        let s = Stats::default();
        assert_eq!((s.watched(), s.failed()), (0, 0));
        s.record(Path::new("/ok/one"), true);
        s.record(Path::new("/ok/two"), true);
        assert_eq!((s.watched(), s.failed()), (2, 0));
        s.record(Path::new("/nope"), false);
        assert_eq!((s.watched(), s.failed()), (2, 1), "a failure must not count as watched");
    }

    /// The fix this round added: the warning has to name the directory, or it
    /// is unactionable noise. Captured through a real subscriber so the
    /// assertion is on the formatted line an operator actually sees, not on a
    /// re-implementation of the message.
    #[test]
    fn failure_warning_names_the_directory_and_successes_stay_quiet() {
        let dir = scratch("named");
        let captured = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let stats = Stats::default();

        tracing::subscriber::with_default(
            tracing_subscriber::fmt()
                .with_writer(Sink(captured.clone()))
                .with_ansi(false)
                .finish(),
            || {
                stats.record(&dir, false);
                stats.record(Path::new("/fine"), true);
            },
        );

        let log = String::from_utf8(captured.lock().clone()).unwrap();
        let lines: Vec<&str> = log.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 1, "only failures should log, got: {log:?}");
        assert!(
            lines[0].contains(&dir.display().to_string()),
            "the warning must name the directory, got: {log:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Routes the formatter's output into a shared buffer.
    struct Sink(Arc<parking_lot::Mutex<Vec<u8>>>);

    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
        type Writer = Sink;
        fn make_writer(&'a self) -> Self::Writer {
            Sink(self.0.clone())
        }
    }

    /// `add_watches` must count a real directory it watched, and must survive
    /// a directory that does not exist (which is what a create/delete race
    /// hands it).
    #[test]
    fn add_watches_counts_a_real_directory_and_tolerates_a_vanished_one() {
        let dir = scratch("real");
        let stats = Stats::default();
        let mut watcher = notify::recommended_watcher(|_: notify::Result<notify::Event>| {})
            .expect("create watcher");
        add_watches(&mut watcher, &dir, 0, &stats);
        assert_eq!(stats.watched(), 1, "the scratch dir should be watched");
        assert_eq!(stats.failed(), 0);

        let gone = dir.join("vanished");
        add_watches(&mut watcher, &gone, 0, &stats);
        assert_eq!(stats.failed(), 1, "a vanished path is a watch failure, not a crash");
        assert_eq!(stats.watched(), 1, "and must not be counted as watched");

        // Depth guard: beyond MAX_DEPTH we stop rather than recursing forever.
        let before = (stats.watched(), stats.failed());
        add_watches(&mut watcher, &dir, MAX_DEPTH + 1, &stats);
        assert_eq!((stats.watched(), stats.failed()), before, "MAX_DEPTH stops the walk");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `project_of` maps an event path to the project directory it lives in —
    /// the root of every debounced rescan. A wrong answer silently rescans the
    /// wrong thing.
    #[test]
    fn maps_events_to_their_project_directory() {
        let roots = vec![PathBuf::from("/srv/Projects")];
        let p = project_of(Path::new("/srv/Projects/alpha/src/lib.rs"), &roots);
        assert_eq!(p, Some(PathBuf::from("/srv/Projects/alpha")));
        assert_eq!(project_of(Path::new("/srv/Projects"), &roots), None);
        assert_eq!(project_of(Path::new("/elsewhere/alpha"), &roots), None);
    }
}
