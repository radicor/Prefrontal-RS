mod watch;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Request, State,
    },
    http::{HeaderMap, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use prefrontal_core::cortex::CortexClient;
use prefrontal_core::search::SearchIndex;
use prefrontal_core::{scan_all, Config};
use prefrontal_protocol::{
    ColonyStatus, CortexHit, DocContent, DocEntry, DocWrite, DocWriteResult, Event,
    GitCommitRequest, GitPaths, GitStashRequest, GitSwitchRequest, Project, SearchHit,
};
use tokio::sync::{broadcast, Mutex, RwLock};
use tower_http::services::ServeDir;
use tracing::{error, info, warn};

/// Floor between two full rescans. `POST /api/rescan` is unauthenticated and
/// a scan is a whole-filesystem walk; without a floor a loop of requests is a
/// free local DoS.
const RESCAN_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Origin-boundary policy. The daemon has no authentication: its entire
/// security posture is "the caller is the local user", which stops being true
/// the moment a web page is open. `Sec-Fetch-Site` (or a matching `Origin` for
/// browsers that omit it) re-establishes that per request. See docs/API.md.
const ALLOWED_FETCH_SITES: [&str; 2] = ["same-origin", "none"];

/// Hardened default for every response. `ui-web` has no inline scripts, so
/// `script-src` needs no exceptions; `connect-src 'self' ws: wss:` keeps the
/// dashboard's own WebSocket alive.
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                    img-src 'self' data:; font-src 'self'; connect-src 'self' ws: wss:; \
                    object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";

/// Belt-and-braces for `/raw`: even if a browser ever renders an attacker
/// SVG as a document, it executes nothing. SVGs referenced from a doc still
/// render — `<img>` never runs SVG script and ignores Content-Disposition.
const RAW_CSP: &str = "sandbox; script-src 'none'; object-src 'none'";

pub struct AppState {
    pub cfg: Config,
    pub projects: RwLock<Vec<Project>>,
    pub tx: broadcast::Sender<Event>,
    /// None when the index couldn't be opened — search degrades, nothing else does.
    pub search: Option<Arc<SearchIndex>>,
    /// Some(...) only when features.cerebro is on; inner None until first use
    /// (the client spawns lazily and respawns after any error).
    pub cortex: Option<Arc<std::sync::Mutex<Option<CortexClient>>>>,
    /// Latest colony sweep; empty default when colony.enabled is off.
    pub colony: RwLock<ColonyStatus>,
    /// Held for the duration of a full rescan so a second request doesn't start
    /// a second walk; `try_lock` is the check, not mutual exclusion.
    pub rescan_gate: Mutex<()>,
    pub last_scan_unix: AtomicU64,
    /// Bumped per rescan; a scan whose generation is stale is discarded
    /// instead of overwriting a newer result.
    pub scan_gen: AtomicU64,
    pub watcher: watch::Stats,
    /// False once the index writer has been poisoned and not yet recovered.
    pub index_ok: std::sync::atomic::AtomicBool,
    /// Index-health and last-rescan detail for `GET /api/health`.
    pub last_scan: RwLock<Option<ScanReport>>,
    /// Precomputed from `server.bind` at startup — the guard reads it on
    /// every request, so it must not rebuild the list each time.
    pub allowed_hosts: Vec<String>,
}

/// What the UI needs to tell "the daemon is quiet" apart from "the daemon is
/// broken" — the watcher losing directories is otherwise invisible.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ScanReport {
    pub last_scan_unix: u64,
    pub last_scan_failed: bool,
    pub watched_dirs: u64,
    pub failed_dirs: u64,
}

/// The hosts a request may claim. Derived from `server.bind` — widening the
/// bind widens this too, which is the point: a non-loopback bind is a
/// deliberate decision, not a silent consequence.
fn allowed_hosts(cfg: &Config) -> Vec<String> {
    let bind_host = cfg
        .server
        .bind
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(&cfg.server.bind)
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    let mut hosts = vec![bind_host.clone()];
    // `http://localhost:7320` is what people type, so it must resolve here too.
    for alias in ["localhost", "::1", "0.0.0.0"] {
        if !hosts.iter().any(|h| h == alias) {
            hosts.push(alias.to_string());
        }
    }
    hosts
}

fn request_host(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::HOST)?
        .to_str()
        .ok()
        .map(|h| h.split(':').next().unwrap_or(h).trim_matches(['[', ']']).to_ascii_lowercase())
}

/// The origin boundary, in one place: `Host` must be one we serve; the
/// WebSocket must come from our own UI; and any state-changing request must
/// look same-origin. That closes DNS rebinding, cross-site writes, and the
/// body-less POSTs (`rescan`, `push`, `fetch`, `cortex/sync`) that need no
/// preflight to reach us.
async fn origin_guard(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let Some(host) = request_host(req.headers()) else {
        return (StatusCode::BAD_REQUEST, "missing Host header").into_response();
    };
    if !state.allowed_hosts.contains(&host) {
        warn!("refused request for foreign Host header: {host}");
        return (StatusCode::FORBIDDEN, "unknown host").into_response();
    }

    let path = req.uri().path().to_string();
    // Both checks apply independently. Whichever browser header is present,
    // the other must not contradict it: `Sec-Fetch-Site: none` must not let a
    // foreign `Origin` through, and a matching `Sec-Fetch-Site` must not excuse
    // an `Origin` that says the request came from somewhere else.
    let origin_ok = match header_str(req.headers(), "origin").as_deref() {
        Some(o) => same_origin(o, req.headers()),
        None => true, // no Origin: CLI, MCP, curl
    };
    let refused = if path == "/ws" {
        // Browsers do not enforce same-origin on a WebSocket handshake, so an
        // unchecked `/ws` hands any page the whole `Snapshot` — project paths,
        // branches, commit subjects, remote URLs with embedded credentials.
        // Non-browser clients send no `Origin` and stay welcome.
        !origin_ok
    } else if matches!(req.method(), &Method::GET | &Method::HEAD | &Method::OPTIONS) {
        false
    } else {
        let site_ok = match header_str(req.headers(), "sec-fetch-site").as_deref() {
            // Browsers always send this on a cross-origin request; a missing
            // header means a non-browser client (CLI, MCP, curl).
            Some(site) => ALLOWED_FETCH_SITES.contains(&site),
            None => true,
        };
        !site_ok || !origin_ok
    };
    if refused {
        warn!("refused cross-origin {} {path}", req.method());
        return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
    }
    next.run(req).await
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name)?.to_str().ok().map(str::to_string)
}

/// For browsers that omit `Sec-Fetch-Site`, the only legitimate `Origin` is
/// our own scheme+authority — the daemon speaks plain HTTP, so that is exactly
/// `http://` plus the Host header the request already carries. Comparing the
/// strings means ports must match too, and no second daemon on another port
/// can pass for us.
fn same_origin(origin: &str, headers: &HeaderMap) -> bool {
    let Some(host) = headers.get(axum::http::header::HOST).and_then(|h| h.to_str().ok()) else {
        return false;
    };
    origin.eq_ignore_ascii_case(&format!("http://{host}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "prefrontald=info,tower_http=warn".into()),
        )
        .init();

    let cfg = Config::load()?;
    let bind = cfg.server.bind.clone();
    let ui_dir = cfg.server.ui_dir.clone();
    // ui_dir is relative to the CWD; say so loudly when that misses, instead of
    // serving an API with no dashboard and no explanation.
    let ui_path = std::path::Path::new(&ui_dir);
    if !ui_path.is_dir() {
        let resolved = ui_path
            .canonicalize()
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default().join(&ui_dir));
        warn!(
            "ui_dir {ui_dir:?} is not a directory (resolved: {}) — the dashboard will not load; \
             run from the repo root or set [server] ui_dir",
            resolved.display()
        );
    }


    let initial = {
        let cfg = cfg.clone();
        tokio::task::spawn_blocking(move || scan_all(&cfg)).await?
    };
    info!("initial scan: {} projects", initial.len());

    let search = match prefrontal_core::search::default_index_dir() {
        Some(dir) => match prefrontal_core::search::open(&dir) {
            Ok(s) => Some(Arc::new(s)),
            Err(e) => {
                warn!("search index unavailable ({e:#}) — /api/search disabled");
                None
            }
        },
        None => None,
    };

    let cortex = if cfg.features.cerebro && !cfg.cortex.command.is_empty() {
        info!("cortex layer enabled — {}", cfg.cortex.command);
        Some(Arc::new(std::sync::Mutex::new(None)))
    } else {
        None
    };

    let colony = if cfg.colony.enabled {
        let cfg2 = cfg.clone();
        let projects = initial.clone();
        tokio::task::spawn_blocking(move || prefrontal_core::colony_status(&cfg2, &projects))
            .await?
    } else {
        ColonyStatus::default()
    };

    let (tx, _) = broadcast::channel(64);
    let allowed_hosts = allowed_hosts(&cfg);
    let state = Arc::new(AppState {
        allowed_hosts,
        cfg,
        projects: RwLock::new(initial),
        tx,
        search: search.clone(),
        cortex,
        colony: RwLock::new(colony),
        rescan_gate: Mutex::new(()),
        last_scan_unix: AtomicU64::new(0),
        scan_gen: AtomicU64::new(0),
        watcher: watch::Stats::default(),
        index_ok: std::sync::atomic::AtomicBool::new(search.is_some()),
        last_scan: RwLock::new(None),
    });

    if let Err(e) = watch::spawn(state.clone()) {
        error!("file watcher failed ({e:#}) — dashboard is static; POST /api/rescan to refresh");
    }
    tokio::spawn(build_index(state.clone()));
    if state.cfg.colony.enabled {
        tokio::spawn(colony_loop(state.clone()));
    }

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    info!("prefrontald up — http://{bind} (ui from {ui_dir}/)");
    axum::serve(listener, app(state)).await?;
    Ok(())
}

fn app(state: Arc<AppState>) -> Router {
    let ui_dir = state.cfg.server.ui_dir.clone();
    Router::new()
        .route("/api/projects", get(list_projects))
        .route("/api/colony", get(colony_handler))
        .route("/api/health", get(health_handler))
        .route("/api/rescan", post(rescan))
        .route("/api/search", get(search_handler))
        .route("/api/cortex", get(cortex_recall))
        .route("/api/cortex/sync", post(cortex_sync))
        .route("/api/docs/{project}", get(list_docs))
        .route("/api/doc/{project}/{*path}", get(read_doc).put(write_doc))
        .route("/api/git/{project}/status", get(git_status))
        .route("/api/git/{project}/diff", get(git_diff))
        .route("/api/git/{project}/log", get(git_log))
        .route("/api/git/{project}/commit/{id}", get(git_commit_detail))
        .route("/api/git/{project}/refs", get(git_refs))
        .route("/api/git/{project}/tree", get(git_tree))
        .route("/api/git/{project}/file", get(git_file))
        .route("/api/git/{project}/stage", post(git_stage))
        .route("/api/git/{project}/unstage", post(git_unstage))
        .route("/api/git/{project}/commit", post(git_commit))
        .route("/api/git/{project}/switch", post(git_switch))
        .route("/api/git/{project}/stash", post(git_stash))
        .route("/api/git/{project}/push", post(git_push))
        .route("/api/git/{project}/fetch", post(git_fetch))
        .route("/raw/{project}/{*path}", get(raw_asset))
        .route("/ws", get(ws_upgrade))
        .fallback_service(ServeDir::new(&ui_dir))
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn_with_state(state.clone(), origin_guard))
        .with_state(state)
}

/// Applied to every response, including the ones `ServeDir` produces — the UI
/// itself is the origin an XSS payload would want. CSP is *appended* rather
/// than set, so `/raw`'s stricter sandbox policy survives alongside this one
/// instead of being replaced by it (browsers enforce the intersection).
async fn security_headers(req: Request, next: Next) -> Response {
    use axum::http::header::{HeaderName, CONTENT_SECURITY_POLICY, REFERRER_POLICY};
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers
        .entry(CONTENT_SECURITY_POLICY)
        .or_insert_with(|| axum::http::HeaderValue::from_static(CSP));
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        REFERRER_POLICY,
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        axum::http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        axum::http::HeaderValue::from_static("same-origin"),
    );
    res
}

/// Watcher coverage and index health, so a dashboard that has quietly stopped
/// tracking projects can say so.
async fn health_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let w = &state.watcher;
    Json(serde_json::json!({
        "ok": true,
        "watch": {
            "watched_dirs": w.watched(),
            "failed_dirs": w.failed(),
        },
        "index_ok": state.index_ok.load(Ordering::Relaxed),
        "last_scan": *state.last_scan.read().await,
        "projects": state.projects.read().await.len(),
    }))
}

async fn list_projects(State(state): State<Arc<AppState>>) -> Json<Vec<Project>> {
    Json(state.projects.read().await.clone())
}

async fn colony_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ColonyStatus>, ApiError> {
    if !state.cfg.colony.enabled {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "colony panel disabled".into()));
    }
    Ok(Json(state.colony.read().await.clone()))
}

/// Periodic liveness sweep. Equal sweeps are suppressed like equal rescans —
/// the timestamp still updates so /api/colony reports honest freshness, but
/// nothing hits the WS unless a sibling actually changed state.
async fn colony_loop(state: Arc<AppState>) {
    let interval = state.cfg.colony.probe_interval_secs.max(5);
    // First sweep almost immediately: the boot sweep runs before the daemon
    // binds its own port, so Prefrontal would report itself down for a whole
    // interval otherwise.
    let mut delay = 2;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        delay = interval;
        let cfg = state.cfg.clone();
        let projects = state.projects.read().await.clone();
        let fresh =
            match tokio::task::spawn_blocking(move || prefrontal_core::colony_status(&cfg, &projects))
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    warn!("colony sweep panicked: {e}");
                    continue;
                }
            };
        let changed = fresh.siblings != state.colony.read().await.siblings;
        *state.colony.write().await = fresh.clone();
        if changed {
            let _ = state.tx.send(Event::Colony { colony: fresh });
        }
    }
}

/// Full rescan on demand — the escape hatch when the watcher can't run
/// (or for a client that wants certainty).
///
/// Three things this must not do: blank the dashboard when the scan panics,
/// discard deltas the watcher applied while the walk was in flight, or let two
/// overlapping scans resolve out of order. Hence: a failed scan keeps the
/// previous state, results merge per project by freshness, and a stale
/// generation is thrown away rather than written.
async fn rescan(State(state): State<Arc<AppState>>) -> Result<Json<Vec<Project>>, ApiError> {
    let Ok(_gate) = state.rescan_gate.try_lock() else {
        // A scan is already running; its result is at most seconds away and
        // starting a second walk only makes both answers later.
        return Ok(Json(state.projects.read().await.clone()));
    };
    let last = state.last_scan_unix.load(Ordering::Relaxed);
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now_unix.saturating_sub(last) < RESCAN_MIN_INTERVAL.as_secs() {
        return Ok(Json(state.projects.read().await.clone()));
    }
    state.last_scan_unix.store(now_unix, Ordering::Relaxed);

    let gen = state.scan_gen.fetch_add(1, Ordering::SeqCst) + 1;
    let cfg = state.cfg.clone();
    let started_unix = now_unix;
    let fresh = match tokio::task::spawn_blocking(move || scan_all(&cfg)).await {
        Ok(fresh) => fresh,
        Err(e) => {
            // A panicked scan used to become an empty Vec and wipe the
            // dashboard for every open tab. Keep what we have and say so.
            error!("rescan panicked ({e}) — keeping the previous project list");
            let mut report = state.last_scan.read().await.clone().unwrap_or_default();
            report.last_scan_unix = now_unix;
            report.last_scan_failed = true;
            *state.last_scan.write().await = Some(report);
            // The throttle window was consumed by a scan that produced
            // nothing; hand it back so the next retry actually runs instead
            // of answering 200 with the old state.
            state.last_scan_unix.store(0, Ordering::Relaxed);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("rescan failed: {e}")));
        }
    };

    if state.scan_gen.load(Ordering::SeqCst) != gen {
        warn!("discarding a rescan that a newer one superseded");
        return Ok(Json(state.projects.read().await.clone()));
    }
    let merged = {
        let mut projects = state.projects.write().await;
        let merged = merge_scan(fresh, &projects, started_unix);
        *projects = merged.clone();
        merged
    };
    let mut report = state.last_scan.read().await.clone().unwrap_or_default();
    report.last_scan_unix = now_unix;
    report.last_scan_failed = false;
    report.watched_dirs = state.watcher.watched();
    report.failed_dirs = state.watcher.failed();
    *state.last_scan.write().await = Some(report);
    let _ = state.tx.send(Event::Snapshot { projects: merged.clone() });
    Ok(Json(merged))
}

/// Fold a full scan into the live list. The scan read the filesystem before
/// the walk finished, so any slot the watcher has touched since (`started_unix`)
/// is strictly newer than what the scan saw — keep it, drop the scan's copy.
fn merge_scan(fresh: Vec<Project>, current: &[Project], started_unix: u64) -> Vec<Project> {
    let fresh_paths: std::collections::HashSet<String> =
        fresh.iter().map(|p| p.path.clone()).collect();
    let mut merged: Vec<Project> = fresh
        .into_iter()
        .map(|p| match current.iter().find(|c| c.path == p.path) {
            Some(c) if c.last_touched_unix > p.last_touched_unix => c.clone(),
            _ => p,
        })
        .collect();
    // Not in the scan's output: deleted, or created while it walked. Keep it
    // when the watcher proved it is newer than the scan.
    for c in current {
        if !fresh_paths.contains(&c.path) && c.last_touched_unix as u64 >= started_unix {
            merged.push(c.clone());
        }
    }
    merged.sort_by_key(|p| std::cmp::Reverse(p.last_touched_unix));
    merged
}


/// Full index build, once, in the background — the watcher keeps it fresh after.
/// Also the refill path after a poisoned writer forced a rebuild.
async fn build_index(state: Arc<AppState>) {
    let Some(search) = state.search.clone() else { return };
    let projects: Vec<(String, String)> = state
        .projects
        .read()
        .await
        .iter()
        .map(|p| (p.name.clone(), p.path.clone()))
        .collect();
    let total = projects.len();
    let started = std::time::Instant::now();
    let rebuilt = !search.is_healthy();
    if rebuilt {
        warn!("rebuilding the search index — the previous writer was poisoned");
    }
    let indexer = search.clone();
    let docs = tokio::task::spawn_blocking(move || {
        let mut docs = 0usize;
        for (name, path) in projects {
            match indexer.reindex_project(&name, std::path::Path::new(&path)) {
                Ok(n) => docs += n,
                Err(e) => warn!("indexing {name} failed: {e:#}"),
            }
        }
        docs
    })
    .await
    .unwrap_or(0);
    search.mark_healthy();
    state.index_ok.store(true, Ordering::Relaxed);
    info!(
        "search index ready — {docs} documents across {total} projects in {:.1}s{}",
        started.elapsed().as_secs_f32(),
        if rebuilt { " (rebuilt)" } else { "" }
    );
}

/// Keep `/api/health` honest about the index between rebuilds.
fn publish_index_health(state: &Arc<AppState>) {
    state.index_ok.store(state.search.as_ref().is_some_and(|s| s.is_healthy()), Ordering::Relaxed);
}

#[derive(serde::Deserialize)]
struct SearchParams {
    q: String,
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    30
}

async fn search_handler(
    axum::extract::Query(params): axum::extract::Query<SearchParams>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<SearchHit>>, ApiError> {
    let Some(search) = state.search.clone() else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "search index unavailable".into()));
    };
    let dirs: std::collections::HashMap<String, std::path::PathBuf> = state
        .projects
        .read()
        .await
        .iter()
        .map(|p| (p.name.clone(), std::path::PathBuf::from(&p.path)))
        .collect();
    let limit = params.limit.min(100);
    let q = params.q.clone();
    let hits = tokio::task::spawn_blocking(move || search.search_hits(&q, limit, &dirs))
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
    Ok(Json(hits))
}

/// Run a closure against the lazily-spawned cortex client; any error drops
/// the client so the next call respawns fresh.
///
/// The spawn happens *outside* the lock — `initialize` is a full round trip to
/// a child process, and holding the slot across it meant one slow cortex
/// serialized (and with no timeout, deadlocked) every other request. A
/// poisoned mutex is recovered rather than `expect`-ed: one panic under the
/// lock used to disable the whole feature for the daemon's lifetime.
async fn with_cortex<T, F>(state: &Arc<AppState>, f: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce(&mut CortexClient) -> anyhow::Result<T> + Send + 'static,
{
    let Some(slot) = state.cortex.clone() else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "cortex layer disabled".into()));
    };
    let cortex_cfg = state.cfg.cortex.clone();
    tokio::task::spawn_blocking(move || {
        if !lock_slot(&slot).is_some() {
            let client = CortexClient::spawn(&cortex_cfg)
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("{e:#}")))?;
            lock_slot(&slot).get_or_insert(client);
        }
        let mut guard = lock_slot(&slot);
        match guard.as_mut() {
            Some(client) => f(client).map_err(|e| {
                *guard = None; // poisoned pipe or protocol drift — respawn next time
                (StatusCode::BAD_GATEWAY, format!("{e:#}"))
            }),
            None => Err((StatusCode::BAD_GATEWAY, "cortex client unavailable".into())),
        }
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

/// A poisoned slot means a panic left an unknown client state in it; drop that
/// client and carry on rather than disabling the feature permanently.
fn lock_slot(
    slot: &std::sync::Mutex<Option<CortexClient>>,
) -> std::sync::MutexGuard<'_, Option<CortexClient>> {
    match slot.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!("cortex slot poisoned — dropping the client and continuing");
            let mut guard = poisoned.into_inner();
            *guard = None;
            guard
        }
    }
}

#[derive(serde::Deserialize)]
struct CortexParams {
    q: String,
}

async fn cortex_recall(
    axum::extract::Query(params): axum::extract::Query<CortexParams>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<CortexHit>>, ApiError> {
    let top_k = state.cfg.cortex.top_k;
    let q = params.q.clone();
    let hits = with_cortex(&state, move |c| c.recall(&q, top_k)).await?;
    Ok(Json(hits))
}

async fn cortex_sync(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let projects = state.projects.read().await.clone();
    let (created, updated) = with_cortex(&state, move |c| {
        let mut created = 0u32;
        let mut updated = 0u32;
        for p in &projects {
            match c.sync_project(p)? {
                true => created += 1,
                false => updated += 1,
            }
        }
        Ok((created, updated))
    })
    .await?;
    info!("cortex sync: {created} created, {updated} updated");
    Ok(Json(serde_json::json!({ "created": created, "updated": updated })))
}

type ApiError = (StatusCode, String);

/// Projects are addressed by name; the daemon resolves to a path only through
/// its own scan cache — clients never send filesystem paths for projects.
async fn project_dir(state: &Arc<AppState>, name: &str) -> Result<std::path::PathBuf, ApiError> {
    state
        .projects
        .read()
        .await
        .iter()
        .find(|p| p.name == name)
        .map(|p| std::path::PathBuf::from(&p.path))
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("unknown project: {name}")))
}

fn render_markdown(raw: &str) -> String {
    let mut opts = comrak::Options::default();
    opts.extension.table = true;
    opts.extension.strikethrough = true;
    opts.extension.tasklist = true;
    opts.extension.autolink = true;
    // Raw HTML passes through comrak, then ammonia strips anything active
    // (scripts, handlers, iframes) while keeping the img/div/table furniture
    // READMEs actually use for banners. The dashboard origin can write files,
    // so cloned-from-anywhere docs must never execute in it.
    opts.render.r#unsafe = true;
    ammonia::clean(&restore_task_boxes(&comrak::markdown_to_html(raw, &opts)))
}

/// ammonia's default allow-list has no `input`, so comrak's tasklist
/// checkboxes are stripped and `- [ ]` renders with no box at all. Swap them
/// for glyphs *before* sanitizing — the glyph carries the state in its text,
/// which survives, unlike the attribute ammonia would have dropped.
fn restore_task_boxes(html: &str) -> String {
    html.replace(
        "<input type=\"checkbox\" checked=\"\" disabled=\"\" />",
        "<span>☑</span>",
    )
    .replace("<input type=\"checkbox\" disabled=\"\" />", "<span>☐</span>")
}

async fn list_docs(
    Path(project): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<DocEntry>>, ApiError> {
    let dir = project_dir(&state, &project).await?;
    // A panicked walk used to answer "no docs", which the UI cannot tell from
    // a project that genuinely has none.
    let docs = tokio::task::spawn_blocking(move || prefrontal_core::list_docs(&dir))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("listing docs failed: {e}")))?;
    Ok(Json(docs))
}

async fn read_doc(
    Path((project, path)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<DocContent>, ApiError> {
    let dir = project_dir(&state, &project).await?;
    let rel = path.clone();
    let (raw, modified_unix) =
        tokio::task::spawn_blocking(move || prefrontal_core::read_doc(&dir, &rel))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    let html = render_markdown(&raw);
    Ok(Json(DocContent { project, path, raw, html, modified_unix }))
}

async fn write_doc(
    Path((project, path)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<DocWrite>,
) -> Result<Json<DocWriteResult>, ApiError> {
    let dir = project_dir(&state, &project).await?;
    let result = tokio::task::spawn_blocking(move || {
        prefrontal_core::write_doc(&dir, &path, &body.content)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    // no manual cache poke: the watcher sees the write (and the commit) and
    // pushes the ProjectChanged delta itself
    Ok(Json(result))
}

#[derive(serde::Deserialize)]
struct GitDiffQuery {
    path: String,
    #[serde(default)]
    cached: bool,
    rev: Option<String>,
}

#[derive(serde::Deserialize)]
struct GitLogQuery {
    #[serde(default = "default_log_limit")]
    limit: u32,
    #[serde(default)]
    skip: u32,
}
fn default_log_limit() -> u32 {
    50
}

#[derive(serde::Deserialize)]
struct GitTreeQuery {
    rev: Option<String>,
    path: Option<String>,
}

#[derive(serde::Deserialize)]
struct GitFileQuery {
    path: String,
    rev: Option<String>,
}

async fn git_status(
    Path(project): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<prefrontal_protocol::GitStatus>, ApiError> {
    let dir = project_dir(&state, &project).await?;
    let allow_push = state.cfg.git.allow_push;
    let status = tokio::task::spawn_blocking(move || prefrontal_core::git::status(&dir, allow_push))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    Ok(Json(status))
}

async fn git_diff(
    Path(project): Path<String>,
    axum::extract::Query(q): axum::extract::Query<GitDiffQuery>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<prefrontal_protocol::GitDiff>, ApiError> {
    let dir = project_dir(&state, &project).await?;
    let rev = q.rev.clone();
    let diff = tokio::task::spawn_blocking(move || {
        prefrontal_core::git::diff(&dir, &q.path, q.cached, rev.as_deref())
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    Ok(Json(diff))
}

async fn git_log(
    Path(project): Path<String>,
    axum::extract::Query(q): axum::extract::Query<GitLogQuery>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<prefrontal_protocol::CommitSummary>>, ApiError> {
    let dir = project_dir(&state, &project).await?;
    let log = tokio::task::spawn_blocking(move || prefrontal_core::git::log(&dir, q.limit, q.skip))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    Ok(Json(log))
}

async fn git_commit_detail(
    Path((project, id)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<prefrontal_protocol::GitCommitDetail>, ApiError> {
    let dir = project_dir(&state, &project).await?;
    let detail = tokio::task::spawn_blocking(move || prefrontal_core::git::commit_detail(&dir, &id))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    Ok(Json(detail))
}

async fn git_refs(
    Path(project): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<prefrontal_protocol::GitRef>>, ApiError> {
    let dir = project_dir(&state, &project).await?;
    let refs = tokio::task::spawn_blocking(move || prefrontal_core::git::refs(&dir))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    Ok(Json(refs))
}

async fn git_tree(
    Path(project): Path<String>,
    axum::extract::Query(q): axum::extract::Query<GitTreeQuery>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<prefrontal_protocol::GitTreeEntry>>, ApiError> {
    let dir = project_dir(&state, &project).await?;
    let tree = tokio::task::spawn_blocking(move || {
        prefrontal_core::git::tree(&dir, q.rev.as_deref(), q.path.as_deref())
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    Ok(Json(tree))
}

async fn git_file(
    Path(project): Path<String>,
    axum::extract::Query(q): axum::extract::Query<GitFileQuery>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<prefrontal_protocol::GitFile>, ApiError> {
    let dir = project_dir(&state, &project).await?;
    let file = tokio::task::spawn_blocking(move || {
        prefrontal_core::git::file_at(&dir, q.rev.as_deref(), &q.path)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    Ok(Json(file))
}

async fn git_stage(
    Path(project): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<GitPaths>,
) -> Result<Json<prefrontal_protocol::GitOpResult>, ApiError> {
    let dir = project_dir(&state, &project).await?;
    let result = tokio::task::spawn_blocking(move || prefrontal_core::git::stage(&dir, &body.paths))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    Ok(Json(result))
}

async fn git_unstage(
    Path(project): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<GitPaths>,
) -> Result<Json<prefrontal_protocol::GitOpResult>, ApiError> {
    let dir = project_dir(&state, &project).await?;
    let result = tokio::task::spawn_blocking(move || prefrontal_core::git::unstage(&dir, &body.paths))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    Ok(Json(result))
}

async fn git_commit(
    Path(project): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<GitCommitRequest>,
) -> Result<Json<prefrontal_protocol::GitOpResult>, ApiError> {
    let dir = project_dir(&state, &project).await?;
    let result = tokio::task::spawn_blocking(move || prefrontal_core::git::commit(&dir, &body))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    Ok(Json(result))
}

async fn git_switch(
    Path(project): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<GitSwitchRequest>,
) -> Result<Json<prefrontal_protocol::GitOpResult>, ApiError> {
    let dir = project_dir(&state, &project).await?;
    let result = tokio::task::spawn_blocking(move || prefrontal_core::git::switch(&dir, &body))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    Ok(Json(result))
}

async fn git_stash(
    Path(project): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<GitStashRequest>,
) -> Result<Json<prefrontal_protocol::GitOpResult>, ApiError> {
    let dir = project_dir(&state, &project).await?;
    let result = tokio::task::spawn_blocking(move || prefrontal_core::git::stash(&dir, &body))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    Ok(Json(result))
}

async fn git_push(
    Path(project): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<prefrontal_protocol::GitOpResult>, ApiError> {
    let dir = project_dir(&state, &project).await?;
    let allow = state.cfg.git.allow_push;
    let result = tokio::task::spawn_blocking(move || prefrontal_core::git::push(&dir, allow))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    Ok(Json(result))
}

async fn git_fetch(
    Path(project): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<prefrontal_protocol::GitOpResult>, ApiError> {
    let dir = project_dir(&state, &project).await?;
    let allow = state.cfg.git.allow_push;
    let result = tokio::task::spawn_blocking(move || prefrontal_core::git::fetch(&dir, allow))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    Ok(Json(result))
}

/// Read-only project images so docs can show their banners/screenshots.
///
/// `ASSET_EXTENSIONS` deliberately includes `svg` so README banners render,
/// which makes this the one place attacker-controlled bytes get served from
/// the dashboard's own origin. An SVG opened as a document runs its embedded
/// `<script>` with full same-origin rights — enough to `PUT /api/doc/...` and
/// commit. So: force a download (`Content-Disposition: attachment`), which
/// `<img>` ignores (banners still render) but a navigation honors, and
/// sandbox the response so a navigation can't execute even if the header is
/// dropped somewhere. `nosniff` is already global.
async fn raw_asset(
    Path((project, path)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
) -> Result<Response, ApiError> {
    let dir = project_dir(&state, &project).await?;
    let rel = path.clone();
    let bytes = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
        let p = prefrontal_core::docs::resolve_asset_path(&dir, &rel)?;
        Ok(std::fs::read(&p)?)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;

    let mut headers = raw_headers(&path);
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(mime_for_path(&path)),
    );
    Ok((headers, bytes).into_response())
}

/// The extension → mime table for `/raw`. Every arm is a literal, so the
/// header value is provably static rather than `expect`-ed at request time.
fn mime_for_path(path: &str) -> &'static str {
    match path.rsplit('.').next().map(|e| e.to_lowercase()).as_deref() {
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("bmp") => "image/bmp",
        Some("avif") => "image/avif",
        _ => "application/octet-stream",
    }
}

/// `/raw` response headers: the sandbox policy, plus a
/// `Content-Disposition: attachment` so a hostile SVG can never be rendered as
/// a document at the dashboard origin (H1).
///
/// The filename is attacker-controlled — projects can be cloned from anywhere.
/// `HeaderValue` rejects anything outside visible ASCII, so a name like
/// `banner-é.png`, or one carrying a control byte, must never be able to panic
/// the request path. The quoted parameter is rewritten to safe ASCII, the
/// original survives verbatim via RFC 5987, and if that still fails the header
/// is dropped rather than the request: the sandbox policy is what actually
/// prevents execution.
fn raw_headers(path: &str) -> HeaderMap {
    let filename = path.rsplit('/').next().filter(|s| !s.is_empty()).unwrap_or("asset");
    let safe: String = filename
        .chars()
        .map(|c| match c {
            '"' | '\\' => '_',
            c if c.is_ascii() && !c.is_ascii_control() => c,
            _ => '?',
        })
        .collect();
    let encoded: String = filename
        .bytes()
        .map(|b| match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect();
    let mut headers = HeaderMap::new();
    let disposition = format!("attachment; filename=\"{safe}\"; filename*=UTF-8''{encoded}");
    match axum::http::HeaderValue::from_str(&disposition) {
        Ok(value) => {
            headers.insert(axum::http::header::CONTENT_DISPOSITION, value);
        }
        Err(_) => warn!("dropping Content-Disposition for {filename:?} — header value rejected"),
    }
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(RAW_CSP),
    );
    headers
}

/// The handshake itself. The `Origin` check lives in `origin_guard` so it runs
/// before any extractor sees the request.
async fn ws_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| ws_session(socket, state))
}

/// Full state for one client: Snapshot, then Colony when the panel is on.
/// Sent on connect and after a lagged receiver — covers all gaps either way.
async fn send_full_state(socket: &mut WebSocket, state: &Arc<AppState>) -> Result<(), axum::Error> {
    let snapshot = Event::Snapshot { projects: state.projects.read().await.clone() };
    send_event(socket, &snapshot).await?;
    if state.cfg.colony.enabled {
        let colony = Event::Colony { colony: state.colony.read().await.clone() };
        send_event(socket, &colony).await?;
    }
    Ok(())
}

async fn ws_session(mut socket: WebSocket, state: Arc<AppState>) {
    // Subscribe before snapshotting so no delta can fall between the two.
    let mut rx = state.tx.subscribe();
    if send_full_state(&mut socket, &state).await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(ev) => {
                    if send_event(&mut socket, &ev).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    if send_full_state(&mut socket, &state).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            msg = socket.recv() => match msg {
                Some(Ok(_)) => {} // clients only listen; drain to notice a close
                _ => break,
            },
        }
    }
}

async fn send_event(socket: &mut WebSocket, ev: &Event) -> Result<(), axum::Error> {
    match serde_json::to_string(ev) {
        Ok(json) => socket.send(Message::Text(json.into())).await,
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Request};
    use tower::ServiceExt;

    fn test_state() -> Arc<AppState> {
        let mut cfg = Config::default();
        cfg.server.bind = "127.0.0.1:7320".into();
        cfg.server.ui_dir = "ui-web".into();
        test_state_with(cfg)
    }

    fn test_state_with(cfg: Config) -> Arc<AppState> {
        let (tx, _) = broadcast::channel(4);
        let allowed_hosts = allowed_hosts(&cfg);
        Arc::new(AppState {
            allowed_hosts,
            cfg,
            projects: RwLock::new(Vec::new()),
            tx,
            search: None,
            cortex: None,
            colony: RwLock::new(ColonyStatus::default()),
            rescan_gate: Mutex::new(()),
            last_scan_unix: AtomicU64::new(0),
            scan_gen: AtomicU64::new(0),
            watcher: watch::Stats::default(),
            index_ok: std::sync::atomic::AtomicBool::new(false),
            last_scan: RwLock::new(None),
        })
    }

    fn get(path: &str) -> Request<Body> {
        Request::builder()
            .uri(path)
            .header(header::HOST, "127.0.0.1:7320")
            .body(Body::empty())
            .unwrap()
    }


    #[tokio::test]
    async fn foreign_host_is_refused() {
        let res = app(test_state())
            .oneshot(
                Request::builder()
                    .uri("/api/projects")
                    // DNS rebinding: the browser resolves this name to us.
                    .header(header::HOST, "attacker.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn missing_host_is_refused() {
        let res = app(test_state())
            .oneshot(Request::builder().uri("/api/projects").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn cross_origin_bodyless_post_is_refused() {
        // A simple request: no preflight, so it reaches the daemon either way.
        let res = app(test_state())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/rescan")
                    .header(header::HOST, "127.0.0.1:7320")
                    .header("sec-fetch-site", "cross-site")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn cross_origin_origin_header_is_refused() {
        let res = app(test_state())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/git/anything/push")
                    .header(header::HOST, "127.0.0.1:7320")
                    .header(header::ORIGIN, "http://evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn same_origin_post_reaches_the_handler() {
        let res = app(test_state())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/git/nope/push")
                    .header(header::HOST, "127.0.0.1:7320")
                    .header(header::ORIGIN, "http://127.0.0.1:7320")
                    .header("sec-fetch-site", "same-origin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // 404 unknown project, not 403 — the request was allowed through.
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn non_browser_client_without_origin_is_allowed() {
        let res = app(test_state()).oneshot(get("/api/projects")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn every_response_carries_the_security_headers() {
        let res = app(test_state()).oneshot(get("/api/projects")).await.unwrap();
        let h = res.headers();
        let csp = h.get(header::CONTENT_SECURITY_POLICY).unwrap().to_str().unwrap();
        assert!(csp.contains("script-src 'self'"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert_eq!(h.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
        assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");
        assert_eq!(h.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(h.get("cross-origin-resource-policy").unwrap(), "same-origin");
    }

    #[tokio::test]
    async fn websocket_from_a_foreign_origin_is_refused() {
        let res = app(test_state())
            .oneshot(
                Request::builder()
                    .uri("/ws")
                    .header(header::HOST, "127.0.0.1:7320")
                    .header(header::ORIGIN, "http://evil.example")
                    .header(header::CONNECTION, "Upgrade")
                    .header(header::UPGRADE, "websocket")
                    .header(header::SEC_WEBSOCKET_VERSION, "13")
                    .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    /// Regression for the gate gap: `Sec-Fetch-Site` presence must not excuse
    /// a foreign `Origin`. Previously `none`/`same-origin` short-circuited the
    /// `Origin` check entirely.
    #[tokio::test]
    async fn fetch_site_does_not_excuse_a_foreign_origin() {
        for site in ["none", "same-origin", "same-site"] {
            let res = app(test_state())
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/api/git/alpha/push")
                        .header(header::HOST, "127.0.0.1:7320")
                        .header("sec-fetch-site", site)
                        .header(header::ORIGIN, "http://evil.example")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::FORBIDDEN, "site={site}");
        }
        // …and a same-origin Site is still not enough to smuggle a bad Origin
        // on the websocket either.
        let res = app(test_state())
            .oneshot(
                Request::builder()
                    .uri("/ws")
                    .header(header::HOST, "127.0.0.1:7320")
                    .header("sec-fetch-site", "same-origin")
                    .header(header::ORIGIN, "http://evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "ws with foreign origin");
    }

    #[test]
    fn same_origin_requires_an_exact_authority() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "127.0.0.1:7320".parse().unwrap());
        assert!(same_origin("http://127.0.0.1:7320", &headers));
        assert!(!same_origin("http://127.0.0.1:9999", &headers));
        assert!(!same_origin("http://localhost:7320", &headers));
        assert!(!same_origin("null", &headers));
        headers.insert(header::HOST, "localhost:7320".parse().unwrap());
        assert!(same_origin("http://localhost:7320", &headers));
    }

    #[test]
    fn allowed_hosts_follow_the_bind_address() {
        let cfg = Config::default();
        assert!(allowed_hosts(&cfg).contains(&"127.0.0.1".to_string()));
        let mut wide = Config::default();
        wide.server.bind = "192.168.1.10:7320".into();
        assert!(allowed_hosts(&wide).contains(&"192.168.1.10".to_string()));
    }

    /// End-to-end through the handler: a rescan of a real root merges into
    /// the live list (it no longer replaces it), broadcasts a snapshot, and a
    /// second request inside the throttle window answers from state instead of
    /// starting another filesystem walk.
    #[tokio::test]
    async fn rescan_merges_and_is_throttled() {
        let root = std::env::temp_dir().join(format!("pf-rescan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let project = root.join("alpha");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("README.md"), "# alpha").unwrap();

        let cfg = Config {
            roots: vec![root.to_string_lossy().into_owned()],
            ..Config::default()
        };
        let state = test_state_with(cfg);
        // Pretend the watcher already knows about alpha, with a newer touch.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let seeded = sample_project(&project.to_string_lossy(), now + 10_000);
        state.projects.write().await.push(seeded.clone());

        let mut events = state.tx.subscribe();
        let fresh = rescan(State(state.clone())).await.unwrap().0;
        assert_eq!(fresh.len(), 1, "the project on disk is present");
        assert_eq!(
            fresh[0].last_touched_unix,
            seeded.last_touched_unix,
            "the watcher's newer value survives the merge"
        );
        let _ = events.try_recv(); // Snapshot was broadcast
        assert_eq!(state.scan_gen.load(Ordering::SeqCst), 1);

        std::fs::remove_dir_all(&project).unwrap();
        let throttled = rescan(State(state.clone())).await.unwrap();
        assert_eq!(
            throttled.0.len(),
            1,
            "a second rescan inside the window returns state, not a fresh walk"
        );
        assert_eq!(state.scan_gen.load(Ordering::SeqCst), 1, "no second scan started");
        std::fs::remove_dir_all(&root).ok();
    }

    fn sample_project(path: &str, touched: i64) -> Project {
        serde_json::from_value(serde_json::json!({
            "name": "a",
            "path": path,
            "git": null,
            "activity": "warm",
            "last_touched_unix": touched,
            "languages": [],
            "tags": [],
            "tagline": null,
            "health": [],
            "has_readme": false,
            "has_claude_md": false,
        }))
        .unwrap()
    }

    #[test]
    fn merge_keeps_watcher_updates_the_scan_missed() {
        let current = vec![
            sample_project("/touched", 500), // watcher updated after the scan started
            sample_project("/deleted", 400), // scan saw it; watcher removed it
        ];
        let fresh = vec![
 sample_project("/touched", 100), // stale scan copy
        ];
        let merged = merge_scan(fresh, &current, 450);
        let paths: Vec<&str> = merged.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(paths, vec!["/touched"]);
        assert_eq!(merged[0].last_touched_unix, 500, "watcher's newer value wins");
    }

    #[test]
    fn merge_adopts_the_scan_for_untouched_projects() {
        let current = vec![sample_project("/p", 100)];
        let fresh = vec![sample_project("/p", 200)];
        let merged = merge_scan(fresh, &current, 150);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].last_touched_unix, 200);
    }

    #[test]
    fn tasklist_boxes_survive_sanitization() {
        let html = render_markdown("- [ ] open\n- [x] done\n");
        assert!(html.contains('☐'), "{html}");
        assert!(html.contains('☑'), "{html}");
        assert!(!html.contains("<input"), "{html}");
    }

    #[test]
    fn markdown_scripts_never_survive() {
        let html = render_markdown("<script>fetch('/api/doc/p/n.md',{method:'PUT'})</script>\n");
        assert!(!html.contains("script"), "{html}");
    }

    /// Regression: `HeaderValue::from_str` rejects anything outside visible
    /// ASCII, so a hostile or merely internationalised filename used to panic
    /// the request path (`main.rs:996`, reproduced live with `a%01b.png`).
    /// No filename may be able to panic the handler, and the sandbox policy
    /// must survive even when the disposition header cannot be built.
    #[test]
    fn hostile_asset_filenames_never_panic_header_construction() {
        for path in [
            "assets/normal.svg",
            "assets/banner-é.png",
            "assets/🎨.gif",
            "assets/a\u{1}b.png",
            "assets/t\u{9}ab.png",
            "assets/injected\"; evil=x.svg",
            "assets/back\\slash.png",
            "assets/\u{7F}.png",
            "",
            "/",
        ] {
            let headers = raw_headers(path);
            assert_eq!(
                headers.get(axum::http::header::CONTENT_SECURITY_POLICY),
                Some(&axum::http::HeaderValue::from_static(RAW_CSP)),
                "sandbox policy must be present for {path:?}"
            );
        }
        let h = raw_headers("assets/banner-é.png");
        let disp = h
            .get(axum::http::header::CONTENT_DISPOSITION)
            .expect("disposition for a UTF-8 filename")
            .to_str()
            .unwrap()
            .to_string();
        assert!(disp.starts_with("attachment;"), "{disp}");
        assert!(disp.contains(r#"filename="banner-?.png""#), "{disp}");
        // the original bytes survive for the download name (RFC 5987)
        assert!(disp.contains("filename*=UTF-8''banner-%C3%A9.png"), "{disp}");
        assert_eq!(mime_for_path("assets/x.SVG"), "image/svg+xml");
        assert_eq!(mime_for_path("assets/x.png"), "image/png");
        assert_eq!(mime_for_path("assets/x.unknown"), "application/octet-stream");
    }
}

