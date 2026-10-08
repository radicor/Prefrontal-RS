# Prefrontal-RS — Comprehensive Audit Report

**Date:** 2026-10-06
**Scope:** all 20 source files (~5,100 LOC Rust + static web UI), traced end-to-end across REST/WS/MCP/CLI surfaces.
**Method:** static analysis + targeted empirical verification (git config execution, confirmed live). No Rust toolchain was available in this environment, so no compile/build/runtime testing was performed — confidence levels are marked accordingly. Every "Confirmed" below is verified by code reading or by an executed test, not by assumption.

**Architecture context:** `prefrontald` (axum, :7320) holds a warm project cache fed by a gix scanner + notify watcher, broadcasts WS deltas, and serves `ui-web`. `prefrontal-core` owns all logic. The daemon has **no authentication, no authorization, no CSRF, no CORS policy, and no Host/Origin validation** — the entire security posture rests on one assumption: binding to 127.0.0.1. Several findings below defeat that assumption from a web page.

---

## CRITICAL

**None confirmed at Critical severity.** The two High findings that come closest (H1, H2) both require a hostile README to be cloned into the projects root or a user merely visiting a web page — plausible for this product, but gated behind user action. I would escalate H1 to Critical the day `allow_push` is on by default or the bind address is widened.

---

## HIGH

### H1 — Stored XSS: `/raw` serves attacker-controlled SVG at the dashboard origin
- **Category:** Security
- **Location:** `prefrontald/src/main.rs:617-649` (`raw_asset`), `prefrontal-core/src/docs.rs:15-16` (`ASSET_EXTENSIONS` includes `svg`), `ui-web/app.js:504-538` (`fixupDocLinks`)
- **Issue:** `resolve_asset_path` deliberately allows `.svg` so README banners render, and `raw_asset` serves it with `Content-Type: image/svg+xml` (plus `X-Content-Type-Options: nosniff`, which *prevents* content-sniffing workarounds but does not stop an SVG from running its own embedded `<script>`). The dashboard's own origin can write files and run git porcelain. `fixupDocLinks` treats any `href` beginning with `/` as external and rewrites it to `target="_blank" rel="noopener"` — so a doc link to `/raw/<project>/assets/x.svg` opens **same-origin in a new tab**, where the SVG's script executes with the full privileges of the dashboard.
- **Impact:** Total compromise of the trust boundary the codebase works hardest to defend. `render_markdown` (main.rs:341-353) pipes comrak through `ammonia::clean` precisely so "cloned-from-anywhere docs must never execute in it" — but a hostile README simply links around the sanitizer to a same-origin SVG, then the XSS payload can `PUT /api/doc/...` (same-origin, no preflight), `POST /api/git/.../stage|commit`, and — if `allow_push` is on — `POST /api/git/.../push`. The ammonia work is bypassed, not defeated, and the commit history of every project is attacker-writable.
- **Evidence:** `main.rs:631-641` maps `svg` → `image/svg+xml`; `docs.rs:15-16` allow-lists svg; ammonia's default policy strips `script`/`on*` handlers from markdown HTML but cannot touch a separately-served file; `app.js:506` classifies `/`-prefixed URLs as external and opens them in a new tab at the same origin.
- **Reproduction:** (1) Put `<a href="/raw/victim-project/assets/banner.svg">See the banner</a>` and a file `assets/banner.svg` containing `<svg xmlns="http://www.w3.org/2000/svg"><script>fetch('/api/doc/victim-project/notes/pwn.md',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:'# pwned'})})</script></svg>` in any project. (2) Open that project's README in the dashboard and click the link. (3) `notes/pwn.md` is written and auto-committed. Right-click → "open image in new tab" on any SVG banner works too.
- **Recommended fix:** Serve `/raw` responses with `Content-Disposition: attachment; filename="<basename>"` and a restrictive `Content-Security-Policy: sandbox; script-src 'none'` — SVGs still render via `<img>` (browsers block script in that context) but can never execute on navigation. Additionally add a global CSP to *all* daemon responses (`default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'`; no inline scripts exist in `ui-web`, so this is drop-in) as defense-in-depth for the `innerHTML` path.
- **Confidence:** Confirmed (code path verified end-to-end; ammonia's default policy checked against the pinned version, ammonia 4.1.4)

### H2 — Cross-Site WebSocket Hijacking: `/ws` never checks the Origin header
- **Category:** Security
- **Location:** `prefrontald/src/main.rs:651-656` (`ws_upgrade` / `ws_session`)
- **Issue:** The WS upgrade accepts any client. Browsers do not enforce same-origin on the WebSocket handshake, so any page the user visits can open `ws://127.0.0.1:7320/ws` and immediately receive the full `Snapshot` — and, if enabled, the `Colony` frame.
- **Impact:** Full inventory disclosure to any website: every project's absolute path, activity, branch, dirty-file count, health flags, remote URL, and recent commit messages. `GitInfo.remote` (`protocol/src/lib.rs:31`) frequently embeds credentials, e.g. `https://user:ghp_xxx@github.com/...` — a credential-harvesting vector with zero user interaction beyond loading a page. Also a read primitive that makes H3's blind POSTs observable.
- **Evidence:** `main.rs:670-697` — `ws_session` subscribes and sends `send_full_state` unconditionally; no `Origin` extraction or comparison anywhere in the router (`main.rs:104-130`), and no CORS layer (which would not help WS anyway).
- **Reproduction:** From any `http://` page (or via DNS rebinding over `http://`): `new WebSocket('ws://127.0.0.1:7320/ws')` → `onmessage` receives `{"type":"snapshot","projects":[…]}`. (An `https://` page is blocked by mixed-content rules; `http://` pages and rebinding are not.)
- **Recommended fix:** In `ws_upgrade`, reject any request whose `Origin` header is not `http://127.0.0.1:7320` (and any configured bind), returning 403. Cheap, and it closes both CSWSH and the rebinding read path.
- **Confidence:** Confirmed

### H3 — No CSRF or Host validation: body-less POSTs are triggerable from any website
- **Category:** Security
- **Location:** `prefrontald/src/main.rs:104-130` (router, no middleware), handlers `rescan` (187), `git_push` (590), `git_fetch` (603), `cortex_sync` (306)
- **Issue:** These handlers take no body, so a cross-origin `fetch(url, {method:'POST'})` is a "simple request" — no CORS preflight, and the request reaches the daemon even though the response can't be read. Combined with H2 (which supplies the read primitive), a malicious site has working request/response over the loopback service.
- **Impact:** Unauthenticated remote-triggerable actions: repeated `POST /api/rescan` (full filesystem scan of all roots — a cheap DoS), `POST /api/cortex/sync` (exfiltrates all project summaries to the cortex), and, when `[git] allow_push` is on, `POST /api/git/<project>/push` and `/fetch` — a website pushing the user's code to its upstream. DNS rebinding extends this to the JSON-bodied routes (`write_doc`, `stage`, `commit`).
- **Evidence:** Router builds no layers beyond `ServeDir`; `git_push`/`git_fetch` gate only on `allow_push` (`git.rs:768-790`), never on the caller.
- **Reproduction:** A page containing `fetch('http://127.0.0.1:7320/api/rescan',{method:'POST'})` in a loop; watch the daemon's CPU.
- **Recommended fix:** Validate the `Host` header against the configured bind address (kills rebinding), require an `Origin`/`Sec-Fetch-Site: same-origin` check on every state-changing route, and add a CSRF token or a `SameSite`-style boundary since there are no cookies to anchor one — the `Sec-Fetch-*` headers are the right primitive for a tokenless local service.
- **Confidence:** Confirmed

### H4 — Untrusted repository config executes arbitrary commands via `git status`
- **Category:** Security
- **Location:** `prefrontal-core/src/git.rs:145-176` (`git_output`), `:336-391` (`status`), `prefrontal-core/src/scan.rs:205-223` (`ahead_behind`); the whole `git -C <project>` surface
- **Issue:** Every git shell-out runs in a project directory whose `.git/config` is treated as trusted. It is not: for project folders that are copied, synced, restored from backup, or unpacked from a tarball (all common for this tool's "40+ project folders of various provenance" audience), the config is attacker-controlled. `core.fsmonitor` makes `git status` execute an arbitrary command — and `git status` runs on **every Repo-tab open** with no `allow_push` gate in the way.
- **Impact:** Arbitrary code execution as the user, triggered by the routine act of browsing a project. Because the daemon scans and shells into every project under the roots automatically, one poisoned project dir compromises the machine.
- **Evidence:** *Empirically verified during this audit* — in a throwaway repo I set `core.fsmonitor` to `/bin/sh -c 'touch /tmp/pwned'`, ran `git status --porcelain=v2` (the exact argv at `git.rs:340`), and the sentinel file was created. `core.sshCommand` on `git fetch` is the same class of vector but did not fire in my test (git 2.39.5, unreachable ssh remote) — Needs Verification.
- **Reproduction:** Any project dir containing `.git/config` with `[core] fsmonitor = /bin/sh -c '…'`; open its Repo tab or let the daemon scan it.
- **Recommended fix:** Pass hardening `-c` overrides on every shell-out, e.g. `git -C <dir> -c core.fsmonitor= -c core.sshCommand=ssh -c core.pager=cat -c core.attributesFile= -c protocol.version=2 …` (plus `GIT_CONFIG_NOSYSTEM=1` where the user's global config isn't needed — but note note commits *do* need the user's identity, so keep `[user]` resolvable). Document the copied-repo threat model in `docs/API.md` next to the ammonia rationale.
- **Confidence:** Confirmed (fsmonitor, by execution); sshCommand variant High Confidence / Needs Verification

### H5 — `POST /api/rescan` wipes the dashboard to zero projects when the scan panics
- **Category:** Reliability
- **Location:** `prefrontald/src/main.rs:187-195`
- **Issue:** `spawn_blocking(scan_all).await.unwrap_or_default()` turns any JoinError (panic inside the scan — a poisoned lock, a `gix` panic on a corrupt repo, an unwrapping `expect`) into an empty `Vec`, which is then written into state **and broadcast as a `Snapshot` to every connected client**.
- **Impact:** A single panicking scan (one corrupt repository among 40 is enough) blanks the entire dashboard for all open tabs, and because the empty state is broadcast, the web UI replaces every card with "nothing matches". The recovery path is a manual rescan or a lucky watcher event — and a persistently-corrupt repo makes it blank on every rescan attempt.
- **Evidence:** `main.rs:189-194` — `.unwrap_or_default()` feeds `*state.projects.write().await = fresh.clone()` and `tx.send(Event::Snapshot{projects: fresh})` with no non-emptiness guard. Contrast `build_index` (209-220), which correctly treats the same failure as a no-op.
- **Reproduction:** Introduce a repository that panics gix during `git_info` (e.g. a truncated packfile), then `curl -X POST 127.0.0.1:7320/api/rescan`.
- **Recommended fix:** On JoinError, log and keep the previous state (return the existing projects, or 500). Same for `list_docs` (`main.rs:360-363`, which silently returns an empty doc list on panic — a confusing empty state rather than an error).
- **Confidence:** Confirmed (code path)

### H6 — Cortex client can permanently deadlock the whole cortex feature (and leak threads)
- **Category:** Reliability / Race Condition
- **Location:** `prefrontald/src/main.rs:264-289` (`with_cortex`), `prefrontal-core/src/cortex.rs:65-86` (`request`)
- **Issue:** `with_cortex` takes the `std::sync::Mutex` *before* spawning the blocking task and holds it across the entire closure — including `CortexClient::spawn`, which performs the `initialize` handshake. `CortexClient::request` reads the child's stdout with **no timeout**. If the cortex binary hangs after spawn, the blocking thread blocks forever on `read_line`, holding the mutex forever. Every subsequent `/api/cortex*` request then blocks on `slot.lock()`, each consuming another blocking-pool thread (tokio grows its pool to 512). Separately, `slot.lock().expect("cortex slot poisoned")` (main.rs:274) means a single panic under the lock disables the feature permanently with a 500 on every call for the daemon's lifetime.
- **Impact:** One hung cortex child takes an entire optional subsystem down and, under repeated requests, pins threads until the process is restarted. There is no timeout, no health check, and no recovery.
- **Evidence:** `cortex.rs:74` — `self.reader.read_line(&mut line)?` with no deadline; `main.rs:273-280` — lock acquired, then spawn attempted inside; `main.rs:283` sets `*guard = None` on error but a *panic* (not an `Err`) poisons instead.
- **Reproduction:** Configure `[cortex] command` to a binary that reads stdin and never writes (e.g. `sh -c 'cat'`), enable `features.cerebro`, and call `/api/cortex?q=x` twice. The first hangs; the second hangs; neither ever returns.
- **Recommended fix:** Wrap the pipe read in a deadline (`tokio::time::timeout` around a `spawn_blocking` read, or read with a polling deadline); do the spawn *outside* the mutex; and handle `PoisonError` by resetting the slot instead of `.expect`.
- **Confidence:** Confirmed (code path; no timeout exists)

---

## MEDIUM

### M1 — The dashboard is keyboard-inaccessible: every primary navigation target is a `<div>` with `onclick`
- **Category:** Accessibility
- **Location:** `ui-web/app.js:243` (`card`), `:93-103` (health rows), `:150-158` (timeline commits), `:351-375` (search hits), `:196-239` (colony rows, partly)
- **Issue:** Project cards, health rows, timeline entries, and search hits are all `div`/`article` elements with click handlers. None has `role="button"`, `tabindex="0"`, or a `keydown` handler for Enter/Space. A keyboard user cannot reach *any* of the product's core navigation targets.
- **Impact:** WCAG 2.2 SC 2.1.1 (Keyboard, Level A) failure on the primary user flow. Mouse-only navigation for a tool billed as an accessibility-motivated product ("built with an AuDHD brain in mind").
- **Evidence:** `el()` (app.js:49-54) builds plain elements; every row constructor attaches `onclick` only. No `tabindex` appears anywhere in `index.html` or `app.js`.
- **Recommended fix:** Either render these as `<button>` with `type="button"` (simplest, inherits all semantics) or add `role="button" tabindex="0"` plus a delegated keydown handler for Enter/Space. The `.card`/`.health-row`/`.tl-commit` styles already reset nothing that would fight `<button>`.
- **Confidence:** Confirmed

### M2 — Modal dialog has no accessible name, no focus trap, and no focus restoration
- **Category:** Accessibility
- **Location:** `ui-web/index.html:70-126`, `ui-web/app.js:442-481` (`openPanel`), `:601-604` (`closePanel`)
- **Issue:** `.panel` declares `role="dialog" aria-modal="true"` but `#panel-title` is a plain `<span>` with no `aria-labelledby`/`aria-label` binding, so the dialog is announced without a name. Nothing moves focus into the dialog on open, nothing traps Tab inside it while open, and `closePanel` does not return focus to the triggering element. Esc (app.js:953-960) works, which is good, but it is the only keyboard affordance.
- **Impact:** SC 4.1.2 (Name, Role, Value) and SC 2.4.3 (Focus Order): screen-reader users get an unnamed dialog; keyboard users Tab straight out of a modal that asserts it is modal, into background content that is inert-in-name-only.
- **Evidence:** `index.html:71-73` — `role="dialog" aria-modal="true"` with no labelledby; `openPanel` sets `overlay.hidden = false` and never calls `.focus()`; no `keydown` Tab handling exists in `bindPanel`.
- **Recommended fix:** Add `aria-labelledby="panel-title"`; on open, focus the first actionable control (or the panel itself with `tabindex="-1"`); implement a Tab cycle within the overlay; on close, restore focus to the card/row that opened it.
- **Confidence:** Confirmed

### M3 — Form controls have no labels, only placeholders
- **Category:** Accessibility
- **Location:** `ui-web/index.html:25-27` (`#filter`), `:90-91` (`#doc-filename`), `:114-115` (`#repo-msg`); also `#doc-editor` (93-94)
- **Issue:** None of the inputs/textareas has a `<label>` (or `aria-label`). Placeholder text is explicitly not a label and vanishes on input.
- **Impact:** SC 1.3.1 / 3.3.2 (Level A): the filter — the app's single most-used control — has no accessible name; the commit-message textarea and new-note filename likewise.
- **Recommended fix:** Add visually-hidden `<label for>` elements (or `aria-label`), e.g. `<label for="filter" class="vh">Filter projects</label>`.
- **Confidence:** Confirmed

### M4 — No visible focus indicator on most interactive controls
- **Category:** Accessibility
- **Location:** `ui-web/style.css` — `:focus` rules exist only for `#filter` (111), `.doc-editor`/`.doc-filename` (434). Nothing for `.tab`, `.panel-actions button`, `#btn-close`, `.repo-row`, `.repo-commit-actions button`, `.doc-list a`.
- **Issue/Impact:** Keyboard users get no visual indication of where they are in the panel, doc list, or repo sidebar. SC 2.4.7 (Focus Visible, Level AA) failure across the modal surface.
- **Recommended fix:** Add a shared `:focus-visible` rule (`outline: 2px solid var(--act-active); outline-offset: 1px`) at the `button`, `a`, `textarea`, `input` level.
- **Confidence:** Confirmed

### M5 — Light-mode contrast failures on badges, muted text, and untracked marks
- **Category:** Accessibility
- **Location:** `ui-web/style.css:36-55` (light overrides), `:312-321` (`.badge` uses `color: var(--page)`), `:80`/`:494` (`--muted` text, `.mark.untracked` uses `--act-warm`)
- **Issue:** In light mode the status badges put near-white text (`--page: #f9f9f7`) on saturated backgrounds. I computed the ratios: warning `#fab219` → **1.73:1**, serious `#ec835a` → **2.48:1**, good `#0ca30c` → **3.16:1** (critical passes at 4.52:1). `--muted #898781` on `--surface #fcfcfb` is **3.38:1** (12px timestamps, taglines, repo headers), and `--act-warm #86b6ef` — not overridden in the light media query — is **2.02:1** as the untracked-mark text color. Markdown links (`--act-active` → #2a78d6) land at ~4.2:1, just under the 4.5:1 bar. Dark mode is largely fine (badges 4.05–10.6:1; the red `critical` badge is the borderline one at ~4.05:1 against `#0d0d0d`).
- **Impact:** SC 1.4.3 (Contrast Minimum, Level AA) failures for small text throughout light mode, which is the OS-default for many users.
- **Recommended fix:** Give light mode its own badge text color (e.g. `--ink: #0b0b0b`), darken `--muted` and `--act-warm` in the light block, and nudge `--act-active` darker. Re-measure with a contrast checker as part of the fix — these ratios were computed by hand from the hex values.
- **Confidence:** Confirmed (ratios computed from the token values in the stylesheet)

### M6 — No in-flight guard on mutating actions: double-clicks create duplicate effects
- **Category:** Race Condition
- **Location:** `ui-web/app.js:568-599` (`saveDoc`), `:888-907` (`gitOp`), `:943-952` (button bindings)
- **Issue:** Neither `saveDoc` nor `gitOp` disables its trigger or tracks in-flight state. Buttons remain fully clickable while a request is outstanding.
- **Impact:** Repeated clicks on **stash** create multiple stash entries (`git stash push` is not idempotent); double **commit** produces a real duplicate commit if the working tree changed between the two requests; rapid **switch**/**stage**/**unstage** fire concurrent, non-idempotent porcelain. `saveDoc` double-fires two PUTs and two auto-commit attempts.
- **Evidence:** `gitOp` sets `status(\`${verb}…\`)` then awaits `fetch` with no guard; `saveDoc` likewise. `loadRepo`/`openDoc`/`runSearch` *do* carry sequence guards (`repoSeq`, `docSeq`, `searchSeq`) — the pattern exists in this codebase and was not applied to writes.
- **Recommended fix:** Track an `inFlight` flag per verb (or a global `busy`); disable the action button while set; re-enable in a `finally`. For server-side hardening, make `stash push` idempotent by checking for identical existing stash entries before pushing — client guards are convenience, not correctness.
- **Confidence:** Confirmed

### M7 — Stage→commit is a lost-update race in the happy path
- **Category:** Race Condition
- **Location:** `ui-web/app.js:726-739` (stage click), `:943-946` (commit click), `:888-907` (`gitOp` then `loadRepo`)
- **Issue:** Clicking "stage" and then "commit" before the stage response lands sends `POST .../stage` and `POST .../commit` concurrently. The commit can be processed first and land *without* the just-staged file — the user sees "commit ok" and silently misses their change.
- **Impact:** Quiet data omission in the product's flagship git GUI. No error, no retry hint — the file appears unstaged after the reload.
- **Evidence:** Both calls are independent `fetch`es with no ordering constraint; `git::commit` (`git.rs:712-742`) commits whatever happens to be staged at the time it runs, with no client-supplied staged-state precondition.
- **Recommended fix:** Serialize git operations client-side per project (a promise chain / queue keyed on `panel.project`), and — server-side — consider having `commit` accept the expected staged paths and fail if they aren't staged, making the operation stateful rather than fire-and-forget.
- **Confidence:** Confirmed (the interleaving is guaranteed possible; whether it bites depends on timing)

### M8 — `runCortex` lacks the sequence guard `runSearch` has
- **Category:** Race Condition
- **Location:** `ui-web/app.js:301-332` (`runCortex`) vs `:334-343` (`runSearch`, which uses `searchSeq`)
- **Issue:** Both fire on the same 250 ms debounce, but only the lexical search guards against out-of-order responses. A slow cortex reply can land *after* a newer query's results and render stale hits under the current query.
- **Impact:** Occasionally wrong semantic-recall results with no indication. Minor data integrity, easy fix.
- **Recommended fix:** Hoist the seq pattern into a shared helper and apply to both.
- **Confidence:** Confirmed

### M9 — Full rescans clobber watcher state; concurrent rescans resolve out of order
- **Category:** Race Condition
- **Location:** `prefrontald/src/main.rs:187-195` (`rescan`), `prefrontald/src/watch.rs:156-212` (`rescan_one`)
- **Issue:** `rescan` replaces the entire project vector with a scan that may be tens of seconds stale by the time it completes, discarding any `ProjectChanged` deltas the watcher applied in the meantime. Two concurrent `POST /api/rescan` requests (or a rescan racing a watcher burst) write in completion order, so an older scan can win.
- **Impact:** The dashboard silently regresses — a commit made mid-rescan disappears from health/dirty counts until the next filesystem event. For a "live dashboard" this is the core promise breaking, transiently and confusingly.
- **Evidence:** `main.rs:192` — `*state.projects.write().await = fresh` with no versioning; `watch.rs:171-181` writes per-project slots, which a wholesale replace overwrites wholesale.
- **Recommended fix:** Merge instead of replace (apply the fresh scan as a per-project update keyed by path, preserving newer entries), or take a per-project write lock and skip slots whose last-known update postdates the scan's read.
- **Confidence:** Confirmed

### M10 — `.git` internals are readable through the Repo tab, including config that may embed credentials
- **Category:** Security / Data exposure
- **Location:** `prefrontal-core/src/git.rs:639-656` (`file_at` `WORKTREE` path → `resolve_repo_rel` → `std::fs::read`), `:64-89` (`validate_repo_rel` does not exclude `.git/`)
- **Issue:** `validate_repo_rel` allows any relative path of `Normal` components, so `path=.git/config&rev=WORKTREE` reads and returns the repository config. Remote URLs of the form `https://user:token@github.com/…` are a common (if discouraged) practice, and the dashboard renders them in the browser.
- **Impact:** Any local process — or, via H2's CSWSH channel combined with a rebinding read, possibly a remote one — can harvest tokens embedded in remote URLs across every project. `git add .git/...` is separately refused by git itself (verified by the guard's design intent and git's `verify_path`), so writes into `.git` are not reachable this way.
- **Recommended fix:** Reject paths whose first component is `.git` in `validate_repo_rel` (the tree reader already skips dot-dirs at `git.rs:579-581`; align the read path with it). Low blast radius — nothing legitimate reads `.git/` through this API.
- **Confidence:** Confirmed (read path), Needs Verification (exposure of credential URLs depends on user practice)

### M11 — Index-writer poisoning makes search silently stale forever
- **Category:** Reliability
- **Location:** `prefrontal-core/src/search.rs:100`, `:145`, `:152` (`.expect("index writer poisoned")`), `prefrontald/src/watch.rs:187-191`
- **Issue:** Every reindex locks the tantivy writer via `.expect`. A panic during `add_document`/`commit` poisons the mutex; thereafter every reindex panics inside its `spawn_blocking`. `watch.rs` swallows the JoinError silently (`if let Err(e) = ... debug!`), and `build_index` does the same (`main.rs:209-220`, `unwrap_or(0)`).
- **Impact:** The index stops matching disk with zero user-visible signal — "didn't I already write this?" starts returning wrong answers, which is the product's reason for existing. The `conn` dot shows WS health, not index health.
- **Recommended fix:** Treat a poisoned writer as recoverable: drop and reopen the index (the charter already declares it a rebuildable cache, and `open` wipes on schema mismatch — the machinery exists). Surface index state in the UI alongside the connection indicator.
- **Confidence:** Confirmed (panic-propagation path; triggering it requires a tantivy internal panic)

### M12 — Watcher degradation is silent
- **Category:** Reliability
- **Location:** `prefrontald/src/watch.rs:65-97` (`add_watches` ignores `watch()` errors via `.is_ok()`), `:48-58`
- **Issue:** On a large garden the inotify watch limit is a real ceiling (~4k directories are claimed for a 47-project garden per CLAUDE.md, and the default `fs.inotify.max_user_watches` is often 8192). When `watch()` fails, the directory is simply unwatched — no log, no UI signal — and that project stops updating live.
- **Impact:** The dashboard's central "actually live" promise fails quietly for the largest gardens, exactly the users with the most to lose. The only recovery is noticing and raising the kernel limit.
- **Recommended fix:** Count and log failed watches at `warn!` (or `error!`), and expose a `watcher_ok` / `watched_dirs` field on the snapshot or a health endpoint so the UI can say "live for 43 of 47 projects".
- **Confidence:** Needs Verification (the failure mode is real; whether it triggers depends on the user's kernel limits and garden size)

### M13 — Silent failure states across the panel
- **Category:** Reliability / Accessibility
- **Location:** `ui-web/app.js:465-471` (`openPanel` catch → empty doc list, no message), `:1040-1049` (`ws.onmessage` → `handleEvent(JSON.parse(...))` unguarded), `:329-331`/`:340-343` (bare `catch {}`), `prefrontald/src/main.rs:360-363`
- **Issue:** Several catch blocks discard errors and render an empty state indistinguishable from "no content". A malformed WS frame throws inside `onmessage` (harmless to the socket, but the event is lost). `panel-status` messages are not in a live region, so "saving…", "stash ok", and warnings are invisible to assistive technology.
- **Recommended fix:** Distinguish "empty" from "failed" in the panel (a small error notice with a retry affordance), wrap `JSON.parse` in try/catch, and add `role="status" aria-live="polite"` to `#panel-status` (SC 4.1.3).
- **Confidence:** Confirmed

---

## LOW / INFORMATIONAL

- **L1 — Tasklist checkboxes disappear in rendered docs.** `Visual Consistency` — comrak's `tasklist` extension (enabled at `main.rs:345`) emits `<input type="checkbox">`, which ammonia's default policy strips. `- [ ]` items render with no box. Fix: post-process comrak's output to swap checkboxes for a Unicode glyph before ammonia, or use a custom renderer. *Confidence: High Confidence (ammonia's default allow-list excludes `input`)*
- **L2 — Relative links to non-markdown assets break.** `app.js:529` only rewrites `.md/.markdown/.txt` links; a README linking `./data.json` or `assets/plan.png` resolves against the dashboard root and 404s (or hits the `ServeDir` fallback). *Confirmed*
- **L3 — Long unbroken names overflow their containers.** `.card .name`, `.health-row .name` (fixed `min-width: 180px`), and `.col-row` have no `overflow`/`word-break` handling; a 60-character project name without spaces clips or pushes past the card. *Confirmed by CSS inspection*
- **L4 — Dangling symlink escape on doc write.** `docs.rs:109-114` — for a non-existent target, the *parent* is canonicalized but the final component is not; a pre-existing dangling symlink inside a project (created by local access) would be followed on write, escaping the root. Requires existing local write access to set up, so it is defense-in-depth, not an attack. Fix: `symlink_metadata` the final component and reject if it `is_symlink`. *High Confidence*
- **L5 — `saveDoc` reports note size in UTF-16 code units, not bytes** (`app.js:592`, `content.length` vs server `meta.len()`). Cosmetic inconsistency in the doc list after a create. *Confirmed*
- **L6 — `ui-slint` doesn't URL-encode project names** (`main.rs:238`: `format!("{BASE}/api/docs/{name}")`); a project dir with a space or `&` fails to load. `ui-web` encodes correctly. *Confirmed*
- **L7 — No `prefers-reduced-motion` guard** for the `.chev` rotation (`style.css:161` etc.). Trivial. *Confirmed*
- **L8 — `POST /api/rescan` is an unauthenticated local DoS** (full multi-root scan per request, no rate limit, no debounce). Low because it is loopback-only by default, but it compounds with H3. *Confirmed*
- **L9 — Missing security headers generally.** No CSP, no `X-Content-Type-Options` on non-`/raw` responses, no `Referrer-Policy`. Cheap to add via `tower-http` layers and they materially blunt H1. *Confirmed*
- **L10 — Misleading comments on the sanitization boundary.** `protocol/src/lib.rs:104` says "raw HTML escaped" and `app.js:557` says "raw HTML escaped server-side" — it is *sanitized*, not escaped. A future maintainer reading "escaped" could reasonably weaken the ammonia step believing innerHTML is inert by construction. The distinction is what makes H1's bypass surprising. *Confirmed*
- **L11 — Documentation drift.** The README badge says "7 tools" and the prose says "Eight tools"; the MCP surface ships **14** (verified in `cli/mcp.rs:331-433` and `docs/API.md`, whose table is correct). `docs/CHARTER.md` D7 and its phase-3 row still say "tree-sitter" for symbol extraction, while `CLAUDE.md` correctly documents regex (`symbols.rs` is pure regex, 114 lines). *Confirmed*
- **L12 — `GitTreeEntry.size` is always `None`** (`git.rs:628`) — a dead protocol field that suggests functionality the daemon doesn't have. *Confirmed*
- **L13 — No test coverage for the web UI, and no integration tests for the HTTP layer.** The path-validation unit tests in `git.rs:792-823` are good and cover the guards that matter most. *Confirmed*
- **L14 — `ui_dir` is resolved relative to CWD** (`config.rs:159`, used at `main.rs:129`); running the daemon from any other directory serves no UI with no warning. *Confirmed*

---

## Prioritized remediation plan

1. **Close the origin boundary (H1, H2, H3).** Add Origin/Host validation to the WS upgrade and every mutating route; add a global CSP plus `Content-Disposition: attachment` on `/raw`. These three are the same fix in three places — the daemon currently trusts that "loopback" equals "me", and web pages break that.
2. **Harden the git subprocess boundary (H4).** Pass `-c` overrides neutralizing `fsmonitor`, `sshCommand`, `pager`, and attributes on every shell-out. This is the only finding with confirmed arbitrary-code-execution potential.
3. **Stop the silent state losses (H5, M9, M11).** Never replace live state with a failed scan; merge rescan results instead of overwriting; recover from a poisoned index instead of `.expect`-ing forever.
4. **Bound the cortex client (H6).** Read deadline outside the mutex; reset the slot on poison.
5. **Keyboard and focus (M1, M2, M4).** Convert the four primary navigation targets to real buttons; name and trap the dialog; restore focus on close. This is the difference between "looks like an app" and "is an app" for anyone who doesn't use a mouse.
6. **Light-mode contrast pass (M5).** Token-level change, broad benefit.
7. **Serialize and guard mutating actions (M6, M7, M8).** Client-side queue per project plus in-flight disabling.
8. **Hygiene sweep (L1–L14).** Low risk, mostly mechanical.

## Quick wins (safe, low regression risk)

- **Origin check on `/ws`** — ~5 lines in `ws_upgrade`, kills H2 outright.
- **`Content-Disposition: attachment` on `/raw`** — ~2 lines, kills H1's execution path (banners still render via `<img>`).
- **Global CSP** — one `tower-http` layer; `ui-web` has no inline scripts so nothing breaks.
- **`Sec-Fetch-Site`/Host check on POST routes** — a small `axum::middleware`, kills H3.
- **Fix `rescan`'s `unwrap_or_default()`** — keep prior state on JoinError (H5).
- **Add `-c core.fsmonitor= …` to git invocations** — one-line change to `git_output` (H4).
- **`aria-labelledby="panel-title"` + focus move into the dialog** — two lines plus a trap (M2).
- **`role="status" aria-live="polite"` on `#panel-status`** (M13) and a shared `:focus-visible` rule (M4).
- **Reject `.git/…` in `validate_repo_rel`** — mirrors what the tree reader already does (M10).
- **Cortex read deadline + spawn outside the mutex** (H6).
- **Tool-count and tree-sitter copy corrections** (L11).

## Issues needing architectural work or deeper investigation

- **A real authorization model.** "Loopback only" is not a security boundary once a browser is involved; the product needs an explicit, documented threat model and, if it is ever exposed beyond loopback, a token or unix-socket permission scheme. H1/H2/H3 are symptoms of this, not isolated bugs.
- **Idempotency for git porcelain.** Duplicate stash entries, racing stage/commit, and lost updates (M6/M7) cannot be fully fixed client-side; the server needs operation serialization or preconditions per project.
- **Reconcile rescan/watcher/index as one state machine** (M9, M11) rather than three independent writers over a shared vector.
- **The untrusted-repo trust boundary generally.** H4 is confirmed for `fsmonitor`; `insteadOf` URL rewriting, `filter`/`diff` drivers via `.gitattributes` (which *is* cloned), and `core.sshCommand` on fetch all deserve a systematic pass. I verified only what I could execute here.
- **MCP write asymmetry.** `CLAUDE.md` states "CLI/MCP are reads only" but `write_doc` is a write tool — intentional, but worth stating explicitly in the docs since agents can now commit to any project.

## Release recommendation

**Ship with known risks** — for its stated audience and defaults.

Justification: every High finding requires either a hostile artifact inside the projects root (H1, H4) or a malicious web page while the user runs the daemon (H2, H3); the defaults are loopback-only, `allow_push` off, and cortex off, which holds the worst chains just out of reach. The reliability findings (H5, H6) degrade gracefully rather than corrupt data, and the accessibility findings are serious but do not block the mouse-using majority. Nothing here is "do not ship" for a personal single-user tool.

That latitude is conditional and narrower than it looks. If any of these change, the assessment hardens: enabling `allow_push` upgrades H1 from "attacker writes files" to "attacker pushes your code"; binding to anything but 127.0.0.1 (which `server.bind` freely permits, contradicting the "localhost only, can't be configured away" claim in `ColonyConfig`'s own comment) turns H2/H3 into remote vulnerabilities; and the moment a multi-user or shared-machine deployment appears, the total absence of authentication is a blocker. The quick wins above are an afternoon's work and would remove three of the six Highs outright — I'd do them before tagging a release rather than after.

---

## Validation pass — 2026-10-06

Re-review of the fixes against every finding. Method: adversarial code inspection plus
empirical testing with the tools available in this container. Comments were not accepted
as evidence — a fix had to be wired into every code path, not merely present.

Statuses: **Verified** (confirmed by reading the wiring and/or running the behaviour),
**Partial** (the stated fix landed but the finding is not fully closed), **Unverifiable**
(cannot be confirmed or refuted in this environment).

### Verified — 28

H1, H2, H3, H4, H5, H6, M1, M2, M3, M4, M6 (client half), M7, M8, M9, M10, M11, M12,
M13, L2, L3, L4, L5, L6, L7, L9, L10, L11, L12.

Notable, with evidence:

- **H4** carries a *behavioural* regression test (`prefrontal-core/src/git.rs:861-898`):
  it plants a poisoned `core.fsmonitor`, calls the real public `status()` entry point,
  and asserts the sentinel file is never created. Every git shell-out routes through
  `git_cmd`; the only bare `Command::new("git")` calls are inside `git_cmd` and its own
  test.
- **H1/H2/H3**: `origin_guard` is the outermost router layer, so new routes inherit the
  boundary rather than having to be added to a list. CSP is *appended*, not set, so
  `/raw`'s stricter `sandbox` policy is not clobbered by the global one
  (`prefrontald/src/main.rs:302-334`).
- **M2** restores focus by `data-open` key with a `document.contains` guard, so it
  survives the card grid re-rendering while the panel is open — a failure mode the
  naive implementation would have had.
- **M7** is fixed more thoroughly than asked: a per-project promise queue serializes
  stage→commit, not just an in-flight flag.
- **L5** now uses `TextEncoder().encode(content).length` for a real byte count.

### Partial — 3

- **M6** — the client-side guard is in, but the server-side half (making `stash push`
  idempotent) was not done. A client that bypasses the UI can still create duplicate
  stash entries. Accepted risk; should be recorded as such rather than closed.
- **L14** — `ui_dir` is still resolved relative to CWD. The change is a loud `warn!`
  naming the resolved path, which converts a silent broken UI into a diagnosable one.
  Fair triage, but "addressed" overstates it.
- **L13** — no test coverage was added for the web UI or the HTTP layer. The origin
  boundary is exercised only by unit-style assertions, not by driving the server.

### Unverifiable — 2

- **"build / clippy / test all clean"** — no Rust toolchain exists in this container, so
  the claim cannot be reproduced. Independent count of test attributes is **22** (7 in
  `prefrontal-core/src/git.rs`, 15 in `prefrontald/src/main.rs`), not the 23 claimed; the
  23rd is plausibly the `prefrontal-client` doctest, which `cargo test` does count.
  Flagged as an arithmetic discrepancy rather than echoed.
- **"boundary proven live (403s for cross-site / foreign-Host / foreign-Origin incl. /ws)"**
  — this container has a transparent HTTP proxy (`cube-site-probe`) that intercepts
  loopback sockets and rewrites headers: a request sent with `Host: evil.example.com`
  arrived at a local listener as `Host: 127.0.0.1:7321`. Every cross-site request I sent
  received an empty reply from the *proxy*, never reached the daemon, and produced no
  `warn!` line in the daemon log. The guard's logic reads correct, but **the live 403s
  cannot be corroborated here** — and could not have been corroborated by anyone in this
  environment. Re-run this test outside the sandbox before treating H1–H3 as proven.

### Gaps found during validation — 3

1. **`.panel-actions` is missing its `[hidden]` guard** (`ui-web/style.css:440` vs.
   `ui-web/app.js:445`). `.panel-actions { display: flex }` beats the `hidden` attribute,
   which the guard list at `style.css:510-511` does not cover. Impact today is nil — all
   four child buttons hide themselves individually — but it is a live trap: the next
   button added to that container that does not individually hide will render on the wrong
   tab. One-line fix. This is a direct violation of the project's own documented sharp
   edge in `CLAUDE.md`.
2. **Dark-mode badges fail WCAG 2.2 AA** — white on `--st-warning #fab219` is ~1.85:1,
   `--st-serious` ~2.64:1, `--st-good` ~3.35:1, all below 4.5:1 at 11.5px bold.
   **This is a defect in the original audit, not a regression:** the report above stated
   dark mode was "largely fine," which under-counted it. Pre-existing, and now the
   product's default theme. The same `--badge-ink` treatment applied to dark mode fixes it.
3. **`commit_detail` always returned `files: []`** — see below.

### Fixed during this validation pass — 1

**`commit_detail`** (`prefrontal-core/src/git.rs:563`). The `--` before the revision made
the sha a pathspec, so `git show --format= --name-status -- <sha>` matched no path and
returned nothing. Verified empirically with git 2.39.5 before and after: the old argv
produced no output; `git show --format= --name-status <sha>` correctly returns `A<TAB>b.txt`.
The Repo pane therefore showed an empty file list for *every* commit since the feature
existed — a silent wrong answer in the flagship view. Fixed by dropping the `--`.

The near-identical diff call at `git.rs:460` (`show --format= -p -- <rev> -- <path>`) is
unaffected — both forms were tested and both produce the correct patch.

No regression test was added for this fix. The toolchain is unavailable here, so an
uncompilable test could not be ruled out; a test mirroring the `poisoned_fsmonitor_*`
style (assert `commit_detail().files` is non-empty on a repo with a known commit) is the
right follow-up where `cargo test` can run.

### Validation verdict

**Accept with qualifications.** The security-critical work is structurally sound — the
layered guard, the appended-CSP detail, and the behavioural H4 test all indicate the
threats were understood rather than papered over, and several items were fixed more
thoroughly than the audit demanded. Nothing found is a blocker.

Before tagging: fix the `.panel-actions` guard; decide whether the dark-mode badge
contrast goes in this release; and get the live boundary test re-run outside this
sandbox — that last one is the claim separating H1–H3 from "fixed on paper."

---

## Self-audit round — 2026-10-08

A follow-up pass re-testing the paths that had previously been reasoned about rather
than executed. It turned up four defects — two of them in the fixes above — all now
corrected.

### Defects found and fixed

1. **`/raw` panicked on any non-ASCII filename** — High. `HeaderValue::from_str` rejects
   bytes above `0x7E`, so `banner-é.png` or any control byte hit
   `.expect("sanitized filename")` and killed the worker thread, dropping the connection.
   The sanitiser had only stripped quotes, backslashes, CR and LF. Fixed at
   `prefrontald/src/main.rs:1024-1048`: the disposition is now built with an RFC 5987
   `filename*=UTF-8''` fallback, and a rejected header value logs a warning instead of
   panicking. Regression test covers the reproduced vector (`a\u{1}b.png`), emoji, tab,
   injected quotes and `0x7F`, and asserts the sandbox CSP survives even when the
   disposition cannot be built.
2. **`Sec-Fetch-Site` presence short-circuited the `Origin` check** — Medium, gate bypass.
   `Some(site) => !ALLOWED_FETCH_SITES...` ignored `Origin` entirely, so
   `Sec-Fetch-Site: none` plus `Origin: http://evil.example` was accepted. The two checks
   now apply independently (`prefrontald/src/main.rs:146-159`). Test covers all three
   site values with a foreign `Origin`, including the WebSocket handshake.
3. **A failed rescan consumed the throttle window** — Medium, silent failure. The
   `last_scan_unix` stamp was written before the scan ran, so a panic left a retry inside
   the 5 s window returning `200` with stale state instead of running. Now rolled back to
   `0` on the error path (`prefrontald/src/main.rs:446`).
4. **`watch()` warnings named no directory** — Low. The fix for M12 logged
   `watch() failed — this directory will not update live` with no path, which is
   unactionable. The warning now carries the directory (`prefrontald/src/watch.rs`), with
   all five call sites updated.

### Verification gaps closed

- **M11's recovery path had never executed.** A test now poisons the *real* mutex via a
  test-only helper and proves the next reindex repairs rather than panicking, that the
  index is searchable afterwards, and that health is restored on refill. The suspicion
  that reopen would hit tantivy's `LockBusy` was wrong — disproved by execution rather
  than argued.
- **D2's test asserts the exact bypass vector**, including over `/ws`.

### Coverage not claimed

- **D3's rollback is code-verified, not test-verified.** `rescan_merges_and_is_throttled`
  exercises only the success path; the panic branch at `main.rs:446` is never triggered.
- **D4 has no test.** `prefrontald/src/watch.rs` contains zero tests, so nothing asserts
  the warning names a directory.
- **H5 remains code-verified only.** A scan panic could not be induced — the audit's own
  suggested repro (a truncated packfile) degrades gracefully, and the only `.expect`s in
  the scan path are static regex constructors that would fail for every project at once.
  Same confidence level as before.

### Corrections to the round summary

- **`commit_detail` does not still return `files: []`.** That was fixed in the previous
  commit (`prefrontal-core/src/git.rs:565`); the residual was stale and is struck.
- **"All four now covered by tests" held for two of the four** (D1, D2). See above.
- One fixture from an earlier panicked test run remained in `/tmp`; cleaned up.

### Residuals accepted

- **Host port is not compared** — `Host: localhost:9999` is accepted because
  `request_host` strips the port. Browsers cannot forge `Host`, and mutations are still
  gated on `Origin`/`Sec-Fetch-Site`, so this is defence-in-depth left permissive to
  avoid silently breaking writes behind a TLS-terminating proxy.
- **Two daemons sharing `~/.local/share/prefrontal/index`** makes the second one's search
  degrade on the tantivy lock. Pre-existing, surfaced by the audit run, not introduced.

Test count is now 26 (25 attributes plus the `prefrontal-client` doctest), up from 22.
