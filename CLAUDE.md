# CLAUDE.md — Prefrontal-RS maintainer's brief

You are working on Prefrontal-RS: a fully local, live dashboard over the
user's projects root. Built idea-to-public in one session (2026-07-29); this
file is that session's expertise, distilled. Read `docs/CHARTER.md` before
any non-trivial change — **the decisions log (D1–D9 + dated entries) is
binding**; amend it with a dated entry when a decision changes, never
silently.

## Architecture in one breath

`prefrontald` (axum, :7320 — "PFC" on a phone keypad) holds a warm cache of
`Project`s, fed by a gix scanner and a notify watcher, and broadcasts WS
deltas. `prefrontal-core` owns all logic (scan/config/docs/search/cortex) so
the CLI works daemon-less. `prefrontal-protocol` is the wire: **frontends
deserialize the same enums the daemon serializes — never string-match, never
invent shapes**. Frontends: `ui-web` (daily driver, static, no build step, no
CDN), `ui-slint` (reading surface ONLY per D4 — no editing, no markdown
rendering), `prefrontal-cli` (humans + `mcp` stdio server for agents),
`prefrontal-client` (SDK).

## Invariants — break these and you've broken the product

- **Loopback is not a boundary on its own.** The daemon has no auth, so
  `origin_guard` (in `prefrontald/src/main.rs`) re-establishes "the caller is
  the local user" per request: `Host` must be the configured bind, and every
  mutating request plus `/ws` must be `Sec-Fetch-Site: same-origin|none` or
  carry an `Origin` matching our own authority. Every response gets a CSP,
  `nosniff`, and friends. A new route is inside this boundary automatically —
  do not add one outside the router.
- **Project directories are untrusted.** Anything under the roots may have
  been copied or unpacked from somewhere else, `.git/config` included. Every
  `git` shell-out goes through `core::git::git_cmd`, which neutralizes
  `core.fsmonitor`, `core.attributesFile`, `credential.helper`,
  `core.sshCommand`, `core.pager` and pins `core.hooksPath`. Use it; a bare
  `Command::new("git")` reintroduces remote code execution.
- **Never replace live state with a failed scan.** `rescan` merges by
  freshness and keeps the previous list on a panic; `SearchIndex` rebuilds
  itself when the writer is poisoned. `.expect` on a poisoned index or
  `unwrap_or_default()` on a scan is how the dashboard used to go blank.
- **Path inputs are hostile.** Doc paths go through `docs::resolve_rel_path`
  (relative, no `..`, extension allow-listed, symlink-escape checked). Git
  pathspecs go through `git::resolve_repo_rel` / `validate_repo_rel` — same
  guards, no extension allow-list, no magic `:(` / `:!` / globs. Projects
  are addressed by *name*, resolved only through the scan cache — clients
  never send filesystem paths.
- **Note commits are pathspec-scoped** (`git add -- <file> && git commit
  -- <file>`, message `[prefrontal] note: <path>`) so they can NEVER sweep up
  staged work. Notes never push. Repo-tab Push is explicit, never `--force`,
  gated by `[git] allow_push` (default off). Report failures honestly.
- **The index is a cache, never truth** — schema mismatch wipes and rebuilds
  (`search::open`). Any schema change is therefore safe but costs a rebuild.
- **Central config only** (`~/.config/prefrontal/config.toml`); no
  per-project dotfiles, ever (D5).
- **Cortex is optional** (D6): `features.cerebro` off ⇒ every cortex path is
  dark and lexical search never notices. `/api/cortex` 503s, UI goes quiet.
- **Rendered HTML is sanitized, not escaped** — the distinction matters.
  comrak with `render.r#unsafe = true` piped through `ammonia::clean`:
  banners/img/div survive, scripts and handlers must not. Never write
  "escaped" in a comment here; a future maintainer who believes `innerHTML`
  is inert by construction will weaken the one step standing between a cloned
  README and the dashboard's write access.
- **The UI is keyboard-operable.** Cards, health rows, timeline entries and
  search hits are real `<button>`s; the project dialog is named
  (`aria-labelledby`), traps Tab, takes focus on open and gives it back on
  close. Interactive elements never nest. `ui-web/app.js` builds everything
  with `el()`/`textContent` — keep it that way.
- **Pure Rust, no C linking** (D7): gix not libgit2, regex symbols not
  tree-sitter, comrak not a JS renderer. Sanctioned `git` shell-outs: note
  commits, complete status (`porcelain=v2`), unified diffs, and the
  allowlisted porcelain writes (identity/hooks). Slint stays in `ui-slint`.
- **Typography**: body text is system sans (~1.5–1.6 line-height); monospace
  strictly inside code blocks. This is an accessibility decision (owner's
  eyes), not taste.

## Where things live / how they work

- `core/scan.rs` — scanner. Activity derives from last-touch (7/30/180d);
  health flags: no_git, no_remote, never_committed, dirty_pile. Tagline =
  first `###` or first paragraph of README, HTML-stripped. `SKIP_DIRS` is THE
  shared skip list (watcher + docs walk + indexer + repo tree).
- `core/git.rs` — phase 7 working tree. Reads: gix log/refs/tree/blob +
  `git status --porcelain=v2` / `git diff` (dated exception). Writes: allowlisted
  `git -C` only, always via `git_cmd` (see the untrusted-repo invariant).
  CLI/MCP are reads only **except** `write_doc`, which writes one markdown
  file and auto-commits it locally — deliberate, but it means an agent can
  land a commit in any project under the roots.
- `prefrontald/watch.rs` — per-directory watches (NEVER blanket-recursive:
  `target/` would eat inotify), `.git` watched surgically (dir non-recursive
  + `refs/` recursive → commits/branch-switches register without object-store
  noise). 600 ms quiet-period debounce per project; equal rescans are
  suppressed via protocol `PartialEq`. ~4k watches on a 47-project garden.
- `core/search.rs` — one tantivy index: files (content indexed, not stored —
  snippets/line numbers read from disk at query time), commit summaries
  (1000/project via gix walk, stored), symbol cards (regex per language, one
  tiny doc per declaration; name queries outrank files naturally). Index dir:
  `~/.local/share/prefrontal/index`.
- `core/cortex.rs` — MCP stdio *client* (mirror of `cli/mcp.rs`'s server).
  Spawns `[cortex] command` (cerebro-mcp). Upserts are tag-deduped
  (`prefrontal` + `project:<name>`, shared visibility). Client respawns after
  any pipe error (daemon holds it in `Mutex<Option<_>>`).
- `cli/mcp.rs` — hand-rolled MCP server, newline JSON-RPC. Tool failures are
  MCP `isError` results with helpful text; JSON-RPC errors only for protocol
  breakage. Scans cached 10 s per process.
- WS contract: snapshot on connect covers all gaps — clients need zero replay
  logic. Keep it that way.

## Sharp edges met and filed down (don't rediscover these)

- axum 0.8: routes are `/{param}` and `/{*path}`, not `:param`.
- comrak 0.54: the field is `render.r#unsafe` (raw identifier).
- tantivy 0.26: `TopDocs::with_limit(n).order_by_score()`.
- gix 0.86: unborn HEAD ⇒ `head_commit()` errs ⇒ that's `never_committed`;
  dirty count via `status(...).into_index_worktree_iter(Vec::new())`.
- CSS: an author `display:` beats the `hidden` attribute — every element that
  toggles `hidden` and declares its own display needs a `[hidden]{display:none}`
  guard. **Render-test UI changes; curl is not enough.**
- **The MCP registration points at `target/release/prefrontal`** (in
  `~/Projects/.mcp.json`). After changing the CLI/MCP surface, run
  `cargo build --release` or agents run a stale binary.

## Workflow

```sh
cargo build --workspace && cargo clippy --workspace   # clippy-zero policy
pkill -x prefrontald; ./target/debug/prefrontald &    # run from repo root (ui-web resolves via cwd)
curl -s 127.0.0.1:7320/api/projects | head            # smoke
```

Verification style: prove features on real data (this repo flagged its own
`no-git` at birth; the first note ever committed was its own phase-3 ideas
file). WS testing: python3 + `websockets` (see session pattern: connect,
mutate a file, assert the delta). House commit voice: story-telling subject
lines; significant work updates `docs/CHARTER.md`'s log. README banners are
generated with Imaginarium-RS and credited by job id.

## Roadmap seeds (charter-consistent, unscheduled)

`notes/phase-3-ideas.md` holds search follow-ups; open questions live at the
bottom of the charter (local-LLM resume blurbs, multi-root UI, note-push
policy). The hermes twin-checkout duplicate-hit quirk is fixable with an
`[overrides] ignore` — user's call, not code's.
