# Handoff — remaining audit items

**To:** producer AI
**From:** PM (validation round, 2026-10-08)
**Re:** the four items not yet closed, plus the coverage gaps

All 33 original findings in `AUDIT.md` were addressed, and the self-audit round
(2026-10-08) fixed four further defects. **31 of the 33 are fully closed.** This file
covers what is left, written so each item can be picked up independently — no context
from the audit thread is needed beyond this document and `AUDIT.md`.

Nothing below is an exploit path or a data-loss risk. The security boundary (H1–H4) is
closed and behaviourally tested. What remains is one accessibility failure on the default
theme, one latent CSS trap, one half-finished race guard, and two test-coverage gaps.

**Do not re-open closed items.** Every fix below was verified by reading the wiring, not
the comments; several were re-verified by the producer's own tests. If you believe a
closed item is still broken, reproduce it and open a new defect rather than reverting.

---

## R1 — Dark-mode badge contrast fails WCAG 2.2 AA

- **Severity:** Medium (Accessibility)
- **Finding this descends from:** M5, which was verified fixed for *light* mode only
- **State:** open. `--badge-ink` is `#ffffff` in the dark scope (`ui-web/style.css:37`)
  and is overridden to `#0b0b0b` only inside the light media query (`:63`). Dark mode is
  the product's default theme.

**The problem.** Status badges render white text on saturated backgrounds. Measured
against the token values in the dark scope:

| Token | Background | Contrast | Passes 4.5:1? |
|---|---|---|---|
| `--st-warning` | `#fab219` | 1.83:1 | no |
| `--st-serious` | `#ec835a` | 2.64:1 | no |
| `--st-good` | `#0ca30c` | 3.35:1 | no |
| `--st-critical` | `#d03b3b` | 4.80:1 | yes |

The badges are 11.5px bold, so 4.5:1 is the bar (SC 1.4.3 Contrast Minimum).

**Why this was missed.** The original audit stated dark mode was "largely fine," which
under-counted it. The M5 fix correctly added `--badge-ink` but only wired it into the
light override. This is a defect in the audit, not a regression — but it is still a live
failure on the default theme.

**Fix.** Give the dark scope its own dark-on-light treatment: add a dark-mode
`--badge-ink` (something like `#0b0b0b`) or per-status text tokens, and confirm
`--st-critical` still reads acceptably against its own background once the ink changes.
Light mode must stay as it is — it passes. Re-measure with a contrast checker; the ratios
above were computed by hand from the hex values and should be confirmed.

**Verify by:** rendering each badge in dark mode and confirming the computed ratio;
ideally a check that asserts the token, since CSS contrast is hard to unit-test.

---

## R2 — `.panel-actions` is missing its `[hidden]` guard

- **Severity:** Low (latent trap, Visual Consistency)
- **Finding this descends from:** the `[hidden]` sharp edge documented in `CLAUDE.md`
- **State:** open. Guards exist at `ui-web/style.css:398` and `:510-511`; `.panel-actions`
  is not among them.

**The problem.** An author `display:` property beats the HTML `hidden` attribute — the
project's own documented sharp edge. `.panel-actions` declares `display: flex`
(`ui-web/style.css:440`) and its container `#notes-actions` toggles `hidden`
(`ui-web/app.js:445`), so without a guard the attribute is inert.

**Impact today is nil**, because all four child buttons (`btn-new`, `btn-edit`, `btn-save`,
`btn-cancel`) hide themselves individually and the empty flex box contributes no visible
space. It is a trap, not a current bug: the next button added to that container that does
not individually hide will render on the wrong tab, silently.

**Fix.** One line — add `#notes-actions[hidden]` to the existing rule at
`ui-web/style.css:510`:

```css
.repo-body[hidden], #notes-body[hidden], #repo-commit-bar[hidden],
#repo-tree[hidden], #repo-banner[hidden], #notes-actions[hidden] { display: none; }
```

**Verify by:** opening the Repo tab and confirming the notes actions are absent, then the
Notes tab and confirming they are present. `curl` will not show this — render it.

---

## R3 — M6 is half-fixed: server-side stash idempotency

- **Severity:** Medium (Race Condition)
- **Finding this descends from:** M6, closed as "partial" in the validation round
- **State:** client side done, server side not done.

**What is fixed.** `saveDoc` and `gitOp` now guard against double-fire and disable their
triggers while in flight (`ui-web/app.js`). Stage→commit is serialized by a per-project
promise queue, which closes M7 properly.

**What is not fixed.** `git stash push` remains non-idempotent on the server. Nothing in
`prefrontal-core/src/git.rs` serializes or de-duplicates: no lock, no precondition
(`grep` for `Mutex`/`RwLock` in that file returns nothing). Any client that bypasses the
UI guard — a script, an MCP call, a second tab — can still interleave and create
duplicate stash entries.

**Fix.** Either serialise the porcelain writes per project, or make `stash push`
idempotent by checking for an identical existing entry before pushing. The client-side
guard is convenience, not correctness — do not treat it as the fix.

**Note:** this was triaged as an accepted risk in the validation round, so confirm with
the owner before changing server semantics. If they prefer to keep it client-side only,
say so in `AUDIT.md` and close it as accepted rather than leaving it partial.

---

## Coverage gaps — not functional defects

These are tests that should exist for fixes that are already correct in the code. Neither
changes behaviour.

### C1 — D3's rollback branch is never exercised
`rescan_merges_and_is_throttled` (`prefrontald/src/main.rs:1339`) tests only the success
path. The actual defect — `last_scan_unix` being consumed before the scan, now rolled
back to `0` on the error path at `prefrontal-core/.../main.rs:446` — is never triggered.
Add a case that forces the scan to fail and asserts a retry inside the 5 s window runs.

### C2 — `watch.rs` has zero tests
D4's fix (the warning now naming the directory) has no test at all. Nothing asserts the
path appears in the message. This is the only file in the workspace with logic and no
tests.

---

## Accepted residuals — leave alone

These were reviewed and deliberately left as-is. They are recorded here so they are not
re-litigated:

- **Host port is not compared.** `Host: localhost:9999` is accepted because
  `request_host` strips the port. Browsers cannot forge `Host`, mutations are still gated
  on `Origin`/`Sec-Fetch-Site`, and comparing it would silently break writes behind a
  TLS-terminating proxy.
- **Two daemons sharing `~/.local/share/prefrontal/index`** make the second one's search
  degrade on the tantivy lock. Pre-existing, surfaced by the audit run, not introduced.
- **H5 is code-verified only.** A `scan_all` panic could not be induced — a truncated
  packfile degrades gracefully, and the only `.expect`s in the scan path are static regex
  constructors that would fail for every project at once.

---

## When you are done

Update the validation section in `AUDIT.md` — move R1, R2 and R3 from open to closed (or
accepted, with the owner's call recorded for R3) and note the coverage gaps as closed.
State plainly which of the four are test-verified versus code-verified; the last round's
summary claimed "all covered by tests" when only two of four were, and the correction is
already in the document.

Two notes on working in this repo. The shell's working directory resets between commands
in this environment — always use absolute paths or `git -C`, or a commit or push will
silently land in the wrong repository. And `CLAUDE.md`'s invariants are binding: in
particular, never weaken the ammonia sanitisation step or introduce a bare
`Command::new("git")` outside `git_cmd`.
