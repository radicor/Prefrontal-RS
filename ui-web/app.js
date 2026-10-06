// Prefrontal-RS ui-web — snapshot over WS with REST fallback, client-side filter.
// Types mirror prefrontal-protocol; frontends never invent their own shapes.

"use strict";

const ACTIVITY_ORDER = ["active", "warm", "cold", "parked", "archived"];
const ACTIVITY_DOT = {
  active: "var(--act-active)",
  warm: "var(--act-warm)",
  cold: "var(--act-cold)",
  parked: "var(--act-parked)",
  archived: "transparent",
};
const LANG_DOT = {
  rust: "var(--lang-rust)",
  node: "var(--lang-node)",
  python: "var(--lang-python)",
  godot: "var(--lang-godot)",
};
// severity classes map to the reserved status palette; icon + label, never color alone
const FLAG_VIEW = {
  no_git: { label: "no git", icon: "✖", cls: "critical" },
  no_remote: { label: "no remote", icon: "☁", cls: "serious" },
  never_committed: { label: "never committed", icon: "∅", cls: "serious" },
  dirty_pile: { label: "dirty", icon: "⚠", cls: "warning" },
};

let projects = [];
let colony = null;
// once the user opens/closes the drawer themselves, stop auto-managing it
let healthTouched = false;
let wsRetryMs = 1000;
let wsRetryTimer = null;

function flagText(f) {
  const v = FLAG_VIEW[f.flag] ?? { label: f.flag, icon: "•", cls: "warning" };
  const extra = f.flag === "dirty_pile" ? ` ×${f.count}` : "";
  return { ...v, text: `${v.icon} ${v.label}${extra}` };
}

function ago(unix) {
  const days = Math.max(0, Math.floor(Date.now() / 1000 - unix) / 86400) | 0;
  if (days === 0) return "today";
  if (days === 1) return "1d ago";
  if (days < 60) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

function renderStats() {
  const wrap = document.getElementById("stats");
  wrap.replaceChildren();
  const dirtyTotal = projects.reduce((s, p) => s + (p.git?.dirty_files ?? 0), 0);
  const tiles = [
    { k: "projects", v: projects.length },
    { k: "active", v: projects.filter((p) => p.activity === "active").length },
    { k: "warm", v: projects.filter((p) => p.activity === "warm").length },
    { k: "flagged", v: projects.filter((p) => p.health.length).length, alert: true },
    { k: "uncommitted files", v: dirtyTotal, alert: dirtyTotal > 0 },
  ];
  for (const t of tiles) {
    const tile = el("div", "tile" + (t.alert && t.v > 0 ? " alert" : ""));
    tile.append(el("div", "v", String(t.v)), el("div", "k", t.k));
    wrap.append(tile);
  }
}

function renderHealth(list) {
  const panel = document.getElementById("health");
  const flagged = list.filter((p) => p.health.length);
  panel.hidden = flagged.length === 0;

  // collapsed summary: total + per-flag breakdown, so the alert reads at a glance
  const counts = {};
  for (const p of flagged) for (const f of p.health) counts[f.flag] = (counts[f.flag] ?? 0) + 1;
  const parts = Object.entries(counts).map(
    ([k, n]) => `${FLAG_VIEW[k]?.label ?? k} ×${n}`
  );
  document.getElementById("health-summary").textContent =
    `${flagged.length} need${flagged.length === 1 ? "s" : ""} attention — ${parts.join(" · ")}`;

  // a handful auto-opens; a wall of them stays tidy behind the drawer
  if (!healthTouched) panel.open = flagged.length > 0 && flagged.length <= 4;

  const rows = document.getElementById("health-list");
  rows.replaceChildren();
  for (const p of flagged) {
    const row = el("button", "health-row");
    row.type = "button";
    row.dataset.open = p.name;
    row.onclick = () => openPanel(p.name, { tab: "repo" });
    row.append(el("span", "name", p.name));
    for (const f of p.health) {
      const v = flagText(f);
      row.append(el("span", `badge ${v.cls}`, v.text));
    }
    rows.append(row);
  }
}

function dayLabel(unix) {
  const d = new Date(unix * 1000);
  const today = new Date();
  const midnight = new Date(today.getFullYear(), today.getMonth(), today.getDate());
  const daysBack = Math.floor((midnight - new Date(d.getFullYear(), d.getMonth(), d.getDate())) / 86400000);
  if (daysBack <= 0) return "today";
  if (daysBack === 1) return "yesterday";
  return d.toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short" });
}

function renderTimeline(list) {
  const panel = document.getElementById("timeline");
  const entries = [];
  for (const p of list)
    for (const c of p.git?.recent_commits ?? [])
      entries.push({ project: p.name, ...c });
  entries.sort((a, b) => b.time_unix - a.time_unix);
  panel.hidden = entries.length === 0;
  if (!entries.length) return;

  const projCount = new Set(entries.map((e) => e.project)).size;
  document.getElementById("timeline-summary").textContent =
    `where was I — ${entries.length} commits across ${projCount} project${projCount === 1 ? "" : "s"}`;

  // day → runs of consecutive same-project commits
  const wrap = document.getElementById("tl-list");
  wrap.replaceChildren();
  let day = null, dayEl = null, block = null, blockProject = null;
  for (const e of entries) {
    const label = dayLabel(e.time_unix);
    if (label !== day) {
      day = label;
      dayEl = el("div", "tl-day");
      dayEl.append(el("h3", "", label));
      wrap.append(dayEl);
      block = null;
      blockProject = null;
    }
    if (e.project !== blockProject) {
      blockProject = e.project;
      block = el("div", "tl-block");
      block.append(el("div", "tl-proj", e.project));
      dayEl.append(block);
    }
    const row = el("button", "tl-commit");
    row.type = "button";
    row.dataset.open = e.project;
    const time = new Date(e.time_unix * 1000).toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
    });
    row.append(el("span", "t", time), el("span", "msg", e.summary));
    row.title = `${e.id} — ${e.summary}`;
    row.onclick = () => openPanel(e.project, { tab: "repo", commitId: e.id });
    block.append(row);
  }
}

/* ---------- colony panel ---------- */

// Mirrors prefrontal_protocol::SiblingSurface — same enum, no invented shapes.
const SURFACE_LABEL = {
  web_ui: "web ui",
  http_api: "api",
  mcp: "mcp",
  cli: "cli",
  native: "native",
  no_runtime: "—",
};

function renderColony() {
  const panel = document.getElementById("colony");
  if (!colony || !colony.siblings.length) {
    panel.hidden = true;
    return;
  }
  // installed is an OR of independent signals: a sibling can be live with no
  // checkout (binary installs) or checked out and dormant
  const rows = colony.siblings.map((s) => ({
    ...s,
    installed: Boolean(s.checkout || s.binary || s.live === true),
  }));
  const live = rows.filter((s) => s.live === true).length;
  const idle = rows.filter((s) => s.installed && s.live !== true).length;
  const missing = rows.length - live - idle;
  panel.hidden = false;
  document.getElementById("colony-summary").textContent =
    `colony — ${live} live · ${idle} installed · ${missing} not here`;

  const list = document.getElementById("colony-list");
  list.replaceChildren();
  for (const s of rows) {
    const row = el("div", "col-row");
    // dot + state word together — never color alone
    const dot = el("span", "dot" + (s.installed ? "" : " hollow"));
    if (s.live === true) dot.style.background = "var(--st-good)";
    else if (s.installed) dot.style.background = "var(--act-parked)";
    const stateWord = s.live === true ? "live" : s.installed ? "installed" : "not installed";
    row.append(
      dot,
      el("span", "name", s.name),
      el("span", "state" + (s.installed ? "" : " dim"), stateWord),
      el("span", "tagline", s.tagline)
    );

    const reach = el("span", "reach");
    if (s.url && s.live === true) {
      const a = el("a", "", `:${s.port} ↗`);
      a.href = s.url;
      a.target = "_blank";
      a.rel = "noopener";
      a.title = s.url;
      reach.append(a);
    } else if (s.port && s.installed) {
      reach.append(el("code", "", `:${s.port}`));
    }
    if (s.mcp && s.installed) reach.append(el("code", "", `mcp:${s.mcp}`));
    if (s.installed && !s.url && !s.port && !s.mcp && s.binary)
      reach.append(el("code", "", s.binary.split("/").pop()));
    if (!s.installed) {
      const a = el("a", "", "lander ↗");
      a.href = s.lander;
      a.target = "_blank";
      a.rel = "noopener";
      a.title = s.lander;
      reach.append(a);
    }
    reach.append(el("span", "kind", SURFACE_LABEL[s.surface] ?? s.surface));
    row.append(reach);

    row.title =
      [s.checkout && `checkout: ${s.checkout}`, s.binary && `binary: ${s.binary}`]
        .filter(Boolean)
        .join("\n") || "not detected on this machine";
    list.append(row);
  }
}

function card(p) {
  const c = el("button", "card" + (p.activity === "archived" ? " archived" : ""));
  c.type = "button";
  c.title = `open docs & notes for ${p.name}`;
  c.dataset.open = p.name;
  c.onclick = () => openPanel(p.name);

  const head = el("div", "head");
  head.append(el("span", "name", p.name), el("span", "ago", ago(p.last_touched_unix)));
  c.append(head);

  if (p.tagline) c.append(el("div", "tagline", p.tagline));

  if (p.git) {
    const g = el("div", "git-line");
    if (p.git.branch) g.append(el("span", "branch", `⎇ ${p.git.branch}`));
    if (p.git.commit_count != null) g.append(el("span", "", `${p.git.commit_count} commits`));
    if (p.git.dirty_files) g.append(el("span", "dirty", `${p.git.dirty_files} dirty`));
    if (p.git.ahead) g.append(el("span", "ab", `↑${p.git.ahead}`));
    if (p.git.behind) g.append(el("span", "ab", `↓${p.git.behind}`));
    c.append(g);
  }

  const meta = el("div", "meta");
  for (const lang of p.languages) {
    const chip = el("span", "chip");
    const dot = el("span", "dot");
    dot.style.background = LANG_DOT[lang] ?? "var(--muted)";
    chip.append(dot, document.createTextNode(lang));
    meta.append(chip);
  }
  for (const tag of p.tags) meta.append(el("span", "chip", `#${tag}`));
  for (const f of p.health) {
    const v = flagText(f);
    meta.append(el("span", `badge ${v.cls}`, v.text));
  }
  if (meta.childElementCount) c.append(meta);
  return c;
}

/* ---------- content search ---------- */

let searchTimer = null;
let searchSeq = 0;
let cortexSeq = 0;

// Both panels answer the same debounced query; a slow reply from one must not
// paint over the other's newer results.
function isCurrent(seq) {
  return seq === searchSeq && seq === cortexSeq;
}

let cortexAvailable = true; // flips off on the first 503 so we stop asking

function scheduleSearch() {
  clearTimeout(searchTimer);
  const q = document.getElementById("filter").value.trim();
  if (q.length < 3) {
    document.getElementById("search-results").hidden = true;
    document.getElementById("cortex-results").hidden = true;
    return;
  }
  searchTimer = setTimeout(() => {
    runSearch(q);
    runCortex(q);
  }, 250);
}

async function runCortex(q) {
  const seq = ++cortexSeq;
  const section = document.getElementById("cortex-results");
  if (!cortexAvailable) return;
  try {
    const res = await fetch(`/api/cortex?q=${encodeURIComponent(q)}`);
    if (res.status === 503) {
      cortexAvailable = false; // feature off — stay quiet for the session
      return;
    }
    if (!res.ok) {
      section.hidden = true;
      return;
    }
    const hits = await res.json();
    if (!isCurrent(seq)) return; // a newer query is in flight
    section.hidden = hits.length === 0;
    document.getElementById("cortex-count").textContent = hits.length ? `(${hits.length})` : "";
    const list = document.getElementById("cortex-list");
    list.replaceChildren();
    for (const h of hits) {
      const row = el("div", "hit");
      const top = el("div", "top");
      top.append(el("span", "proj", h.agent_id || "memory"), el("span", "kind", "recall"));
      if (h.score != null) top.append(el("span", "loc", h.score.toFixed(2)));
      for (const t of h.tags.slice(0, 4)) top.append(el("span", "loc", `#${t}`));
      row.append(top, el("div", "snippet", h.content.slice(0, 220)));
      row.title = h.content.slice(0, 1000);
      list.append(row);
    }
  } catch {
    section.hidden = true;
  }
}

async function runSearch(q) {
  const seq = ++searchSeq;
  try {
    const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
    if (!res.ok || !isCurrent(seq)) return; // stale response — a newer query is in flight
    renderHits(await res.json());
  } catch {
    /* daemon gone; the conn dot already says so */
  }
}

function renderHits(hits) {
  const section = document.getElementById("search-results");
  section.hidden = hits.length === 0;
  document.getElementById("search-count").textContent = hits.length ? `(${hits.length})` : "";
  const list = document.getElementById("hit-list");
  list.replaceChildren();
  for (const h of hits) {
    const isDoc = h.kind === "doc";
    const isCommit = h.kind === "commit";
    const isCode = h.kind === "code" || h.kind === "symbol";
    const openable = isDoc || isCommit || isCode;
    const row = el(openable ? "button" : "div", "hit" + (openable ? " openable" : ""));
    if (openable) {
      row.type = "button";
      row.dataset.open = h.project;
    }
    const top = el("div", "top");
    const loc =
      h.kind === "commit" ? `commit ${h.path}` : h.line ? `${h.path}:${h.line}` : h.path;
    top.append(el("span", "proj", h.project), el("span", "kind", h.kind), el("span", "loc", loc));
    row.append(top, el("div", "snippet", h.snippet));
    if (isDoc) {
      row.title = "open in the docs panel";
      row.onclick = async () => {
        await openPanel(h.project, { tab: "notes" });
        openDoc(h.path);
      };
    } else if (isCommit) {
      row.title = "open commit in the repo pane";
      row.onclick = () => openPanel(h.project, { tab: "repo", commitId: h.path });
    } else if (isCode) {
      row.title = "open file in the repo pane";
      row.onclick = () => openPanel(h.project, { tab: "repo", filePath: h.path, tree: true });
    }
    list.append(row);
  }
}

/* ---------- project panel (docs & notes) ---------- */

const panel = {
  project: null,
  docs: [],
  docsError: null,
  opener: null, // the element focus returns to when the panel closes
  openPath: null,
  raw: "",
  mode: "view", // view | edit | create
  tab: "notes", // notes | repo
  repoMode: "wt", // wt | files
  git: null,
  refs: [],
  log: [],
  selPath: null,
  selCached: false,
  selCommit: null,
  treePath: "",
  treeRev: "HEAD",
};

const $ = (id) => document.getElementById(id);
const enc = encodeURIComponent;

function status(msg, cls) {
  const s = $("panel-status");
  s.replaceChildren(cls ? el("span", cls, msg) : document.createTextNode(msg));
}

function setMode(mode) {
  panel.mode = mode;
  const editing = mode !== "view";
  $("doc-view").hidden = editing;
  $("doc-editor").hidden = !editing;
  $("doc-filename").hidden = mode !== "create";
  $("btn-edit").hidden = editing || !panel.openPath || panel.tab === "repo";
  $("btn-save").hidden = !editing;
  $("btn-cancel").hidden = !editing;
  $("btn-new").hidden = editing || panel.tab === "repo";
  if (editing && panel.tab === "notes") $(mode === "create" ? "doc-filename" : "doc-editor").focus();
}

function setTab(tab) {
  panel.tab = tab;
  const repo = tab === "repo";
  $("notes-body").hidden = repo;
  $("repo-body").hidden = !repo;
  $("notes-actions").hidden = repo;
  $("repo-commit-bar").hidden = !repo;
  $("tab-notes").classList.toggle("sel", !repo);
  $("tab-repo").classList.toggle("sel", repo);
  document.querySelector(".panel").classList.toggle("wide", repo);
  $("repo-mode-wt").classList.toggle("sel", panel.repoMode === "wt");
  $("repo-mode-files").classList.toggle("sel", panel.repoMode === "files");
  $("repo-status").hidden = panel.repoMode !== "wt";
  $("repo-tree").hidden = panel.repoMode !== "files";
  if (repo) {
    if (panel.mode !== "view") setMode("view");
    loadRepo();
  } else {
    $("btn-new").hidden = false;
    $("btn-edit").hidden = !panel.openPath;
  }
}

async function openPanel(projectName, opts = {}) {
  // Keyed, not element-keyed: the card grid re-renders on every WS delta, so
  // the node that opened the panel is often gone by the time it closes.
  if ($("overlay").hidden) {
    panel.opener = document.activeElement;
    panel.openerKey = document.activeElement?.dataset?.open ?? null;
  }
  const prev = panel.project;
  panel.project = projectName;
  panel.openPath = null;
  panel.selPath = opts.filePath ?? null;
  panel.selCached = false;
  panel.selCommit = opts.commitId ?? null;
  panel.treePath = "";
  panel.treeRev = "HEAD";
  if (opts.tree && opts.filePath) {
    panel.repoMode = "files";
    const slash = opts.filePath.lastIndexOf("/");
    panel.treePath = slash >= 0 ? opts.filePath.slice(0, slash) : "";
  } else if (opts.tab !== "repo" || prev !== projectName) {
    panel.repoMode = "wt";
  }
  $("panel-title").textContent = projectName;
  $("panel-path").textContent = "";
  $("doc-view").replaceChildren();
  $("repo-view").textContent = "";
  status("");
  setMode("view");
  $("overlay").hidden = false;
  // The dialog asserts modality; move focus into it so the keyboard is here
  // rather than back in the card grid behind the scrim.
  $("tab-notes").focus();
  panel.docsError = null;
  try {
    const res = await fetch(`/api/docs/${enc(projectName)}`);
    if (res.ok) {
      panel.docs = await res.json();
    } else {
      panel.docs = [];
      panel.docsError = await res.text();
    }
  } catch {
    panel.docs = [];
    panel.docsError = "daemon unreachable";
  }
  renderDocList();
  if (panel.docs.length) {
    openDoc(panel.docs[0].path); // README sorts first server-side
  } else if (panel.docsError) {
    $("doc-view").replaceChildren(
      el("div", "empty", `couldn't list docs — ${panel.docsError}`),
      retryButton(() => openPanel(projectName, opts))
    );
  } else {
    $("doc-view").replaceChildren(el("div", "empty", "no docs here yet — start one with ＋ note"));
  }
  const proj = projects.find((p) => p.name === projectName);
  const dirty = (proj?.git?.dirty_files ?? 0) > 0;
  const wantRepo = opts.tab === "repo" || (!opts.tab && dirty);
  setTab(wantRepo ? "repo" : "notes");
}

/// A failed load must not look like an empty one — say so, and offer the retry.
function retryButton(onRetry) {
  const b = el("button", "retry", "retry");
  b.type = "button";
  b.onclick = onRetry;
  return b;
}

function renderDocList() {
  const list = $("doc-list");
  list.replaceChildren();
  if (!panel.docs.length) {
    list.append(el("div", "none", panel.docsError ? "docs unavailable" : "no docs"));
    return;
  }
  for (const d of panel.docs) {
    const a = el("a", d.path === panel.openPath ? "sel" : "", d.path);
    a.href = "#";
    a.title = d.path;
    a.onclick = (e) => {
      e.preventDefault();
      openDoc(d.path);
    };
    list.append(a);
  }
}

// Resolve doc-relative references: images and other files go through /raw,
// sibling docs navigate inside the panel, external links open a fresh tab.
// Anything relative that used to be left alone resolved against the dashboard
// root and 404'd into the UI's own ServeDir, which is never what the author
// meant.
function fixupDocLinks(container, project, docPath) {
  const dir = docPath.includes("/") ? docPath.slice(0, docPath.lastIndexOf("/") + 1) : "";
  const isExternal = (u) => /^([a-z][a-z0-9+.-]*:)?\/\//i.test(u) || u.startsWith("data:") || u.startsWith("/");
  const resolve = (rel) => {
    const out = [];
    for (const p of (dir + rel).split("/")) {
      if (p === "" || p === ".") continue;
      if (p === "..") out.pop();
      else out.push(p);
    }
    return out.join("/");
  };
  const rawUrl = (rel) =>
    `/raw/${encodeURIComponent(project)}/${resolve(rel).split("/").map(encodeURIComponent).join("/")}`;

  for (const img of container.querySelectorAll("img")) {
    const src = img.getAttribute("src") ?? "";
    if (src && !isExternal(src)) img.src = rawUrl(src);
  }
  for (const a of container.querySelectorAll("a")) {
    const href = a.getAttribute("href") ?? "";
    if (!href || href.startsWith("#")) continue;
    if (isExternal(href)) {
      a.target = "_blank";
      a.rel = "noopener";
    } else if (/\.(md|markdown|txt)(#.*)?$/i.test(href)) {
      const target = resolve(href.split("#")[0]);
      a.href = "#";
      a.onclick = (e) => {
        e.preventDefault();
        openDoc(target);
      };
    } else {
      // A relative link to a non-doc file. /raw serves the image extensions a
      // README actually references and refuses the rest with a reason, which
      // beats a silent 404 from the dashboard root.
      a.href = rawUrl(href.split("#")[0]);
      a.target = "_blank";
      a.rel = "noopener";
      a.title = `${a.getAttribute("title") ?? a.textContent} — served from the project`;
    }
  }
}

let docSeq = 0;

async function openDoc(path) {
  const seq = ++docSeq;
  try {
    const res = await fetch(
      `/api/doc/${encodeURIComponent(panel.project)}/${path.split("/").map(encodeURIComponent).join("/")}`
    );
    if (seq !== docSeq) return; // a newer openDoc superseded this one
    if (!res.ok) {
      const why = await res.text();
      status(why, "warn");
      $("doc-view").replaceChildren(
        el("div", "empty", `couldn't read ${path} — ${why}`),
        retryButton(() => openDoc(path))
      );
      return;
    }
    const doc = await res.json();
    panel.openPath = doc.path;
    panel.raw = doc.raw;
    $("panel-path").textContent = doc.path;
    $("doc-view").innerHTML = doc.html; // comrak output, ammonia-sanitized server-side
    fixupDocLinks($("doc-view"), panel.project, doc.path);
    $("doc-view").scrollTop = 0;
    status("");
    setMode("view");
    renderDocList();
  } catch {
    status("daemon unreachable", "warn");
  }
}

let saving = false;

async function saveDoc() {
  if (saving) return; // a double-click would PUT twice and auto-commit twice
  const path = panel.mode === "create" ? $("doc-filename").value.trim() : panel.openPath;
  if (!path) {
    status("give the note a filename", "warn");
    return;
  }
  const content = $("doc-editor").value;
  saving = true;
  $("btn-save").disabled = true;
  status("saving…");
  try {
    const res = await fetch(
      `/api/doc/${encodeURIComponent(panel.project)}/${path.split("/").map(encodeURIComponent).join("/")}`,
      { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ content }) }
    );
    if (!res.ok) {
      status(await res.text(), "warn");
      return;
    }
    const r = await res.json();
    if (r.committed) {
      status(`saved · committed ${r.commit_id ?? ""}`, "ok");
    } else {
      status(`saved · not committed${r.detail ? ` — ${r.detail}` : ""}`, "warn");
    }
    if (panel.mode === "create" && !panel.docs.some((d) => d.path === path)) {
      // the server reports bytes; content.length would count UTF-16 units
      panel.docs.push({
        path,
        size: new TextEncoder().encode(content).length,
        modified_unix: Date.now() / 1000,
      });
      panel.docs.sort((a, b) => (a.path !== "README.md") - (b.path !== "README.md") || a.path.localeCompare(b.path));
    }
    openDoc(path);
  } catch {
    status("save failed — daemon unreachable", "warn");
  } finally {
    saving = false;
    $("btn-save").disabled = false;
  }
}

function closePanel() {
  $("overlay").hidden = true;
  panel.project = null;
  // Modality means focus has to come back out to where it came from.
  const target = panel.openerKey
    ? document.querySelector(`[data-open="${CSS.escape(panel.openerKey)}"]`)
    : panel.opener;
  if (target && document.contains(target)) target.focus();
  panel.opener = null;
  panel.openerKey = null;
}

let repoSeq = 0;

function changeLetter(ch) {
  if (ch === "none") return "";
  if (ch === "modified") return "M";
  if (ch === "added") return "A";
  if (ch === "deleted") return "D";
  if (ch === "renamed") return "R";
  if (ch === "copied") return "C";
  if (ch === "type_changed") return "T";
  if (ch === "untracked") return "?";
  if (ch === "unmerged") return "U";
  return ch.slice(0, 1).toUpperCase();
}

function entryMark(e) {
  if (e.conflicted) return { t: "UU", cls: "conflict" };
  if (e.worktree === "untracked") return { t: "??", cls: "untracked" };
  const i = changeLetter(e.index);
  const w = changeLetter(e.worktree);
  if (i && w) return { t: i + w, cls: "unstaged" };
  if (i) return { t: i + ".", cls: "staged" };
  if (w) return { t: "." + w, cls: "unstaged" };
  return { t: "··", cls: "" };
}

async function loadRepo() {
  if (!panel.project) return;
  const seq = ++repoSeq;
  try {
    const p = enc(panel.project);
    const [stRes, refsRes, logRes] = await Promise.all([
      fetch(`/api/git/${p}/status`),
      fetch(`/api/git/${p}/refs`),
      fetch(`/api/git/${p}/log?limit=40`),
    ]);
    if (seq !== repoSeq) return;
    if (!stRes.ok) {
      status(await stRes.text(), "warn");
      return;
    }
    panel.git = await stRes.json();
    panel.refs = refsRes.ok ? await refsRes.json() : [];
    panel.log = logRes.ok ? await logRes.json() : [];
    const allow = Boolean(panel.git.allow_push);
    $("btn-repo-push").disabled = !allow;
    $("btn-repo-fetch").disabled = !allow;
    const tip = allow ? "push to upstream" : "enable [git] allow_push in ~/.config/prefrontal/config.toml";
    $("btn-repo-push").title = tip;
    $("btn-repo-fetch").title = allow ? "fetch from remotes" : tip;
    renderRepoChrome();
    if (panel.repoMode === "files") await renderTree();
    else renderStatusList();
    if (panel.selCommit) await openCommit(panel.selCommit);
    else if (panel.selPath && panel.repoMode === "files") await openRepoFile(panel.selPath, panel.treeRev);
    else if (panel.selPath) await openDiff(panel.selPath, panel.selCached);
  } catch {
    status("daemon unreachable", "warn");
  }
}

function renderRepoChrome() {
  const g = panel.git;
  const banner = $("repo-banner");
  if (g?.rebasing) {
    banner.hidden = false;
    banner.textContent = "rebase in progress — resolve in your editor";
  } else if (g?.merging) {
    banner.hidden = false;
    banner.textContent = "merge in progress — resolve in your editor";
  } else {
    banner.hidden = true;
    banner.textContent = "";
  }

  const wrap = $("repo-branches");
  wrap.replaceChildren(el("div", "repo-h", "branches"));
  if (g) {
    const bits = [];
    if (g.detached) bits.push("detached");
    else if (g.branch) bits.push(g.branch);
    if (g.upstream) bits.push(g.upstream);
    if (g.ahead) bits.push(`↑${g.ahead}`);
    if (g.behind) bits.push(`↓${g.behind}`);
    if (bits.length) wrap.append(el("div", "repo-ab", bits.join(" · ")));
  }
  for (const r of (panel.refs || []).filter((x) => x.kind === "local")) {
    const row = el("button", "repo-row" + (r.current ? " sel" : ""));
    row.type = "button";
    row.append(el("span", "nm", `${r.current ? "●" : "○"} ${r.name}`));
    row.onclick = () => {
      if (!r.current) gitOp("switch", { name: r.name, create: false });
    };
    wrap.append(row);
  }
  const add = el("button", "repo-row");
  add.type = "button";
  add.append(el("span", "nm", "＋ new branch"));
  add.onclick = () => {
    const name = window.prompt("new branch name");
    if (name && name.trim()) gitOp("switch", { name: name.trim(), create: true });
  };
  wrap.append(add);
}

function renderStatusList() {
  const list = $("repo-status");
  list.replaceChildren();
  const entries = panel.git?.entries ?? [];
  const groups = [
    ["conflicted", entries.filter((e) => e.conflicted)],
    ["staged", entries.filter((e) => !e.conflicted && e.index !== "none")],
    ["unstaged", entries.filter((e) => !e.conflicted && e.worktree !== "none" && e.worktree !== "untracked")],
    ["untracked", entries.filter((e) => e.worktree === "untracked")],
  ];
  for (const [title, rows] of groups) {
    if (!rows.length) continue;
    list.append(el("div", "repo-h", `${title} (${rows.length})`));
    for (const e of rows) {
      const mark = entryMark(e);
      const staged = e.index !== "none" && e.worktree === "none";
      // Two sibling buttons, not a button with a nested control: nesting an
      // interactive element inside another is invalid, and the stage action
      // was previously a <span onclick> that no keyboard could reach.
      const entry = el("div", "repo-entry");
      const row = el("button", "repo-row" + (panel.selPath === e.path && !panel.selCommit ? " sel" : ""));
      row.type = "button";
      row.append(el("span", `mark ${mark.cls}`, mark.t), el("span", "nm", e.path));
      row.title = e.path;
      row.onclick = () => openDiff(e.path, staged);
      const act = el("button", "act", staged ? "unstage" : "stage");
      act.type = "button";
      act.title = `${staged ? "unstage" : "stage"} ${e.path}`;
      act.onclick = () => gitOp(staged ? "unstage" : "stage", { paths: [e.path] }, act);
      entry.append(row, act);
      list.append(entry);
    }
  }
  if ((panel.git?.stashes ?? []).length) {
    list.append(el("div", "repo-h", `stash (${panel.git.stashes.length})`));
    for (const s of panel.git.stashes) {
      list.append(el("div", "repo-ab", `stash@{${s.index}} ${s.message}`));
    }
    const pop = el("button", "repo-row");
    pop.type = "button";
    pop.append(el("span", "nm", "pop stash"));
    pop.onclick = () => gitOp("stash", { action: "pop" });
    list.append(pop);
  }
  if (panel.log.length) {
    list.append(el("div", "repo-h", "history"));
    for (const c of panel.log) {
      const row = el("button", "repo-row" + (panel.selCommit === c.id ? " sel" : ""));
      row.type = "button";
      row.append(el("span", "mark", c.id.slice(0, 7)), el("span", "nm", c.summary));
      row.title = `${c.id} — ${c.summary}`;
      row.onclick = () => openCommit(c.id);
      list.append(row);
    }
  }
  if (!entries.length && !panel.log.length) {
    list.append(el("div", "none", "clean working tree"));
  }
}

async function renderTree() {
  const list = $("repo-tree");
  list.replaceChildren(el("div", "repo-h", panel.treePath || "/"));
  try {
    const q = new URLSearchParams();
    if (panel.treeRev) q.set("rev", panel.treeRev);
    if (panel.treePath) q.set("path", panel.treePath);
    const res = await fetch(`/api/git/${enc(panel.project)}/tree?${q}`);
    if (!res.ok) {
      list.append(el("div", "none", await res.text()));
      return;
    }
    const entries = await res.json();
    if (panel.treePath) {
      const up = el("button", "repo-row");
      up.type = "button";
      up.append(el("span", "nm", ".."));
      up.onclick = () => {
        const slash = panel.treePath.lastIndexOf("/");
        panel.treePath = slash >= 0 ? panel.treePath.slice(0, slash) : "";
        renderTree();
      };
      list.append(up);
    }
    for (const e of entries) {
      const name = e.path.includes("/") ? e.path.slice(e.path.lastIndexOf("/") + 1) : e.path;
      const row = el("button", "repo-row" + (panel.selPath === e.path ? " sel" : ""));
      row.type = "button";
      row.append(el("span", "mark", e.kind === "dir" ? "▸" : "·"), el("span", "nm", name));
      row.onclick = () => {
        if (e.kind === "dir") {
          panel.treePath = e.path;
          renderTree();
        } else {
          panel.selPath = e.path;
          openRepoFile(e.path, panel.treeRev);
          renderTree();
        }
      };
      list.append(row);
    }
  } catch {
    list.append(el("div", "none", "could not list tree"));
  }
}

async function openDiff(path, cached) {
  panel.selPath = path;
  panel.selCached = cached;
  panel.selCommit = null;
  $("panel-path").textContent = path + (cached ? " (staged)" : "");
  const q = new URLSearchParams({ path });
  if (cached) q.set("cached", "true");
  try {
    const res = await fetch(`/api/git/${enc(panel.project)}/diff?${q}`);
    const pre = $("repo-view");
    pre.className = "diff";
    if (!res.ok) {
      pre.textContent = await res.text();
      return;
    }
    const d = await res.json();
    if (d.binary) pre.textContent = "(binary file)";
    else pre.textContent = d.patch || "(no textual diff)";
    if (d.truncated) pre.textContent += "\n\n… truncated";
    renderStatusList();
  } catch {
    status("daemon unreachable", "warn");
  }
}

async function openCommit(id) {
  panel.selCommit = id;
  panel.selPath = null;
  try {
    const res = await fetch(`/api/git/${enc(panel.project)}/commit/${enc(id)}`);
    const pre = $("repo-view");
    pre.className = "source";
    if (!res.ok) {
      pre.textContent = await res.text();
      return;
    }
    const c = await res.json();
    $("panel-path").textContent = c.short_id;
    const lines = [
      `${c.short_id}  ${c.summary}`,
      `${c.author} <${c.author_email}>`,
      "",
    ];
    if (c.body) lines.push(c.body, "");
    for (const f of c.files) lines.push(`${changeLetter(f.status) || " "}  ${f.path}`);
    pre.textContent = lines.join("\n");
    renderStatusList();
  } catch {
    status("daemon unreachable", "warn");
  }
}

async function openRepoFile(path, rev) {
  panel.selPath = path;
  panel.selCommit = null;
  $("panel-path").textContent = path;
  const q = new URLSearchParams({ path });
  if (rev) q.set("rev", rev);
  try {
    const res = await fetch(`/api/git/${enc(panel.project)}/file?${q}`);
    const pre = $("repo-view");
    pre.className = "source";
    if (!res.ok) {
      pre.textContent = await res.text();
      return;
    }
    const f = await res.json();
    if (f.binary) pre.textContent = "(binary file)";
    else pre.textContent = f.text || "(empty)";
    if (f.truncated) pre.textContent += "\n\n… truncated";
  } catch {
    status("daemon unreachable", "warn");
  }
}

// Git porcelain is not idempotent and the server has no per-project ordering,
// so the client owns the serialization: one queue per project, one op at a
// time. Clicking "commit" while "stage" is still in flight used to land a
// commit without the file the user just staged.
const gitQueue = new Map(); // project -> tail of its chain

function gitOp(verb, body, trigger) {
  const project = panel.project;
  const prev = gitQueue.get(project) ?? Promise.resolve();
  const run = prev.then(() => runGitOp(project, verb, body, trigger));
  const tail = run.catch(() => {});
  gitQueue.set(project, tail);
  // drop the key once this op is the last one queued, so the map stays
  // proportional to in-flight work rather than to the garden size
  tail.then(() => {
    if (gitQueue.get(project) === tail) gitQueue.delete(project);
  });
  return run;
}

async function runGitOp(project, verb, body, trigger) {
  if (trigger) trigger.disabled = true;
  status(`${verb}…`);
  try {
    const res = await fetch(`/api/git/${enc(project)}/${verb}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body ?? {}),
    });
    const r = res.ok ? await res.json() : { ok: false, detail: await res.text() };
    if (!r.ok) {
      status(r.detail || `${verb} failed`, "warn");
    } else {
      status(r.commit_id ? `${verb} · ${r.commit_id}` : `${verb} ok`, "ok");
      if (verb === "commit") $("repo-msg").value = "";
    }
    await loadRepo();
  } catch {
    status(`${verb} failed — daemon unreachable`, "warn");
  } finally {
    if (trigger) trigger.disabled = false;
  }
}

function bindPanel() {
  $("btn-close").onclick = closePanel;
  $("overlay").onclick = (e) => {
    if (e.target === $("overlay")) closePanel();
  };
  $("btn-edit").onclick = () => {
    $("doc-editor").value = panel.raw;
    setMode("edit");
  };
  $("btn-cancel").onclick = () => {
    if (panel.openPath) openDoc(panel.openPath);
    else {
      setMode("view");
      $("doc-view").replaceChildren(el("div", "empty", "no docs here yet — start one with ＋ note"));
    }
  };
  $("btn-new").onclick = () => {
    const stamp = new Date().toISOString().slice(0, 10);
    $("doc-filename").value = `notes/${stamp}-idea.md`;
    $("doc-editor").value = "";
    setMode("create");
    $("doc-filename").select();
  };
  $("btn-save").onclick = saveDoc;
  $("tab-notes").onclick = () => setTab("notes");
  $("tab-repo").onclick = () => setTab("repo");
  $("repo-mode-wt").onclick = () => {
    panel.repoMode = "wt";
    setTab("repo");
  };
  $("repo-mode-files").onclick = () => {
    panel.repoMode = "files";
    setTab("repo");
  };
  $("btn-repo-commit").onclick = (e) =>
    gitOp("commit", { message: $("repo-msg").value }, e.currentTarget);
  $("btn-repo-stash").onclick = (e) => {
    const message = $("repo-msg").value.trim();
    gitOp("stash", { action: "push", message: message || null }, e.currentTarget);
  };
  $("btn-repo-push").onclick = (e) => gitOp("push", {}, e.currentTarget);
  $("btn-repo-fetch").onclick = (e) => gitOp("fetch", {}, e.currentTarget);
  document.addEventListener("keydown", (e) => {
    if ($("overlay").hidden) return;
    if (e.key === "Escape") closePanel();
    if (e.key === "Tab") trapTab(e);
    if ((e.ctrlKey || e.metaKey) && e.key === "s" && panel.mode !== "view" && panel.tab === "notes") {
      e.preventDefault();
      saveDoc();
    }
  });
}

/// `aria-modal` is only true if Tab stays inside. Without this, Tab walks
/// straight out of the panel into the card grid behind the scrim.
function trapTab(e) {
  const focusable = $("overlay").querySelectorAll(
    'button:not([disabled]), a[href], input, textarea, select, [tabindex]:not([tabindex="-1"])'
  );
  const visible = [...focusable].filter((n) => n.offsetParent !== null || n === document.activeElement);
  if (!visible.length) return;
  const first = visible[0];
  const last = visible[visible.length - 1];
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  } else if (!$("overlay").contains(document.activeElement)) {
    e.preventDefault();
    first.focus();
  }
}

function render() {
  const q = document.getElementById("filter").value.trim().toLowerCase();
  const list = !q
    ? projects
    : projects.filter((p) =>
        [p.name, p.tagline ?? "", p.languages.join(" "), p.tags.join(" ")]
          .join(" ")
          .toLowerCase()
          .includes(q)
      );

  renderStats();
  renderHealth(list);
  renderTimeline(list);

  const groups = document.getElementById("groups");
  groups.replaceChildren();
  for (const state of ACTIVITY_ORDER) {
    const members = list.filter((p) => p.activity === state);
    if (!members.length) continue;
    const section = el("section", "group");
    const h = el("h2");
    const dot = el("span", "dot");
    dot.style.background = ACTIVITY_DOT[state];
    if (state === "archived") dot.style.border = "1px solid var(--muted)";
    h.append(dot, document.createTextNode(state + " "), el("span", "count", `(${members.length})`));
    section.append(h);
    const grid = el("div", "grid");
    members.forEach((p) => grid.append(card(p)));
    section.append(grid);
    groups.append(section);
  }
  if (!list.length) groups.append(el("div", "empty", "nothing matches"));
}

function setConn(live) {
  const conn = document.getElementById("conn");
  conn.classList.toggle("live", live);
  conn.title = live ? "live (websocket)" : "snapshot (rest)";
}

function handleEvent(ev) {
  if (ev.type === "colony") {
    colony = ev.colony;
    renderColony(); // own renderer — project cards are untouched by a sweep
    return;
  }
  if (ev.type === "snapshot") {
    projects = ev.projects;
  } else if (ev.type === "project_changed") {
    const i = projects.findIndex((p) => p.path === ev.project.path);
    if (i >= 0) projects[i] = ev.project;
    else projects.push(ev.project);
    projects.sort((a, b) => b.last_touched_unix - a.last_touched_unix);
  } else if (ev.type === "project_removed") {
    projects = projects.filter((p) => p.path !== ev.path);
  }
  render();
  if (
    ev.type === "project_changed" &&
    panel.project &&
    ev.project.name === panel.project &&
    panel.tab === "repo"
  ) {
    loadRepo();
  }
}

function connectWS() {
  wsRetryTimer = null;
  let ws;
  try {
    ws = new WebSocket(`ws://${location.host}/ws`);
  } catch {
    scheduleReconnect();
    return;
  }
  ws.onopen = () => {
    setConn(true);
    wsRetryMs = 1000;
  };
  ws.onmessage = (m) => {
    let ev;
    try {
      ev = JSON.parse(m.data);
    } catch {
      return; // one malformed frame must not kill the rest of the stream
    }
    if (ev && typeof ev.type === "string") handleEvent(ev);
  };
  ws.onclose = () => {
    setConn(false);
    scheduleReconnect(); // fresh snapshot on reconnect covers anything missed
  };
  ws.onerror = () => ws.close();
}

function scheduleReconnect() {
  if (wsRetryTimer) return;
  wsRetryTimer = setTimeout(connectWS, wsRetryMs);
  wsRetryMs = Math.min(wsRetryMs * 2, 15_000);
}

async function boot() {
  document.getElementById("filter").addEventListener("input", () => {
    render();
    scheduleSearch();
  });
  document.getElementById("health").addEventListener("toggle", (e) => {
    if (e.isTrusted) healthTouched = true;
  });
  setInterval(render, 60_000); // keep "Nd ago" and day labels honest while the tab sits open
  bindPanel();
  connectWS();
  // REST fallback / first paint even if WS is slow
  try {
    const res = await fetch("/api/projects");
    if (res.ok && !projects.length) {
      projects = await res.json();
      render();
    }
  } catch {
    document.getElementById("groups").replaceChildren(
      el("div", "empty", "daemon unreachable — is prefrontald running?")
    );
  }
  try {
    const res = await fetch("/api/colony");
    if (res.ok && !colony) {
      colony = await res.json();
      renderColony();
    } // 503 = panel disabled — stays hidden, like cortex
  } catch {
    /* daemon gone; the conn dot already says so */
  }
  loadHealth();
}

/// The connection dot says "can I talk to the daemon". It never said whether
/// the daemon can still *see* the disk — a watcher that lost directories to
/// the inotify limit looks exactly like a live one.
async function loadHealth() {
  const note = document.getElementById("foot-note");
  const base = "Prefrontal-RS · phase 7: working tree · 127.0.0.1 only";
  try {
    const res = await fetch("/api/health");
    if (!res.ok) return;
    const h = await res.json();
    const parts = [base];
    if (h.watch?.failed_dirs) {
      parts.push(`live for ${h.watch.watched_dirs} of ${h.watch.watched_dirs + h.watch.failed_dirs} projects — ${h.watch.failed_dirs} unwatched (inotify limit?)`);
    }
    if (h.index_ok === false) parts.push("search index rebuilding");
    if (h.last_scan?.last_scan_failed) parts.push("last rescan failed — showing the last good state");
    note.textContent = parts.join(" · ");
    if (h.watch?.failed_dirs || h.index_ok === false) note.classList.add("warn");
  } catch {
    /* daemon gone; the conn dot already says so */
  }
}

boot();
