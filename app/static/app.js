/* Watchtower log dashboard.
   Loads history via /api/logs, then follows /api/stream (SSE) for live
   entries and periodic stats. Filters re-query the API so they always
   search the full in-memory history, not just what is rendered. */

"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  level: "",
  query: "",
  paused: false,
  nextCheckAt: null,
  lastSessionAt: null,
  intervalSeconds: 600,
  lastDay: "",
};

const MAX_ROWS = 1500;

/* ------------------------------------------------------------------ */
/* Rendering                                                           */
/* ------------------------------------------------------------------ */

function fmtTime(iso) {
  return new Date(iso).toLocaleTimeString([], {
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  });
}

function fmtDay(iso) {
  return new Date(iso).toLocaleDateString([], {
    weekday: "short", day: "numeric", month: "short",
  });
}

function relTime(iso) {
  if (!iso) return "—";
  const seconds = Math.max(0, (Date.now() - new Date(iso)) / 1000);
  if (seconds < 60) return `${Math.round(seconds)}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

const LEVEL_TAG = { info: "INF", warning: "WRN", error: "ERR", fatal: "FTL", panic: "PNC" };

function buildRow(entry) {
  const li = document.createElement("li");
  li.className = `row ${entry.level}`;
  if (entry.msg.startsWith("Found new ")) li.classList.add("is-update");

  const t = document.createElement("span");
  t.className = "t";
  t.textContent = fmtTime(entry.ts);

  const lv = document.createElement("span");
  lv.className = "lv";
  lv.textContent = LEVEL_TAG[entry.level] || entry.level.toUpperCase().slice(0, 3);

  const m = document.createElement("span");
  m.className = "m";
  m.textContent = entry.msg;

  // Session summaries get their counters as chips instead of raw k=v text.
  if (entry.msg === "Session done") {
    for (const key of ["Scanned", "Updated", "Failed"]) {
      const value = entry.fields[key] ?? "0";
      const chip = document.createElement("span");
      chip.className = "chip";
      if (key === "Updated" && value !== "0") chip.classList.add("good");
      if (key === "Failed" && value !== "0") chip.classList.add("bad");
      chip.textContent = `${key.toLowerCase()} ${value}`;
      m.appendChild(chip);
    }
  } else {
    for (const [key, value] of Object.entries(entry.fields)) {
      const chip = document.createElement("span");
      chip.className = "chip";
      chip.textContent = `${key}=${value}`;
      m.appendChild(chip);
    }
  }

  li.append(t, lv, m);
  return li;
}

function daySeparator(iso) {
  const li = document.createElement("li");
  li.className = "day-sep";
  li.textContent = fmtDay(iso);
  return li;
}

/* Render a full (newest-first) list of entries. */
function renderAll(entries) {
  const log = $("log");
  log.replaceChildren();
  state.lastDay = "";
  let currentDay = "";
  for (const entry of entries) {
    const day = entry.ts.slice(0, 10);
    if (day !== currentDay) {
      log.appendChild(daySeparator(entry.ts));
      currentDay = day;
    }
    log.appendChild(buildRow(entry));
  }
  if (entries.length > 0) state.lastDay = entries[0].ts.slice(0, 10);
  $("empty").hidden = entries.length > 0;
}

/* Prepend one live entry (newest on top). */
function renderLive(entry) {
  if (state.paused) return;
  if (state.level && !matchesLevel(entry)) return;
  if (state.query && !matchesQuery(entry)) return;

  const log = $("log");
  const day = entry.ts.slice(0, 10);
  if (day !== state.lastDay) {
    log.prepend(daySeparator(entry.ts));
    // Separator goes above the row, so insert row after re-prepending it.
    state.lastDay = day;
    log.insertBefore(buildRow(entry), log.children[1] || null);
  } else {
    // Keep the newest day separator on top, rows right below it.
    const first = log.firstElementChild;
    if (first && first.classList.contains("day-sep")) {
      log.insertBefore(buildRow(entry), first.nextSibling);
    } else {
      log.prepend(buildRow(entry));
    }
  }
  while (log.children.length > MAX_ROWS) log.removeChild(log.lastChild);
  $("empty").hidden = true;
}

function matchesLevel(entry) {
  if (state.level === "error") return ["error", "fatal", "panic"].includes(entry.level);
  return entry.level === state.level;
}

function matchesQuery(entry) {
  const needle = state.query.toLowerCase();
  return (
    entry.msg.toLowerCase().includes(needle) ||
    Object.values(entry.fields).some((v) => v.toLowerCase().includes(needle))
  );
}

/* ------------------------------------------------------------------ */
/* Stats + beacon                                                      */
/* ------------------------------------------------------------------ */

function applyStats(stats) {
  state.nextCheckAt = stats.next_check_at;
  state.lastSessionAt = stats.last_session_at;
  state.intervalSeconds = stats.interval_seconds;

  $("host").textContent = stats.host;
  $("stat-last").textContent = relTime(stats.last_session_at);
  $("stat-scanned").textContent = stats.scanned;
  $("stat-updates").textContent = stats.updates_24h;
  $("stat-failures").textContent = stats.failures_24h;
  $("tile-failures").classList.toggle("is-bad", stats.failures_24h > 0);
  $("container-name").textContent = stats.container || "(searching…)";

  if (stats.ntfy_topic) {
    $("ntfy-link").href = `${stats.ntfy_url}/${stats.ntfy_topic}`;
    $("ntfy-link").textContent = `ntfy · ${stats.ntfy_topic}`;
  } else {
    $("ntfy-link").textContent = "ntfy (not configured)";
  }

  // Beacon: red when the tailer is down or updates failed,
  // amber when there were warnings/errors, teal when all is calm.
  const beacon = $("beacon");
  beacon.classList.remove("is-warn", "is-down");
  if (!stats.connected || stats.failures_24h > 0) beacon.classList.add("is-down");
  else if (stats.errors_24h > 0) beacon.classList.add("is-warn");

  // Attention banner.
  const problems = [];
  if (!stats.connected) problems.push("Not connected to the watchtower container.");
  if (stats.failures_24h > 0) problems.push(`${stats.failures_24h} container update(s) failed in the last 24 h.`);
  if (stats.errors_24h > 0) problems.push(`${stats.errors_24h} warning/error line(s) in the last 24 h.`);
  $("attention").hidden = problems.length === 0;
  $("attention-text").textContent = problems.join(" ");

  tick(); // update the countdown right away instead of waiting a second
}

/* Countdown to the next sweep, ticking locally every second. */
function tick() {
  const el = $("countdown");
  if (!state.nextCheckAt) { el.textContent = "--:--"; return; }
  let remaining = (new Date(state.nextCheckAt) - Date.now()) / 1000;
  if (remaining <= 0) {
    // Watchtower is due; roll forward so the clock keeps meaning something.
    const overshoot = -remaining % state.intervalSeconds;
    remaining = state.intervalSeconds - overshoot;
    el.classList.add("is-due");
  } else {
    el.classList.remove("is-due");
  }
  const m = String(Math.floor(remaining / 60)).padStart(2, "0");
  const s = String(Math.floor(remaining % 60)).padStart(2, "0");
  el.textContent = `${m}:${s}`;
  $("stat-last").textContent = relTime(state.lastSessionAt);
}
setInterval(tick, 1000);

/* ------------------------------------------------------------------ */
/* Data loading                                                        */
/* ------------------------------------------------------------------ */

async function loadHistory() {
  const params = new URLSearchParams({ limit: "1000" });
  if (state.level) params.set("level", state.level);
  if (state.query) params.set("q", state.query);
  const response = await fetch(`/api/logs?${params}`);
  const data = await response.json();
  renderAll(data.entries);
}

function connectStream() {
  const source = new EventSource("/api/stream");
  source.addEventListener("log", (event) => renderLive(JSON.parse(event.data)));
  source.addEventListener("stats", (event) => applyStats(JSON.parse(event.data)));
  source.onopen = () => $("live-pill").classList.remove("is-off");
  source.onerror = () => $("live-pill").classList.add("is-off");
}

/* ------------------------------------------------------------------ */
/* Controls                                                            */
/* ------------------------------------------------------------------ */

for (const button of document.querySelectorAll(".seg")) {
  button.addEventListener("click", () => {
    document.querySelector(".seg.is-active").classList.remove("is-active");
    button.classList.add("is-active");
    state.level = button.dataset.level;
    loadHistory();
  });
}

let searchTimer;
$("search").addEventListener("input", (event) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    state.query = event.target.value.trim();
    loadHistory();
  }, 250);
});

$("pause").addEventListener("click", () => {
  state.paused = !state.paused;
  $("pause").setAttribute("aria-pressed", String(state.paused));
  $("pause").textContent = state.paused ? "Resume" : "Pause";
  if (!state.paused) loadHistory(); // catch up on what was missed
});

$("test-alert").addEventListener("click", async () => {
  const button = $("test-alert");
  button.disabled = true;
  button.textContent = "sending…";
  try {
    const response = await fetch("/api/test-alert", { method: "POST" });
    const data = await response.json();
    button.textContent = data.sent ? "sent ✓" : "not configured";
  } catch {
    button.textContent = "failed";
  }
  setTimeout(() => { button.textContent = "send test alert"; button.disabled = false; }, 3000);
});

$("logout").addEventListener("click", async () => {
  await fetch("/auth/logout", { method: "POST" });
  window.location.replace("/auth/login");
});

/* ------------------------------------------------------------------ */

loadHistory();
connectStream();
fetch("/api/stats").then((r) => r.json()).then(applyStats);
