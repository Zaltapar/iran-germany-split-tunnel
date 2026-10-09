// Split-Tunnel Dashboard — local read-only UI. No external scripts, fonts,
// or CDN resources. All data comes from the local /api/v1 endpoints.

"use strict";

// API base path, derived from the page URL so the UI works both when served
// at the site root (local loopback mode) and under a mounted random 32-hex
// BasePath (server-hosted TLS mode). Everything is relative to the current
// page, so the same embedded bundle works in either deployment.
function apiBase() {
  let p = window.location.pathname;
  if (!p.endsWith("/")) p += "/";
  return p + "api/v1";
}
const API_BASE = apiBase();

// --- state ---
let pollTimer = null;

// --- DOM refs ---
const overviewEl   = document.getElementById("overview");
const detailEl     = document.getElementById("detail");
const detailTitle  = document.getElementById("detailTitle");
const detailBody   = document.getElementById("detailBody");
const lastPollEl   = document.getElementById("lastPoll");
const refreshBtn   = document.getElementById("refreshBtn");
const pollChk      = document.getElementById("pollChk");
const pollSecInput = document.getElementById("pollSec");
const detailBack   = document.getElementById("detailBack");

// --- helpers ---
function esc(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

function fmtBytes(n) {
  if (n == null) return "—";
  if (n >= 1e9)  return (n/1e9).toFixed(2) + " GB";
  if (n >= 1e6)  return (n/1e6).toFixed(2) + " MB";
  if (n >= 1e3)  return (n/1e3).toFixed(1) + " KB";
  return Math.round(n) + " B";
}

function fmtRate(n) {
  if (n == null) return "—";
  return fmtBytes(n) + "/s";
}

function statusBadge(status) {
  return '<span class="badge ' + esc(status) + '">' + esc(status) + '</span>';
}

async function api(path, opts) {
  const res = await fetch(API_BASE + path, opts);
  if (!res.ok) {
    let body;
    try { body = await res.json(); } catch { body = { error: res.statusText }; }
    throw new Error(body.error || res.statusText);
  }
  return res.json();
}

// --- overview ---
async function loadOverview() {
  const data = await api("/overview");
  overviewEl.innerHTML = "";
  for (const s of data.servers || []) {
    const card = document.createElement("div");
    card.className = "card";
    card.dataset.id = s.id;
    card.innerHTML = `
    <h3>${esc(s.name || s.id)} ${statusBadge(s.status)}</h3>
    <div class="metric-row"><span class="label">Role</span><span>${esc(s.role || "unknown")}</span></div>
    <div class="metric-row"><span class="label">Active sessions</span><span>${s.activeSessions ?? "—"}</span></div>
    <div class="metric-row"><span class="label">↑ bytes/s</span><span>${fmtRate(s.bytesUpPerSec)}</span></div>
    <div class="metric-row"><span class="label">↓ bytes/s</span><span>${fmtRate(s.bytesDownPerSec)}</span></div>
    <div class="metric-row"><span class="label">Carrier losses</span><span>${s.carrierLossEvents ?? "—"}</span></div>
    <div class="metric-row"><span class="label">Last collected</span><span>${new Date(s.collectedAt).toLocaleString()}</span></div>
    ${s.errors && s.errors.length ? '<div class="warnings">' + s.errors.map(esc).join('<br>') + '</div>' : ''}
  `;
    card.addEventListener("click", () => showDetail(s.id));
    overviewEl.appendChild(card);
  }
  if (data.warnings && data.warnings.length) {
    const w = document.createElement("div");
    w.className = "warnings";
    w.style.marginTop = "0.5rem";
    w.textContent = "Warnings: " + data.warnings.join("; ");
    overviewEl.appendChild(w);
  }
  lastPollEl.textContent = "Last poll: " + new Date().toLocaleTimeString();
}

// --- detail view ---
async function showDetail(id) {
  document.getElementById("overview").style.display = "none";
  detailEl.hidden = false;
  detailTitle.textContent = "Server: " + id;
  detailBody.innerHTML = '<p class="muted">Loading…</p>';

  try {
    const [snap, logs, cfg] = await Promise.all([
      api("/servers/" + encodeURIComponent(id)),
      api("/servers/" + encodeURIComponent(id) + "/logs?limit=50"),
      api("/servers/" + encodeURIComponent(id) + "/config"),
    ]);
    renderDetail(id, snap, logs, cfg);
  } catch (e) {
    detailBody.innerHTML = '<p class="warnings">Error: ' + esc(e.message) + '</p>';
  }
}

function renderDetail(id, snap, logs, cfg) {
  detailBody.innerHTML = "";

  // Errors (from snapshot).
  if (snap.errors && snap.errors.length) {
    const errDiv = document.createElement("div");
    errDiv.className = "warnings";
    errDiv.innerHTML = '<h3>Collection Warnings</h3>' +
      snap.errors.map(e => '<div>' + esc(e) + '</div>').join("");
    detailBody.appendChild(errDiv);
  }

  // Services table.
  if (snap.services && snap.services.length) {
    const tbl = document.createElement("div");
    tbl.className = "table-wrap";
    let rows = "";
    for (const s of snap.services) {
      const enabled = s.enabled ? ' <span class="muted">(' + esc(s.enabled) + ')</span>' : "";
      const pid = s.mainPid ? ' <span class="muted">pid ' + s.mainPid + '</span>' : "";
      rows += `<tr><td>${esc(s.unit)}</td><td>${esc(s.state)}${enabled}</td><td>${esc(s.subState || "—")}</td><td>${pid || "—"}</td></tr>`;
    }
    tbl.innerHTML = `
      <h3>Services</h3>
      <table><thead><tr><th>Unit</th><th>State</th><th>SubState</th><th> PID</th></tr></thead>
      <tbody>${rows}</tbody></table>
    `;
    detailBody.appendChild(tbl);
  }

  // Listeners table.
  if (snap.listeners && snap.listeners.length) {
    const tbl = document.createElement("div");
    tbl.className = "table-wrap";
    let rows = "";
    for (const l of snap.listeners) {
      rows += `<tr><td>${esc(l.protocol)}</td><td>${esc(l.address)}</td><td>${l.pid || "—"}</td></tr>`;
    }
    tbl.innerHTML = `
      <h3>Listeners</h3>
      <table><thead><tr><th>Proto</th><th>Address</th><th>PID</th></tr></thead>
      <tbody>${rows}</tbody></table>
    `;
    detailBody.appendChild(tbl);
  }

  // Memory / Disk resource row.
  if (snap.memoryMB || snap.diskBytes) {
    const resDiv = document.createElement("div");
    resDiv.className = "table-wrap";
    resDiv.innerHTML = `
      <h3>Resources</h3>
      <table><tbody>
      ${snap.memoryMB ? `<tr><td>Memory (used)</td><td>${fmtBytes(snap.memoryMB * 1024 * 1024)}</td></tr>` : ""}
      ${snap.diskBytes ? `<tr><td>Disk (used)</td><td>${fmtBytes(snap.diskBytes)}</td></tr>` : ""}
      ${snap.uptimeSec ? `<tr><td>Uptime</td><td>${Math.round(snap.uptimeSec / 3600)}h ${Math.round((snap.uptimeSec % 3600) / 60)}m</td></tr>` : ""}
      </tbody></table>
    `;
    detailBody.appendChild(resDiv);
  }

  // Metrics table.
  if (snap.metrics && snap.metrics.samples) {
    const tbl = document.createElement("div");
    tbl.className = "table-wrap";
    let rows = "";
    for (const s of snap.metrics.samples) {
      const name = s.labels
        ? s.name + "{" + Object.entries(s.labels).map(([k,v]) => `${k}=${v}`).join(",") + "}"
        : s.name;
      const rate = snap.rates ? snap.rates[name] : null;
      rows += `<tr><td>${esc(name)}</td><td>${s.value}</td><td>${rate ? rate.perSec.toFixed(2) + "/s" : "—"}</td></tr>`;
    }
    tbl.innerHTML = `
      <h3>Metric</h3>
      <table><thead><tr><th>Metric</th><th>Value</th><th>Rate</th></tr></thead>
      <tbody>${rows}</tbody></table>
    `;
    detailBody.appendChild(tbl);
  }

  // Logs.
  if (logs.entries && logs.entries.length) {
    const logDiv = document.createElement("div");
    logDiv.className = "logs";
    logDiv.innerHTML = logs.entries.map(e =>
      `<div class="log-line ${esc(e.level)}"><span class="ts">${new Date(e.timestamp).toLocaleString()}</span> ${esc(e.level)} ${esc(e.message)}</div>`
    ).join("");
    detailBody.appendChild(logDiv);
  }

  // Safe config view.
  if (cfg.values && cfg.values.length) {
    const tbl = document.createElement("div");
    tbl.className = "table-wrap";
    let rows = "";
    for (const v of cfg.values) {
      const redacted = v.redacted ? " 🔒" : "";
      rows += `<tr><td>${esc(v.key)}${redacted}</td><td>${esc(v.value)}</td><td>${v.requiresRestart ? "yes" : "no"}</td></tr>`;
    }
    tbl.innerHTML = `
      <h3>Safe Config Values</h3>
      <table><thead><tr><th>Key</th><th>Value</th><th>Restart</th></tr></thead>
      <tbody>${rows}</tbody></table>
      ${cfg.warnings ? '<div class="warnings">' + esc(cfg.warnings.join("; ")) + '</div>' : ''}
    `;
    detailBody.appendChild(tbl);
  }

  // Plan form (read-only — apply button is disabled and non-functional).
  detailBody.appendChild(buildPlanForm(id, snap));
}

function buildPlanForm(id, snap) {
  const form = document.createElement("div");
  form.className = "plan-form";
  form.innerHTML = `
    <h3>Dry-run Config Plan</h3>
    <label>SPLIT_TARGET_ADDR_POLICY</label>
    <select id="planPolicy">
      <option value="default">default (dual-stack)</option>
      <option value="prefer-ipv4">prefer-ipv4 (v4-first, v6 fallback)</option>
      <option value="ipv4-only">ipv4-only (hard A-filter — risky)</option>
    </select>
    <label>SPLIT_TARGET_ONLY_IPV4</label>
    <select id="planOnlyV4">
      <option value="false">false</option>
      <option value="true">true</option>
    </select>
    <label>SPLIT_METRICS_PORT</label>
    <input id="planMetricsPort" type="number" min="1" max="65535" value="9101">
    <label>SPLIT_RELAY_BUF</label>
    <input id="planRelayBuf" type="number" min="1024" max="8388608" value="32768">
    <div class="btn-row">
      <button type="button" class="btn-primary" id="submitPlanBtn">Create dry-run plan</button>
      <button type="button" class="btn-disabled" id="applyBtn" disabled title="Mutations disabled in this build">Apply (disabled)</button>
    </div>
    <div id="planResult" class="plan-result" hidden></div>
  `;
  document.body.appendChild(form);

  document.getElementById("submitPlanBtn").addEventListener("click", async () => {
    const changes = [
      { key: "SPLIT_TARGET_ADDR_POLICY", value: document.getElementById("planPolicy").value },
      { key: "SPLIT_TARGET_ONLY_IPV4",   value: document.getElementById("planOnlyV4").value },
      { key: "SPLIT_METRICS_PORT",       value: document.getElementById("planMetricsPort").value },
      { key: "SPLIT_RELAY_BUF",          value: document.getElementById("planRelayBuf").value },
    ];
    const resultEl = document.getElementById("planResult");
    resultEl.hidden = false;
    resultEl.textContent = "Submitting…";
    try {
      const res = await api("/servers/" + encodeURIComponent(id) + "/config/plan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ changes }),
      });
      let out = "Plan ID: " + res.planId + "\n";
      for (const c of res.changes || []) {
        out += `  ${c.key}: ${c.before || "(unknown)"} → ${c.after}\n`;
      }
      if (res.restartRequired) out += "Restart required: yes\n";
      if (res.warnings && res.warnings.length) out += "Warnings:\n" + res.warnings.map(w => "  • " + w).join("\n") + "\n";
      out += "\n⚠ This is a DRY-RUN plan. No host was contacted or modified.";
      resultEl.textContent = out;
    } catch (e) {
      resultEl.textContent = "Error: " + e.message;
    }
  });

  return form;
}

// --- navigation ---
detailBack.addEventListener("click", (e) => {
  e.preventDefault();
  detailEl.hidden = true;
  document.getElementById("overview").style.display = "";
  loadOverview();
});

// --- polling ---
function startPolling() {
  stopPolling();
  if (!pollChk.checked) return;
  let sec = parseInt(pollSecInput.value, 10);
  if (isNaN(sec) || sec < 2) sec = 5;
  pollTimer = setInterval(loadOverview, sec * 1000);
}
function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}
refreshBtn.addEventListener("click", () => loadOverview());
pollChk.addEventListener("change", startPolling);
pollSecInput.addEventListener("change", startPolling);

// --- init ---
loadOverview()
  .then(() => startPolling())
  .catch(err => {
    overviewEl.innerHTML = '<p class="warnings">API error: ' + esc(err.message) +
      ' — check that the dashboard is reachable and the metrics endpoint is up.</p>';
  });
