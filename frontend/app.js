/* ============================================================
   Gədr — SPA frontend
   Vanilla JS, no build step, no external dependencies.
   Talks to the FastAPI backend (same origin).
   ============================================================ */
"use strict";

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

const state = {
  health: null,
  currentScanId: null,
  projects: [],
  scanData: null,
  findingsFilter: { Critical: true, High: true, Medium: true, Low: true },
};

/* ---------------- Utilities ---------------- */
function esc(str) {
  return String(str ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function toast(msg, isError = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.classList.toggle("error", isError);
  el.classList.remove("hidden");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add("hidden"), 4200);
}

async function api(path, options = {}) {
  const res = await fetch(path, options);
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { msg = (await res.json()).detail || msg; } catch (_) { /* ignore */ }
    throw new Error(msg);
  }
  return res.json();
}

const sevColor = { Critical: "var(--crit)", High: "var(--high)", Medium: "var(--med)", Low: "var(--low)" };

function sevBadge(sev) {
  const cls = { Critical: "badge-crit", High: "badge-high", Medium: "badge-med", Low: "badge-low" }[sev] || "badge-low";
  return `<span class="sev-badge ${cls}">${esc(sev)}</span>`;
}

/* ---------------- Navigation ---------------- */
function switchPage(name) {
  $$(".tab").forEach(t => t.classList.toggle("active", t.dataset.page === name));
  ["scan", "ai", "dashboard", "findings"].forEach(p =>
    $("#page-" + p).classList.toggle("hidden", p !== name));
  if (name === "dashboard") loadDashboard();
  if (name === "findings") loadFindingsPage();
  if (name === "ai") loadAiPage();
  if (!state.health) loadHealth();
}

/* ---------------- Health ---------------- */
async function loadHealth() {
  try {
    state.health = await api("/api/health");
    const pill = $("#ai-status");
    pill.classList.add(state.health.ai_enabled ? "online" : "offline");
    $("#ai-status-text").textContent = state.health.ai_enabled
      ? "Gədr: Scanner" : "Gədr: offline (no API key)";
    $("#ai-hint").textContent = state.health.ai_enabled
      ? "Gədr analysis enabled" : "no API key — offline explanations will be used";

    const tools = Object.entries(state.health.tools).filter(([, v]) => v).map(([k]) => k);
    $("#tool-status").textContent = tools.length
      ? `External scanners: ${tools.join(", ")}`
      : "External scanners: Install Bandit, Semgrep, SpotBugs, PMD, or Clang for enhanced detection";
  } catch (e) {
    $("#ai-status").classList.add("offline");
    $("#ai-status-text").textContent = "API unreachable";
    toast("Backend unreachable — is the API running?", true);
  }
}

/* ---------------- Scan page ---------------- */
function initScanPage() {
  const dropzone = $("#dropzone");
  const input = $("#file-input");

  dropzone.addEventListener("click", () => input.click());
  dropzone.addEventListener("dragover", e => { e.preventDefault(); dropzone.classList.add("dragover"); });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
  dropzone.addEventListener("drop", e => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length) runUpload(e.dataTransfer.files[0]);
  });
  input.addEventListener("change", () => { if (input.files.length) runUpload(input.files[0]); });

  $$(".card-tab").forEach(t => t.addEventListener("click", () => {
    $$(".card-tab").forEach(x => x.classList.toggle("active", x === t));
    const mode = t.dataset.scanMode;
    $("#mode-upload").style.display = mode === "upload" ? "" : "none";
    $("#mode-path").style.display = mode === "path" ? "" : "none";
    $("#mode-external").style.display = mode === "external" ? "" : "none";
    if (mode === "external") loadConnectors();
  }));

  $("#scan-path-btn").addEventListener("click", () => {
    const path = $("#path-input").value.trim();
    if (path) runPathScan(path);
  });
  $("#path-input").addEventListener("keydown", e => {
    if (e.key === "Enter") { const p = $("#path-input").value.trim(); if (p) runPathScan(p); }
  });

  $("#external-scan-btn").addEventListener("click", () => {
    const target = $("#external-target").value.trim();
    const connector = $("#connector-select").value;
    if (target && connector) runExternalScan(connector, target);
  });
  $("#external-target").addEventListener("keydown", e => {
    if (e.key === "Enter") {
      const target = $("#external-target").value.trim();
      const connector = $("#connector-select").value;
      if (target && connector) runExternalScan(connector, target);
    }
  });
}

async function loadConnectors() {
  const sel = $("#connector-select");
  try {
    const connectors = await api("/api/connectors");
    if (!connectors.length) {
      sel.innerHTML = `<option>No connectors registered</option>`;
      return;
    }
    sel.innerHTML = connectors.map(c =>
      `<option value="${esc(c.name)}" ${c.available ? "" : "disabled"}>` +
      `${esc(c.display_name)}${c.available ? "" : " (unavailable)"}` +
      `</option>`
    ).join("");
  } catch (e) {
    sel.innerHTML = `<option>Failed to load connectors</option>`;
  }
}

async function runExternalScan(connector, target) {
  const fd = new FormData();
  fd.append("connector", connector);
  fd.append("target", target);
  await startScan("/api/scan/external", fd, `Running ${connector} scan on ${target}…`);
}

async function runUpload(file) {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("use_ai", String($("#use-ai").checked));
  await startScan("/api/scan/upload", fd, `Scanning ${file.name}…`);
}

async function runPathScan(path) {
  const fd = new FormData();
  fd.append("path", path);
  fd.append("use_ai", String($("#use-ai").checked));
  await startScan("/api/scan/project", fd, `Scanning ${path}…`);
}

async function startScan(url, body, label) {
  const btn = $("#scan-btn");
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span>Scanning…`;
  try {
    toast(label);
    const data = await api(url, { method: "POST", body });
    state.currentScanId = data.scan_id;
    renderScanResult(data);
    toast(`Scan complete — ${data.findings_count} findings, score ${data.security_score}/100`);
    $("#scan-result").classList.remove("hidden");
    $("#scan-result").scrollIntoView({ behavior: "smooth" });
  } catch (e) {
    toast("Scan failed: " + e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Start Scan";
  }
}

function renderScanResult(data) {
  const score = data.security_score;
  const grade = data.grade;
  let color = "var(--crit)";
  if (score >= 70) color = "var(--low)";
  else if (score >= 50) color = "var(--med)";
  else if (score >= 30) color = "var(--high)";

  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  data.findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
  const total = data.findings_count || 0;
  const maxCount = Math.max(...Object.values(counts), 1);

  const bars = Object.entries(counts).map(([sev, n]) => `
    <div class="sev-row">
      <span class="sev-label ${sev.toLowerCase()}-c">${sev}</span>
      <div class="sev-bar"><div class="sev-fill ${sev.toLowerCase()}-f" style="width:${(n / maxCount) * 100}%"></div></div>
      <span class="sev-num">${n}</span>
    </div>`).join("");

  const preview = data.findings.slice(0, 10).map(f => `
    <div class="finding" style="--sev:${sevColor[f.severity] || "var(--border)"}">
      <div class="finding-header" onclick="openFinding(this)">
        ${sevBadge(f.severity)}
        <span class="finding-title">${esc(f.title)}</span>
        <span class="finding-loc">${esc(f.file)}:${f.line}</span>
        <span class="chevron">▸</span>
      </div>
      <div class="finding-body">
        <div class="meta-grid">
          <div class="meta-item"><span class="k">Scanner</span><span class="v">${esc(f.scanner)}</span></div>
          <div class="meta-item"><span class="k">CWE</span><span class="v">${esc(f.cwe)}</span></div>
          <div class="meta-item"><span class="k">OWASP</span><span class="v">${esc(f.owasp)}</span></div>
          <div class="meta-item"><span class="k">Rule</span><span class="v">${esc(f.rule_id)}</span></div>
        </div>
        ${f.code ? `<div class="code-block">${esc(f.code)}</div>` : ""}
      </div>
    </div>`).join("");

  $("#scan-result").innerHTML = `
    <div class="card">
      <h3>Scan Result</h3>
      <div class="score-wrap">
        <div class="gauge" style="--val:${score};--gauge-color:${color}">
          <div class="gauge-inner">
            <div class="gauge-num">${score}</div>
            <div class="gauge-max">/ 100</div>
            <div class="grade-badge" style="background:${color};color:#0b1020">${esc(grade)}</div>
          </div>
        </div>
        <div class="summary-meta">
          <b>${data.files_scanned}</b> files scanned · <b>${total}</b> findings<br>
          ${esc(data.summary)}<br>
          Scan ID: <b>${esc(data.scan_id)}</b>
        </div>
        <div class="sev-bars">${bars}</div>
      </div>
      <div class="row-between">
        <span class="hint">Gədr analysis explains each finding and generates secure code fixes.</span>
        <button class="btn btn-primary" id="scan-ai-btn">🤖 Generate Gədr analysis</button>
      </div>
    </div>
    <div class="card">
      <div class="row-between">
        <h3>Top Findings (${Math.min(total, 10)} of ${total})</h3>
        <button class="btn btn-outline" onclick="switchPage('findings')">View all →</button>
      </div>
      <div class="findings-list">${preview || '<div class="empty">No findings — clean code!</div>'}</div>
    </div>`;

  const aiBtn = $("#scan-ai-btn");
  aiBtn.disabled = !(state.health && state.health.ai_enabled);
  aiBtn.addEventListener("click", () => runAiAnalysis(data.scan_id, aiBtn));
}

/* ---------------- Dashboard ---------------- */
async function loadDashboard() {
  const grid = $("#project-grid");
  try {
    const projects = await api("/api/projects");
    state.projects = projects;
    if (!projects.length) {
      grid.innerHTML = `<div class="empty">No projects yet — run a scan first.</div>`;
      return;
    }
    grid.innerHTML = projects.map(p => {
      const s = p.last_score;
      const col = s === null ? "var(--muted)" : s >= 70 ? "var(--low)" : s >= 50 ? "var(--med)" : s >= 30 ? "var(--high)" : "var(--crit)";
      return `<div class="project-card" data-id="${esc(p.id)}" onclick="selectProject('${esc(p.id)}')">
        <div class="project-name">${esc(p.name)}</div>
        <div class="project-lang">${esc(p.language || "unknown")} · created ${esc((p.created_at || "").slice(0, 10))}</div>
        <div class="project-score" style="color:${col}">${s === null ? "—" : s + "/100"}</div>
      </div>`;
    }).join("");
  } catch (e) {
    grid.innerHTML = `<div class="empty">Failed to load: ${esc(e.message)}</div>`;
  }
}

async function selectProject(id) {
  $$(".project-card").forEach(c => c.classList.toggle("selected", c.dataset.id === id));
  try {
    const detail = await api(`/api/projects/${id}`);
    const scans = detail.scans || [];
    const sel = $("#scan-select");
    sel.innerHTML = scans.map(s => `<option value="${s.id}">${esc(s.id)} · ${(s.started_at || "").slice(0, 16).replace("T", " ")} · score ${s.security_score}</option>`).join("");
    sel.onchange = () => loadScanDetail(sel.value);
    $("#dash-detail").classList.remove("hidden");
    $("#dash-project-name").textContent = detail.name;
    if (scans.length) loadScanDetail(scans[0].id);
  } catch (e) {
    toast("Failed to load project: " + e.message, true);
  }
}

async function loadScanDetail(scanId) {
  const body = $("#dash-scan-body");
  body.innerHTML = `<div class="empty"><span class="spinner"></span>Loading scan…</div>`;
  $("#dash-ai-analyze").disabled = !(state.health && state.health.ai_enabled);
  try {
    const data = await api(`/api/scans/${scanId}`);
    state.currentScanId = scanId;
    state.scanData = data;
    const brk = data.severity_breakdown;
    const maxCount = Math.max(...Object.values(brk), 1);
    const bars = Object.entries(brk).map(([sev, n]) => `
      <div class="sev-row">
        <span class="sev-label ${sev.toLowerCase()}-c">${sev}</span>
        <div class="sev-bar"><div class="sev-fill ${sev.toLowerCase()}-f" style="width:${(n / maxCount) * 100}%"></div></div>
        <span class="sev-num">${n}</span>
      </div>`).join("");

    body.innerHTML = `
      <div class="score-wrap" style="margin-bottom:20px">
        <div class="gauge" style="--val:${data.scan.security_score};--gauge-color:var(--accent)">
          <div class="gauge-inner">
            <div class="gauge-num">${data.scan.security_score}</div>
            <div class="gauge-max">/ 100</div>
          </div>
        </div>
        <div class="summary-meta">
          <b>${data.scan.files_scanned}</b> files · <b>${data.findings.length}</b> findings<br>
          ${esc(data.scan.summary || "")}
        </div>
        <div class="sev-bars">${bars}</div>
      </div>
      <div style="margin-bottom:20px">
        <button class="btn btn-primary btn-sm" id="dash-summarize-btn" ${!state.health || !state.health.ai_enabled ? "disabled" : ""}>✨ Gədr Summary</button>
        <div id="dash-summary-panel" style="margin-top:14px"></div>
      </div>
      <div class="findings-list">
        ${data.findings.slice(0, 15).map(f => `
          <div class="finding" style="--sev:${sevColor[f.severity] || "var(--border)"}">
            <div class="finding-header" onclick="openFinding(this)">
              ${sevBadge(f.severity)}
              <span class="finding-title">${esc(f.title)}</span>
              <span class="finding-loc">${esc(f.file)}:${f.line}</span>
              <span class="chevron">▸</span>
            </div>
            <div class="finding-body">
              <div class="code-block">${esc(f.code || "(no snippet)")}</div>
            </div>
          </div>`).join("")}
      </div>`;

    const sumBtn = $("#dash-summarize-btn");
    if (sumBtn && state.health && state.health.ai_enabled) {
      sumBtn.addEventListener("click", () => runAiSummary(scanId, "dash-summary-panel", sumBtn));
    }
  } catch (e) {
    body.innerHTML = `<div class="empty">Failed to load: ${esc(e.message)}</div>`;
  }
}

/* ---------------- Findings page ---------------- */
async function loadFindingsPage() {
  const projSel = $("#findings-project");
  try {
    const projects = await api("/api/projects");
    state.projects = projects;
    projSel.innerHTML = projects.map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join("");
    if (projects.length) {
      projSel.onchange = () => fillScanSelect(projects.find(p => p.id === projSel.value).id);
      fillScanSelect(projects[0].id);
    } else {
      $("#findings-list").innerHTML = `<div class="empty">No projects yet.</div>`;
    }
  } catch (e) {
    toast("Failed to load projects: " + e.message, true);
  }
}

async function loadAiPage() {
  const projSel = $("#ai-project-select");
  const scanSel = $("#ai-scan-select");
  const btn = $("#ai-analyze-btn");
  try {
    const projects = await api("/api/projects");
    if (!projects.length) {
      projSel.innerHTML = `<option>No projects yet</option>`;
      scanSel.innerHTML = `<option>No scans yet</option>`;
      btn.disabled = true;
      return;
    }
    projSel.innerHTML = projects.map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join("");
    const loadScans = async () => {
      const pid = projSel.value;
      if (!pid) { scanSel.innerHTML = `<option>Select a project first</option>`; btn.disabled = true; return; }
      const detail = await api(`/api/projects/${pid}`);
      if (!detail.scans.length) {
        scanSel.innerHTML = `<option>No scans for this project</option>`;
        btn.disabled = true;
        return;
      }
      scanSel.innerHTML = detail.scans.map(s =>
        `<option value="${s.id}">${(s.started_at || "").slice(0, 16).replace("T", " ")} · score ${s.security_score} · ${s.findings_count} findings</option>`
      ).join("");
      btn.disabled = !(state.health && state.health.ai_enabled);
    };
    projSel.onchange = loadScans;
    await loadScans();
  } catch (e) {
    toast("Failed to load: " + e.message, true);
  }
}

async function fillScanSelect(projectId) {
  const scanSel = $("#findings-scan");
  try {
    const detail = await api(`/api/projects/${projectId}`);
    scanSel.innerHTML = detail.scans.map(s =>
      `<option value="${s.id}">${(s.started_at || "").slice(0, 16).replace("T", " ")} · score ${s.security_score}</option>`).join("");
    scanSel.onchange = () => renderFindings(scanSel.value);
    if (detail.scans.length) renderFindings(detail.scans[0].id);
    else $("#findings-list").innerHTML = `<div class="empty">No scans for this project.</div>`;
  } catch (e) {
    toast("Failed to load scans: " + e.message, true);
  }
}

async function renderFindings(scanId) {
  state.currentScanId = scanId;
  const aiEnabled = !!(state.health && state.health.ai_enabled);
  $("#ai-analyze-all").disabled = !aiEnabled;
  $("#ai-analyze-all").dataset.scanId = scanId;
  $("#download-report").disabled = false;
  $("#download-report").dataset.scanId = scanId;
  $("#download-ai-report").disabled = false;
  $("#download-ai-report").dataset.scanId = scanId;
  const list = $("#findings-list");
  list.innerHTML = `<div class="empty"><span class="spinner"></span>Loading findings…</div>`;
  try {
    const data = await api(`/api/scans/${scanId}`);
    state.scanData = data;
    list.innerHTML = data.findings.length ? "" : `<div class="empty">No findings in this scan.</div>`;
    data.findings.forEach(f => list.appendChild(findingElement(f)));
    applySeverityFilter();
  } catch (e) {
    list.innerHTML = `<div class="empty">Failed to load: ${esc(e.message)}</div>`;
  }
}

function findingElement(f) {
  const div = document.createElement("div");
  div.className = "finding";
  div.dataset.severity = f.severity;
  div.style.setProperty("--sev", sevColor[f.severity] || "var(--border)");

  const header = document.createElement("div");
  header.className = "finding-header";
  header.innerHTML = `
    ${sevBadge(f.severity)}
    <span class="finding-title">${esc(f.title)}</span>
    <span class="finding-loc">${esc(f.file)}:${f.line}</span>
    <span class="chevron">▸</span>`;
  header.onclick = () => {
    div.classList.toggle("open");
    if (div.classList.contains("open") && !div.dataset.bodyBuilt) buildFindingBody(div, f);
  };

  const body = document.createElement("div");
  body.className = "finding-body";
  div.appendChild(header);
  div.appendChild(body);
  div.dataset.bodyBuilt = "0";
  return div;
}

function buildFindingBody(div, f) {
  div.dataset.bodyBuilt = "1";
  const body = $(".finding-body", div);
  body.innerHTML = `
    <div class="meta-grid">
      <div class="meta-item"><span class="k">Scanner</span><span class="v">${esc(f.scanner)}</span></div>
      <div class="meta-item"><span class="k">CWE</span><span class="v">${esc(f.cwe)}</span></div>
      <div class="meta-item"><span class="k">OWASP</span><span class="v">${esc(f.owasp)}</span></div>
      <div class="meta-item"><span class="k">Rule</span><span class="v">${esc(f.rule_id)}</span></div>
    </div>
    ${f.code ? `<div class="code-block">${esc(f.code)}</div>` : ""}
    ${f.description ? `<p style="font-size:13px;color:var(--muted)">${esc(f.description)}</p>` : ""}
    <div id="ai-slot-${f.id}"></div>`;

  const rec = f.ai_recommendation;
  if (rec) {
    renderAiPanel($(`#ai-slot-${f.id}`), rec);
  } else if (state.health && state.health.ai_enabled) {
    const slot = $(`#ai-slot-${f.id}`);
    slot.innerHTML = `<button class="btn btn-outline" onclick="analyzeFinding(${f.id})">🤖 Generate Gədr analysis</button>`;
  }
}

function renderAiPanel(slot, rec) {
  slot.innerHTML = `
    <div class="ai-panel">
      <h4>🤖 Gədr Security Analysis</h4>
      <p><b>Explanation:</b> ${esc(rec.explanation)}</p>
      <p><b>Security impact:</b> ${esc(rec.impact)}</p>
      <p><b>Attack scenario:</b> ${esc(rec.attack_scenario)}</p>
      <p><b>Root cause:</b> ${esc(rec.root_cause)}</p>
      <p><b>Recommended fix:</b> ${esc(rec.recommended_fix)}</p>
      ${rec.secure_code ? `<div class="code-block">${esc(rec.secure_code)}</div>` : ""}
      <span class="model-tag">model: Gədr Scanner</span>
    </div>`;
}

async function analyzeFinding(findingId) {
  if (!state.currentScanId) return;
  const slot = $(`#ai-slot-${findingId}`);
  if (!slot) return;
  slot.innerHTML = `<div class="empty"><span class="spinner"></span>Asking Gədr…</div>`;
  try {
    const r = await api(`/api/scans/${state.currentScanId}/ai`, { method: "POST" });
    const data = await api(`/api/scans/${state.currentScanId}`);
    const f = data.findings.find(x => x.id === findingId);
    if (f && f.ai_recommendation) renderAiPanel(slot, f.ai_recommendation);
    else slot.innerHTML = `<p class="hint">Analysis done (${r.analyzed} findings) — reload the list to see results.</p>`;
  } catch (e) {
    slot.innerHTML = `<p class="hint" style="color:var(--crit)">Gədr analysis failed: ${esc(e.message)}</p>`;
  }
}

function applySeverityFilter() {
  $$("#findings-list .finding").forEach(f =>
    f.style.display = state.findingsFilter[f.dataset.severity] ? "" : "none");
}

/* ---------------- Global UI wiring ---------------- */
function openFinding(header) {
  header.closest(".finding").classList.toggle("open");
}

async function downloadReport(scanId) {
  if (!scanId) return;
  const btn = $("#download-report") || $("#dash-download-report");
  if (btn) btn.disabled = true;
  try {
    const url = `/api/scans/${scanId}/report`;
    const res = await fetch(url);
    if (!res.ok) {
      let msg = `HTTP ${res.status}`;
      try { msg = (await res.json()).detail || msg; } catch (_) { /* ignore */ }
      throw new Error(msg);
    }
    const contentType = res.headers.get("content-type") || "";
    if (!contentType.includes("application/pdf")) {
      const body = await res.text();
      throw new Error(body.slice(0, 200) || `Unexpected response type: ${contentType}`);
    }
    const blob = await res.blob();
    const url2 = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url2;
    a.download = `gedr_ai_report_${scanId}.pdf`;
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      a.remove();
      URL.revokeObjectURL(url2);
    }, 1500);
    toast("Gedr AI PDF downloaded");
  } catch (e) {
    toast("Download failed: " + e.message, true);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function runAiAnalysis(scanId, btn) {
  if (!scanId) return;
  if (btn) btn.disabled = true;
  const oldText = btn ? btn.textContent : "";
  if (btn) btn.textContent = "Analyzing…";
  try {
    const r = await api(`/api/scans/${scanId}/ai`, { method: "POST" });
    toast(`Gədr analysis complete — ${r.analyzed}/${r.total} findings`);
    if (!$("#page-findings").classList.contains("hidden")) {
      const sel = $("#findings-scan");
      if (sel.value) renderFindings(sel.value);
    } else if (!$("#page-dashboard").classList.contains("hidden")) {
      if (state.currentScanId) loadScanDetail(state.currentScanId);
    }
  } catch (e) {
    toast("Gədr analysis failed: " + e.message, true);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = oldText; }
  }
}

async function runAiSummary(scanId, panelId, btn) {
  if (!scanId) return;
  const panel = $(`#${panelId}`);
  panel.innerHTML = `<div class="empty"><span class="spinner"></span>Generating Gədr summary…</div>`;
  if (btn) btn.disabled = true;
  try {
    const r = await api(`/api/scans/${scanId}/summary`, { method: "POST" });
    panel.innerHTML = `
      <div class="ai-panel">
        <h4>✨ Gədr Executive Summary</h4>
        <p>${esc(r.summary)}</p>
        <span class="model-tag">source: Gədr Scanner</span>
      </div>`;
  } catch (e) {
    panel.innerHTML = `<p class="hint" style="color:var(--crit)">Summary failed: ${esc(e.message)}</p>`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

function init() {
  $$(".tab").forEach(t => t.addEventListener("click", () => switchPage(t.dataset.page)));
  $$(".sev-filter").forEach(cb => cb.addEventListener("change", () => {
    state.findingsFilter[cb.value] = cb.checked;
    applySeverityFilter();
  }));
  $("#download-report").addEventListener("click", () =>
    downloadReport($("#download-report").dataset.scanId));
  $("#dash-download-report").addEventListener("click", () =>
    downloadReport(state.currentScanId));
  $("#ai-analyze-all").addEventListener("click", () =>
    runAiAnalysis($("#ai-analyze-all").dataset.scanId, $("#ai-analyze-all")));
  $("#dash-ai-analyze").addEventListener("click", () =>
    runAiAnalysis(state.currentScanId, $("#dash-ai-analyze")));

  $("#ai-analyze-btn").addEventListener("click", () => {
    const scanId = $("#ai-scan-select").value;
    if (!scanId) { toast("Select a scan first", true); return; }
    runAiSummary(scanId, "ai-summary-panel", $("#ai-analyze-btn"));
  });

  $("#clear-history").addEventListener("click", async () => {
    if (!confirm("Delete ALL projects, scans, findings and AI analyses? This cannot be undone.")) return;
    try {
      await api("/api/history", { method: "DELETE" });
      state.projects = [];
      state.currentScanId = null;
      $("#project-grid").innerHTML = `<div class="empty">No projects yet — run a scan first.</div>`;
      $("#dash-detail").classList.add("hidden");
      toast("History cleared");
    } catch (e) {
      toast("Failed to clear history: " + e.message, true);
    }
  });

  initScanPage();
  loadHealth();
}

document.addEventListener("DOMContentLoaded", init);
