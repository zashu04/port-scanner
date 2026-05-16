/* ── Helpers ────────────────────────────────────────────────────────────── */
const $ = id => document.getElementById(id);
const STORAGE_KEY = "netscan_history";
const MAX_HIST    = 10;

/* ── Disclaimer dismiss ─────────────────────────────────────────────────── */
$("disc-close").addEventListener("click", () => {
  $("disclaimer-bar").style.display = "none";
});

/* ── Timeout slider ─────────────────────────────────────────────────────── */
const timeoutSlider  = $("timeout-slider");
const timeoutDisplay = $("timeout-display");

timeoutSlider.addEventListener("input", () => {
  const val = (parseInt(timeoutSlider.value) / 10).toFixed(1);
  timeoutDisplay.textContent = val + "s";
});

/* ── Preset buttons ─────────────────────────────────────────────────────── */
let activePreset = "common";

document.querySelectorAll(".preset-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".preset-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    activePreset = btn.dataset.preset;
    $("custom-wrap").style.display = activePreset === "custom" ? "block" : "none";
  });
});

/* ── Consent → enable scan button ──────────────────────────────────────── */
$("consent-check").addEventListener("change", () => {
  $("scan-btn").disabled = !$("consent-check").checked;
});

/* ── Active filter ──────────────────────────────────────────────────────── */
let activeFilter = "all";

document.querySelectorAll(".filter-tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".filter-tab").forEach(t => t.classList.remove("active"));
    tab.classList.add("active");
    activeFilter = tab.dataset.filter;
    applyFilter();
  });
});

function applyFilter() {
  document.querySelectorAll("#results-tbody tr").forEach(row => {
    const status = row.dataset.status;
    if (activeFilter === "all")           row.classList.remove("hidden");
    else if (activeFilter === "open")     row.classList.toggle("hidden", status !== "open");
    else if (activeFilter === "filtered") row.classList.toggle("hidden", status !== "filtered");
  });
}

/* ── Risk badge HTML ────────────────────────────────────────────────────── */
function riskBadge(risk) {
  if (!risk || risk === "none") return `<span class="risk-badge none">—</span>`;
  return `<span class="risk-badge ${risk}">${risk}</span>`;
}

function statusBadge(status) {
  const icons = { open: "●", filtered: "◌", closed: "○" };
  return `<span class="status-badge ${status}">${icons[status] || "?"} ${status}</span>`;
}

/* ── Render results table ───────────────────────────────────────────────── */
function renderTable(results) {
  const tbody = $("results-tbody");
  tbody.innerHTML = results.map(r => `
    <tr data-status="${r.status}">
      <td class="port-cell">${r.port}</td>
      <td class="proto-cell">${r.proto}</td>
      <td>${statusBadge(r.status)}</td>
      <td class="mono" style="font-size:0.82rem">${r.service}</td>
      <td>${riskBadge(r.risk)}</td>
      <td class="desc-cell">${r.desc}</td>
    </tr>`).join("");
  applyFilter();
}

/* ── Render summary ─────────────────────────────────────────────────────── */
function renderSummary(data) {
  $("sum-host").textContent     = data.host;
  $("sum-ip").textContent       = data.ip;
  $("sum-scanned").textContent  = data.ports_scanned;
  $("sum-open").textContent     = data.open_count;
  $("sum-filtered").textContent = data.filtered_count;
  $("sum-duration").textContent = data.elapsed + "s";

  const riskEl = $("sum-risk");
  riskEl.className = "risk-badge " + (data.top_risk === "none" ? "none" : data.top_risk);
  riskEl.textContent = data.top_risk === "none" ? "—" : data.top_risk;
}

/* ── Scan ───────────────────────────────────────────────────────────────── */
$("scan-btn").addEventListener("click", runScan);
$("host-input").addEventListener("keydown", e => {
  if (e.key === "Enter" && !$("scan-btn").disabled) runScan();
});

async function runScan() {
  const host = $("host-input").value.trim();
  if (!host) { $("host-input").focus(); return; }

  const btn = $("scan-btn");
  btn.disabled = true;
  $("scan-btn-text").innerHTML = `<span class="scan-dots"><span class="dot"></span><span class="dot"></span><span class="dot"></span></span> Scanning…`;
  $("error-banner").style.display = "none";

  const payload = {
    host,
    preset: activePreset,
    custom_ports: $("custom-ports").value,
    timeout: parseInt(timeoutSlider.value) / 10,
  };

  try {
    const res  = await fetch("/scan", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(payload),
    });
    const data = await res.json();

    if (data.error) {
      $("error-banner").textContent = "⚠ " + data.error;
      $("error-banner").style.display = "block";
    } else {
      $("results").style.display = "block";
      renderSummary(data);
      renderTable(data.results);
      saveHistory({ host, ip: data.ip, open: data.open_count, dur: data.elapsed, risk: data.top_risk });
      renderHistory();
      $("results").scrollIntoView({ behavior: "smooth", block: "start" });
    }
  } catch (err) {
    $("error-banner").textContent = "⚠ Network error — is the server running?";
    $("error-banner").style.display = "block";
  } finally {
    btn.disabled = false;
    $("scan-btn-text").textContent = "⚡ Start Scan";
  }
}

/* ── History ────────────────────────────────────────────────────────────── */
function loadHistory() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || []; }
  catch { return []; }
}

function saveHistory(entry) {
  const hist = loadHistory();
  entry.time = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  hist.unshift(entry);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(hist.slice(0, MAX_HIST)));
}

function renderHistory() {
  const hist = loadHistory();
  const container = $("history-container");

  if (hist.length === 0) {
    container.innerHTML = `<div class="no-history">No scans yet this session.</div>`;
    return;
  }

  const rows = hist.map(h => `
    <tr>
      <td><span class="hist-host">${h.host}</span></td>
      <td><span class="hist-host">${h.ip}</span></td>
      <td><span class="hist-open">${h.open}</span></td>
      <td>${riskBadge(h.risk && h.risk !== "none" ? h.risk : null)}</td>
      <td><span class="hist-dur">${h.dur}s</span></td>
      <td><span class="hist-time">${h.time}</span></td>
    </tr>`).join("");

  container.innerHTML = `
    <table class="history-table">
      <thead>
        <tr>
          <th>Host</th><th>IP</th><th>Open Ports</th>
          <th>Top Risk</th><th>Duration</th><th>Time</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

$("clear-hist-btn").addEventListener("click", () => {
  localStorage.removeItem(STORAGE_KEY);
  renderHistory();
});

/* ── Init ───────────────────────────────────────────────────────────────── */
renderHistory();
