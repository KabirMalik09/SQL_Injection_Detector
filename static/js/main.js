/**
 * main.js — SQLShield Frontend Logic
 * AI-Powered SQL Injection Detection System
 * Author: Kabir Malik (24CSU089), The NorthCap University
 */

"use strict";

// ── Example payloads ────────────────────────────────────────────────────────
const EXAMPLES = {
  union:   "1 UNION SELECT null, table_name FROM information_schema.tables--",
  boolean: "admin' OR '1'='1'--",
  time:    "1'; WAITFOR DELAY '0:0:5'--",
  benign:  "SELECT name, email FROM customers WHERE id = 42",
};

// ── DOM refs ────────────────────────────────────────────────────────────────
const queryInput      = document.getElementById("queryInput");
const charCounter     = document.getElementById("charCounter");
const inputErrorMsg   = document.getElementById("inputErrorMsg");
const analyseBtn      = document.getElementById("analyseBtn");
const analyseBtnText  = document.getElementById("analyseBtnText");
const analyseSpinner  = document.getElementById("analyseSpinner");

// Dashboard result elements
const resultCard      = document.getElementById("resultCard");       // the d-result-content div
const resultEmptyState= document.getElementById("resultEmptyState"); // empty placeholder
const verdictPanel    = document.getElementById("verdictPanel");
const verdictIcon     = document.getElementById("verdictIcon");
const verdictLabel    = document.getElementById("verdictLabel");
const verdictSublabel = document.getElementById("verdictSublabel");
const confVal         = document.getElementById("confVal");
const confBar         = document.getElementById("confBar");
const attackBadge     = document.getElementById("attackBadge");
const responseTime    = document.getElementById("responseTime");

const historyBody     = document.getElementById("historyBody");
const historyEmpty    = document.getElementById("historyEmpty");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");
const exportCsvBtn    = document.getElementById("exportCsvBtn");

const toastContainer  = document.getElementById("toastContainer");

const modelTableBody  = document.getElementById("modelTableBody");

// Batch mode — now uses tab buttons
const batchToggleBtn  = document.getElementById("tabBatchToggle");  // new tab btn
const tabSingle       = document.getElementById("tabSingle");
const batchHint       = document.getElementById("batchHint");
const batchResultCard = document.getElementById("batchResultCard");
const batchResultBody = document.getElementById("batchResultBody");
const batchResultCount= document.getElementById("batchResultCount");

// Copy result
const copyResultBtn   = document.getElementById("copyResultBtn");
const copyTooltip     = document.getElementById("copyTooltip");

// ApexCharts instance
let perfChart = null;

// Local history array (mirrors server state)
let localHistory = [];

// Current result data for copy feature
let lastResultData = null;

// Batch mode flag
let isBatchMode = false;

// ── Batch mode toggle — tab buttons ──────────────────────────────────────────
function switchToBatch() {
  isBatchMode = true;
  if (batchToggleBtn) batchToggleBtn.classList.add("active");
  if (tabSingle) tabSingle.classList.remove("active");
  if (batchHint) batchHint.classList.remove("hidden");

  const queryLbl = document.getElementById("queryInputLabel");
  if (queryLbl) queryLbl.textContent = "Enter SQL Queries (one per line)";
  queryInput.placeholder = "Enter one query per line (max 20)\u2026";
  queryInput.rows = 8;

  // Hide single-mode result, show empty state
  if (resultCard) resultCard.classList.add("hidden");
  if (resultEmptyState) resultEmptyState.classList.remove("hidden");

  // Update button label
  if (analyseBtnText) analyseBtnText.textContent = "Analyse Batch";

  charCounter.textContent = "0 / 2000";
  queryInput.value = "";
  clearInputError();
}

function switchToSingle() {
  isBatchMode = false;
  if (tabSingle) tabSingle.classList.add("active");
  if (batchToggleBtn) batchToggleBtn.classList.remove("active");
  if (batchHint) batchHint.classList.add("hidden");

  const queryLbl = document.getElementById("queryInputLabel");
  if (queryLbl) queryLbl.textContent = "Enter SQL Query or Web Input";
  queryInput.placeholder = "Enter a SQL query or web input to analyse\u2026";
  queryInput.rows = 6;

  // Hide batch results
  if (batchResultCard) batchResultCard.classList.add("hidden");

  // Update button label
  if (analyseBtnText) analyseBtnText.textContent = "Analyze Query";

  charCounter.textContent = "0 / 2000";
  queryInput.value = "";
  clearInputError();
}

if (batchToggleBtn) batchToggleBtn.addEventListener("click", switchToBatch);
if (tabSingle) tabSingle.addEventListener("click", switchToSingle);

// ── Char counter ─────────────────────────────────────────────────────────────
queryInput.addEventListener("input", () => {
  if (isBatchMode) {
    const lines = queryInput.value.split("\n").filter(l => l.trim() !== "");
    charCounter.textContent = `${lines.length} line${lines.length !== 1 ? "s" : ""} / 20 max`;
    if (lines.length > 20) {
      charCounter.classList.add("error");
      analyseBtn.disabled = true;
    } else {
      charCounter.classList.remove("error", "warn");
      analyseBtn.disabled = false;
    }
  } else {
    const len = queryInput.value.length;
    charCounter.textContent = `${len} / 2000`;
    if (len > 2000) {
      charCounter.classList.add("error");
      charCounter.classList.remove("warn");
      analyseBtn.disabled = true;
    } else if (len > 1700) {
      charCounter.classList.add("warn");
      charCounter.classList.remove("error");
      analyseBtn.disabled = false;
    } else {
      charCounter.classList.remove("error", "warn");
      analyseBtn.disabled = false;
    }
  }

  // Clear error state on typing
  queryInput.classList.remove("error");
  inputErrorMsg.textContent = "";
});

// ── Example buttons ─────────────────────────────────────────────────────────
document.querySelectorAll(".btn-example").forEach((btn) => {
  btn.addEventListener("click", () => {
    const query = btn.dataset.query;
    if (query) {
      queryInput.value = query;
      queryInput.dispatchEvent(new Event("input"));
      queryInput.focus();
    }
  });
});

// ── Analyse button ──────────────────────────────────────────────────────────
analyseBtn.addEventListener("click", () => {
  if (isBatchMode) runBatchAnalysis();
  else runAnalysis();
});

queryInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
    if (isBatchMode) runBatchAnalysis();
    else runAnalysis();
  }
});

// ── Single analysis ─────────────────────────────────────────────────────────
async function runAnalysis() {
  const query = queryInput.value.trim();

  if (!query) {
    setInputError("Please enter a query to analyse.");
    return;
  }
  if (query.length > 2000) {
    setInputError("Query exceeds 2000 characters.");
    return;
  }

  setLoadingState(true);
  clearInputError();

  try {
    const res  = await fetch("/api/predict", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ query }),
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || `HTTP ${res.status}`);
    }

    const data = await res.json();
    lastResultData = data;
    showResult(data);
    addHistoryRow(data, true);
  } catch (err) {
    showToast(`Detection failed: ${err.message}`, "error");
    queryInput.classList.add("error");
  } finally {
    setLoadingState(false);
  }
}

// ── FIX 2 — Batch analysis ───────────────────────────────────────────────────
async function runBatchAnalysis() {
  const lines = queryInput.value
    .split("\n")
    .map(l => l.trim())
    .filter(l => l !== "");

  if (lines.length === 0) {
    setInputError("Please enter at least one query (one per line).");
    return;
  }
  if (lines.length > 20) {
    setInputError("Maximum 20 queries per batch.");
    return;
  }

  setLoadingState(true);
  clearInputError();

  try {
    const res = await fetch("/api/predict/batch", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ queries: lines }),
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || `HTTP ${res.status}`);
    }

    const data = await res.json();
    renderBatchResults(data.results);

    // Add all to local history
    data.results.forEach(r => {
      if (!r.error) addHistoryRow(r, false);
    });
    // Flash newest
    if (data.results.length > 0 && !data.results[0].error) {
      renderHistory(data.results[0].id);
    } else {
      renderHistory();
    }

  } catch (err) {
    showToast(`Batch detection failed: ${err.message}`, "error");
    queryInput.classList.add("error");
  } finally {
    setLoadingState(false);
  }
}

function renderBatchResults(results) {
  batchResultBody.innerHTML = "";
  batchResultCount.textContent = `— ${results.length} quer${results.length !== 1 ? "ies" : "y"}`;
  batchResultCard.classList.remove("hidden");
  batchResultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });

  results.forEach((entry, idx) => {
    const tr = document.createElement("tr");

    if (entry.error) {
      tr.innerHTML = `
        <td style="color:var(--text-secondary);font-family:'JetBrains Mono',monospace;font-size:12px;">${idx + 1}</td>
        <td class="query-cell" title="${escHtml(entry.query || '')}">${escHtml((entry.query || "").slice(0, 45))}${(entry.query || "").length > 45 ? "…" : ""}</td>
        <td colspan="3" style="color:var(--accent-red);font-size:12px;">⚠ ${escHtml(entry.error)}</td>
      `;
    } else {
      const isSqli    = entry.label === "SQL Injection";
      const confClass = entry.confidence >= 80 ? "high" : entry.confidence >= 60 ? "medium" : "low";
      const badgeCls  = isSqli ? "badge-sqli" : "badge-benign";
      const shortQ    = entry.query.length > 45 ? entry.query.slice(0, 45) + "…" : entry.query;
      const confColor = confClass === "high" ? "var(--accent-green)"
                      : confClass === "medium" ? "var(--accent-orange)"
                      : "var(--accent-red)";

      tr.innerHTML = `
        <td style="color:var(--text-secondary);font-family:'JetBrains Mono',monospace;font-size:12px;">${idx + 1}</td>
        <td class="query-cell" title="${escHtml(entry.query)}">${escHtml(shortQ)}</td>
        <td><span class="badge ${badgeCls}">${escHtml(entry.label)}</span></td>
        <td class="conf-cell" style="color:${confColor}">${entry.confidence.toFixed(1)}%</td>
        <td><span class="badge badge-neutral">${escHtml(entry.attack_type)}</span></td>
      `;
    }
    batchResultBody.appendChild(tr);
  });
}

// ── Loading state ────────────────────────────────────────────────────────────
function setLoadingState(loading) {
  analyseBtn.disabled        = loading;
  analyseSpinner.classList.toggle("hidden", !loading);
  const analyseIcon = document.getElementById("analyseIcon");
  if (analyseIcon) analyseIcon.style.display = loading ? "none" : "";
  if (loading) {
    analyseBtnText.textContent = isBatchMode ? "Analysing batch\u2026" : "Analysing\u2026";
  } else {
    analyseBtnText.textContent = isBatchMode ? "Analyse Batch" : "Analyze Query";
  }
}

// ── Input error helpers ──────────────────────────────────────────────────────
function setInputError(msg) {
  queryInput.classList.remove("error");
  void queryInput.offsetWidth;
  queryInput.classList.add("error");
  inputErrorMsg.textContent = msg;
}

function clearInputError() {
  queryInput.classList.remove("error");
  inputErrorMsg.textContent = "";
}

// ── Show result (dashboard card style) ─────────────────────────────────────
function showResult(data) {
  const isSqli = data.label === "SQL Injection";
  const conf   = data.confidence;  // already a percentage

  // Verdict panel
  verdictPanel.className    = `d-verdict-panel ${isSqli ? "sqli" : "benign"}`;
  verdictIcon.textContent   = isSqli ? "\u26A0" : "\u2713";
  verdictLabel.textContent  = isSqli ? "SQL INJECTION\nDETECTED" : "BENIGN QUERY";
  verdictLabel.style.whiteSpace = "pre-line";
  verdictSublabel.textContent = isSqli
    ? "Malicious pattern detected"
    : "Input appears safe";

  // Confidence colouring
  const confClass = conf >= 80 ? "high" : conf >= 60 ? "medium" : "low";
  confVal.textContent = `${conf.toFixed(1)}%`;
  confVal.className   = `rs-val conf-val ${isSqli ? "sqli" : "benign"} ${confClass}`;
  confBar.style.width = `${conf}%`;
  confBar.style.background = isSqli ? "var(--red)" : "var(--green)";
  confBar.setAttribute("aria-valuenow", conf);

  // Attack type
  const badgeClass = isSqli ? "badge-sqli" : "badge-benign";
  attackBadge.textContent = data.attack_type;
  attackBadge.className   = `rs-val attack-val badge ${badgeClass}`;

  // Response time
  responseTime.textContent = `${data.response_ms} ms`;

  // Show result card, hide empty state
  if (resultEmptyState) resultEmptyState.classList.add("hidden");
  resultCard.classList.remove("hidden");
  resultCard.classList.add("animate__animated", "animate__fadeIn");
}

// ── FIX 6 — Copy result button ───────────────────────────────────────────────
copyResultBtn.addEventListener("click", () => {
  if (!lastResultData) return;

  const formatted = JSON.stringify({
    query:       lastResultData.query,
    label:       lastResultData.label,
    confidence:  `${lastResultData.confidence}%`,
    attack_type: lastResultData.attack_type,
    timestamp:   lastResultData.timestamp,
    response_ms: lastResultData.response_ms,
  }, null, 2);

  navigator.clipboard.writeText(formatted).then(() => {
    copyResultBtn.classList.add("copied");
    copyTooltip.classList.remove("hidden");

    setTimeout(() => {
      copyResultBtn.classList.remove("copied");
      copyTooltip.classList.add("hidden");
    }, 1800);
  }).catch(() => {
    showToast("Clipboard copy failed.", "error");
  });
});

// ── History ──────────────────────────────────────────────────────────────────
function addHistoryRow(data, flash = false) {
  localHistory.unshift(data);  // newest first
  if (localHistory.length > 20) localHistory.pop();
  if (flash) renderHistory(data.id);
}

function renderHistory(flashId = null) {
  if (localHistory.length === 0) {
    historyEmpty.classList.remove("hidden");
    historyBody.innerHTML = "";
    return;
  }

  historyEmpty.classList.add("hidden");
  historyBody.innerHTML = "";

  localHistory.forEach((entry, idx) => {
    const tr = document.createElement("tr");
    // Add Animate.css fadeIn to the new row if it's the flash row
    if (flashId && entry.id === flashId) {
      tr.classList.add("new-row",
        "animate__animated", "animate__fadeIn");
    }

    const isSqli   = entry.label === "SQL Injection";
    const confClass = entry.confidence >= 80 ? "high"
                    : entry.confidence >= 60 ? "medium" : "low";
    const badgeCls  = isSqli ? "badge-sqli" : "badge-benign";
    const shortQuery = entry.query.length > 40
      ? entry.query.slice(0, 40) + "…"
      : entry.query;
    const confColor = confClass === "high" ? "var(--accent-green)"
                    : confClass === "medium" ? "var(--accent-orange)"
                    : "var(--accent-red)";

    tr.innerHTML = `
      <td style="color:var(--text-secondary);font-family:'JetBrains Mono',monospace;font-size:12px;">${localHistory.length - idx}</td>
      <td class="query-cell" title="${escHtml(entry.query)}">${escHtml(shortQuery)}</td>
      <td><span class="badge ${badgeCls}">${escHtml(entry.label)}</span></td>
      <td class="conf-cell" style="color:${confColor}">${entry.confidence.toFixed(1)}%</td>
      <td><span class="badge badge-neutral">${escHtml(entry.attack_type)}</span></td>
      <td class="ts-cell">${formatTime(entry.timestamp)}</td>
    `;
    historyBody.appendChild(tr);
  });
}

clearHistoryBtn.addEventListener("click", async () => {
  try {
    await fetch("/api/history", { method: "DELETE" });
    localHistory = [];
    renderHistory();
    showToast("History cleared.", "success");
  } catch {
    showToast("Could not clear history.", "error");
  }
});

// ── FIX 3 — Export history as CSV ────────────────────────────────────────────
exportCsvBtn.addEventListener("click", () => {
  if (localHistory.length === 0) {
    showToast("No history to export.", "error");
    return;
  }

  const headers = ["#", "Query", "Label", "Confidence (%)", "Attack Type", "Time"];
  const rows = localHistory.map((entry, idx) => [
    localHistory.length - idx,
    `"${entry.query.replace(/"/g, '""')}"`,
    entry.label,
    entry.confidence.toFixed(2),
    entry.attack_type,
    entry.timestamp,
  ]);

  const csvContent = [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  const ts   = new Date().toISOString().slice(0, 19).replace(/:/g, "-");
  a.href     = url;
  a.download = `sqlshield_history_${ts}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showToast(`Exported ${localHistory.length} entr${localHistory.length !== 1 ? "ies" : "y"} as CSV.`, "success");
});

function formatTime(isoStr) {
  try {
    const d = new Date(isoStr);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch { return isoStr; }
}

// ── Model Comparison Chart ────────────────────────────────────────────────────
async function loadModelResults() {
  try {
    const res  = await fetch("/api/models");
    if (!res.ok) return;
    const data = await res.json();
    renderModelTable(data.models);
    renderModelChart(data.models);
  } catch {
    // silent — table will show no-data message
  }
}

function renderModelTable(models) {
  if (!modelTableBody) return;
  modelTableBody.innerHTML = "";

  if (!models || models.length === 0) {
    modelTableBody.innerHTML = `<tr><td colspan="6" class="no-results-msg">Run train.py to generate model results.</td></tr>`;
    return;
  }

  models.forEach((m) => {
    const tr = document.createElement("tr");
    if (m.is_best) tr.classList.add("best-row");

    tr.innerHTML = `
      <td>
        ${escHtml(m.name)}
        ${m.is_best ? '<span class="active-badge">✓ Active</span>' : ""}
      </td>
      <td>${(m.accuracy  * 100).toFixed(2)}%</td>
      <td>${(m.precision * 100).toFixed(2)}%</td>
      <td>${(m.recall    * 100).toFixed(2)}%</td>
      <td style="font-weight:600;color:${m.is_best ? 'var(--accent-blue)' : 'inherit'}">${(m.f1_score * 100).toFixed(2)}%</td>
    `;
    modelTableBody.appendChild(tr);
  });
}

function renderModelChart(models) {
  const el = document.getElementById("modelChart");
  if (!el || typeof ApexCharts === "undefined") return;

  const labels = models.map((m) => m.name);
  const f1s    = models.map((m) => +(m.f1_score * 100).toFixed(2));
  const accs   = models.map((m) => +(m.accuracy  * 100).toFixed(2));

  if (perfChart) {
    perfChart.destroy();
    perfChart = null;
  }

  const options = {
    chart: {
      type: "bar",
      height: 240,
      background: "#0d1117",
      toolbar: { show: false },
      animations: {
        enabled: true,
        easing: "easeinout",
        speed: 700,
        animateGradually: { enabled: true, delay: 100 },
        dynamicAnimation:  { enabled: true, speed: 350 },
      },
      theme: { mode: "dark" },
    },
    theme: { mode: "dark" },
    plotOptions: {
      bar: {
        borderRadius: 4,
        columnWidth: "55%",
        dataLabels: { position: "top" },
      },
    },
    series: [
      { name: "F1-Score (%)", data: f1s },
      { name: "Accuracy (%)", data: accs },
    ],
    colors: ["#3b82f6", "#10b981"],
    xaxis: {
      categories: labels,
      labels: {
        style: { colors: "#e6edf3", fontFamily: "'Inter', sans-serif", fontSize: "12px" },
      },
      axisBorder: { color: "#30363d" },
      axisTicks:  { color: "#30363d" },
    },
    yaxis: {
      min: 0,
      max: 100,
      labels: {
        style: { colors: "#e6edf3", fontFamily: "'JetBrains Mono', monospace", fontSize: "11px" },
        formatter: (v) => `${v}%`,
      },
    },
    grid: {
      borderColor: "#30363d",
      strokeDashArray: 3,
    },
    legend: {
      labels: { colors: "#e6edf3" },
      fontFamily: "'Inter', sans-serif",
    },
    tooltip: {
      theme: "dark",
      style: { fontFamily: "'Inter', sans-serif" },
      y: {
        formatter: (val) => `${val.toFixed(2)}%`,
      },
    },
    dataLabels: { enabled: false },
  };

  perfChart = new ApexCharts(el, options);
  perfChart.render();
}

// ── FIX 4 — Model Evaluation Images ─────────────────────────────────────────
function renderEvalImages() {
  const grid = document.getElementById("evalImagesGrid");
  if (!grid) return;

  const images = [
    { src: "/static/img/confusion_matrix.png", label: "Confusion Matrix" },
    { src: "/static/img/roc_curve.png",        label: "ROC Curve" },
  ];

  grid.innerHTML = "";

  images.forEach(({ src, label }) => {
    const card = document.createElement("div");
    card.className = "eval-image-card";

    const img = new Image();
    img.onload = () => {
      card.innerHTML = `
        <img src="${src}" alt="${label}" loading="lazy" />
        <div class="eval-image-label">${label}</div>
      `;
    };
    img.onerror = () => {
      card.innerHTML = `
        <div class="eval-placeholder">
          <div class="eval-ph-icon">📊</div>
          <p><strong style="color:var(--text-primary);">${label}</strong><br />
          Run <code>python train.py</code> to generate evaluation charts.</p>
        </div>
        <div class="eval-image-label">${label}</div>
      `;
    };
    img.src = src;

    grid.appendChild(card);
  });
}

// ── Toast notification ────────────────────────────────────────────────────────
function showToast(msg, type = "error") {
  const div = document.createElement("div");
  div.className = `toast ${type === "success" ? "success" : ""}`;
  div.textContent = msg;
  toastContainer.appendChild(div);
  setTimeout(() => {
    div.style.opacity    = "0";
    div.style.transform  = "translateY(10px)";
    div.style.transition = "opacity .3s, transform .3s";
    setTimeout(() => div.remove(), 350);
  }, 3500);
}

// ── XSS-safe html escape ─────────────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ── Init ──────────────────────────────────────────────────────────────────────
(function init() {
  loadModelResults();
  renderHistory();
  renderEvalImages();

  // AutoAnimate on history tbody
  if (typeof autoAnimate !== "undefined") {
    autoAnimate(historyBody);
  }

  // Keyboard shortcut: Ctrl+K focuses search
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "k") {
      e.preventDefault();
      const s = document.getElementById("d-search-input");
      if (s) s.focus();
    }
  });

  // Highlight active sidebar nav item on scroll
  const sections = [
    { id: "detectionCard", nav: "nav-analyze" },
    { id: "modelComparisonCard", nav: "nav-performance" },
    { id: "modelEvalCard", nav: "nav-eval" },
    { id: "historyCard", nav: "nav-history" },
  ];
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        document.querySelectorAll(".d-nav-item").forEach(n => n.classList.remove("active"));
        const s = sections.find(s => s.id === entry.target.id);
        if (s) {
          const nav = document.getElementById(s.nav);
          if (nav) nav.classList.add("active");
        }
      }
    });
  }, { threshold: 0.3 });
  sections.forEach(s => {
    const el = document.getElementById(s.id);
    if (el) observer.observe(el);
  });

  // Update status dot based on model availability
  const statusDot  = document.getElementById("statusDot");
  const statusText = document.getElementById("statusText");
  fetch("/api/models").then((r) => {
    const online = r.ok;
    if (statusDot)  statusDot.classList.toggle("offline", !online);
    if (statusText) statusText.textContent = online ? "Model Active" : "Model Offline";
  }).catch(() => {
    if (statusDot)  statusDot.classList.add("offline");
    if (statusText) statusText.textContent = "Model Offline";
  });
})();
