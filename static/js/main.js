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

const resultCard      = document.getElementById("resultCard");
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

const toastContainer  = document.getElementById("toastContainer");

const modelTableBody  = document.getElementById("modelTableBody");

// Chart.js instance
let perfChart = null;

// Local history array (mirrors server state)
let localHistory = [];

// ── Char counter ─────────────────────────────────────────────────────────────
queryInput.addEventListener("input", () => {
  const len = queryInput.value.length;
  charCounter.textContent = `${len} / 2000`;
  charCounter.className   = "char-counter";

  if (len > 2000) {
    charCounter.classList.add("error");
    analyseBtn.disabled = true;
  } else if (len > 1700) {
    charCounter.classList.add("warn");
    analyseBtn.disabled = false;
  } else {
    analyseBtn.disabled = false;
  }

  // Clear error state on typing
  queryInput.classList.remove("error");
  inputErrorMsg.textContent = "";
});

// ── Example buttons ─────────────────────────────────────────────────────────
document.querySelectorAll(".btn-example").forEach((btn) => {
  btn.addEventListener("click", () => {
    const key = btn.dataset.example;
    if (EXAMPLES[key]) {
      queryInput.value = EXAMPLES[key];
      queryInput.dispatchEvent(new Event("input"));
      queryInput.focus();
    }
  });
});

// ── Analyse button ──────────────────────────────────────────────────────────
analyseBtn.addEventListener("click", runAnalysis);

queryInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
    runAnalysis();
  }
});

async function runAnalysis() {
  const query = queryInput.value.trim();

  // Validate client-side
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
    showResult(data);
    addHistoryRow(data, true);
  } catch (err) {
    showToast(`Detection failed: ${err.message}`, "error");
    queryInput.classList.add("error");
  } finally {
    setLoadingState(false);
  }
}

// ── Loading state ────────────────────────────────────────────────────────────
function setLoadingState(loading) {
  analyseBtn.disabled        = loading;
  analyseSpinner.classList.toggle("hidden", !loading);
  analyseBtnText.textContent = loading ? "Analysing…" : "Analyse Query";
}

// ── Input error helpers ──────────────────────────────────────────────────────
function setInputError(msg) {
  queryInput.classList.add("error");
  inputErrorMsg.textContent = msg;
}

function clearInputError() {
  queryInput.classList.remove("error");
  inputErrorMsg.textContent = "";
}

// ── Show result card ─────────────────────────────────────────────────────────
function showResult(data) {
  const isSqli = data.label === "SQL Injection";
  const conf   = data.confidence;  // already a percentage

  // Verdict panel
  verdictPanel.className    = `verdict-panel ${isSqli ? "sqli" : "benign"}`;
  verdictIcon.textContent   = isSqli ? "⚠" : "✓";
  verdictLabel.textContent  = isSqli ? "SQL INJECTION\nDETECTED" : "BENIGN QUERY";
  verdictLabel.style.whiteSpace = "pre-line";
  verdictSublabel.textContent = isSqli
    ? "Malicious pattern detected"
    : "Input appears safe";

  // Confidence colouring
  const confClass = conf >= 80 ? "high" : conf >= 60 ? "medium" : "low";
  confVal.textContent = `${conf.toFixed(1)}%`;
  confVal.className   = `confidence-val ${confClass}`;
  confBar.style.width = `${conf}%`;
  confBar.className   = `confidence-bar ${confClass}`;

  // Attack type badge
  const badgeClass = isSqli ? "badge-sqli" : "badge-benign";
  attackBadge.textContent = data.attack_type;
  attackBadge.className   = `badge ${badgeClass}`;

  // Response time
  responseTime.textContent = `${data.response_ms} ms`;

  // Show card
  resultCard.classList.remove("hidden");
  resultCard.classList.add("visible");
  resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// ── History ──────────────────────────────────────────────────────────────────
function addHistoryRow(data, flash = false) {
  localHistory.unshift(data);  // newest first
  if (localHistory.length > 20) localHistory.pop();
  renderHistory(flash ? data.id : null);
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
    if (flashId && entry.id === flashId) tr.classList.add("new-row");

    const isSqli   = entry.label === "SQL Injection";
    const confClass = entry.confidence >= 80 ? "high"
                    : entry.confidence >= 60 ? "medium" : "low";
    const badgeCls  = isSqli ? "badge-sqli" : "badge-benign";
    const shortQuery = entry.query.length > 40
      ? entry.query.slice(0, 40) + "…"
      : entry.query;

    tr.innerHTML = `
      <td style="color:var(--text-secondary);font-family:'JetBrains Mono',monospace;font-size:12px;">${localHistory.length - idx}</td>
      <td class="query-cell" title="${escHtml(entry.query)}">${escHtml(shortQuery)}</td>
      <td><span class="badge ${badgeCls}">${escHtml(entry.label)}</span></td>
      <td class="conf-cell" style="color:var(--accent-${confClass === 'high' ? 'green' : confClass === 'medium' ? 'orange' : 'red'})">${entry.confidence.toFixed(1)}%</td>
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
  const canvas = document.getElementById("modelChart");
  if (!canvas || !window.Chart) return;

  const labels = models.map((m) => m.name);
  const f1s    = models.map((m) => +(m.f1_score * 100).toFixed(2));
  const accs   = models.map((m) => +(m.accuracy  * 100).toFixed(2));

  const colors = models.map((m) =>
    m.is_best ? "rgba(88,166,255,0.85)" : "rgba(88,166,255,0.30)"
  );
  const borderColors = models.map((m) =>
    m.is_best ? "rgba(88,166,255,1)" : "rgba(88,166,255,0.55)"
  );

  if (perfChart) { perfChart.destroy(); }

  perfChart = new Chart(canvas, {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: "F1-Score (%)",
          data: f1s,
          backgroundColor: colors,
          borderColor: borderColors,
          borderWidth: 1.5,
          borderRadius: 4,
        },
        {
          label: "Accuracy (%)",
          data: accs,
          backgroundColor: models.map(() => "rgba(63,185,80,0.25)"),
          borderColor:     models.map(() => "rgba(63,185,80,0.7)"),
          borderWidth: 1.5,
          borderRadius: 4,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: {
            color: "#8b949e",
            font: { family: "'Inter', sans-serif", size: 12 },
            boxWidth: 12,
          },
        },
        tooltip: {
          backgroundColor: "#21262d",
          borderColor: "#30363d",
          borderWidth: 1,
          titleColor: "#e6edf3",
          bodyColor:  "#8b949e",
          callbacks: {
            label: (ctx) => ` ${ctx.dataset.label}: ${ctx.parsed.y}%`,
          },
        },
      },
      scales: {
        x: {
          ticks: { color: "#8b949e", font: { family: "'Inter',sans-serif", size: 12 } },
          grid:  { color: "rgba(48,54,61,0.6)" },
        },
        y: {
          min: 90,
          max: 100,
          ticks: {
            color: "#8b949e",
            font:  { family: "'JetBrains Mono',monospace", size: 11 },
            callback: (v) => `${v}%`,
          },
          grid: { color: "rgba(48,54,61,0.6)" },
        },
      },
    },
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

  // Update status dot based on model availability
  const statusDot  = document.getElementById("statusDot");
  const statusText = document.getElementById("statusText");
  fetch("/api/models").then((r) => {
    const online = r.ok;
    if (statusDot) {
      statusDot.classList.toggle("offline", !online);
    }
    if (statusText) {
      statusText.textContent = online ? "Model Active" : "Model Offline";
    }
  }).catch(() => {
    if (statusDot)  statusDot.classList.add("offline");
    if (statusText) statusText.textContent = "Model Offline";
  });
})();
