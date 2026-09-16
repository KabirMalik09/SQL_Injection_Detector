
html = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SQLShield - AI-Powered SQL Injection Detector</title>
  <meta name="description" content="SQLShield detects SQL injection attempts in real time using machine learning. Compare 4 ML models and get instant confidence scores." />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet" />
  <script src="https://cdn.jsdelivr.net/npm/apexcharts"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css" />
  <link rel="stylesheet" href="{{ url_for('static', filename='css/dashboard.css') }}" />
</head>
<body>

<div id="dashboard">

  <!-- SIDEBAR -->
  <aside class="d-sidebar" role="navigation" aria-label="Sidebar navigation">
    <div class="d-sidebar-logo">
      <div class="logo-row">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        SQLShield
      </div>
      <div class="tagline">Detect. Prevent. Secure.</div>
    </div>
    <nav class="d-nav">
      <a class="d-nav-item active" href="#" id="nav-dashboard" aria-current="page">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
        Dashboard
      </a>
      <a class="d-nav-item" href="#detectionCard" id="nav-analyze">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        Analyze Query
      </a>
      <a class="d-nav-item" href="#modelComparisonCard" id="nav-performance">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
        Model Performance
      </a>
      <a class="d-nav-item" href="#modelEvalCard" id="nav-eval">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg>
        Model Evaluation
      </a>
      <a class="d-nav-item" href="#historyCard" id="nav-history">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
        Detection History
      </a>
      <a class="d-nav-item" href="#batchResultCard" id="nav-batch">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
        Batch Analysis
      </a>
      <a class="d-nav-item" href="/api/docs" id="nav-api">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
        API &amp; Docs
      </a>
      <a class="d-nav-item" href="/landing" id="nav-home">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
        Back to Home
      </a>
    </nav>
    <div class="d-sidebar-bottom">
      <div class="d-sidebar-tagline">SECURE TODAY<br>SAFER TOMORROW</div>
    </div>
  </aside>

  <!-- MAIN -->
  <main class="d-main" id="main">

    <!-- TOP BAR -->
    <header class="d-topbar" role="banner">
      <div class="d-search">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input type="text" placeholder="Search queries, history, or documentation..." id="d-search-input" aria-label="Search" />
        <span class="d-search-kbd">Ctrl K</span>
      </div>
      <div class="d-topbar-right">
        <div class="d-status-pill" id="modelStatusPill">
          <span class="status-dot" id="statusDot"></span>
          <span id="statusText">Checking model...</span>
        </div>
        <div class="d-user-info">
          <div class="d-user-name">Kabir Malik</div>
        </div>
        <div class="d-avatar" aria-hidden="true">KM</div>
      </div>
    </header>

    <div class="d-content">

      {% if not model_loaded %}
      <div class="d-alert-banner" role="alert">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        <span>ML model not found. Run <code>python train.py</code> to train and save the model, then restart the server.</span>
      </div>
      {% endif %}

      <!-- HERO STRIP -->
      <div class="d-hero-strip">
        <div class="d-hero-text">
          <h1>AI-Powered <span>SQL Injection</span> Detection</h1>
          <p>Analyze queries in real-time using machine learning. Detect. Prevent. Secure.</p>
        </div>
        <div class="d-hero-stats">
          <div class="d-stat-pill total"><div><div class="sp-num">30,919</div><div class="sp-label">Total Queries</div></div></div>
          <div class="d-stat-pill benign"><div><div class="sp-num">19,537</div><div class="sp-label">Benign</div></div></div>
          <div class="d-stat-pill sqli"><div><div class="sp-num">11,382</div><div class="sp-label">SQL Injection</div></div></div>
        </div>
      </div>

      <!-- ROW 1: QUERY + RESULT -->
      <div class="d-grid-2" id="detectionCard">

        <section class="d-card" aria-labelledby="analyzeHeading">
          <div class="d-card-header">
            <div class="d-card-title" id="analyzeHeading">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              Analyze a Query
            </div>
            <div class="d-tabs">
              <button class="d-tab active" id="tabSingle" type="button">Single Query</button>
              <button class="d-tab" id="tabBatchToggle" type="button">Batch Analysis</button>
            </div>
          </div>
          <div class="d-card-body">
            <div class="d-batch-hint hidden" id="batchHint" role="status">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
              Batch Mode: enter one query per line (max 20).
            </div>
            <label class="d-query-label" for="queryInput" id="queryInputLabel">Enter SQL Query or Web Input</label>
            <div class="d-textarea-wrap">
              <textarea class="d-textarea" id="queryInput" name="query" rows="6" maxlength="20001"
                placeholder="Enter a SQL query or web input to analyse..."
                aria-describedby="charCounter inputErrorMsg" spellcheck="false" autocomplete="off"></textarea>
            </div>
            <div class="d-char-count"><span id="charCounter">0 / 2000</span></div>
            <div class="d-input-error" id="inputErrorMsg" role="alert" aria-live="assertive"></div>
            <div class="d-examples-label">Try an example:</div>
            <div class="d-chips" role="list">
              <button class="d-chip sqli-chip btn-example" data-query="1 UNION SELECT null, table_name FROM information_schema.tables--" type="button" title="UNION-based SQLi payload">UNION Attack</button>
              <button class="d-chip sqli-chip btn-example" data-query="admin' OR '1'='1'--" type="button" title="Boolean-based SQLi payload">Boolean Attack</button>
              <button class="d-chip sqli-chip btn-example" data-query="1'; WAITFOR DELAY '0:0:5'--" type="button" title="Time-based SQLi payload">Time-based</button>
              <button class="d-chip sqli-chip btn-example" data-query="'; DROP TABLE users --" type="button" title="Stacked query SQLi payload">Stacked Query</button>
              <button class="d-chip benign-chip btn-example" data-query="SELECT name, email FROM customers WHERE id = 42" type="button" title="Benign SQL query">Benign Query</button>
            </div>
            <button class="d-analyse-btn" id="analyseBtn" type="button" aria-label="Analyse the entered query">
              <span class="d-spinner hidden" id="analyseSpinner" aria-hidden="true"></span>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              <span id="analyseBtnText">Analyze Query</span>
            </button>
            <div class="d-analyse-hint">Press <kbd>Ctrl</kbd> + <kbd>Enter</kbd> to analyze</div>
          </div>
        </section>

        <section class="d-card" aria-labelledby="resultHeading" aria-live="polite">
          <div class="d-card-header">
            <div class="d-card-title" id="resultHeading">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              Detection Result
            </div>
            <div style="position:relative;">
              <button class="d-btn-copy" id="copyResultBtn" type="button" title="Copy result as JSON" aria-label="Copy result as JSON">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
                Copy
              </button>
              <div class="d-copy-tooltip hidden" id="copyTooltip">Copied!</div>
            </div>
          </div>
          <div class="d-card-body" id="resultBody">
            <div class="d-result-empty" id="resultEmptyState">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              <p>No analysis yet</p>
              <small>Enter a query and click "Analyze Query" to see results.</small>
            </div>
            <div class="d-result-content hidden" id="resultCard" aria-live="polite">
              <div class="d-verdict-panel benign" id="verdictPanel" role="status">
                <div class="d-verdict-icon" id="verdictIcon" aria-hidden="true">&#10003;</div>
                <div class="d-verdict-label" id="verdictLabel">BENIGN QUERY</div>
                <div class="d-verdict-sub" id="verdictSublabel">Input appears safe</div>
              </div>
              <div class="d-result-grid">
                <div class="d-result-stat">
                  <div class="rs-label">CONFIDENCE SCORE</div>
                  <div class="rs-val conf-val benign" id="confVal">&mdash;</div>
                  <div class="d-result-bar-track" style="margin-top:8px;">
                    <div class="d-result-bar-fill" id="confBar" style="width:0%;" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100"></div>
                  </div>
                </div>
                <div class="d-result-stat">
                  <div class="rs-label">ATTACK TYPE</div>
                  <div class="rs-val attack-val" id="attackBadge">&mdash;</div>
                </div>
                <div class="d-result-stat">
                  <div class="rs-label">RESPONSE TIME</div>
                  <div class="rs-val" id="responseTime" style="color:var(--blue);font-size:15px;">&mdash;</div>
                </div>
                <div class="d-result-stat">
                  <div class="rs-label">MODEL</div>
                  <div class="rs-val" style="color:var(--muted2);font-size:13px;">Random Forest</div>
                </div>
              </div>
            </div>
          </div>
        </section>
      </div>

      <!-- BATCH RESULTS -->
      <section class="d-card d-full hidden" id="batchResultCard" aria-labelledby="batchResultHeading" aria-live="polite">
        <div class="d-card-header">
          <div class="d-card-title" id="batchResultHeading">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            Batch Analysis Results
            <span id="batchResultCount" style="font-size:11px;color:var(--muted);font-weight:400;margin-left:4px;"></span>
          </div>
        </div>
        <div class="d-card-body" style="padding:0;">
          <table class="d-hist-table" aria-label="Batch analysis results table">
            <thead><tr><th scope="col">#</th><th scope="col">QUERY</th><th scope="col">LABEL</th><th scope="col">CONFIDENCE</th><th scope="col">ATTACK TYPE</th></tr></thead>
            <tbody id="batchResultBody"></tbody>
          </table>
        </div>
      </section>

      <!-- MODEL PERFORMANCE -->
      <section class="d-card d-full" id="modelComparisonCard" aria-labelledby="modelHeading">
        <div class="d-card-header">
          <div class="d-card-title" id="modelHeading">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
            Model Performance Comparison
          </div>
          <div class="d-perf-badge">&#127942; Random Forest (Best Model)</div>
        </div>
        <div class="d-card-body">
          <div class="d-perf-inner">
            <div class="d-chart-wrap">
              <div id="modelChart" aria-label="Model performance bar chart" role="img"></div>
              <div class="d-chart-legend">
                <span class="legend-item"><span class="legend-dot" style="background:#3b82f6"></span>F1-Score (%)</span>
                <span class="legend-item"><span class="legend-dot" style="background:#10b981"></span>Accuracy (%)</span>
              </div>
            </div>
            <div class="d-model-table-wrap">
              <table class="d-model-table" aria-label="Model metrics table">
                <thead><tr><th scope="col">MODEL</th><th scope="col">ACCURACY</th><th scope="col">PRECISION</th><th scope="col">RECALL</th><th scope="col">F1-SCORE</th></tr></thead>
                <tbody id="modelTableBody"><tr><td colspan="5" class="d-hist-empty">Loading model results...</td></tr></tbody>
              </table>
            </div>
          </div>
        </div>
      </section>

      <!-- ROW 3: EVAL + HISTORY -->
      <div class="d-grid-2">

        <section class="d-card" id="modelEvalCard" aria-labelledby="evalHeading">
          <div class="d-card-header">
            <div class="d-card-title" id="evalHeading">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg>
              Model Evaluation <span style="font-size:11px;color:var(--muted);font-weight:400;margin-left:4px;">(Random Forest)</span>
            </div>
          </div>
          <div class="d-card-body">
            <div class="d-eval-images-grid" id="evalImagesGrid"></div>
          </div>
        </section>

        <section class="d-card" id="historyCard" aria-labelledby="historyHeading">
          <div class="d-card-header">
            <div class="d-card-title" id="historyHeading">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
              Detection History
              <span style="font-size:11px;color:var(--muted);font-weight:400;margin-left:4px;">(last 20)</span>
            </div>
            <div class="d-history-actions">
              <button class="d-btn-sm d-btn-export" id="exportCsvBtn" type="button" aria-label="Export history as CSV">&#8595; Export CSV</button>
              <button class="d-btn-sm d-btn-clear" id="clearHistoryBtn" type="button" aria-label="Clear all history">Clear History</button>
            </div>
          </div>
          <div class="d-card-body" style="padding:0;">
            <table class="d-hist-table" aria-label="Detection history table">
              <thead><tr><th scope="col">#</th><th scope="col">QUERY</th><th scope="col">LABEL</th><th scope="col">CONFIDENCE</th><th scope="col">ATTACK TYPE</th><th scope="col">TIME</th></tr></thead>
              <tbody id="historyBody"></tbody>
            </table>
            <div class="d-hist-empty" id="historyEmpty">No detections yet. Analyse a query to begin.</div>
          </div>
        </section>

      </div>

    </div><!-- /d-content -->

    <footer class="d-footer" role="contentinfo">
      <span>Kabir Malik &middot; SQLShield v1.0.0</span>
      <div class="d-footer-links">
        <a href="https://github.com/KabirMalik09/SQL_Injection_Detector" target="_blank" rel="noopener noreferrer">GitHub</a>
        <a href="/api/docs" target="_blank" rel="noopener noreferrer">API Docs</a>
        <a href="/api/models" target="_blank" rel="noopener noreferrer">Model Results</a>
      </div>
    </footer>

  </main><!-- /d-main -->
</div><!-- /dashboard -->

<div class="d-toast-container" id="toastContainer" aria-live="assertive" aria-atomic="true"></div>
<script src="https://cdn.jsdelivr.net/npm/@formkit/auto-animate@0.8.2/index.umd.min.js"></script>
<script src="{{ url_for('static', filename='js/main.js') }}"></script>
</body>
</html>
"""

with open("templates/index.html", "w", encoding="utf-8") as f:
    f.write(html)

print("Written OK, lines:", html.count("\\n"))
