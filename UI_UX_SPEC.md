# UI_UX_SPEC.md — UI/UX Specification
## AI-Powered SQL Injection Detection System

---

## 1. Design Philosophy

- **Dark theme** — cybersecurity aesthetic, reduces eye strain
- **Single page** — no navigation, everything visible on scroll
- **Card-based layout** — clear visual separation of sections
- **Color-coded results** — red = danger, green = safe, instant readability
- **Minimal, professional** — portfolio-ready, not toy-looking

---

## 2. Color Palette

| Token | Hex | Usage |
|---|---|---|
| `--bg-primary` | `#0d1117` | Page background |
| `--bg-secondary` | `#161b22` | Card backgrounds |
| `--bg-tertiary` | `#21262d` | Input fields, table rows |
| `--accent-blue` | `#58a6ff` | Primary buttons, links, headings |
| `--accent-green` | `#3fb950` | Benign result, success states |
| `--accent-red` | `#f85149` | SQLi detected, danger states |
| `--accent-orange` | `#d29922` | Warning, medium confidence |
| `--text-primary` | `#e6edf3` | Main body text |
| `--text-secondary` | `#8b949e` | Labels, captions, placeholders |
| `--border` | `#30363d` | Card borders, dividers |

---

## 3. Typography

| Element | Font | Size | Weight |
|---|---|---|---|
| Page Title | `JetBrains Mono` | 28px | 700 |
| Section Heading | `JetBrains Mono` | 18px | 600 |
| Body Text | `Inter` | 14px | 400 |
| Code / Query | `JetBrains Mono` | 13px | 400 |
| Button | `Inter` | 14px | 600 |
| Badge/Label | `Inter` | 11px | 700 |

Import from Google Fonts:
```html
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
```

---

## 4. Page Layout

```
┌──────────────────────────────────────────────────────┐
│                     HEADER                           │
│   🛡️ SQLShield        AI-Powered SQLi Detection      │
│   Subtitle: NorthCap University · Kabir Malik        │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│                  DETECTION CARD                      │
│   [ Query Input Textarea                           ] │
│   [ Example buttons: UNION | Boolean | Benign ]      │
│   [          ANALYSE QUERY  ▶           ]            │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│                   RESULT CARD                        │
│   (hidden until first prediction)                    │
│   ┌────────────────┐  ┌────────────────────────────┐ │
│   │  BENIGN ✅      │  │ Confidence: 97.3%          │ │
│   │  or             │  │ Attack Type: —             │ │
│   │  SQL INJECTION  │  │ Time: 0.12s                │ │
│   │  DETECTED 🚨    │  │                            │ │
│   └────────────────┘  └────────────────────────────┘ │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│               MODEL COMPARISON                       │
│   Bar chart + table: 4 models × 4 metrics            │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│               DETECTION HISTORY                      │
│   Table: Query | Label | Confidence | Type | Time    │
│   [Clear History]                                    │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│                    FOOTER                            │
│   Built by Kabir Malik · B.Tech CSE (Cybersecurity)  │
│   The NorthCap University · GitHub link              │
└──────────────────────────────────────────────────────┘
```

---

## 5. Component Specifications

### 5.1 Header
- Background: `--bg-secondary` with bottom border `--border`
- Shield emoji + "SQLShield" in `JetBrains Mono`, `--accent-blue`
- Subtitle in `--text-secondary`, 13px
- Sticky at top on scroll

### 5.2 Query Input Card
- `textarea` — 4 rows minimum, expands on content
- Placeholder: `Enter a SQL query or web input to analyse...`
- Font: `JetBrains Mono` 13px
- Border: `--border`, focus border: `--accent-blue`
- Background: `--bg-tertiary`
- Max characters: 2000 (show counter: `0 / 2000`)

**Example buttons** (pre-fill textarea on click):
```
[UNION Attack]  [Boolean Attack]  [Time-Based]  [Benign Query]
```
Small pill buttons, `--bg-tertiary`, `--text-secondary`

**Analyse button:**
- Full width
- Background: `--accent-blue`, text: white
- Height: 44px, border-radius: 6px
- Loading spinner while waiting
- Disabled state during request

### 5.3 Result Card
- Hidden (`display: none`) until first prediction
- Slides in with CSS animation on reveal
- Two panels side by side (flex):

**Left panel — Verdict:**
- SQLi: background `rgba(248,81,73,0.1)`, border `--accent-red`
- Text: "⚠ SQL INJECTION DETECTED", `--accent-red`, 22px bold
- Benign: background `rgba(63,185,80,0.1)`, border `--accent-green`
- Text: "✓ BENIGN QUERY", `--accent-green`, 22px bold

**Right panel — Details:**
- Confidence: large percentage number, color-coded
  - ≥ 80%: `--accent-green`
  - 60–79%: `--accent-orange`
  - < 60%: `--accent-red`
- Attack Type: badge pill (e.g. `UNION-based`, `Boolean-based`)
- Response time in ms

### 5.4 Model Comparison Section
- Section heading: "Model Performance Comparison"
- Horizontal bar chart (Chart.js) — F1-Score per model
- Below chart: table with columns:
  `Model | Accuracy | Precision | Recall | F1-Score`
- Best model row: highlighted with `--accent-blue` left border
- Badge: "✓ Active Model" on best row

### 5.5 Detection History Table
- Max 20 rows (oldest removed when exceeded)
- Columns: `#`, `Query`, `Label`, `Confidence`, `Attack Type`, `Time`
- Query column: truncated to 40 chars with tooltip on hover
- Label: color-coded badge (red/green)
- Empty state: "No detections yet. Analyse a query to begin."
- Clear History button: right-aligned, `--accent-red` outline style

---

## 6. Responsive Behavior

| Breakpoint | Layout Change |
|---|---|
| Desktop (≥1024px) | Two-column result card, full table |
| Tablet (768–1023px) | Single column result, horizontal scroll on table |
| Mobile (< 768px) | Stacked layout, abbreviated table columns |

---

## 7. Interactions & States

| Element | State | Behavior |
|---|---|---|
| Analyse button | Loading | Spinner + "Analysing..." text, disabled |
| Analyse button | Error | Shake animation + red border on input |
| Result card | First load | Fade + slide-up animation |
| History row | New entry | Flash highlight for 1s |
| Example buttons | Hover | Background lightens |
| Table rows | Hover | Subtle background highlight |

---

## 8. Error States

| Error | Display |
|---|---|
| Empty input | Red border on textarea + "Please enter a query" |
| Input > 2000 chars | Counter turns red, button disabled |
| API error | Toast notification: "Detection failed. Try again." |
| Model not loaded | Full-page error message with retry |
