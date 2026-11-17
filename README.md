# SQLShield 🛡️

![CI](https://github.com/KabirMalik09/SQL_Injection_Detector/actions/workflows/ci.yml/badge.svg)

> AI-Powered SQL Injection Detection System  
> CSL236 End-Term Project — Kabir Malik (24CSU089), The NorthCap University

SQLShield is a production-grade machine-learning service that classifies SQL query strings as **benign** or **malicious (SQL injection)** in real time. It exposes a FastAPI REST API, an interactive Swagger UI, and a rich HTML dashboard — all backed by a scikit-learn TF-IDF + ML pipeline tracked with MLflow.

---

## Architecture Overview

```
SQL injection project/
├── app/
│   ├── __init__.py
│   ├── main.py          ← FastAPI application (all routes)
│   └── schemas.py       ← Pydantic request / response models
├── data/
│   └── Modified_SQL_Dataset.csv
├── models/
│   ├── model.joblib     ← Best MLflow Pipeline (vectorizer + classifier)
│   ├── sqli_model.pkl   ← Legacy model (backward-compat fallback)
│   ├── tfidf_vectorizer.pkl
│   └── model_results.json
├── static/              ← CSS / JS / images
├── templates/           ← Jinja2 HTML templates
├── tests/
│   └── test_api.py      ← 7 pytest tests (FastAPI TestClient)
├── train.py             ← MLflow training pipeline
├── Dockerfile
├── .dockerignore
├── Procfile
├── requirements.txt
└── .github/workflows/ci.yml
```

---

## Quick Start

### 1. Prerequisites

- Python 3.11+
- (Optional) Docker

### 2. Create a virtual environment

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Environment variables

Copy `.env` and edit the secret key (**never commit the file**):

```bash
cp .env.example .env   # or edit .env directly
```

```env
SECRET_KEY=your-random-32-byte-hex-key-here
PORT=8000
```

> **Security note**: `.env` is listed in `.gitignore`. Never print or commit its values.

---

## Training the Model

```bash
python train.py
```

This will:
1. Load `data/Modified_SQL_Dataset.csv`
2. Split data with `random_state=42`, stratified (80/20)
3. Log **3 MLflow runs** to the `sqli-detection` experiment:
   - Random Forest (`n_estimators=200`, `max_depth=None`)
   - Random Forest (`n_estimators=100`, `max_depth=10`)
   - Logistic Regression (`C=1.0`)
4. Train the full 4-model set (RF, LR, Gradient Boosting, Linear SVM) for the UI dashboard
5. Save the best-by-F1 model to `models/model.joblib` as a scikit-learn Pipeline
6. Generate evaluation plots in `static/img/`

Expected output:

```
=================================================================
  SQLShield — ML Training Pipeline  (MLflow Edition)
  ...
[3/6] MLflow experiment: 'sqli-detection'
  [Random Forest (n=200, depth=None)] F1=0.9965 | ...
  [Random Forest (n=100, depth=10)]   F1=0.9950 | ...
  [Logistic Regression (C=1.0)]       F1=0.9934 | ...
...
Training complete.
```

---

## MLflow Tracking

After training, launch the MLflow UI to compare runs:

```bash
mlflow ui
```

Then open **http://localhost:5000** in your browser.

### What is logged per run

| Item | Details |
|------|---------|
| **Parameters** | `model_type`, `n_estimators`, `max_depth`, `C`, TF-IDF params |
| **Metrics** | `accuracy`, `precision`, `recall`, `f1_score`, `train_time_s` |
| **Artifact** | `plots/confusion_matrix.png` |

### Selecting the best model

The best run (highest F1 on the held-out test set) is automatically saved to `models/model.joblib`. The FastAPI app loads this pipeline at startup.

---

## Running the API Server

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

| URL | Description |
|-----|-------------|
| `http://localhost:8000/` | HTML dashboard |
| `http://localhost:8000/landing` | Landing / marketing page |
| `http://localhost:8000/docs` | **Swagger UI** (interactive) |
| `http://localhost:8000/redoc` | ReDoc documentation |
| `http://localhost:8000/health` | Health check (JSON) |

### Key endpoints

```http
GET  /health                 → { status, model_loaded, model_name }
POST /api/predict            → { is_malicious, confidence, model_name, … }
POST /api/predict/batch      → { results: […], count }
GET  /api/history            → [ … last 20 entries … ]
DELETE /api/history          → { message }
GET  /api/models             → model comparison JSON
```

#### Example — single prediction

```bash
curl -X POST http://localhost:8000/api/predict \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM users WHERE id = 1 OR 1=1--"}'
```

```json
{
  "is_malicious": true,
  "confidence": 99.87,
  "model_name": "Random Forest (n=200, depth=None)",
  "label": "SQL Injection",
  "attack_type": "Boolean-based",
  ...
}
```

---

## Running Tests

```bash
pytest tests/ -v
```

The suite (7 tests) covers:

| Test | What it checks |
|------|---------------|
| `test_health_returns_200` | `/health` → 200 |
| `test_benign_query_not_malicious` | Benign SQL → `is_malicious: false` |
| `test_sqli_query_is_malicious` | `' OR 1=1--` → `is_malicious: true` |
| `test_empty_query_returns_422` | Empty string → 422 (Pydantic validation) |
| `test_response_schema` | All fields present with correct Python types |
| `test_history_accumulates` | History endpoint grows after predictions |
| `test_models_endpoint` | `/api/models` returns 200 or 404 gracefully |

---

## Docker

### Build

```bash
docker build -t sqlshield .
```

### Run

```bash
docker run -p 8000:8000 sqlshield
```

The container:
- Uses `python:3.11-slim` base image
- Copies `requirements.txt` first for layer caching
- Runs as a **non-root user** (`appuser`)
- Includes a `HEALTHCHECK` that hits `/health` every 30 s

---

## CI/CD

`.github/workflows/ci.yml` runs on every push and pull request:

1. **Checkout** the repository
2. **Set up Python 3.11** (with pip cache)
3. **Install** `requirements.txt`
4. **Train** the model (`python train.py`) — ensures `models/model.joblib` exists
5. **Run pytest** (`tests/`)
6. **Build** the Docker image

---

## Secrets & Security

| Item | Status |
|------|--------|
| `SECRET_KEY` in `.env` | ✅ Read from env, never hardcoded |
| `.env` in `.gitignore` | ✅ Will not be committed |
| `FLASK_ENV` variable | ⚠️ Legacy — no longer used (FastAPI). Remove from `.env` if desired |
| Rate limiting | ✅ 200/hour default; 30/min on `/api/predict` |
| Security headers | ✅ X-Frame-Options, CSP, X-XSS-Protection, etc. |
| Non-root Docker user | ✅ `appuser` |

---

## Dataset

| Field | Value |
|-------|-------|
| File | `data/Modified_SQL_Dataset.csv` |
| Columns | `Query` (string), `Label` (0 = benign, 1 = SQLi) |
| Size | ~30,918 rows |
| Benign | ~63% |
| SQLi | ~37% |

---

## Authors

Kabir Malik · 24CSU089 · The NorthCap University  
Course: CSL236 — End-Term Project
