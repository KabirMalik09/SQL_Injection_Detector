"""
app/main.py — SQLShield FastAPI Backend
AI-Powered SQL Injection Detection System
Author: Kabir Malik (24CSU089), The NorthCap University

Replaces the original Flask app.py while keeping every route and behaviour.
Model is loaded once at startup via the FastAPI lifespan context.
Swagger UI is available at /docs, ReDoc at /redoc.
"""

from __future__ import annotations

import json
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import joblib
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.schemas import (
    BatchPredictRequest,
    HealthResponse,
    PredictRequest,
    PredictResponse,
)

# ──────────────────────────────────────────────────────────────────────────────
# ENVIRONMENT
# ──────────────────────────────────────────────────────────────────────────────
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# PATHS — resolve relative to the *project root* (parent of this file's dir)
# ──────────────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent  # …/SQL injection project/

MODEL_PATH      = ROOT / "models" / "model.joblib"        # new MLflow pipeline
LEGACY_MODEL    = ROOT / "models" / "sqli_model.pkl"      # fallback
LEGACY_VEC      = ROOT / "models" / "tfidf_vectorizer.pkl"
RESULTS_PATH    = ROOT / "models" / "model_results.json"
TEMPLATES_DIR   = ROOT / "templates"
STATIC_DIR      = ROOT / "static"

MAX_QUERY_LEN   = 2000

# ──────────────────────────────────────────────────────────────────────────────
# ATTACK TYPE CLASSIFIER  (rule-based, unchanged from original app.py)
# ──────────────────────────────────────────────────────────────────────────────
ATTACK_PATTERNS: dict[str, list[str]] = {
    "Time-based":    ["sleep(", "waitfor delay", "pg_sleep", "benchmark("],
    "UNION-based":   ["union select", "union all select", "union all", "union"],
    "Error-based":   ["@@version", "@@global", "extractvalue", "utl_inaddr",
                      "updatexml", "exp(", "floor(rand", "information_schema",
                      "@@datadir", "1/0"],
    "Stacked Query": [";drop", "; drop", ";insert", "; insert",
                      ";update", "; update", ";delete", "; delete",
                      ";exec", "; exec", ";select"],
    "Auth Bypass":   ["admin'--", "admin' --", "' or '1'='1",
                      "or '1'='1'", "admin'#"],
    "Boolean-based": ["or 1=1", "and 1=1", "or 1 =1", "and 1=2",
                      "or '1'='1'", "or '1' = '1'", 'or "1"="1"',
                      "or 'a'='a'", "or 'a' = 'a'",
                      "or true", "and false", "or false",
                      "' or '", '" or "', "10 or 1=1"],
    "Obfuscated":    ["or%20", "%20or%20", "or/**/", "/**/or",
                      " or  ", "o r ", "or\t", "oR ", " Or "],
    "Encoded":       ["%27", "%20", "%3d", "%2d%2d", "char(",
                      "0x", "concat(", "hex("],
    "Comment-based": ["--", "/*", "*/", "#"],
}


def classify_attack_type(query: str) -> str:
    """Return the single dominant attack type (priority-based, unchanged logic)."""
    q = query.lower().strip()

    if any(x in q for x in ["sleep(", "waitfor delay", "pg_sleep(", "benchmark(",
                              "and sleep", "or sleep"]):
        return "Time-based"
    if any(x in q for x in ["union select", "union all select", "union select null"]):
        return "UNION-based"
    if any(x in q for x in ["extractvalue(", "updatexml(", "@@version", "@@datadir",
                              "utl_inaddr", "1/0", "and 1/0"]):
        return "Error-based"
    if any(x in q for x in [";drop", "; drop", ";insert", "; insert",
                              ";update", "; update", ";delete", "; delete",
                              ";select"]):
        return "Stacked Query"
    if any(x in q for x in ["admin'--", "admin' --", "' or '1'='1",
                              "or '1'='1'", "admin'#"]):
        return "Auth Bypass"
    if any(x in q for x in ["or 1=1", "and 1=1", "or 1 =1", "and 1=2",
                              "or 'a'='a'", "' or '", '" or "',
                              "or true", "and false", "10 or 1=1"]):
        return "Boolean-based"
    if any(x in q for x in ["or%20", "%20or%20", "or/**/", "/**/or",
                              " or  ", "o r ", "or\t"]):
        return "Obfuscated"
    if any(x in q for x in ["%27", "%20", "%3d", "%2d%2d",
                              "char(", "0x", "concat(", "hex("]):
        return "Encoded"
    if any(x in q for x in ["--", "#", "/*", "*/"]):
        return "Comment-based"
    return "Unknown SQLi"


# ──────────────────────────────────────────────────────────────────────────────
# APPLICATION STATE  (populated at lifespan startup)
# ──────────────────────────────────────────────────────────────────────────────
class AppState:
    model: Any = None
    vectorizer: Any = None   # None when model is a Pipeline
    model_results: Optional[dict] = None
    model_name: str = "unknown"
    is_pipeline: bool = False   # True → model already includes vectorizer

    detection_history: list = []
    history_counter: int = 0


state = AppState()


def _load_model() -> None:
    """Try new pipeline first, fall back to legacy separate pkl files."""
    if MODEL_PATH.exists():
        try:
            pipeline = joblib.load(MODEL_PATH)
            state.model      = pipeline
            state.vectorizer = None
            state.is_pipeline = True
            # Try to extract model name stored by train.py
            state.model_name = getattr(pipeline, "model_name_", "Pipeline")
            logger.info("Loaded MLflow pipeline from %s", MODEL_PATH)
            return
        except Exception as exc:
            logger.warning("Failed to load %s: %s — trying legacy files.", MODEL_PATH, exc)

    if LEGACY_MODEL.exists() and LEGACY_VEC.exists():
        try:
            state.model      = joblib.load(LEGACY_MODEL)
            state.vectorizer = joblib.load(LEGACY_VEC)
            state.is_pipeline = False
            state.model_name  = "Legacy Model"
            logger.info("Loaded legacy model + vectorizer.")
            return
        except Exception as exc:
            logger.error("Failed to load legacy models: %s", exc)

    logger.error("No model found. Run `python train.py` first.")


def _predict_query(query: str) -> tuple[int, float]:
    """Return (pred_label, confidence_pct). Raises RuntimeError if model absent."""
    if state.model is None:
        raise RuntimeError("Model not loaded.")
    if state.is_pipeline:
        pred   = int(state.model.predict([query])[0])
        proba  = state.model.predict_proba([query])[0]
    else:
        X     = state.vectorizer.transform([query])
        pred  = int(state.model.predict(X)[0])
        proba = state.model.predict_proba(X)[0]
    conf_pct = round(float(proba[pred]) * 100, 2)
    return pred, conf_pct


# ──────────────────────────────────────────────────────────────────────────────
# LIFESPAN  (load model once at startup)
# ──────────────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    _load_model()
    try:
        with open(RESULTS_PATH) as f:
            state.model_results = json.load(f)
        logger.info("model_results.json loaded.")
    except FileNotFoundError:
        logger.warning("model_results.json not found.")
    yield  # app runs here
    logger.info("SQLShield shutting down.")


# ──────────────────────────────────────────────────────────────────────────────
# RATE LIMITER  (slowapi — mirrors Flask-Limiter behaviour)
# ──────────────────────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/hour", "40/minute"])

# ──────────────────────────────────────────────────────────────────────────────
# FASTAPI APP
# ──────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SQLShield API",
    description=(
        "AI-powered SQL Injection Detection System. "
        "Classifies SQL queries as benign or malicious using a trained ML pipeline. "
        "Built for CSL236 end-term project — Kabir Malik (24CSU089), The NorthCap University."
    ),
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files & templates
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# ──────────────────────────────────────────────────────────────────────────────
# SECURITY HEADERS MIDDLEWARE
# ──────────────────────────────────────────────────────────────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]          = "DENY"
    response.headers["X-XSS-Protection"]         = "1; mode=block"
    response.headers["Referrer-Policy"]          = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data: blob: https://fastapi.tiangolo.com; "
        "connect-src 'self';"
    )
    return response


# ──────────────────────────────────────────────────────────────────────────────
# HTML ROUTES
# ──────────────────────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def index(request: Request):
    """Serve the main single-page application."""
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "model_loaded": state.model is not None,
            "model_results": state.model_results,
        },
    )


@app.get("/landing", include_in_schema=False)
async def landing(request: Request):
    """Serve the landing / marketing page."""
    return templates.TemplateResponse("landing.html", {"request": request})


@app.get("/api/docs", include_in_schema=False)
@app.get("/api/docs-page", include_in_schema=False)
async def api_docs_page(request: Request):
    """Render the HTML API documentation page (legacy route kept)."""
    return templates.TemplateResponse("api_docs.html", {"request": request})


# ──────────────────────────────────────────────────────────────────────────────
# HEALTH
# ──────────────────────────────────────────────────────────────────────────────
@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Returns 200 with model load status. Used by Docker HEALTHCHECK and load balancers.",
    tags=["Operations"],
)
async def health():
    return HealthResponse(
        status="ok",
        model_loaded=state.model is not None,
        model_name=state.model_name if state.model is not None else None,
    )


# ──────────────────────────────────────────────────────────────────────────────
# PREDICT
# ──────────────────────────────────────────────────────────────────────────────
@app.post(
    "/api/predict",
    response_model=PredictResponse,
    summary="Classify a SQL query",
    description=(
        "Accepts a single SQL query string and returns a prediction: benign or malicious. "
        "Confidence is expressed as a percentage (0–100). "
        "Attack type is classified by a rule-based post-processor when the query is flagged."
    ),
    tags=["Prediction"],
)
async def predict(body: PredictRequest):
    if state.model is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model not loaded. Run train.py first.",
        )

    query = body.query.strip()

    t_start = time.time()
    try:
        pred, conf_pct = _predict_query(query)
    except Exception as exc:
        logger.error("Prediction error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Prediction failed. Please try again.",
        ) from exc
    elapsed_ms = int((time.time() - t_start) * 1000)

    label_str   = "SQL Injection" if pred == 1 else "Benign"
    attack_type = classify_attack_type(query) if pred == 1 else "—"
    ts          = datetime.now().isoformat(timespec="seconds")

    state.history_counter += 1
    entry = {
        "id":          state.history_counter,
        "query":       query,
        "label":       label_str,
        "confidence":  conf_pct,
        "attack_type": attack_type,
        "timestamp":   ts,
        "response_ms": elapsed_ms,
        "is_malicious": pred == 1,
        "model_name":  state.model_name,
    }

    state.detection_history.append(entry)
    if len(state.detection_history) > 20:
        state.detection_history.pop(0)

    logger.info("Predicted: %s (%.2f%%) | %s | %dms", label_str, conf_pct, attack_type, elapsed_ms)
    return entry


# ──────────────────────────────────────────────────────────────────────────────
# BATCH PREDICT
# ──────────────────────────────────────────────────────────────────────────────
@app.post(
    "/api/predict/batch",
    summary="Classify multiple SQL queries",
    description="Accepts a list of 1–20 SQL query strings and returns a prediction for each.",
    tags=["Prediction"],
)
async def predict_batch(body: BatchPredictRequest):
    if state.model is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model not loaded. Run train.py first.",
        )

    results: list[dict] = []
    for q_raw in body.queries:
        q = q_raw.strip() if isinstance(q_raw, str) else ""
        if not q:
            results.append({"query": str(q_raw)[:80], "error": "Input cannot be empty."})
            continue

        t_start = time.time()
        try:
            pred, conf = _predict_query(q)
        except Exception as exc:
            logger.error("Batch prediction error: %s", exc)
            results.append({"query": q, "error": "Prediction failed."})
            continue

        elapsed_ms  = int((time.time() - t_start) * 1000)
        label_str   = "SQL Injection" if pred == 1 else "Benign"
        attack_type = classify_attack_type(q) if pred == 1 else "—"
        ts          = datetime.now().isoformat(timespec="seconds")

        state.history_counter += 1
        entry = {
            "id":          state.history_counter,
            "query":       q,
            "label":       label_str,
            "confidence":  conf,
            "attack_type": attack_type,
            "timestamp":   ts,
            "response_ms": elapsed_ms,
            "is_malicious": pred == 1,
            "model_name":  state.model_name,
        }
        state.detection_history.append(entry)
        if len(state.detection_history) > 20:
            state.detection_history.pop(0)
        results.append(entry)

    return {"results": results, "count": len(results)}


# ──────────────────────────────────────────────────────────────────────────────
# HISTORY
# ──────────────────────────────────────────────────────────────────────────────
@app.get(
    "/api/history",
    summary="Get detection history",
    description="Returns the last 20 detection entries, newest first.",
    tags=["History"],
)
async def history():
    return list(reversed(state.detection_history))


@app.delete(
    "/api/history",
    summary="Clear detection history",
    description="Wipes all in-memory detection history entries.",
    tags=["History"],
)
async def clear_history():
    state.detection_history  = []
    state.history_counter    = 0
    return {"message": "History cleared."}


# ──────────────────────────────────────────────────────────────────────────────
# MODEL RESULTS
# ──────────────────────────────────────────────────────────────────────────────
@app.get(
    "/api/models",
    summary="Get model comparison data",
    description="Returns metrics for all models trained during the last training run.",
    tags=["Models"],
)
async def get_model_results():
    if state.model_results is None:
        raise HTTPException(status_code=404, detail="model_results.json not found.")
    return state.model_results


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT  (direct run only — production uses uvicorn via Procfile)
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)
