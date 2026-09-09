"""
app.py — SQLShield Flask Backend
AI-Powered SQL Injection Detection System
Author: Kabir Malik (24CSU089), The NorthCap University
"""

import os
import json
import time
import hashlib
import logging
from datetime import datetime

import joblib
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

# ──────────────────────────────────────────────────────────────────────────────
# APP INIT
# ──────────────────────────────────────────────────────────────────────────────
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB max request

# Logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# CORS — open in dev, restrict in production
CORS(app)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour", "40 per minute"],
    storage_uri="memory://",
)

# ──────────────────────────────────────────────────────────────────────────────
# MODEL PATHS
# ──────────────────────────────────────────────────────────────────────────────
MODEL_PATH      = os.path.join("models", "sqli_model.pkl")
VECTORIZER_PATH = os.path.join("models", "tfidf_vectorizer.pkl")
RESULTS_PATH    = os.path.join("models", "model_results.json")

# ──────────────────────────────────────────────────────────────────────────────
# ATTACK TYPE CLASSIFIER  (rule-based, runs after ML prediction)
# ──────────────────────────────────────────────────────────────────────────────
ATTACK_PATTERNS = {
    "Time-based":    ["sleep(", "waitfor delay", "pg_sleep", "benchmark("],
    "UNION-based":   ["union select", "union all select", "union all", "union"],
    "Error-based":   ["@@version", "@@global", "extractvalue", "utl_inaddr",
                      "updatexml", "exp(", "floor(rand", "information_schema"],
    "Stacked Query": [";drop", "; drop", ";insert", "; insert",
                      ";update", "; update", ";delete", "; delete",
                      ";exec", "; exec", ";select"],
    "Boolean-based": ["or 1=1", "and 1=1", "or 1 =1", "and 1 =1",
                      "or '1'='1'", "or '1' = '1'", "or \"1\"=\"1\"",
                      "or 'a'='a'", "or 'a' = 'a'",
                      "or true", "and true", "or false",
                      "' or '", "\" or \""],
    "Comment-based": ["--", "/*", "*/", "#"],
}


def classify_attack(query: str) -> str:
    """Return attack type label for a query (benign returns '—')."""
    q = query.lower()
    matched = []
    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pat in patterns:
            if pat in q:
                matched.append(attack_type)
                break

    if len(matched) == 0:
        return "Unknown SQLi"
    if len(matched) == 1:
        return matched[0]
    return "Multiple Types"


# ──────────────────────────────────────────────────────────────────────────────
# INPUT VALIDATION
# ──────────────────────────────────────────────────────────────────────────────
MAX_QUERY_LEN = 2000


def validate_input(query) -> tuple:
    """Returns (is_valid: bool, cleaned_query_or_error: str)."""
    if not isinstance(query, str):
        return False, "Input must be a string."
    if not query.strip():
        return False, "Input cannot be empty."
    if len(query) > MAX_QUERY_LEN:
        return False, f"Input exceeds maximum length of {MAX_QUERY_LEN} characters."
    return True, query.strip()


# ──────────────────────────────────────────────────────────────────────────────
# LOAD MODEL AT STARTUP
# ──────────────────────────────────────────────────────────────────────────────
model      = None
vectorizer = None
model_results = None
_history_id_counter = 0

def load_model():
    global model, vectorizer, model_results
    try:
        model      = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)
        logger.info("Model and vectorizer loaded successfully.")
    except FileNotFoundError as e:
        logger.error(f"Model files not found: {e}")
        logger.error("Run `python train.py` first to generate model artifacts.")
        model      = None
        vectorizer = None

    try:
        with open(RESULTS_PATH) as f:
            model_results = json.load(f)
        logger.info("model_results.json loaded successfully.")
    except FileNotFoundError:
        logger.warning("model_results.json not found — model comparison will be unavailable.")
        model_results = None


load_model()

# ──────────────────────────────────────────────────────────────────────────────
# IN-MEMORY SESSION HISTORY  (max 20 entries, FIFO)
# ──────────────────────────────────────────────────────────────────────────────
detection_history = []


# ──────────────────────────────────────────────────────────────────────────────
# SECURITY HEADERS
# ──────────────────────────────────────────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]          = "DENY"
    response.headers["X-XSS-Protection"]         = "1; mode=block"
    response.headers["Referrer-Policy"]          = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:;"
    )
    return response


# ──────────────────────────────────────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/", methods=["GET"])
def index():
    """Serve the main single-page application."""
    model_loaded = model is not None and vectorizer is not None
    return render_template(
        "index.html",
        model_loaded=model_loaded,
        model_results=model_results,
    )


@app.route("/api/predict", methods=["POST"])
@limiter.limit("30 per minute")
def predict():
    """
    POST /api/predict
    Body: { "query": "<sql string>" }
    Returns: { label, confidence, attack_type, timestamp, response_ms, query }
    """
    global detection_history, _history_id_counter

    # ── 1. Parse JSON body
    if not request.is_json:
        return jsonify({"error": "Request must be JSON."}), 400

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "Invalid JSON body."}), 400

    query_raw = data.get("query", "")

    # ── 2. Validate input
    is_valid, result = validate_input(query_raw)
    if not is_valid:
        return jsonify({"error": result}), 400

    query = result  # cleaned

    # ── 3. Check model is loaded
    if model is None or vectorizer is None:
        return jsonify({"error": "Model not loaded. Run train.py first."}), 503

    # ── 4. Predict
    t_start = time.time()
    try:
        X        = vectorizer.transform([query])
        pred     = int(model.predict(X)[0])
        proba    = model.predict_proba(X)[0]
        conf_pct = round(float(proba[pred]) * 100, 2)
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return jsonify({"error": "Prediction failed. Please try again."}), 500

    elapsed_ms = int((time.time() - t_start) * 1000)

    # ── 5. Classify attack type
    label_str = "SQL Injection" if pred == 1 else "Benign"
    if pred == 1:
        attack_type = classify_attack(query)
    else:
        attack_type = "—"

    # ── 6. Build response
    ts = datetime.now().isoformat(timespec="seconds")
    entry = {
        "id":          _history_id_counter + 1,
        "query":       query,
        "label":       label_str,
        "confidence":  conf_pct,
        "attack_type": attack_type,
        "timestamp":   ts,
        "response_ms": elapsed_ms,
    }

    # ── 7. Store in history (max 20, FIFO)
    _history_id_counter += 1
    detection_history.append(entry)
    if len(detection_history) > 20:
        detection_history.pop(0)

    logger.info(f"Predicted: {label_str} ({conf_pct}%) | {attack_type} | {elapsed_ms}ms")
    return jsonify(entry), 200


@app.route("/api/history", methods=["GET"])
def history():
    """Return last 20 detection entries (newest first)."""
    return jsonify(list(reversed(detection_history))), 200


@app.route("/api/history", methods=["DELETE"])
def clear_history():
    """Clear all detection history."""
    global detection_history, _history_id_counter
    detection_history     = []
    _history_id_counter   = 0
    return jsonify({"message": "History cleared."}), 200


@app.route("/api/models", methods=["GET"])
def get_model_results():
    """Return model comparison data."""
    if model_results is None:
        return jsonify({"error": "model_results.json not found."}), 404
    return jsonify(model_results), 200


# ──────────────────────────────────────────────────────────────────────────────
# ERROR HANDLERS
# ──────────────────────────────────────────────────────────────────────────────
@app.errorhandler(Exception)
def handle_generic_error(e):
    logger.error(f"Unhandled exception: {e}")
    return jsonify({"error": "An internal error occurred."}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found."}), 404


@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Too many requests. Please slow down."}), 429


@app.errorhandler(413)
def request_too_large(e):
    return jsonify({"error": "Request too large."}), 413


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV", "development") == "development"
    logger.info(f"Starting SQLShield on http://127.0.0.1:{port}  (debug={debug})")
    app.run(host="0.0.0.0", port=port, debug=debug)
