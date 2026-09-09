# SECURITY.md — Security Requirements & Threat Model
## AI-Powered SQL Injection Detection System

---

## 1. Security Philosophy

SQLShield is itself a security tool — it must be built securely. A SQL injection detector that is itself vulnerable to attacks would be ironic and unacceptable. This document defines all security requirements, threat vectors, and mitigations.

---

## 2. Threat Model

### 2.1 Assets to Protect
| Asset | Sensitivity | Risk if Compromised |
|---|---|---|
| ML model files (`.pkl`) | High | Model theft, adversarial bypass |
| Detection history (in-memory) | Low | Privacy leak of tested queries |
| Server resources | Medium | DoS, resource exhaustion |
| Application availability | Medium | Service downtime |

### 2.2 Threat Actors
| Actor | Motivation | Capability |
|---|---|---|
| Script kiddie | Curiosity, disruption | Low |
| Security researcher | Testing, bypass research | Medium-High |
| Automated scanner | Vulnerability discovery | Medium |
| Adversarial ML attacker | Bypass detection | High |

---

## 3. Input Validation

### 3.1 Rules (enforced server-side, not just client-side)

```python
def validate_input(query: str) -> tuple[bool, str]:
    # Rule 1: Must be a string
    if not isinstance(query, str):
        return False, "Input must be a string"

    # Rule 2: Must not be empty
    if not query.strip():
        return False, "Input cannot be empty"

    # Rule 3: Max length
    if len(query) > 2000:
        return False, "Input exceeds maximum length of 2000 characters"

    # Rule 4: Must be valid UTF-8 (Flask handles this via JSON parsing)
    # Rule 5: Strip leading/trailing whitespace
    return True, query.strip()
```

### 3.2 What is NOT validated (intentional)
- SQL keywords are allowed — that's the point of the tool
- Special characters (`'`, `"`, `;`, `--`) are allowed — they are the payload
- The tool must accept malicious input to classify it

---

## 4. API Security

### 4.1 Rate Limiting
Implement basic rate limiting to prevent abuse:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per hour", "20 per minute"]
)

@app.route('/api/predict', methods=['POST'])
@limiter.limit("30 per minute")
def predict():
    ...
```

### 4.2 Request Size Limit
```python
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024  # 16KB max request size
```

### 4.3 CORS Policy
```python
from flask_cors import CORS
CORS(app, origins=["https://sqlshield.onrender.com"])  # restrict in production
# For development: CORS(app) — allows all origins
```

### 4.4 HTTP Security Headers
```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com;"
    )
    return response
```

---

## 5. Model Security

### 5.1 Pickle / Joblib Safety
**Risk:** `.pkl` files can execute arbitrary code if tampered with.

**Mitigations:**
- Never load `.pkl` files from user uploads
- Store model files outside web-accessible directories
- Validate file integrity on startup:

```python
import hashlib

MODEL_HASH = "abc123..."  # pre-computed SHA256 of sqli_model.pkl

def verify_model_integrity():
    with open('models/sqli_model.pkl', 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    if file_hash != MODEL_HASH:
        raise RuntimeError("Model file integrity check failed")
```

### 5.2 Adversarial Input Resistance
**Risk:** Attacker crafts inputs that look benign but are actual SQLi (adversarial ML attack).

**Mitigations:**
- Character-level n-gram features (harder to fool than word-level)
- Low confidence threshold: flag anything > 40% as suspicious
- Future: adversarial training with obfuscated SQLi payloads

### 5.3 Model File Access
```python
# Never expose model files via routes
# BAD:
@app.route('/models/<filename>')
def serve_model(filename):
    return send_from_directory('models', filename)  # NEVER DO THIS

# Models are only loaded internally at startup
```

---

## 6. XSS Prevention

The app displays user input back in the result UI (history table).

**Risk:** Stored XSS via malicious input in query field.

**Mitigations:**
1. Jinja2 auto-escapes all template variables by default — keep this enabled
2. Never use `{{ query | safe }}` — always let Jinja2 escape
3. In JavaScript, use `textContent` not `innerHTML` when inserting query strings:

```javascript
// SAFE:
queryCell.textContent = entry.query;

// UNSAFE — never do this:
queryCell.innerHTML = entry.query;
```

---

## 7. Dependency Security

### 7.1 Pinned Dependencies (`requirements.txt`)
```
flask==3.0.3
scikit-learn==1.4.2
pandas==2.2.2
numpy==1.26.4
joblib==1.4.2
flask-limiter==3.7.0
flask-cors==4.0.1
gunicorn==22.0.0
```

### 7.2 Vulnerability Scanning
Before deployment, run:
```bash
pip install pip-audit
pip-audit
```

---

## 8. Error Handling & Information Disclosure

**Risk:** Stack traces and error messages reveal internal structure.

```python
# Production: never expose debug info
app.config['DEBUG'] = False
app.config['PROPAGATE_EXCEPTIONS'] = False

@app.errorhandler(Exception)
def handle_error(e):
    # Log internally, return generic message externally
    app.logger.error(f"Unhandled exception: {str(e)}")
    return jsonify({"error": "An internal error occurred"}), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Too many requests. Please slow down."}), 429
```

---

## 9. Deployment Security Checklist

| Item | Requirement |
|---|---|
| `DEBUG=False` | ✅ Required in production |
| `SECRET_KEY` | ✅ Random 32-byte hex, set via environment variable |
| HTTPS | ✅ Enforced by Render/HuggingFace automatically |
| Rate limiting | ✅ 30 req/min per IP on `/api/predict` |
| Model integrity check | ✅ SHA256 verified at startup |
| Security headers | ✅ All 5 headers set |
| No debug endpoints | ✅ No `/debug`, `/admin`, `/shell` routes |
| Dependency audit | ✅ `pip-audit` run before deploy |

---

## 10. Environment Variables

```bash
# .env (never commit this file)
SECRET_KEY=your-random-32-byte-hex-key-here
FLASK_ENV=production
MAX_REQUESTS_PER_MINUTE=30
MODEL_PATH=models/sqli_model.pkl
VECTORIZER_PATH=models/tfidf_vectorizer.pkl
```

```python
# app.py — load from environment
import os
from dotenv import load_dotenv

load_dotenv()
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(32)
```

---

## 11. Known Limitations (Honest Disclosure)

| Limitation | Impact | Future Fix |
|---|---|---|
| In-memory history not encrypted | Low (no PII stored) | Add SQLite + encryption |
| No authentication on API | Medium (public use) | Add API key system |
| Model can be bypassed with obfuscation | Medium | Adversarial training |
| Rate limiting is IP-based (bypassable via proxy) | Medium | Token-based auth |
| No audit logging | Low | Add structured logging |
