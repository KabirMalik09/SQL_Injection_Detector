# ──────────────────────────────────────────────────────────────────────────────
# Dockerfile — SQLShield FastAPI
# Base: python:3.11-slim
# Runs as a non-root user; includes HEALTHCHECK.
# Build:  docker build -t sqlshield .
# Run:    docker run -p 8000:8000 sqlshield
# ──────────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim

# ── System metadata
LABEL maintainer="Kabir Malik <24CSU089@tnu.edu.in>"
LABEL description="SQLShield — AI-Powered SQL Injection Detection System"

# ── Environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

# ── Install dependencies first (layer is cached if requirements.txt unchanged)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# ── Copy the project source
COPY . .

# ── Create a non-root user and switch to it
RUN addgroup --system appgroup \
 && adduser  --system --ingroup appgroup appuser \
 && chown -R appuser:appgroup /app

USER appuser

# ── Expose the application port
EXPOSE 8000

# ── Health check (uses the /health endpoint we added)
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://localhost:%s/health' % os.environ.get('PORT', '8000'))" \
  || exit 1

# ── Default start command
#    Shell form so $PORT set by the host (Render, Railway, Cloud Run…) is honoured.
#    --proxy-headers makes request.client reflect the real client behind the proxy.
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips="*"

