"""
tests/test_api.py — pytest suite for SQLShield FastAPI (7 tests)

Uses fastapi.testclient.TestClient against the real application so that
every request passes through routing, middleware, Pydantic validation,
and the lifespan (model loading).

What is tested:
  1. GET  /health         → 200, model_loaded is true
  2. POST /api/predict    → benign query classified as not malicious
  3. POST /api/predict    → "' OR 1=1--" classified as malicious
  4. POST /api/predict    → empty string rejected with 422
  5. POST /api/predict    → response body matches PredictResponse schema
  6. POST /api/predict    → missing "query" field rejected with 422
  7. POST /api/predict    → long input (2 001 chars) rejected with 422
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


# ──────────────────────────────────────────────────────────────────────────────
# FIXTURE — a single TestClient shared across the module
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    """Create a TestClient that triggers the app lifespan (model loading)."""
    with TestClient(app) as c:
        yield c


# ──────────────────────────────────────────────────────────────────────────────
# TEST 1 — GET /health → 200, model_loaded is true
# ──────────────────────────────────────────────────────────────────────────────

def test_health_returns_200_with_model_loaded(client: TestClient):
    """GET /health must return 200 with model_loaded=true after startup."""
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["model_loaded"] is True
    assert isinstance(body.get("model_name"), str)


# ──────────────────────────────────────────────────────────────────────────────
# TEST 2 — Benign query → is_malicious false
# ──────────────────────────────────────────────────────────────────────────────

def test_benign_query_not_malicious(client: TestClient):
    """A plain SELECT must be classified as benign (is_malicious=false)."""
    resp = client.post(
        "/api/predict",
        json={"query": "SELECT name FROM employees WHERE department = 'Engineering'"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["is_malicious"] is False
    assert body["label"] == "Benign"
    assert 0.0 <= body["confidence"] <= 100.0


# ──────────────────────────────────────────────────────────────────────────────
# TEST 3 — SQL injection → is_malicious true
# ──────────────────────────────────────────────────────────────────────────────

def test_sqli_query_is_malicious(client: TestClient):
    """The classic "' OR 1=1--" injection must be flagged as malicious."""
    resp = client.post(
        "/api/predict",
        json={"query": "' OR 1=1--"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["is_malicious"] is True
    assert body["label"] == "SQL Injection"
    assert body["confidence"] > 50.0


# ──────────────────────────────────────────────────────────────────────────────
# TEST 4 — Empty string → 422 Unprocessable Entity
# ──────────────────────────────────────────────────────────────────────────────

def test_empty_query_returns_422(client: TestClient):
    """An empty query string violates min_length=1 and must yield 422."""
    resp = client.post(
        "/api/predict",
        json={"query": ""},
    )
    assert resp.status_code == 422
    errors = resp.json()["detail"]
    field_locs = [e["loc"] for e in errors]
    assert any("query" in loc for loc in field_locs)


# ──────────────────────────────────────────────────────────────────────────────
# TEST 5 — Response schema: all expected fields present with correct types
# ──────────────────────────────────────────────────────────────────────────────

def test_response_schema(client: TestClient):
    """The JSON response for a valid prediction must include every PredictResponse field."""
    resp = client.post(
        "/api/predict",
        json={"query": "SELECT 1"},
    )
    assert resp.status_code == 200
    body = resp.json()

    # Required fields and their expected Python/JSON types
    expected_fields = {
        "is_malicious": bool,
        "confidence":   (int, float),
        "model_name":   str,
        "label":        str,
        "attack_type":  str,
        "timestamp":    str,
        "response_ms":  int,
        "query":        str,
        "id":           int,
    }

    for field, types in expected_fields.items():
        assert field in body, f"Missing field: {field}"
        assert isinstance(body[field], types), (
            f"Field '{field}' expected {types}, got {type(body[field])}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# TEST 6 — Missing "query" field → 422 Unprocessable Entity
# ──────────────────────────────────────────────────────────────────────────────

def test_missing_field_returns_422(client: TestClient):
    """A request body without the required "query" field must yield 422."""
    resp = client.post(
        "/api/predict",
        json={"not_a_real_field": "hello"},
    )
    assert resp.status_code == 422
    errors = resp.json()["detail"]
    field_locs = [e["loc"] for e in errors]
    assert any("query" in loc for loc in field_locs)


# ──────────────────────────────────────────────────────────────────────────────
# TEST 7 — Long input (>2000 chars) → 422 Unprocessable Entity
# ──────────────────────────────────────────────────────────────────────────────

def test_long_input_returns_422(client: TestClient):
    """A query exceeding max_length=2000 must be rejected with 422."""
    long_query = "A" * 2001
    resp = client.post(
        "/api/predict",
        json={"query": long_query},
    )
    assert resp.status_code == 422
    errors = resp.json()["detail"]
    field_locs = [e["loc"] for e in errors]
    assert any("query" in loc for loc in field_locs)
