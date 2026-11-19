"""
app/schemas.py — Pydantic request/response schemas for SQLShield FastAPI
Author: Kabir Malik (24CSU089), The NorthCap University
"""

from __future__ import annotations

import base64
import binascii
from typing import Annotated, Any, Optional

from pydantic import BaseModel, Field, model_validator


def _b64_to_text(value: Any) -> str:
    """Decode a base64 (standard alphabet) UTF-8 string, or raise ValueError."""
    if not isinstance(value, str):
        raise ValueError("base64 value must be a string")
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ValueError("invalid base64 / UTF-8 payload") from exc


# Why the *_b64 fields exist: the hosted app sits behind a Cloudflare WAF that
# rejects request bodies containing obvious SQL injection (e.g. stacked queries
# like "1; DROP TABLE users --") with a 403 before they reach this API. The
# dashboard therefore sends queries base64-encoded. The plain fields keep
# working for direct API clients. Decoded values go through the same
# length validation as plain ones.


class PredictRequest(BaseModel):
    """Body expected by POST /api/predict: `query` or `query_b64`."""

    @model_validator(mode="before")
    @classmethod
    def _decode_b64(cls, data: Any) -> Any:
        if isinstance(data, dict) and "query_b64" in data:
            if "query" in data:
                raise ValueError("send either 'query' or 'query_b64', not both")
            data = {**data, "query": _b64_to_text(data["query_b64"])}
            data.pop("query_b64")
        return data

    query: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="The SQL query string to analyse for injection attacks.",
        examples=["SELECT * FROM users WHERE id = 1"],
    )


class PredictResponse(BaseModel):
    """Canonical prediction result returned to the client."""

    is_malicious: bool = Field(description="True when the query is classified as SQL injection.")
    confidence: float = Field(description="Model confidence score (0.0 – 100.0).")
    model_name: str = Field(description="Name of the ML model that produced this prediction.")

    # Extended fields preserved from the Flask version
    label: str
    attack_type: str
    timestamp: str
    response_ms: int
    query: str
    id: int


class BatchPredictRequest(BaseModel):
    """Body expected by POST /api/predict/batch: `queries` or `queries_b64`."""

    @model_validator(mode="before")
    @classmethod
    def _decode_b64(cls, data: Any) -> Any:
        if isinstance(data, dict) and "queries_b64" in data:
            if "queries" in data:
                raise ValueError("send either 'queries' or 'queries_b64', not both")
            items = data["queries_b64"]
            if not isinstance(items, list):
                raise ValueError("'queries_b64' must be a list of base64 strings")
            data = {**data, "queries": [_b64_to_text(q) for q in items]}
            data.pop("queries_b64")
        return data

    # Each item is capped like a single query; without this a 20-item batch
    # could carry megabytes and tie up the worker for seconds.
    queries: list[Annotated[str, Field(max_length=2000)]] = Field(
        ...,
        min_length=1,
        max_length=20,
        description="List of SQL query strings (1–20).",
    )


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_name: Optional[str] = None
