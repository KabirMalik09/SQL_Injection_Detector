"""
app/schemas.py — Pydantic request/response schemas for SQLShield FastAPI
Author: Kabir Malik (24CSU089), The NorthCap University
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class PredictRequest(BaseModel):
    """Body expected by POST /api/predict."""

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
    queries: list[str] = Field(
        ...,
        min_length=1,
        max_length=20,
        description="List of SQL query strings (1–20).",
    )


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_name: Optional[str] = None
