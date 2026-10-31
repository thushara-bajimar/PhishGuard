"""Validated API request and response models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AnalyzeURLRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    url: str = Field(min_length=1, max_length=4096, description="An HTTP(S) URL or bare web hostname.")

    @field_validator("url")
    @classmethod
    def validate_http_url(cls, value: str) -> str:
        candidate = value if "://" in value or value.startswith("//") else f"//{value}"
        try:
            parsed = urlsplit(candidate)
            port = parsed.port
        except ValueError as error:
            raise ValueError("Enter a valid HTTP or HTTPS URL.") from error
        del port
        if "://" in value and parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs can be analyzed.")
        if not parsed.hostname or any(character.isspace() for character in parsed.hostname):
            raise ValueError("Enter a URL with a valid hostname, such as example.com.")
        return value


class IndicatorResponse(BaseModel):
    name: str
    description: str
    source: Literal["heuristic", "model"]


class ModelInfoResponse(BaseModel):
    algorithm: str
    dataset_source: str | None = None
    dataset_source_url: str | None = None
    sklearn_version: str | None = None
    tldextract_version: str | None = None
    feature_schema_version: int
    risk_score_note: str


class URLAnalysisResponse(BaseModel):
    id: str
    scan_type: Literal["url"]
    created_at: datetime
    prediction: Literal["potential_phishing", "no_phishing_detected"]
    risk_score: int = Field(ge=0, le=100)
    risk_category: Literal["low", "medium", "high", "critical"]
    indicators: list[IndicatorResponse]
    disclaimer: str
    model_name: str
    model_version: str
    model_confidence: float = Field(ge=0.0, le=1.0, description="Uncalibrated predicted-class score, not a real-world probability.")
    model_info: ModelInfoResponse
    explanation_note: str
