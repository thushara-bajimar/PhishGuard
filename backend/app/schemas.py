"""Validated API request and response models."""

from __future__ import annotations

import ipaddress
import re
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
        hostname = parsed.hostname
        if not hostname or any(character.isspace() for character in hostname):
            raise ValueError("Enter a URL with a valid hostname, such as example.com.")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            if hostname.lower() != "localhost":
                try:
                    ascii_hostname = hostname.rstrip(".").encode("idna").decode("ascii")
                except UnicodeError as error:
                    raise ValueError("Enter a URL with a valid hostname, such as example.com.") from error
                labels = ascii_hostname.split(".")
                label_pattern = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
                if len(labels) < 2 or len(ascii_hostname) > 253 or not all(label_pattern.fullmatch(label) for label in labels):
                    raise ValueError("Enter a URL with a valid hostname, such as example.com.")
        return value


class AnalyzeMessageRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    content: str = Field(min_length=1, max_length=30_000, description="Email or SMS text to classify; do not include unnecessary sensitive data.")


class AnalysisIndicatorResponse(BaseModel):
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
    scope_note: str | None = None


class AnalysisResponse(BaseModel):
    id: str
    scan_type: Literal["url", "message"]
    created_at: datetime
    prediction: Literal["potential_phishing", "no_phishing_detected"]
    risk_score: int = Field(ge=0, le=100)
    risk_category: Literal["low", "medium", "high", "critical"]
    indicators: list[AnalysisIndicatorResponse]
    disclaimer: str
    model_name: str
    model_version: str
    model_confidence: float = Field(ge=0.0, le=1.0, description="Uncalibrated predicted-class score, not a real-world probability.")
    model_info: ModelInfoResponse
    explanation_note: str
    input_excerpt: str | None = None


class ScanRecordResponse(BaseModel):
    id: str
    scan_type: Literal["url", "message"]
    input_excerpt: str
    created_at: datetime
    prediction: Literal["potential_phishing", "no_phishing_detected"]
    risk_score: int = Field(ge=0, le=100)
    risk_category: Literal["low", "medium", "high", "critical"]


class HistoryResponse(BaseModel):
    items: list[ScanRecordResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)


class StatisticsResponse(BaseModel):
    total_scans: int = Field(ge=0)
    phishing_detections: int = Field(ge=0)
    suspicious_results: int = Field(ge=0)
    url_scans: int = Field(ge=0)
    message_scans: int = Field(ge=0)
    last_scan_at: datetime | None = None
