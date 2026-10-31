"""Message classification and independent rule-based warning indicators."""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import uuid4

import joblib
import numpy as np
from sklearn.pipeline import Pipeline

DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "message_phishing_model.joblib"
FEATURE_SCHEMA_VERSION = 1
MODEL_NAME = "PhishGuard Message TF-IDF Logistic Regression"
DISCLAIMER = (
    "This automated assessment is informational and may be wrong. A low score or 'no phishing detected' "
    "does not guarantee that a message or linked destination is safe. Verify requests through a trusted channel."
)

URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+|\b[a-z0-9][a-z0-9.-]*\.(?:com|net|org|io|co|uk|ru|cn|info|biz|app|dev)(?:/[^\s<>\"']*)?")
URGENT_PATTERN = re.compile(r"(?i)\b(?:urgent|immediately|act now|asap|final notice|expires? today|within\s+\d+\s+hours?|limited time|without delay)\b")
CREDENTIAL_PATTERN = re.compile(r"(?i)\b(?:password|passcode|one[- ]time code|\botp\b|verify (?:your )?(?:account|identity)|login credentials|security code|sign[ -]?in)\b")
THREAT_PATTERN = re.compile(r"(?i)\b(?:suspend(?:ed)?|terminate(?:d)?|close your account|legal action|arrest|penalt(?:y|ies)|will be disabled|account will be locked|fines?)\b")
PAYMENT_PATTERN = re.compile(r"(?i)\b(?:wire transfer|gift cards?|crypto(?:currency)?|bitcoin|payment due|pay now|bank transfer|claim (?:your )?(?:prize|refund)|processing fee|payment details)\b")


class ModelUnavailableError(RuntimeError):
    """Raised when no compatible locally trained message model is available."""


@lru_cache(maxsize=4)
def _load_artifact(path_string: str) -> tuple[Pipeline, dict[str, Any]]:
    path = Path(path_string)
    if not path.is_file():
        raise ModelUnavailableError(
            "The message model is not trained or the artifact is missing. Follow the README steps to supply a labeled email dataset and train it."
        )
    try:
        artifact = joblib.load(path)
    except Exception as error:
        raise ModelUnavailableError("The message model artifact could not be loaded. Retrain it from a trusted local dataset.") from error
    if not isinstance(artifact, dict) or not isinstance(artifact.get("pipeline"), Pipeline) or not isinstance(artifact.get("metadata"), dict):
        raise ModelUnavailableError("The message model artifact format is invalid. Retrain it using the project training command.")
    if artifact["metadata"].get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
        raise ModelUnavailableError("The message model feature schema is incompatible. Retrain the message model.")
    if 1 not in list(artifact["pipeline"].classes_):
        raise ModelUnavailableError("The message artifact does not contain a phishing class. Retrain it with both labels.")
    return artifact["pipeline"], artifact["metadata"]


def extract_message_indicators(text: str) -> list[dict[str, str]]:
    """Report visible warning patterns independently; not model explanations."""
    indicators: list[dict[str, str]] = []
    checks = (
        (URGENT_PATTERN, "Urgent request", "The message uses urgency or time pressure that can push a recipient to act before verifying."),
        (CREDENTIAL_PATTERN, "Credential or account request", "The message refers to passwords, sign-in, verification, or security codes; do not share these in response to an unsolicited message."),
        (THREAT_PATTERN, "Threatening language", "The message mentions account suspension, penalties, or other consequences that may pressure the recipient."),
        (PAYMENT_PATTERN, "Unusual payment request", "The message refers to a payment method or prize/refund fee often associated with hard-to-reverse transfers."),
    )
    for pattern, name, description in checks:
        if pattern.search(text):
            indicators.append({"name": name, "description": description, "source": "heuristic"})
    links = URL_PATTERN.findall(text)
    if links:
        indicators.append({
            "name": "Link present",
            "description": f"The message contains {len(links)} link-like string(s). Inspect each destination independently; this service does not open or resolve links.",
            "source": "heuristic",
        })
    return indicators


class MessagePredictionService:
    def __init__(self, model_path: Path | None = None) -> None:
        configured_path = os.environ.get("PHISHGUARD_MESSAGE_MODEL_PATH")
        self.model_path = Path(configured_path) if configured_path else (model_path or DEFAULT_MODEL_PATH)

    def analyze(self, text: str) -> dict[str, Any]:
        pipeline, metadata = _load_artifact(str(self.model_path.resolve()))
        try:
            phishing_index = list(pipeline.classes_).index(1)
            phishing_score = float(pipeline.predict_proba([text])[0][phishing_index])
        except (AttributeError, IndexError, TypeError, ValueError) as error:
            raise ModelUnavailableError("The message artifact cannot classify text. Retrain it with this project's message training pipeline.") from error

        phishing_score = float(np.clip(phishing_score, 0.0, 1.0))
        risk_score = int(round(phishing_score * 100))
        if risk_score >= 80:
            risk_category = "critical"
        elif risk_score >= 50:
            risk_category = "high"
        elif risk_score >= 25:
            risk_category = "medium"
        else:
            risk_category = "low"
        return {
            "id": str(uuid4()),
            "scan_type": "message",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "prediction": "potential_phishing" if phishing_score >= 0.5 else "no_phishing_detected",
            "risk_score": risk_score,
            "risk_category": risk_category,
            "indicators": extract_message_indicators(text),
            "disclaimer": DISCLAIMER,
            "model_name": str(metadata.get("model_name", MODEL_NAME)),
            "model_version": str(metadata.get("trained_at_utc", "unknown")),
            # This classifier's scores are not calibrated and must not be interpreted as real-world probability.
            "model_confidence": max(phishing_score, 1.0 - phishing_score),
            "model_info": {
                "algorithm": metadata.get("algorithm", "TfidfVectorizer + LogisticRegression"),
                "dataset_source": metadata.get("dataset_source"),
                "dataset_source_url": metadata.get("dataset_source_url"),
                "sklearn_version": metadata.get("sklearn_version"),
                "feature_schema_version": metadata.get("feature_schema_version"),
                "risk_score_note": "Derived from the model's uncalibrated phishing-class score; not a calibrated probability.",
                "scope_note": "Training source contains email bodies; performance on SMS text has not been evaluated.",
            },
            "explanation_note": "Indicators are independently matched message warning patterns, not explanations or feature attributions from the text classifier.",
        }


def clear_model_cache() -> None:
    _load_artifact.cache_clear()
