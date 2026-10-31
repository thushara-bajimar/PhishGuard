"""Load a trained artifact and generate URL-only model assessments."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import uuid4

import joblib
import numpy as np
from sklearn.pipeline import Pipeline

from app.ml.url_features import extract_heuristic_indicators

DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "url_phishing_model.joblib"
FEATURE_SCHEMA_VERSION = 2
MODEL_NAME = "PhishGuard URL Random Forest"
DISCLAIMER = (
    "This automated assessment is informational and may be wrong. A low score or 'no phishing detected' "
    "does not guarantee that a URL is safe. Verify the destination independently."
)


class ModelUnavailableError(RuntimeError):
    """Raised when no compatible locally trained model artifact is available."""


@lru_cache(maxsize=4)
def _load_artifact(path_string: str) -> tuple[Pipeline, dict[str, Any]]:
    path = Path(path_string)
    if not path.is_file():
        raise ModelUnavailableError(
            "The URL model is not trained or the artifact is missing. Follow the README training steps to supply a labeled CSV and train it."
        )
    try:
        artifact = joblib.load(path)
    except Exception as error:
        raise ModelUnavailableError("The URL model artifact could not be loaded. Retrain it from a trusted local dataset.") from error
    if not isinstance(artifact, dict) or not isinstance(artifact.get("pipeline"), Pipeline) or not isinstance(artifact.get("metadata"), dict):
        raise ModelUnavailableError("The URL model artifact format is invalid. Retrain the model using the project training command.")
    metadata = artifact["metadata"]
    if metadata.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
        raise ModelUnavailableError("The URL model feature schema is incompatible with this backend. Retrain the model.")
    if 1 not in list(artifact["pipeline"].classes_):
        raise ModelUnavailableError("The model artifact does not contain a phishing class. Retrain it with both labels.")
    return artifact["pipeline"], metadata


class URLPredictionService:
    def __init__(self, model_path: Path | None = None) -> None:
        configured_path = os.environ.get("PHISHGUARD_MODEL_PATH")
        self.model_path = Path(configured_path) if configured_path else (model_path or DEFAULT_MODEL_PATH)

    def analyze(self, url: str) -> dict[str, Any]:
        pipeline, metadata = _load_artifact(str(self.model_path.resolve()))
        try:
            phishing_index = list(pipeline.classes_).index(1)
            probabilities = pipeline.predict_proba([url])[0]
            phishing_probability = float(probabilities[phishing_index])
        except (AttributeError, IndexError, TypeError, ValueError) as error:
            raise ModelUnavailableError("The trained artifact cannot score URLs. Retrain it with this project's training pipeline.") from error

        phishing_probability = float(np.clip(phishing_probability, 0.0, 1.0))
        prediction = "potential_phishing" if phishing_probability >= 0.5 else "no_phishing_detected"
        risk_score = int(round(phishing_probability * 100))
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
            "scan_type": "url",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "prediction": prediction,
            "risk_score": risk_score,
            "risk_category": risk_category,
            "indicators": [
                {**indicator, "source": "heuristic"}
                for indicator in extract_heuristic_indicators(url)
            ],
            "disclaimer": DISCLAIMER,
            "model_name": str(metadata.get("model_name", MODEL_NAME)),
            "model_version": str(metadata.get("trained_at_utc", "unknown")),
            # Random-forest probabilities are not calibrated; this is a score, not a real-world probability.
            "model_confidence": max(phishing_probability, 1.0 - phishing_probability),
            "model_info": {
                "algorithm": metadata.get("algorithm", "RandomForestClassifier"),
                "dataset_source": metadata.get("dataset_source"),
                "dataset_source_url": metadata.get("dataset_source_url"),
                "sklearn_version": metadata.get("sklearn_version"),
                "tldextract_version": metadata.get("tldextract_version"),
                "feature_schema_version": metadata.get("feature_schema_version"),
                "risk_score_note": "Derived from the model's uncalibrated phishing-class score; not a calibrated probability.",
            },
            "explanation_note": "Indicators are independently computed URL heuristics, not explanations or feature attributions from the model.",
        }


def clear_model_cache() -> None:
    """Clear loaded model artifacts (useful when replacing a model during development)."""
    _load_artifact.cache_clear()
