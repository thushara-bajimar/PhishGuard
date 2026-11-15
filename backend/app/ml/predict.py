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
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

from app.ml.url_features import FEATURE_LABELS, FEATURE_NAMES, FEATURE_SCHEMA_VERSION, extract_heuristic_indicators

DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "url_phishing_model.joblib"
MODEL_NAME = "PhishGuard URL Random Forest"
DISCLAIMER = (
    "This automated assessment is informational and may be wrong. A low score or 'no phishing detected' "
    "does not guarantee that a URL is safe. Verify the destination independently."
)
EXPLANATION_METHOD = "Random-forest decision-path contributions (per-prediction, exact decomposition of the score)"
MAX_MODEL_INDICATORS = 4
MIN_CONTRIBUTION = 0.01  # one risk-score point
SCOPE_DESCRIPTIONS = {
    "url": "the full URL",
    "hostname": "the hostname only (scheme, port, path, query and a leading 'www.' are removed before scoring)",
    "registered_domain": "the registered domain only",
}
_RATIO_FEATURES = {"digit_ratio", "host_digit_ratio"}
_BOOLEAN_FEATURES = {
    "fragment_present", "https_present", "ip_address_host", "host_has_punycode",
    "shortener_host", "nonstandard_port", "userinfo_present",
}


class ModelUnavailableError(RuntimeError):
    """Raised when no compatible locally trained model artifact is available."""


class ForestExplainer:
    """Per-prediction feature contributions for a fitted RandomForestClassifier.

    For every tree, the change in the phishing-class probability between a node and the next node
    on the sample's decision path is credited to the feature split at that node. Averaged over the
    forest, ``baseline + sum(contributions)`` equals ``predict_proba`` exactly.
    """

    def __init__(self, forest: RandomForestClassifier, class_index: int) -> None:
        self._trees = []
        for estimator in forest.estimators_:
            tree = estimator.tree_
            values = tree.value[:, 0, :]
            totals = values.sum(axis=1)
            probabilities = np.divide(values[:, class_index], totals, out=np.zeros_like(totals), where=totals > 0)
            self._trees.append((estimator, tree.feature.copy(), probabilities))

    def explain(self, row: np.ndarray) -> tuple[float, np.ndarray]:
        sample = np.asarray(row, dtype=np.float32).reshape(1, -1)
        contributions = np.zeros(sample.shape[1], dtype=np.float64)
        baseline = 0.0
        for estimator, features, probabilities in self._trees:
            path = estimator.decision_path(sample).indices  # node ids increase from root to leaf
            path_probabilities = probabilities[path]
            baseline += float(path_probabilities[0])
            np.add.at(contributions, features[path[:-1]], np.diff(path_probabilities))
        count = len(self._trees)
        return baseline / count, contributions / count


@lru_cache(maxsize=4)
def _load_artifact(path_string: str) -> tuple[Pipeline, dict[str, Any], ForestExplainer | None]:
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
    pipeline = artifact["pipeline"]
    if 1 not in list(pipeline.classes_):
        raise ModelUnavailableError("The model artifact does not contain a phishing class. Retrain it with both labels.")
    classifier = pipeline.steps[-1][1]
    explainer = ForestExplainer(classifier, list(pipeline.classes_).index(1)) if isinstance(classifier, RandomForestClassifier) else None
    return pipeline, metadata, explainer


def feature_matrix(pipeline: Pipeline, urls: list[str]) -> np.ndarray:
    """Apply every pipeline step before the classifier (slicing a Pipeline trips sklearn's fitted check)."""
    values: Any = urls
    for _, step in pipeline.steps[:-1]:
        values = step.transform(values)
    return np.asarray(values, dtype=np.float64)


def _format_feature_value(name: str, value: float) -> str:
    if name in _BOOLEAN_FEATURES:
        return "yes" if value else "no"
    if name in _RATIO_FEATURES:
        return f"{value:.0%}"
    return str(int(value)) if float(value).is_integer() else f"{value:.2f}"


def model_indicators(features: np.ndarray, contributions: np.ndarray) -> list[dict[str, str]]:
    """Turn the strongest per-feature contributions into readable source="model" indicators."""
    order = np.argsort(-np.abs(contributions))
    indicators: list[dict[str, str]] = []
    for index in order[:MAX_MODEL_INDICATORS]:
        contribution = float(contributions[index])
        if abs(contribution) < MIN_CONTRIBUTION:
            break
        name = FEATURE_NAMES[index]
        direction = "raised" if contribution > 0 else "lowered"
        indicators.append({
            "name": f"{FEATURE_LABELS[name]} = {_format_feature_value(name, float(features[index]))}",
            "description": f"This feature {direction} the model's phishing score by {abs(contribution) * 100:.0f} points for this input.",
            "source": "model",
        })
    return indicators


class URLPredictionService:
    def __init__(self, model_path: Path | None = None) -> None:
        configured_path = os.environ.get("PHISHGUARD_MODEL_PATH")
        self.model_path = model_path or (Path(configured_path) if configured_path else DEFAULT_MODEL_PATH)

    def status(self) -> dict[str, Any]:
        """Report whether a compatible artifact loads, without scoring anything."""
        try:
            _, metadata, _ = _load_artifact(str(self.model_path.resolve()))
        except ModelUnavailableError as error:
            return {"available": False, "detail": str(error)}
        return {"available": True, "model_version": str(metadata.get("trained_at_utc", "unknown"))}

    def analyze(self, url: str) -> dict[str, Any]:
        pipeline, metadata, explainer = _load_artifact(str(self.model_path.resolve()))
        try:
            phishing_index = list(pipeline.classes_).index(1)
            features = feature_matrix(pipeline, [url])
            probabilities = pipeline.steps[-1][1].predict_proba(features)[0]
            phishing_probability = float(probabilities[phishing_index])
        except (AttributeError, IndexError, TypeError, ValueError) as error:
            raise ModelUnavailableError("The trained artifact cannot score URLs. Retrain it with this project's training pipeline.") from error

        explanation: list[dict[str, str]] = []
        baseline: float | None = None
        if explainer is not None:
            baseline, contributions = explainer.explain(features[0])
            explanation = model_indicators(features[0], contributions)

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

        input_scope = str(metadata.get("input_scope", "url"))
        explanation_note = (
            f"Model indicators come from the URL model itself: the features of {SCOPE_DESCRIPTIONS.get(input_scope, 'the URL')} "
            "that moved this score most"
            + (f", relative to the model's average training score of {baseline * 100:.0f}/100" if baseline is not None else "")
            + ". Heuristic indicators are separate rule checks on the full URL and are not model explanations."
        )
        return {
            "id": str(uuid4()),
            "scan_type": "url",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "prediction": prediction,
            "risk_score": risk_score,
            "risk_category": risk_category,
            "indicators": explanation + [
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
                "input_scope": input_scope,
                "explanation_method": EXPLANATION_METHOD if explainer is not None else None,
                "scope_note": (
                    "Trained on PhiUSIIL, whose legitimate examples are all 'www.' homepages; legitimate sites on other "
                    "subdomains (for example accounts.example.com) are often over-scored."
                    if input_scope == "hostname" else None
                ),
            },
            "explanation_note": explanation_note,
        }


def clear_model_cache() -> None:
    """Clear loaded model artifacts (useful when replacing a model during development)."""
    _load_artifact.cache_clear()
