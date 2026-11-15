"""Train and evaluate the URL classifier from a user-supplied labeled CSV."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlsplit

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier
import tldextract

from app.ml.url_features import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    INPUT_SCOPES,
    URLFeatureTransformer,
    URLScopeTransformer,
    scope_url,
)

DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "url_phishing_model.joblib"
DEFAULT_INPUT_SCOPE = "hostname"
DATASET_SOURCE = "UCI Machine Learning Repository: PhiUSIIL Phishing URL (Website), dataset 967"
DATASET_SOURCE_URL = "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset"
MAX_URL_LENGTH = 4096
_DOMAIN_EXTRACTOR = tldextract.TLDExtract(cache_dir=False, suffix_list_urls=())


def _host_group(url: str) -> str:
    value = url.strip()
    if "://" not in value and not value.startswith("//"):
        value = f"//{value}"
    host = (urlsplit(value).hostname or "").lower().rstrip(".")
    extracted = _DOMAIN_EXTRACTOR(host)
    return extracted.top_domain_under_public_suffix or host


def _normalized_url_key(url: str) -> str | None:
    """Return a duplicate-detection key, or None when the URL cannot be analyzed."""
    try:
        parts = urlsplit(url if "://" in url or url.startswith("//") else f"//{url}")
        port = parts.port
    except ValueError:
        return None
    if parts.scheme and parts.scheme.lower() not in {"http", "https"}:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return None
    scheme = parts.scheme.lower() or "bare"
    return f"{scheme}://{host}:{port or ''}{parts.path.rstrip('/') or '/'}?{parts.query}"


def _deduplicate(keys: Sequence[str], labels: Sequence[str]) -> tuple[list[int], int, int]:
    """Keep the first row per key; drop every row of a key that carries conflicting labels.

    Returns (kept indices in input order, duplicate rows removed, conflicting rows dropped).
    """
    label_sets: dict[str, set[str]] = {}
    for key, label in zip(keys, labels, strict=True):
        label_sets.setdefault(key, set()).add(label)
    kept: list[int] = []
    seen: set[str] = set()
    duplicates = conflicts = 0
    for index, key in enumerate(keys):
        if len(label_sets[key]) > 1:
            conflicts += 1
        elif key in seen:
            duplicates += 1
        else:
            seen.add(key)
            kept.append(index)
    return kept, duplicates, conflicts


def load_labeled_urls(
    csv_path: Path,
    url_column: str,
    label_column: str,
    phishing_label: str,
) -> tuple[list[str], list[int], list[str], dict[str, Any]]:
    """Read a two-class URL CSV, skipping unusable rows and reporting every filtering decision.

    Rows are skipped (not fatal) when the URL or label is missing, the row has the wrong number
    of fields, the URL is longer than 4096 characters, or the URL is not a parseable HTTP(S)
    address. Exact duplicates (after normalizing scheme/host case, trailing slash and default
    port) keep their first occurrence. When the same normalized URL appears with different labels,
    every copy is dropped because the correct label cannot be determined.
    """
    if not csv_path.is_file():
        raise FileNotFoundError(f"Dataset CSV not found: {csv_path}")

    skipped: Counter[str] = Counter()
    candidate_urls: list[str] = []
    candidate_labels: list[str] = []
    candidate_keys: list[str] = []
    rows_read = 0

    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or url_column not in reader.fieldnames or label_column not in reader.fieldnames:
            raise ValueError(
                f"CSV must contain columns {url_column!r} and {label_column!r}; "
                f"found {reader.fieldnames!r}."
            )
        for row in reader:
            rows_read += 1
            if None in row or any(value is None for value in row.values()):
                skipped["malformed_row"] += 1
                continue
            url = row[url_column].strip()
            label = row[label_column].strip()
            if not url or not label:
                skipped["missing_url_or_label"] += 1
                continue
            if len(url) > MAX_URL_LENGTH:
                skipped["url_too_long"] += 1
                continue
            key = _normalized_url_key(url)
            if key is None:
                skipped["invalid_or_non_http_url"] += 1
                continue
            candidate_urls.append(url)
            candidate_labels.append(label)
            candidate_keys.append(key)

    raw_labels = set(candidate_labels)
    if len(raw_labels) != 2:
        raise ValueError(f"Expected exactly 2 distinct labels among valid rows, found {sorted(raw_labels)!r}.")
    if phishing_label not in raw_labels:
        raise ValueError(f"Phishing label {phishing_label!r} is not present in the CSV labels {sorted(raw_labels)!r}.")

    kept, duplicates, conflicts = _deduplicate(candidate_keys, candidate_labels)
    urls = [candidate_urls[index] for index in kept]
    labels = [1 if candidate_labels[index] == phishing_label else 0 for index in kept]
    if len(set(labels)) != 2:
        raise ValueError("Both phishing and legitimate examples must remain after filtering.")

    report: dict[str, Any] = {
        "rows_read": rows_read,
        "rows_skipped": dict(sorted(skipped.items())),
        "rows_skipped_total": sum(skipped.values()),
        "duplicate_rows_removed": duplicates,
        "conflicting_label_rows_dropped": conflicts,
        "unique_rows": len(urls),
        "class_counts": {"legitimate": labels.count(0), "phishing": labels.count(1)},
    }
    return urls, labels, [_host_group(url) for url in urls], report


def _shortcut_diagnostics(urls: Sequence[str], labels: Sequence[int], train_indices, test_indices) -> dict[str, Any]:
    """Measure how separable the classes are using only scheme/www/path surface traits."""
    def traits(url: str) -> list[float]:
        parts = urlsplit(url if "://" in url or url.startswith("//") else f"//{url}")
        host = (parts.hostname or "").lower()
        return [float(parts.scheme.lower() == "https"), float(host.startswith("www.")), float(parts.path.strip("/") != "")]

    matrix = np.asarray([traits(url) for url in urls])
    y = np.asarray(labels)
    rates = {
        name: {
            "legitimate": round(float(matrix[y == 0, column].mean()), 4),
            "phishing": round(float(matrix[y == 1, column].mean()), 4),
        }
        for column, name in enumerate(("https_scheme", "www_prefix", "non_empty_path"))
    }
    baseline = DecisionTreeClassifier(max_depth=3, random_state=0).fit(matrix[train_indices], y[train_indices])
    predicted = baseline.predict(matrix[test_indices])
    return {
        "class_trait_rates": rates,
        "shortcut_only_baseline": {
            "description": "Depth-3 decision tree on (https scheme, www prefix, non-empty path) only, same split.",
            "accuracy": float(accuracy_score(y[test_indices], predicted)),
            "f1_phishing": float(f1_score(y[test_indices], predicted, pos_label=1, zero_division=0)),
        },
    }


def train_model(
    csv_path: Path,
    model_path: Path,
    url_column: str,
    label_column: str,
    phishing_label: str,
    random_state: int = 42,
    input_scope: str = DEFAULT_INPUT_SCOPE,
) -> dict[str, object]:
    if input_scope not in INPUT_SCOPES:
        raise ValueError(f"input_scope must be one of {INPUT_SCOPES}.")
    loaded_urls, loaded_labels, _, loader_report = load_labeled_urls(csv_path, url_column, label_column, phishing_label)

    # Deduplicate again on exactly what the model sees, so the split cannot leak identical inputs.
    scoped = [scope_url(url, input_scope) for url in loaded_urls]
    kept, scope_duplicates, scope_conflicts = _deduplicate(scoped, [str(label) for label in loaded_labels])
    urls = [loaded_urls[index] for index in kept]
    labels = [loaded_labels[index] for index in kept]
    groups = [_host_group(url) for url in urls]
    if len(set(labels)) != 2:
        raise ValueError("Both classes must remain after input-scope deduplication.")

    unique_groups = len(set(groups))
    positive_groups = len({group for group, label in zip(groups, labels, strict=True) if label == 1})
    negative_groups = len({group for group, label in zip(groups, labels, strict=True) if label == 0})
    if unique_groups < 5 or positive_groups < 2 or negative_groups < 2:
        raise ValueError(
            "At least 5 unique host groups and at least 2 groups per class are required "
            "for a leakage-resistant 5-fold split."
        )

    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=random_state)
    train_indices, test_indices = next(splitter.split(urls, labels, groups))
    y_train = [labels[index] for index in train_indices]
    y_test = [labels[index] for index in test_indices]
    if len(set(y_train)) != 2 or len(set(y_test)) != 2:
        raise ValueError("The host-wise split does not contain both classes in train and test. Supply a larger, more diverse dataset.")

    pipeline = Pipeline(
        steps=[
            ("input_scope", URLScopeTransformer(scope=input_scope)),
            ("url_features", URLFeatureTransformer()),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=400,
                    max_features="sqrt",
                    min_samples_leaf=2,
                    class_weight="balanced_subsample",
                    random_state=random_state,
                    n_jobs=-1,
                ),
            ),
        ]
    )
    x_train = [urls[index] for index in train_indices]
    x_test = [urls[index] for index in test_indices]
    pipeline.fit(x_train, y_train)
    predictions = pipeline.predict(x_test)
    probabilities = pipeline.predict_proba(x_test)[:, list(pipeline.classes_).index(1)]
    forest = pipeline.named_steps["classifier"]
    importances = sorted(zip(FEATURE_NAMES, forest.feature_importances_), key=lambda item: item[1], reverse=True)

    matrix = confusion_matrix(y_test, predictions, labels=[0, 1]).tolist()
    metrics: dict[str, object] = {
        "model_name": "PhishGuard URL Random Forest",
        "algorithm": "RandomForestClassifier",
        "random_state": random_state,
        "input_scope": input_scope,
        "dataset_source": DATASET_SOURCE,
        "dataset_source_url": DATASET_SOURCE_URL,
        "dataset_sha256": _sha256(csv_path),
        "url_column": url_column,
        "label_column": label_column,
        "phishing_label_value": phishing_label,
        "label_mapping": {"legitimate": 0, "phishing": 1},
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "sklearn_version": sklearn.__version__,
        "tldextract_version": tldextract.__version__,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "rows": {
            **loader_report,
            "input_scope_duplicate_rows_removed": scope_duplicates,
            "input_scope_conflicting_rows_dropped": scope_conflicts,
            "rows_used_for_training_and_evaluation": len(urls),
        },
        "split": "StratifiedGroupKFold(n_splits=5) first fold, grouped by registered domain (80/20 holdout)",
        "train_rows": len(train_indices),
        "test_rows": len(test_indices),
        "train_host_groups": len({groups[index] for index in train_indices}),
        "test_host_groups": len({groups[index] for index in test_indices}),
        "host_overlap": len({groups[index] for index in train_indices} & {groups[index] for index in test_indices}),
        "phishing_probability_mean_test": float(np.mean(probabilities)),
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision_phishing": float(precision_score(y_test, predictions, pos_label=1, zero_division=0)),
        "recall_phishing": float(recall_score(y_test, predictions, pos_label=1, zero_division=0)),
        "f1_phishing": float(f1_score(y_test, predictions, pos_label=1, zero_division=0)),
        "confusion_matrix_labels": ["legitimate", "phishing"],
        "confusion_matrix": matrix,
        "feature_importances": {name: round(float(value), 5) for name, value in importances},
        "shortcut_diagnostics": _shortcut_diagnostics(urls, labels, train_indices, test_indices),
    }

    model_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_model_path = model_path.with_suffix(model_path.suffix + ".tmp")
    joblib.dump({"pipeline": pipeline, "metadata": metrics}, temporary_model_path)
    temporary_model_path.replace(model_path)
    model_path.with_suffix(".metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    return metrics


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train and evaluate the PhishGuard URL model from a labeled CSV.")
    parser.add_argument("--data", type=Path, required=True, help="Path to the downloaded labeled CSV dataset.")
    parser.add_argument("--url-column", default="URL", help="CSV URL column name (default: URL).")
    parser.add_argument("--label-column", default="label", help="CSV target column name (default: label).")
    parser.add_argument("--phishing-label", required=True, help="Exact label value representing phishing (UCI PhiUSIIL uses 0).")
    parser.add_argument("--output", type=Path, default=DEFAULT_MODEL_PATH, help=f"Model artifact path (default: {DEFAULT_MODEL_PATH}).")
    parser.add_argument("--random-state", type=int, default=42, help="Seed for a reproducible host-group split and forest.")
    parser.add_argument(
        "--input-scope",
        choices=INPUT_SCOPES,
        default=DEFAULT_INPUT_SCOPE,
        help="Part of the URL the model sees (default: hostname). 'url' lets the model use scheme/path, "
        "which are label shortcuts in PhiUSIIL; see README.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        metrics = train_model(
            args.data, args.output, args.url_column, args.label_column, args.phishing_label, args.random_state, args.input_scope
        )
    except (OSError, ValueError, csv.Error) as error:
        print(f"Training failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"artifact": str(args.output.resolve()), **metrics}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
