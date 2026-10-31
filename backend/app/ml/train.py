"""Train and evaluate the URL classifier from a user-supplied labeled CSV."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence
from urllib.parse import urlsplit

import joblib
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
import tldextract

from app.ml.url_features import FEATURE_NAMES, URLFeatureTransformer

DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "url_phishing_model.joblib"
DATASET_SOURCE = "UCI Machine Learning Repository: PhiUSIIL Phishing URL (Website), dataset 967"
DATASET_SOURCE_URL = "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset"
_DOMAIN_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


def _host_group(url: str) -> str:
    value = url.strip()
    if "://" not in value and not value.startswith("//"):
        value = f"//{value}"
    host = (urlsplit(value).hostname or "").lower().rstrip(".")
    extracted = _DOMAIN_EXTRACTOR(host)
    return extracted.top_domain_under_public_suffix or host


def load_labeled_urls(
    csv_path: Path,
    url_column: str,
    label_column: str,
    phishing_label: str,
) -> tuple[list[str], list[int], list[str], dict[str, int]]:
    """Read a two-class CSV and map its explicitly named phishing label to 1."""
    if not csv_path.is_file():
        raise FileNotFoundError(f"Dataset CSV not found: {csv_path}")

    urls: list[str] = []
    labels: list[int] = []
    groups: list[str] = []
    seen: dict[str, str] = {}
    raw_labels: set[str] = set()
    dropped_duplicates = 0

    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or url_column not in reader.fieldnames or label_column not in reader.fieldnames:
            raise ValueError(
                f"CSV must contain columns {url_column!r} and {label_column!r}; "
                f"found {reader.fieldnames!r}."
            )
        for line_number, row in enumerate(reader, start=2):
            url = (row.get(url_column) or "").strip()
            label = (row.get(label_column) or "").strip()
            if not url or not label:
                raise ValueError(f"CSV row {line_number} has an empty URL or label.")
            if len(url) > 4096:
                raise ValueError(f"CSV row {line_number} URL exceeds 4096 characters.")
            raw_labels.add(label)
            group = _host_group(url)
            if not group:
                raise ValueError(f"CSV row {line_number} has no parseable hostname.")
            # Keep scheme variants and duplicate paths for one normalized URL in one record.
            parts = urlsplit(url if "://" in url else f"//{url}")
            try:
                port = parts.port
            except ValueError as error:
                raise ValueError(f"CSV row {line_number} has an invalid URL port.") from error
            if parts.scheme and parts.scheme.lower() not in {"http", "https"}:
                raise ValueError(f"CSV row {line_number} is not an HTTP(S) URL.")
            host = (parts.hostname or "").lower().rstrip(".")
            if not host:
                raise ValueError(f"CSV row {line_number} has no parseable hostname.")
            scheme = parts.scheme.lower() or "bare"
            normalized = f"{scheme}://{host}:{port or ''}{parts.path.rstrip('/') or '/'}?{parts.query}"
            if normalized in seen:
                if seen[normalized] != label:
                    raise ValueError(f"CSV row {line_number} conflicts with the label for a duplicate URL.")
                dropped_duplicates += 1
                continue
            seen[normalized] = label
            urls.append(url)
            labels.append(1 if label == phishing_label else 0)
            groups.append(group)

    if len(raw_labels) != 2:
        raise ValueError(f"Expected exactly 2 distinct labels, found {sorted(raw_labels)!r}.")
    if phishing_label not in raw_labels:
        raise ValueError(f"Phishing label {phishing_label!r} is not present in the CSV labels {sorted(raw_labels)!r}.")
    if len(set(labels)) != 2:
        raise ValueError("Both phishing and legitimate examples must remain after duplicate removal.")

    return urls, labels, groups, {"unique_rows": len(urls), "duplicate_rows_removed": dropped_duplicates}


def train_model(
    csv_path: Path,
    model_path: Path,
    url_column: str,
    label_column: str,
    phishing_label: str,
    random_state: int = 42,
) -> dict[str, object]:
    urls, labels, groups, dataset_counts = load_labeled_urls(csv_path, url_column, label_column, phishing_label)
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

    matrix = confusion_matrix(y_test, predictions, labels=[0, 1]).tolist()
    metrics: dict[str, object] = {
        "model_name": "PhishGuard URL Random Forest",
        "algorithm": "RandomForestClassifier",
        "random_state": random_state,
        "dataset_source": DATASET_SOURCE,
        "dataset_source_url": DATASET_SOURCE_URL,
        "dataset_sha256": _sha256(csv_path),
        "url_column": url_column,
        "label_column": label_column,
        "phishing_label_value": phishing_label,
        "label_mapping": {"legitimate": 0, "phishing": 1},
        "feature_schema_version": 2,
        "feature_names": list(FEATURE_NAMES),
        "sklearn_version": sklearn.__version__,
        "tldextract_version": tldextract.__version__,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "rows": dataset_counts,
        "train_rows": len(train_indices),
        "test_rows": len(test_indices),
        "train_host_groups": len({groups[index] for index in train_indices}),
        "test_host_groups": len({groups[index] for index in test_indices}),
        "host_overlap": len({groups[index] for index in train_indices} & {groups[index] for index in test_indices}),
        "phishing_probability_mean_test": float(sum(float(p) for p in probabilities) / len(probabilities)),
        "precision_phishing": float(precision_score(y_test, predictions, pos_label=1, zero_division=0)),
        "recall_phishing": float(recall_score(y_test, predictions, pos_label=1, zero_division=0)),
        "f1_phishing": float(f1_score(y_test, predictions, pos_label=1, zero_division=0)),
        "confusion_matrix_labels": ["legitimate", "phishing"],
        "confusion_matrix": matrix,
    }

    model_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_model_path = model_path.with_suffix(model_path.suffix + ".tmp")
    temporary_metrics_path = model_path.with_suffix(".metrics.json")
    joblib.dump({"pipeline": pipeline, "metadata": metrics}, temporary_model_path)
    temporary_model_path.replace(model_path)
    temporary_metrics_path.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        metrics = train_model(args.data, args.output, args.url_column, args.label_column, args.phishing_label, args.random_state)
    except (OSError, ValueError, csv.Error) as error:
        print(f"Training failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"artifact": str(args.output.resolve()), **metrics}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
