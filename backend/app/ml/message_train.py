"""Train/evaluate the message classifier from a labeled email-text CSV."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline

DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "message_phishing_model.joblib"
DATASET_SOURCE = "Kaggle: Phishing Email Detection by subhajournal, Phishing_Email.csv"
DATASET_SOURCE_URL = "https://www.kaggle.com/datasets/subhajournal/phishingemails"
FEATURE_SCHEMA_VERSION = 1
MAX_TEXT_LENGTH = 100_000
# Placeholder strings some public CSV exports use for an absent message body.
MISSING_TEXT_MARKERS = frozenset({"empty", "nan", "none", "null"})

_NEAR_DUPLICATE_URL = re.compile(r"(?i)\b(?:https?://|www\.)\S+")
_NEAR_DUPLICATE_DIGITS = re.compile(r"\d+")
_NEAR_DUPLICATE_NON_WORD = re.compile(r"[^\w]+")


def _normalize_text(text: str) -> str:
    return " ".join(text.casefold().split())


def _near_duplicate_key(text: str) -> str:
    """Group key that collapses templated variants (different links, numbers or punctuation)."""
    value = _NEAR_DUPLICATE_URL.sub(" url ", text.casefold())
    value = _NEAR_DUPLICATE_DIGITS.sub("0", value)
    value = " ".join(_NEAR_DUPLICATE_NON_WORD.sub(" ", value).split())
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _read_dataset(
    csv_path: Path, text_column: str, label_column: str, phishing_label: str
) -> tuple[list[str], list[int], list[str], dict[str, Any]]:
    """Load labeled messages, skipping unusable rows and reporting each filtering decision.

    Skipped rows: wrong field count, empty/placeholder text ("empty", "nan", ...), missing label,
    or text over 100,000 characters. Exact duplicates (after case/whitespace normalization) keep
    the first copy; texts that appear with conflicting labels are dropped entirely. Remaining
    messages are grouped by a near-duplicate key so templated variants stay in one split side.
    """
    if not csv_path.is_file():
        raise FileNotFoundError(f"Dataset CSV not found: {csv_path}")
    # Email bodies can exceed the csv module's 128 KiB default field limit.
    csv.field_size_limit(max(csv.field_size_limit(), 16 * 1024 * 1024))

    skipped: Counter[str] = Counter()
    texts: list[str] = []
    raw_label_values: list[str] = []
    exact_keys: list[str] = []
    rows_read = 0

    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or text_column not in reader.fieldnames or label_column not in reader.fieldnames:
            raise ValueError(f"CSV must contain columns {text_column!r} and {label_column!r}; found {reader.fieldnames!r}.")
        for row in reader:
            rows_read += 1
            if None in row or row.get(text_column) is None or row.get(label_column) is None:
                skipped["malformed_row"] += 1
                continue
            text = row[text_column].strip()
            label = row[label_column].strip()
            if not text or text.casefold() in MISSING_TEXT_MARKERS:
                skipped["missing_text"] += 1
                continue
            if not label:
                skipped["missing_label"] += 1
                continue
            if len(text) > MAX_TEXT_LENGTH:
                skipped["text_too_long"] += 1
                continue
            texts.append(text)
            raw_label_values.append(label)
            exact_keys.append(hashlib.sha256(_normalize_text(text).encode("utf-8")).hexdigest())

    raw_labels = set(raw_label_values)
    if len(raw_labels) != 2:
        raise ValueError(f"Expected exactly 2 distinct labels among valid rows, found {sorted(raw_labels)!r}.")
    if phishing_label not in raw_labels:
        raise ValueError(f"Phishing label {phishing_label!r} is not present in the dataset labels {sorted(raw_labels)!r}.")

    label_sets: dict[str, set[str]] = {}
    for key, label in zip(exact_keys, raw_label_values, strict=True):
        label_sets.setdefault(key, set()).add(label)
    kept_texts: list[str] = []
    labels: list[int] = []
    seen: set[str] = set()
    duplicates = conflicts = 0
    for text, label, key in zip(texts, raw_label_values, exact_keys, strict=True):
        if len(label_sets[key]) > 1:
            conflicts += 1
        elif key in seen:
            duplicates += 1
        else:
            seen.add(key)
            kept_texts.append(text)
            labels.append(1 if label == phishing_label else 0)
    if len(set(labels)) != 2:
        raise ValueError("Both phishing and legitimate examples must remain after filtering.")

    groups = [_near_duplicate_key(text) for text in kept_texts]
    report: dict[str, Any] = {
        "rows_read": rows_read,
        "rows_skipped": dict(sorted(skipped.items())),
        "rows_skipped_total": sum(skipped.values()),
        "duplicate_rows_removed": duplicates,
        "conflicting_label_rows_dropped": conflicts,
        "unique_rows": len(kept_texts),
        "near_duplicate_groups": len(set(groups)),
        "class_counts": {"legitimate": labels.count(0), "phishing": labels.count(1)},
    }
    return kept_texts, labels, groups, report


def _top_terms(pipeline: Pipeline, count: int = 20) -> dict[str, list[dict[str, float]]]:
    names = pipeline.named_steps["tfidf"].get_feature_names_out()
    coefficients = pipeline.named_steps["classifier"].coef_[0]
    order = np.argsort(coefficients)
    return {
        "toward_phishing": [{"term": str(names[i]), "coefficient": round(float(coefficients[i]), 4)} for i in order[::-1][:count]],
        "toward_legitimate": [{"term": str(names[i]), "coefficient": round(float(coefficients[i]), 4)} for i in order[:count]],
    }


def train_model(
    csv_path: Path,
    model_path: Path,
    text_column: str,
    label_column: str,
    phishing_label: str,
    random_state: int = 42,
) -> dict[str, object]:
    texts, labels, groups, dataset_report = _read_dataset(csv_path, text_column, label_column, phishing_label)
    if len(set(groups)) < 5 or min(sum(labels), len(labels) - sum(labels)) < 2:
        raise ValueError("At least 5 near-duplicate groups and at least 2 examples from each class are required for a grouped 5-fold split.")

    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=random_state)
    train_indices, test_indices = next(splitter.split(texts, labels, groups))
    y_train = [labels[index] for index in train_indices]
    y_test = [labels[index] for index in test_indices]
    if len(set(y_train)) != 2 or len(set(y_test)) != 2:
        raise ValueError("Grouped split lacks one class in train or test. Supply more unique examples from both classes.")

    pipeline = Pipeline(
        steps=[
            ("tfidf", TfidfVectorizer(
                lowercase=True,
                strip_accents="unicode",
                ngram_range=(1, 2),
                min_df=2,
                max_df=0.98,
                sublinear_tf=True,
                max_features=250_000,
                dtype=np.float32,
            )),
            ("classifier", LogisticRegression(
                class_weight="balanced",
                max_iter=1000,
                solver="liblinear",
                random_state=random_state,
            )),
        ]
    )
    x_train = [texts[index] for index in train_indices]
    x_test = [texts[index] for index in test_indices]
    pipeline.fit(x_train, y_train)
    predicted = pipeline.predict(x_test)
    matrix = confusion_matrix(y_test, predicted, labels=[0, 1]).tolist()
    metrics: dict[str, object] = {
        "model_name": "PhishGuard Message TF-IDF Logistic Regression",
        "algorithm": "TfidfVectorizer + LogisticRegression",
        "random_state": random_state,
        "dataset_source": DATASET_SOURCE,
        "dataset_source_url": DATASET_SOURCE_URL,
        "dataset_sha256": _sha256(csv_path),
        "text_column": text_column,
        "label_column": label_column,
        "phishing_label_value": phishing_label,
        "label_mapping": {"legitimate": 0, "phishing": 1},
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "sklearn_version": sklearn.__version__,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "rows": dataset_report,
        "split": "StratifiedGroupKFold(n_splits=5) first fold, grouped by near-duplicate text key (80/20 holdout)",
        "train_rows": len(train_indices),
        "test_rows": len(test_indices),
        "train_groups": len({groups[index] for index in train_indices}),
        "test_groups": len({groups[index] for index in test_indices}),
        "group_overlap": len({groups[index] for index in train_indices} & {groups[index] for index in test_indices}),
        "vocabulary_size": len(pipeline.named_steps["tfidf"].vocabulary_),
        "accuracy": float(accuracy_score(y_test, predicted)),
        "precision_phishing": float(precision_score(y_test, predicted, pos_label=1, zero_division=0)),
        "recall_phishing": float(recall_score(y_test, predicted, pos_label=1, zero_division=0)),
        "f1_phishing": float(f1_score(y_test, predicted, pos_label=1, zero_division=0)),
        "confusion_matrix_labels": ["legitimate", "phishing"],
        "confusion_matrix": matrix,
        "top_terms": _top_terms(pipeline),
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train/evaluate PhishGuard's TF-IDF message classifier from labeled CSV data.")
    parser.add_argument("--data", type=Path, required=True, help="Path to the downloaded email-text CSV.")
    parser.add_argument("--text-column", default="Email Text", help="CSV message-text column (Kaggle dataset: Email Text).")
    parser.add_argument("--label-column", default="Email Type", help="CSV label column (Kaggle dataset: Email Type).")
    parser.add_argument("--phishing-label", default="Phishing Email", help="Exact label value representing phishing.")
    parser.add_argument("--output", type=Path, default=DEFAULT_MODEL_PATH, help=f"Output artifact path (default: {DEFAULT_MODEL_PATH}).")
    parser.add_argument("--random-state", type=int, default=42)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = train_model(args.data, args.output, args.text_column, args.label_column, args.phishing_label, args.random_state)
    except (OSError, ValueError, csv.Error) as error:
        print(f"Training failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"artifact": str(args.output.resolve()), **result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
