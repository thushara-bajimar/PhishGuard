"""Train/evaluate the message classifier from a labeled email-text CSV."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

import joblib
import numpy as np
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline

DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "message_phishing_model.joblib"
DATASET_SOURCE = "Kaggle: Phishing Email Detection by subhajournal, Phishing_Email.csv"
DATASET_SOURCE_URL = "https://www.kaggle.com/datasets/subhajournal/phishingemails"
FEATURE_SCHEMA_VERSION = 1


def _normalize_text(text: str) -> str:
    return " ".join(text.casefold().split())


def _read_dataset(csv_path: Path, text_column: str, label_column: str, phishing_label: str):
    if not csv_path.is_file():
        raise FileNotFoundError(f"Dataset CSV not found: {csv_path}")
    texts: list[str] = []
    labels: list[int] = []
    groups: list[str] = []
    raw_labels: set[str] = set()
    seen_text: dict[str, str] = {}
    duplicates_removed = 0

    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or text_column not in reader.fieldnames or label_column not in reader.fieldnames:
            raise ValueError(f"CSV must contain columns {text_column!r} and {label_column!r}; found {reader.fieldnames!r}.")
        for row_number, row in enumerate(reader, start=2):
            text = (row.get(text_column) or "").strip()
            label = (row.get(label_column) or "").strip()
            if not text or not label:
                raise ValueError(f"CSV row {row_number} has empty message text or label.")
            if len(text) > 100_000:
                raise ValueError(f"CSV row {row_number} text exceeds 100,000 characters.")
            raw_labels.add(label)
            normalized = _normalize_text(text)
            digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
            if digest in seen_text:
                if seen_text[digest] != label:
                    raise ValueError(f"CSV row {row_number} has a conflicting label for duplicate normalized text.")
                duplicates_removed += 1
                continue
            seen_text[digest] = label
            texts.append(text)
            labels.append(1 if label == phishing_label else 0)
            groups.append(digest)

    if len(raw_labels) != 2:
        raise ValueError(f"Expected exactly 2 distinct labels, found {sorted(raw_labels)!r}.")
    if phishing_label not in raw_labels:
        raise ValueError(f"Phishing label {phishing_label!r} is not present in the dataset labels {sorted(raw_labels)!r}.")
    if len(set(labels)) != 2:
        raise ValueError("Both phishing and legitimate examples must remain after duplicate removal.")
    return texts, labels, groups, {"unique_rows": len(texts), "duplicate_rows_removed": duplicates_removed}


def train_model(
    csv_path: Path,
    model_path: Path,
    text_column: str,
    label_column: str,
    phishing_label: str,
    random_state: int = 42,
) -> dict[str, object]:
    texts, labels, groups, dataset_counts = _read_dataset(csv_path, text_column, label_column, phishing_label)
    if len(set(groups)) < 5 or min(sum(labels), len(labels) - sum(labels)) < 2:
        raise ValueError("At least 5 unique messages and at least 2 examples from each class are required for a grouped 5-fold split.")

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
        "rows": dataset_counts,
        "train_rows": len(train_indices),
        "test_rows": len(test_indices),
        "train_groups": len({groups[index] for index in train_indices}),
        "test_groups": len({groups[index] for index in test_indices}),
        "group_overlap": len({groups[index] for index in train_indices} & {groups[index] for index in test_indices}),
        "precision_phishing": float(precision_score(y_test, predicted, pos_label=1, zero_division=0)),
        "recall_phishing": float(recall_score(y_test, predicted, pos_label=1, zero_division=0)),
        "f1_phishing": float(f1_score(y_test, predicted, pos_label=1, zero_division=0)),
        "confusion_matrix_labels": ["legitimate", "phishing"],
        "confusion_matrix": matrix,
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
