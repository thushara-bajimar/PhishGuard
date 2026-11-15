"""Dataset loader robustness: missing values, malformed rows, duplicates and label conflicts.

All CSV rows here are small hand-written fixtures in tmp_path; none are used as training data.
"""

from __future__ import annotations

import csv
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.ml.message_train import CSV_FIELD_SIZE_LIMIT, MAX_TEXT_LENGTH, _near_duplicate_key, _read_dataset
from app.ml.train import load_labeled_urls


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_url_loader_skips_bad_rows_and_reports_counts(tmp_path: Path) -> None:
    csv_path = write(tmp_path / "urls.csv", "\n".join([
        "URL,label",
        "https://www.good-one.com,1",
        "https://www.good-one.com/,1",          # duplicate after trailing-slash normalization
        "HTTPS://WWW.GOOD-ONE.COM,1",           # duplicate after case normalization
        "http://bad-one.xyz/login,0",
        ",0",                                   # missing URL
        "https://missing-label.com,",           # missing label
        "ftp://files.example.com/x,0",          # non-HTTP scheme
        "https://bad-port.com:99999/,0",        # invalid port
        "https://conflict.com,1",
        "https://conflict.com,0",               # same URL, other label -> both dropped
        "https://too,many,fields.com,1",        # extra fields
        "http://another-bad.top/verify,0",
        "https://www.good-two.org,1",
    ]) + "\n")

    urls, labels, groups, report = load_labeled_urls(csv_path, "URL", "label", "0")

    assert urls == ["https://www.good-one.com", "http://bad-one.xyz/login", "http://another-bad.top/verify", "https://www.good-two.org"]
    assert labels == [0, 1, 1, 0]
    assert groups == ["good-one.com", "bad-one.xyz", "another-bad.top", "good-two.org"]
    assert report["rows_read"] == 13
    assert report["rows_skipped"] == {"invalid_or_non_http_url": 2, "malformed_row": 1, "missing_url_or_label": 2}
    assert report["duplicate_rows_removed"] == 2
    assert report["conflicting_label_rows_dropped"] == 2
    assert report["unique_rows"] == 4
    assert report["class_counts"] == {"legitimate": 2, "phishing": 2}


def test_url_loader_rejects_wrong_label_configuration(tmp_path: Path) -> None:
    csv_path = write(tmp_path / "urls.csv", "URL,label\nhttps://a.com,1\nhttps://b.com,0\n")
    with pytest.raises(ValueError, match="not present"):
        load_labeled_urls(csv_path, "URL", "label", "phishing")
    with pytest.raises(ValueError, match="must contain columns"):
        load_labeled_urls(csv_path, "link", "label", "0")


def test_message_loader_skips_placeholders_dedupes_and_drops_conflicts(tmp_path: Path) -> None:
    long_body = "x" * 100_001
    csv_path = write(tmp_path / "messages.csv", "\n".join([
        ",Email Text,Email Type",
        '0,"Your account is locked, verify now",Phishing Email',
        '1,"your   ACCOUNT is locked, verify now",Phishing Email',   # exact duplicate after normalization
        "2,empty,Safe Email",                                       # placeholder text
        "3,,Safe Email",                                            # missing text
        "4,Lunch at noon?,",                                        # missing label
        f"5,{long_body},Safe Email",                                # too long
        "6,Quarterly report attached,Safe Email",
        "7,Quarterly report attached,Phishing Email",               # conflicting label -> both dropped
        "8,Meeting moved to Friday,Safe Email",
    ]) + "\n")

    texts, labels, groups, report = _read_dataset(csv_path, "Email Text", "Email Type", "Phishing Email")

    assert texts == ["Your account is locked, verify now", "Meeting moved to Friday"]
    assert labels == [1, 0]
    assert len(set(groups)) == 2
    assert report["rows_skipped"] == {"missing_label": 1, "missing_text": 2, "text_too_long": 1}
    assert report["duplicate_rows_removed"] == 1
    assert report["conflicting_label_rows_dropped"] == 2
    assert report["class_counts"] == {"legitimate": 1, "phishing": 1}


def test_near_duplicate_key_groups_templated_variants() -> None:
    first = "Dear user, invoice 4481 is overdue. Pay at https://pay.example/a1"
    second = "dear user  invoice 9920 is overdue! pay at http://other.example/zz"
    assert _near_duplicate_key(first) == _near_duplicate_key(second)
    assert _near_duplicate_key(first) != _near_duplicate_key("Team lunch is on Friday")


@pytest.fixture
def default_csv_field_limit() -> Iterator[None]:
    """Start from the csv module's stock limit so the loader must raise it itself."""
    previous = csv.field_size_limit(128 * 1024)
    yield
    csv.field_size_limit(previous)


def test_message_loader_reads_fields_larger_than_16_mib(tmp_path: Path, default_csv_field_limit: None) -> None:
    # Mirrors the real Kaggle file, whose record 12501 holds a ~17 MB field (above the old 16 MiB cap).
    huge_body = "spam " * (17 * 1024 * 1024 // 5)
    csv_path = tmp_path / "large-field.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["", "Email Text", "Email Type"])
        writer.writerow([0, "Your account is locked, verify now", "Phishing Email"])
        writer.writerow([1, huge_body, "Safe Email"])
        writer.writerow([2, "Meeting moved to Friday", "Safe Email"])

    texts, labels, _, report = _read_dataset(csv_path, "Email Text", "Email Type", "Phishing Email")

    assert csv.field_size_limit() >= CSV_FIELD_SIZE_LIMIT > len(huge_body) > 16 * 1024 * 1024
    assert report["rows_read"] == 3  # parsing continues past the large field
    # The existing per-message length rule (not truncation) decides whether it is used for training.
    assert len(huge_body) > MAX_TEXT_LENGTH and report["rows_skipped"] == {"text_too_long": 1}
    assert texts == ["Your account is locked, verify now", "Meeting moved to Friday"]
    assert labels == [1, 0]


def test_message_loader_keeps_long_bodies_within_the_length_rule_intact(tmp_path: Path, default_csv_field_limit: None) -> None:
    body = "Dear customer, " + "x" * (MAX_TEXT_LENGTH - 20) + " end"  # just under MAX_TEXT_LENGTH
    csv_path = tmp_path / "long-body.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Email Text", "Email Type"])
        writer.writerow([body, "Phishing Email"])
        writer.writerow(["Meeting moved to Friday", "Safe Email"])

    texts, _, _, report = _read_dataset(csv_path, "Email Text", "Email Type", "Phishing Email")

    assert texts[0] == body  # read verbatim, not truncated
    assert report["rows_skipped_total"] == 0
