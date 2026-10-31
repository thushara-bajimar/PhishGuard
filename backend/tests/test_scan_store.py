from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest

from app.services.scan_store import ScanStore, redact_message, redact_url


def sample_result(scan_id: str = "scan-1", scan_type: str = "message") -> dict:
    return {
        "id": scan_id,
        "scan_type": scan_type,
        "created_at": "2026-10-31T12:00:00+00:00",
        "prediction": "potential_phishing",
        "risk_score": 88,
        "risk_category": "critical",
        "indicators": [{"name": "Urgent request", "description": "Urgency detected.", "source": "heuristic"}],
        "disclaimer": "Informational only.",
        "model_name": "Test model",
        "model_version": "test",
        "model_confidence": 0.88,
        "model_info": {"algorithm": "test", "feature_schema_version": 1, "risk_score_note": "test score"},
        "explanation_note": "Heuristic indicator, not model attribution.",
    }


@pytest.fixture

def store(tmp_path: Path) -> ScanStore:
    database = ScanStore(tmp_path / "test.sqlite3")
    database.initialize()
    return database


def test_history_stats_persistence_and_delete(store: ScanStore) -> None:
    saved = store.save(sample_result(), "URGENT contact me at person@example.test, token=abc123")
    assert "[email redacted]" in saved["input_excerpt"]
    assert "abc123" not in saved["input_excerpt"]
    assert "person@example.test" not in saved["input_excerpt"]

    items, total = store.list_scans(limit=10, offset=0)
    assert total == 1
    assert items[0]["id"] == "scan-1"
    assert store.get("scan-1")["prediction"] == "potential_phishing"
    assert store.statistics()["phishing_detections"] == 1
    assert store.delete("scan-1") is True
    assert store.delete("missing") is False
    assert store.statistics()["total_scans"] == 0


def test_url_query_values_and_fragments_are_redacted() -> None:
    redacted = redact_url("https://example.test/login?user=alice&continue=https%3A%2F%2Fexample.org#reset-secret")

    assert [value for _, value in parse_qsl(urlsplit(redacted).query)] == ["[redacted]", "[redacted]"]
    assert "alice" not in redacted
    assert "example.org" not in redacted
    assert "reset-secret" not in redacted


def test_message_redacts_emails_phones_secrets_and_url_queries() -> None:
    redacted = redact_message("Email user@example.test or call +1 555 123 4567; password=secret; https://example.test/?token=xyz")

    assert "user@example.test" not in redacted
    assert "555 123 4567" not in redacted
    assert "secret" not in redacted
    assert "xyz" not in redacted


def test_message_redacts_scheme_less_and_www_link_query_values() -> None:
    redacted = redact_message("Visit www.example.com/reset?token=private or example.org?token=othersecret")

    assert "private" not in redacted
    assert "othersecret" not in redacted
