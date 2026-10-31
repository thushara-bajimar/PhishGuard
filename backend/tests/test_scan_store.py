from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

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


class ScanStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.store = ScanStore(Path(self.temporary_directory.name) / "test.sqlite3")
        self.store.initialize()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_persistence_history_stats_and_delete(self) -> None:
        saved = self.store.save(sample_result(), "URGENT contact me at person@example.test, token=abc123")
        self.assertIn("[email redacted]", saved["input_excerpt"])
        self.assertNotIn("abc123", saved["input_excerpt"])
        self.assertNotIn("person@example.test", saved["input_excerpt"])

        items, total = self.store.list_scans(limit=10, offset=0)
        self.assertEqual(total, 1)
        self.assertEqual(items[0]["id"], "scan-1")
        self.assertEqual(self.store.get("scan-1")["prediction"], "potential_phishing")
        self.assertEqual(self.store.statistics()["phishing_detections"], 1)
        self.assertTrue(self.store.delete("scan-1"))
        self.assertFalse(self.store.delete("missing"))
        self.assertEqual(self.store.statistics()["total_scans"], 0)

    def test_url_query_values_are_redacted(self) -> None:
        redacted = redact_url("https://example.test/login?user=alice&continue=https%3A%2F%2Fexample.org#reset-secret")
        self.assertEqual([value for _, value in parse_qsl(urlsplit(redacted).query)], ["[redacted]", "[redacted]"])
        self.assertNotIn("alice", redacted)
        self.assertNotIn("example.org", redacted)
        self.assertNotIn("reset-secret", redacted)

    def test_message_redacts_emails_phones_secrets_and_url_queries(self) -> None:
        redacted = redact_message("Email user@example.test or call +1 555 123 4567; password=secret; https://example.test/?token=xyz")
        self.assertNotIn("user@example.test", redacted)
        self.assertNotIn("555 123 4567", redacted)
        self.assertNotIn("secret", redacted)
        self.assertNotIn("xyz", redacted)


if __name__ == "__main__":
    unittest.main()
