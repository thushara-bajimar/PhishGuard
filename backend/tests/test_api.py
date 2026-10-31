from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import app.main as api
from app.ml.message_predict import ModelUnavailableError as MessageModelUnavailableError
from app.ml.predict import ModelUnavailableError as URLModelUnavailableError
from app.services.scan_store import ScanStore


def result(scan_type: str, scan_id: str) -> dict:
    return {
        "id": scan_id,
        "scan_type": scan_type,
        "created_at": "2026-10-31T12:00:00+00:00",
        "prediction": "potential_phishing",
        "risk_score": 72,
        "risk_category": "high",
        "indicators": [{"name": "Test signal", "description": "Independent heuristic signal.", "source": "heuristic"}],
        "disclaimer": "Not guaranteed safe.",
        "model_name": "Test model",
        "model_version": "test-version",
        "model_confidence": 0.72,
        "model_info": {"algorithm": "test", "feature_schema_version": 1, "risk_score_note": "Uncalibrated test score."},
        "explanation_note": "Heuristic signal is independent of the model prediction.",
    }


class ApiIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        api.scan_store = ScanStore(Path(self.temporary_directory.name) / "api.sqlite3")
        self.client = TestClient(api.app, raise_server_exceptions=False)
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        self.temporary_directory.cleanup()

    def test_analysis_history_stats_and_delete(self) -> None:
        with patch.object(api.url_prediction_service, "analyze", return_value=result("url", "url-1")):
            response = self.client.post("/api/analyze/url", json={"url": "https://example.test/?email=private@example.test"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["id"], "url-1")
        self.assertNotIn("private@example.test", response.json()["input_excerpt"])

        with patch.object(api.message_prediction_service, "analyze", return_value=result("message", "message-1")):
            message_response = self.client.post("/api/analyze/message", json={"content": "Please review the account notice sent today."})
        self.assertEqual(message_response.status_code, 200)

        history = self.client.get("/api/history")
        self.assertEqual(history.status_code, 200)
        self.assertEqual(history.json()["total"], 2)
        self.assertEqual({row["id"] for row in history.json()["items"]}, {"url-1", "message-1"})
        self.assertEqual(self.client.get("/api/history/message-1").status_code, 200)
        self.assertEqual(self.client.get("/api/stats").json()["message_scans"], 1)

        self.assertEqual(self.client.delete("/api/history/url-1").status_code, 204)
        self.assertEqual(self.client.delete("/api/history/url-1").status_code, 404)
        self.assertEqual(self.client.get("/api/stats").json()["total_scans"], 1)

    def test_unavailable_models_are_503_and_inputs_are_validated(self) -> None:
        with patch.object(api.url_prediction_service, "analyze", side_effect=URLModelUnavailableError("URL model unavailable")):
            self.assertEqual(self.client.post("/api/analyze/url", json={"url": "https://example.test"}).status_code, 503)
        with patch.object(api.message_prediction_service, "analyze", side_effect=MessageModelUnavailableError("Message model unavailable")):
            self.assertEqual(self.client.post("/api/analyze/message", json={"content": "Please review this message."}).status_code, 503)
        self.assertEqual(self.client.post("/api/analyze/message", json={"content": " "}).status_code, 422)
        self.assertEqual(self.client.post("/api/analyze/message", json={"content": "x" * 30_001}).status_code, 422)
        self.assertEqual(self.client.post("/api/analyze/url", json={"url": "javascript:alert(1)"}).status_code, 422)

    def test_health_and_history_not_found(self) -> None:
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        self.assertEqual(self.client.get("/api/history/does-not-exist").status_code, 404)

    def test_unexpected_error_is_generic_and_does_not_echo_input(self) -> None:
        with patch.object(api.message_prediction_service, "analyze", side_effect=RuntimeError("private payload must not appear")):
            response = self.client.post("/api/analyze/message", json={"content": "A harmless message body."})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json(), {"detail": "An unexpected server error occurred."})
        self.assertNotIn("private payload", response.text)


if __name__ == "__main__":
    unittest.main()
