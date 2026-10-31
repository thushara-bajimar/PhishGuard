from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import app.main as api
from app.ml.message_predict import ModelUnavailableError as MessageModelUnavailableError
from app.ml.predict import ModelUnavailableError as URLModelUnavailableError
from app.schemas import AnalysisResponse
from app.services.scan_store import ScanStore


def prediction_result(scan_type: str, scan_id: str) -> dict[str, Any]:
    """API fixture output; it is not used as a model prediction or training data."""
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


@pytest.fixture

def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setattr(api, "scan_store", ScanStore(tmp_path / "api.sqlite3"))
    with TestClient(api.app, raise_server_exceptions=False) as test_client:
        yield test_client


def test_valid_url_analysis_persists_schema_and_redacts_input(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api.url_prediction_service, "analyze", lambda _: prediction_result("url", "url-1"))

    response = client.post("/api/analyze/url", json={"url": "https://example.test/?email=private@example.test"})

    assert response.status_code == 200
    payload = AnalysisResponse.model_validate(response.json())
    assert payload.id == "url-1"
    assert payload.scan_type == "url"
    assert payload.risk_score == 72
    assert payload.model_info.algorithm == "test"
    assert "private@example.test" not in payload.input_excerpt


@pytest.mark.parametrize("url", ["", "ftp://example.test/file", "https://bad host/path", "https://example.test:bad"])
def test_invalid_urls_are_rejected(client: TestClient, url: str) -> None:
    response = client.post("/api/analyze/url", json={"url": url})

    assert response.status_code == 422
    assert "detail" in response.json()


def test_message_request_validation_and_prediction_schema(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api.message_prediction_service, "analyze", lambda _: prediction_result("message", "message-1"))

    assert client.post("/api/analyze/message", json={"content": " "}).status_code == 422
    assert client.post("/api/analyze/message", json={"content": "x" * 30_001}).status_code == 422
    response = client.post("/api/analyze/message", json={"content": "Please review the account notice sent today."})

    assert response.status_code == 200
    payload = AnalysisResponse.model_validate(response.json())
    assert payload.scan_type == "message"
    assert payload.id == "message-1"
    assert payload.indicators[0].source == "heuristic"


def test_invalid_message_errors_do_not_echo_submitted_text(client: TestClient) -> None:
    secret_text = "sensitive-" + ("x" * 30_001)
    response = client.post("/api/analyze/message", json={"content": secret_text})

    assert response.status_code == 422
    assert secret_text not in response.text
    assert "30000" in response.text


def test_history_stats_details_and_delete(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api.url_prediction_service, "analyze", lambda _: prediction_result("url", "url-1"))
    monkeypatch.setattr(api.message_prediction_service, "analyze", lambda _: prediction_result("message", "message-1"))
    assert client.post("/api/analyze/url", json={"url": "example.test"}).status_code == 200
    assert client.post("/api/analyze/message", json={"content": "A message to analyze safely."}).status_code == 200

    history = client.get("/api/history", params={"limit": 1, "offset": 0})
    assert history.status_code == 200
    assert history.json()["total"] == 2
    assert len(history.json()["items"]) == 1
    assert client.get("/api/history/message-1").status_code == 200
    statistics = client.get("/api/stats").json()
    assert {key: value for key, value in statistics.items() if key != "last_scan_at"} == {
        "total_scans": 2,
        "phishing_detections": 2,
        "suspicious_results": 2,
        "url_scans": 1,
        "message_scans": 1,
    }
    assert statistics["last_scan_at"].startswith("2026-10-31T12:00:00")
    assert client.delete("/api/history/url-1").status_code == 204
    assert client.delete("/api/history/url-1").status_code == 404
    assert client.get("/api/history/missing").status_code == 404


def test_untrained_models_and_storage_failure_return_clear_errors(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api.url_prediction_service, "analyze", lambda _: (_ for _ in ()).throw(URLModelUnavailableError("Train URL model first.")))
    monkeypatch.setattr(api.message_prediction_service, "analyze", lambda _: (_ for _ in ()).throw(MessageModelUnavailableError("Train message model first.")))

    assert client.post("/api/analyze/url", json={"url": "https://example.test"}).status_code == 503
    message_error = client.post("/api/analyze/message", json={"content": "Please review this message."})
    assert message_error.status_code == 503
    assert message_error.json()["detail"] == "Train message model first."

    monkeypatch.setattr(api.message_prediction_service, "analyze", lambda _: prediction_result("message", "storage-1"))
    monkeypatch.setattr(api.scan_store, "save", lambda *_: (_ for _ in ()).throw(sqlite3.OperationalError("private path detail")))
    storage_error = client.post("/api/analyze/message", json={"content": "A message for storage."})
    assert storage_error.status_code == 503
    assert storage_error.json() == {"detail": "Scan storage is temporarily unavailable."}


def test_unexpected_error_is_generic_and_does_not_echo_input(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api.message_prediction_service, "analyze", lambda _: (_ for _ in ()).throw(RuntimeError("private payload must not appear")))

    response = client.post("/api/analyze/message", json={"content": "A harmless message body."})

    assert response.status_code == 500
    assert response.json() == {"detail": "An unexpected server error occurred."}
    assert "private payload" not in response.text


def test_health_endpoint(client: TestClient) -> None:
    assert client.get("/api/health").json() == {"status": "ok", "service": "phishguard-api"}
