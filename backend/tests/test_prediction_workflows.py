"""End-to-end API workflows with real (non-mocked) prediction services.

Fixture-trained models in tmp_path exercise the full request -> model -> SQLite -> history path.
The final section runs against the production artifacts in backend/models/ when they have been
trained locally and is skipped otherwise (artifacts are not committed).
"""

from __future__ import annotations

import csv
from collections.abc import Iterator
from pathlib import Path

import joblib
import pytest
from fastapi.testclient import TestClient

import app.main as api
from app.ml import message_predict, predict
from app.ml.message_predict import MessagePredictionService
from app.ml.message_train import train_model as train_message_model
from app.ml.predict import URLPredictionService
from app.ml.train import train_model as train_url_model
from app.schemas import AnalysisResponse
from app.services.scan_store import ScanStore

WORDS = (
    "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike "
    "november oscar papa quebec romeo sierra tango uniform victor whiskey xray yankee"
).split()


@pytest.fixture(scope="module")
def trained_paths(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    directory = tmp_path_factory.mktemp("models")
    url_csv, message_csv = directory / "urls.csv", directory / "messages.csv"
    with url_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["URL", "label"])
        for index, word in enumerate(WORDS):
            writer.writerow([f"http://secure-{word}-login{index}.verify-{word}.xyz/account", "0"])
            writer.writerow([f"https://www.{word}news.com", "1"])
    with message_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Email Text", "Email Type"])
        for word in WORDS:
            writer.writerow([f"urgent verify your password account suspended click {word}", "Phishing Email"])
            writer.writerow([f"agenda for the team meeting and lunch {word}", "Safe Email"])
    url_model, message_model = directory / "url.joblib", directory / "message.joblib"
    train_url_model(url_csv, url_model, "URL", "label", "0", random_state=5)
    train_message_model(message_csv, message_model, "Email Text", "Email Type", "Phishing Email", random_state=5)
    return url_model, message_model


def make_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, url_model: Path, message_model: Path) -> TestClient:
    predict.clear_model_cache()
    message_predict.clear_model_cache()
    monkeypatch.setattr(api, "scan_store", ScanStore(tmp_path / "workflow.sqlite3"))
    monkeypatch.setattr(api, "url_prediction_service", URLPredictionService(url_model))
    monkeypatch.setattr(api, "message_prediction_service", MessagePredictionService(message_model))
    return TestClient(api.app, raise_server_exceptions=False)


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, trained_paths: tuple[Path, Path]) -> Iterator[TestClient]:
    with make_client(tmp_path, monkeypatch, *trained_paths) as test_client:
        yield test_client


def test_url_scan_end_to_end_persists_model_explanations(client: TestClient) -> None:
    response = client.post("/api/analyze/url", json={"url": "http://secure-zulu-login.verify-zulu.xyz/account?session=abc"})

    assert response.status_code == 200
    result = AnalysisResponse.model_validate(response.json())
    assert result.scan_type == "url"
    assert any(item.source == "model" for item in result.indicators)
    assert any(item.source == "heuristic" for item in result.indicators)
    assert result.model_info.input_scope == "hostname"
    assert "abc" not in result.input_excerpt  # query values redacted before storage

    stored = AnalysisResponse.model_validate(client.get(f"/api/history/{result.id}").json())
    assert stored.indicators == result.indicators
    assert stored.risk_score == result.risk_score
    assert client.get("/api/history").json()["total"] == 1


def test_message_scan_end_to_end_persists_model_terms(client: TestClient) -> None:
    response = client.post("/api/analyze/message", json={"content": "URGENT verify your password, account suspended. Reply to me@private.test"})

    assert response.status_code == 200
    result = AnalysisResponse.model_validate(response.json())
    assert result.prediction == "potential_phishing"
    assert any(item.source == "model" and item.name.startswith("Term ") for item in result.indicators)
    assert "me@private.test" not in result.input_excerpt
    statistics = client.get("/api/stats").json()
    assert statistics["message_scans"] == 1 and statistics["phishing_detections"] == 1


def test_health_reports_model_availability(client: TestClient) -> None:
    body = client.get("/api/health").json()

    assert body["status"] == "ok"
    assert body["models"]["url"]["available"] is True
    assert body["models"]["message"]["available"] is True


@pytest.mark.parametrize("artifact", ["missing", "corrupt", "wrong_schema"])
def test_unusable_artifacts_return_503_and_health_says_unavailable(
    artifact: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, trained_paths: tuple[Path, Path]
) -> None:
    broken = tmp_path / "broken.joblib"
    if artifact == "corrupt":
        broken.write_bytes(b"not a joblib file")
    elif artifact == "wrong_schema":
        payload = joblib.load(trained_paths[0])
        payload["metadata"]["feature_schema_version"] = 2
        joblib.dump(payload, broken)

    with make_client(tmp_path, monkeypatch, broken, broken) as test_client:
        url_response = test_client.post("/api/analyze/url", json={"url": "https://example.com"})
        message_response = test_client.post("/api/analyze/message", json={"content": "hello there"})
        health = test_client.get("/api/health").json()

    assert url_response.status_code == 503 and message_response.status_code == 503
    assert "Retrain" in url_response.json()["detail"] or "not trained" in url_response.json()["detail"]
    assert health["models"]["url"]["available"] is False
    assert health["models"]["message"]["available"] is False
    assert test_client.get("/api/history").json()["total"] == 0  # nothing stored on failure


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/api/analyze/url", {"url": "javascript:alert(1)"}),
        ("/api/analyze/url", {"url": "https://" + "a" * 4090 + ".com"}),
        ("/api/analyze/url", {"url": 12345}),
        ("/api/analyze/url", {}),
        ("/api/analyze/message", {"content": ["not", "text"]}),
        ("/api/analyze/message", {"text": "wrong field name"}),
    ],
)
def test_invalid_inputs_are_rejected_before_scoring(client: TestClient, path: str, payload: dict) -> None:
    response = client.post(path, json=payload)

    assert response.status_code == 422
    assert client.get("/api/history").json()["total"] == 0


# --- Production artifacts (run only after `python -m app.ml.train` / `app.ml.message_train`) ---

PRODUCTION_URL_MODEL = predict.DEFAULT_MODEL_PATH
PRODUCTION_MESSAGE_MODEL = message_predict.DEFAULT_MODEL_PATH
needs_url_model = pytest.mark.skipif(not PRODUCTION_URL_MODEL.is_file(), reason="URL model not trained locally")
needs_message_model = pytest.mark.skipif(not PRODUCTION_MESSAGE_MODEL.is_file(), reason="message model not trained locally")


@needs_url_model
@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.10.5/bank/login.php",
        "https://appleid.apple.com.verify-account-locked.info/signin",
        "http://paypal-account-verify.secure-login.xyz/update",
    ],
)
def test_production_url_model_flags_clear_phishing_patterns(url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with make_client(tmp_path, monkeypatch, PRODUCTION_URL_MODEL, PRODUCTION_MESSAGE_MODEL) as test_client:
        response = test_client.post("/api/analyze/url", json={"url": url})
    assert response.status_code == 200
    result = AnalysisResponse.model_validate(response.json())
    assert result.prediction == "potential_phishing"
    assert any(item.source == "model" for item in result.indicators)


@needs_url_model
@pytest.mark.parametrize("url", ["https://www.bbc.co.uk/news", "https://github.com/python/cpython", "https://www.google.com"])
def test_production_url_model_scores_common_legitimate_sites_with_explanations(url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with make_client(tmp_path, monkeypatch, PRODUCTION_URL_MODEL, PRODUCTION_MESSAGE_MODEL) as test_client:
        response = test_client.post("/api/analyze/url", json={"url": url})
        stored_total = test_client.get("/api/history").json()["total"]
    assert response.status_code == 200
    result = AnalysisResponse.model_validate(response.json())
    assert result.prediction == "no_phishing_detected"
    assert result.indicators and result.indicators[0].source == "model"
    assert stored_total == 1


@needs_message_model
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Your account has been suspended. Verify your password within 24 hours at http://secure-update.example/login to avoid closure.", "potential_phishing"),
        ("Hi team, attached are the minutes from Tuesday's planning meeting. Let me know if I missed anything.", "no_phishing_detected"),
    ],
)
def test_production_message_model_classifies_clear_examples(text: str, expected: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with make_client(tmp_path, monkeypatch, PRODUCTION_URL_MODEL, PRODUCTION_MESSAGE_MODEL) as test_client:
        response = test_client.post("/api/analyze/message", json={"content": text})
    assert response.status_code == 200
    result = AnalysisResponse.model_validate(response.json())
    assert result.prediction == expected
    assert any(item.source == "model" for item in result.indicators)
