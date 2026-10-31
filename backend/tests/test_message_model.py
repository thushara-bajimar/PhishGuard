from __future__ import annotations

import csv
from pathlib import Path

from app.ml.message_predict import MessagePredictionService, extract_message_indicators
from app.ml.message_train import train_model


def test_message_indicators_are_heuristics_not_model_attributions() -> None:
    text = "URGENT: verify your password now or your account will be suspended. Pay the processing fee at https://example.test/claim"
    indicators = extract_message_indicators(text)
    names = {item["name"] for item in indicators}

    assert {"Urgent request", "Credential or account request", "Threatening language", "Unusual payment request", "Link present"} <= names
    assert all(item["source"] == "heuristic" for item in indicators)


def test_harmless_message_has_no_matching_warning_rules() -> None:
    assert extract_message_indicators("Meeting moved to 3pm, see you in the office.") == []


def test_training_saves_and_loads_a_fitted_pipeline(tmp_path: Path) -> None:
    # These rows are isolated test fixtures, not the public production dataset or reported metrics.
    dataset_path = tmp_path / "messages.csv"
    model_path = tmp_path / "model.joblib"
    with dataset_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["Email Text", "Email Type"])
        writer.writeheader()
        for index in range(25):
            writer.writerow({"Email Text": f"urgent verify password account secure login notice sample {index}", "Email Type": "Phishing Email"})
            writer.writerow({"Email Text": f"team lunch meeting schedule project discussion sample {index}", "Email Type": "Safe Email"})

    metrics = train_model(dataset_path, model_path, "Email Text", "Email Type", "Phishing Email", random_state=11)

    assert model_path.is_file()
    assert model_path.with_suffix(".metrics.json").is_file()
    assert metrics["group_overlap"] == 0
    assert {"precision_phishing", "recall_phishing", "f1_phishing", "confusion_matrix"} <= metrics.keys()

    result = MessagePredictionService(model_path).analyze("URGENT verify your account password now")
    assert result["prediction"] in {"potential_phishing", "no_phishing_detected"}
    assert 0 <= result["risk_score"] <= 100
    assert all(item["source"] == "heuristic" for item in result["indicators"])
    assert "uncalibrated" in result["model_info"]["risk_score_note"]
