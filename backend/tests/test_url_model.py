from __future__ import annotations

import csv
from pathlib import Path

from app.ml.predict import URLPredictionService
from app.ml.train import train_model


def test_url_pipeline_is_fitted_saved_loaded_and_used(tmp_path: Path) -> None:
    # Synthetic rows are isolated test fixtures only; no production training claim or artifact uses them.
    dataset_path = tmp_path / "urls.csv"
    model_path = tmp_path / "url-model.joblib"
    with dataset_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["link", "class"])
        writer.writeheader()
        for index in range(25):
            writer.writerow({"link": f"http://secure-login-{index}.com/verify-account?token={index}", "class": "phishing"})
            writer.writerow({"link": f"https://news-site-{index}.org/articles/story-{index}", "class": "legitimate"})

    metrics = train_model(dataset_path, model_path, "link", "class", "phishing", random_state=17)

    assert model_path.is_file()
    assert model_path.with_suffix(".metrics.json").is_file()
    assert metrics["host_overlap"] == 0
    assert {"precision_phishing", "recall_phishing", "f1_phishing", "confusion_matrix"} <= metrics.keys()

    response = URLPredictionService(model_path).analyze("http://secure-login-check.com/verify-account")
    assert response["scan_type"] == "url"
    assert response["prediction"] in {"potential_phishing", "no_phishing_detected"}
    assert 0 <= response["risk_score"] <= 100
    assert response["model_info"]["algorithm"] == "RandomForestClassifier"
    assert all(indicator["source"] == "heuristic" for indicator in response["indicators"])
