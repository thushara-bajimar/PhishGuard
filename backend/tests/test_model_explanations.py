"""Model-derived explanations: correctness of the decomposition and the source="model" contract.

Models here are trained on small tmp_path fixtures so the tests run without the public datasets.
"""

from __future__ import annotations

import csv
from pathlib import Path

import numpy as np
import pytest

from app.ml import message_predict, predict
from app.ml.message_predict import MessagePredictionService, message_model_indicators
from app.ml.message_train import train_model as train_message_model
from app.ml.predict import URLPredictionService, model_indicators
from app.ml.train import train_model as train_url_model
from app.ml.url_features import FEATURE_NAMES

WORDS = (
    "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike "
    "november oscar papa quebec romeo sierra tango uniform victor whiskey xray yankee"
).split()


@pytest.fixture(scope="module")
def url_model(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("url-model")
    dataset = directory / "urls.csv"
    with dataset.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["URL", "label"])
        for index, word in enumerate(WORDS):
            writer.writerow([f"http://secure-{word}-login{index}.verify-{word}.xyz/account", "0"])
            writer.writerow([f"https://www.{word}news.com", "1"])
    model_path = directory / "url.joblib"
    train_url_model(dataset, model_path, "URL", "label", "0", random_state=3)
    predict.clear_model_cache()
    return model_path


@pytest.fixture(scope="module")
def message_model(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("message-model")
    dataset = directory / "messages.csv"
    with dataset.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Email Text", "Email Type"])
        for word in WORDS:
            writer.writerow([f"urgent verify your password account suspended click {word}", "Phishing Email"])
            writer.writerow([f"agenda for the team meeting and lunch {word}", "Safe Email"])
    model_path = directory / "message.joblib"
    train_message_model(dataset, model_path, "Email Text", "Email Type", "Phishing Email", random_state=3)
    message_predict.clear_model_cache()
    return model_path


def test_forest_contributions_sum_exactly_to_model_score(url_model: Path) -> None:
    pipeline, _, explainer = predict._load_artifact(str(url_model.resolve()))
    assert explainer is not None
    for url in ("http://secure-zulu-login.verify-zulu.xyz/account", "https://www.zulunews.com", "example.org"):
        features = predict.feature_matrix(pipeline, [url])
        score = pipeline.steps[-1][1].predict_proba(features)[0][list(pipeline.classes_).index(1)]
        baseline, contributions = explainer.explain(features[0])
        assert contributions.shape == (len(FEATURE_NAMES),)
        assert baseline + contributions.sum() == pytest.approx(score, abs=1e-6)


def test_url_analysis_returns_model_indicators_before_heuristics(url_model: Path) -> None:
    result = URLPredictionService(url_model).analyze("http://secure-zulu-login.verify-zulu.xyz/account")

    model = [item for item in result["indicators"] if item["source"] == "model"]
    heuristic = [item for item in result["indicators"] if item["source"] == "heuristic"]
    assert model, "a confident prediction should be explained by at least one feature"
    assert len(model) <= predict.MAX_MODEL_INDICATORS
    assert result["indicators"][: len(model)] == model
    assert any(item["name"] == "HTTPS not present" for item in heuristic)
    assert all("phishing score by" in item["description"] for item in model)
    assert result["model_info"]["input_scope"] == "hostname"
    assert "decision-path" in result["model_info"]["explanation_method"]


def test_model_indicator_formatting_and_threshold() -> None:
    features = np.zeros(len(FEATURE_NAMES))
    features[FEATURE_NAMES.index("subdomain_count")] = 2
    features[FEATURE_NAMES.index("host_digit_ratio")] = 0.25
    contributions = np.zeros(len(FEATURE_NAMES))
    contributions[FEATURE_NAMES.index("subdomain_count")] = 0.31
    contributions[FEATURE_NAMES.index("host_digit_ratio")] = -0.12
    contributions[FEATURE_NAMES.index("hyphen_count")] = 0.004  # below one point: omitted

    indicators = model_indicators(features, contributions)

    assert indicators == [
        {"name": "Subdomain labels = 2", "description": "This feature raised the model's phishing score by 31 points for this input.", "source": "model"},
        {"name": "Digit ratio in hostname = 25%", "description": "This feature lowered the model's phishing score by 12 points for this input.", "source": "model"},
    ]


def test_message_terms_come_from_the_classifier(message_model: Path) -> None:
    pipeline, _, term_names = message_predict._load_artifact(str(message_model.resolve()))
    indicators = message_model_indicators(pipeline, term_names, "URGENT: verify your password or account suspended")

    assert indicators and all(item["source"] == "model" for item in indicators)
    terms = [item["name"].removeprefix('Term "').removesuffix('"') for item in indicators]
    assert set(terms) <= set(pipeline.named_steps["tfidf"].vocabulary_)
    assert all("toward phishing" in item["description"] for item in indicators)
    assert message_model_indicators(pipeline, term_names, "zzzz qqqq") == []  # no known vocabulary


def test_message_analysis_lists_model_terms_then_heuristics(message_model: Path) -> None:
    result = MessagePredictionService(message_model).analyze("Agenda for the team meeting and lunch on Friday")

    sources = [item["source"] for item in result["indicators"]]
    assert sources and sources == sorted(sources, key=lambda source: source != "model")
    assert all("toward legitimate" in item["description"] for item in result["indicators"] if item["source"] == "model")
    assert result["model_info"]["explanation_method"].startswith("TF-IDF")
    assert "SMS classification has not been validated" in result["model_info"]["scope_note"]
