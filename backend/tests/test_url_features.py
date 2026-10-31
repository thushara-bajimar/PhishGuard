from __future__ import annotations

import pytest

from app.ml.url_features import FEATURE_NAMES, URLFeatureTransformer, extract_heuristic_indicators, extract_url_features
from app.schemas import AnalyzeURLRequest


def test_url_feature_extraction_does_not_visit_submitted_address() -> None:
    features = extract_url_features("http://192.0.2.1/login?account=1")

    assert features["ip_address_host"] == 1.0
    assert features["https_present"] == 0.0
    assert features["suspicious_keyword_count"] >= 2.0
    assert features["path_segment_count"] == 1.0


def test_url_indicators_are_labeled_heuristics() -> None:
    indicators = extract_heuristic_indicators("https://bit.ly/verify-account")
    names = {indicator["name"] for indicator in indicators}

    assert "URL shortener" in names
    assert "Sensitive-action wording" in names
    assert all("model" not in indicator for indicator in indicators)


def test_sklearn_transformer_has_stable_feature_order() -> None:
    transformer = URLFeatureTransformer().fit(["https://example.com"])
    values = transformer.transform(["https://example.com"])

    assert values.shape == (1, len(FEATURE_NAMES))
    assert list(transformer.get_feature_names_out()) == list(FEATURE_NAMES)


def test_subdomain_count_uses_public_suffix_rules() -> None:
    features = extract_url_features("https://a.b.example.co.uk/path")

    assert features["subdomain_count"] == 2.0


@pytest.mark.parametrize("url", ["https://example.com/path", "example.com", "http://[::1]:8080/path", "http://localhost:8000/health"])
def test_valid_url_inputs(url: str) -> None:
    assert AnalyzeURLRequest(url=url).url == url


@pytest.mark.parametrize("url", ["", "ftp://example.com/file", "https://example.com:bad/path", "https://not a host/path"])
def test_invalid_url_inputs(url: str) -> None:
    with pytest.raises(ValueError):
        AnalyzeURLRequest(url=url)
