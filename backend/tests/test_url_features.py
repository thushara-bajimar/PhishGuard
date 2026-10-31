from __future__ import annotations

import unittest

from app.ml.url_features import FEATURE_NAMES, URLFeatureTransformer, extract_heuristic_indicators, extract_url_features
from app.schemas import AnalyzeURLRequest


class URLFeatureTests(unittest.TestCase):
    def test_extracts_url_properties_without_network_access(self) -> None:
        features = extract_url_features("http://192.0.2.1/login?account=1")

        self.assertEqual(features["ip_address_host"], 1.0)
        self.assertEqual(features["https_present"], 0.0)
        self.assertGreaterEqual(features["suspicious_keyword_count"], 2.0)
        self.assertEqual(features["path_segment_count"], 1.0)

    def test_shortener_and_word_signals_are_heuristics(self) -> None:
        indicators = extract_heuristic_indicators("https://bit.ly/verify-account")
        names = {indicator["name"] for indicator in indicators}

        self.assertIn("URL shortener", names)
        self.assertIn("Sensitive-action wording", names)
        self.assertTrue(all("model" not in indicator for indicator in indicators))

    def test_sklearn_transformer_has_stable_feature_order(self) -> None:
        transformer = URLFeatureTransformer().fit(["https://example.com"])
        values = transformer.transform(["https://example.com"])

        self.assertEqual(values.shape, (1, len(FEATURE_NAMES)))
        self.assertEqual(list(transformer.get_feature_names_out()), list(FEATURE_NAMES))

    def test_subdomain_count_respects_multi_label_public_suffix(self) -> None:
        features = extract_url_features("https://a.b.example.co.uk/path")

        self.assertEqual(features["subdomain_count"], 2.0)


class URLRequestValidationTests(unittest.TestCase):
    def test_accepts_http_url_bare_host_and_ip_address(self) -> None:
        self.assertEqual(AnalyzeURLRequest(url=" https://example.com/path ").url, "https://example.com/path")
        self.assertEqual(AnalyzeURLRequest(url="example.com").url, "example.com")
        self.assertEqual(AnalyzeURLRequest(url="http://[::1]:8080/path").url, "http://[::1]:8080/path")

    def test_rejects_non_http_scheme_and_invalid_port(self) -> None:
        with self.assertRaises(ValueError):
            AnalyzeURLRequest(url="ftp://example.com/file")
        with self.assertRaises(ValueError):
            AnalyzeURLRequest(url="https://example.com:bad/path")


if __name__ == "__main__":
    unittest.main()
