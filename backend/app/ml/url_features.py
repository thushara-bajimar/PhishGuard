"""Deterministic URL-only features and independently sourced heuristic indicators."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit
from typing import Any, Iterable

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
import tldextract

_DOMAIN_EXTRACTOR = tldextract.TLDExtract(cache_dir=False, suffix_list_urls=())

# 3: pipeline gained the URLScopeTransformer input-scope step ahead of the 23 features.
FEATURE_SCHEMA_VERSION = 3

FEATURE_NAMES = (
    "url_length",
    "hostname_length",
    "hostname_dot_count",
    "subdomain_count",
    "path_length",
    "path_segment_count",
    "query_length",
    "query_parameter_count",
    "fragment_present",
    "https_present",
    "ip_address_host",
    "host_has_punycode",
    "suspicious_character_count",
    "at_sign_count",
    "hyphen_count",
    "host_hyphen_count",
    "digit_count",
    "digit_ratio",
    "host_digit_ratio",
    "suspicious_keyword_count",
    "shortener_host",
    "nonstandard_port",
    "userinfo_present",
)

SUSPICIOUS_KEYWORDS = (
    "account",
    "billing",
    "confirm",
    "credential",
    "invoice",
    "login",
    "password",
    "recover",
    "secure",
    "signin",
    "suspend",
    "update",
    "verify",
    "wallet",
)

SHORTENER_HOSTS = frozenset(
    {
        "bit.ly",
        "goo.gl",
        "t.co",
        "tinyurl.com",
        "is.gd",
        "ow.ly",
        "buff.ly",
        "rb.gy",
        "cutt.ly",
        "shorturl.at",
        "tiny.cc",
        "rebrand.ly",
    }
)

SUSPICIOUS_CHARACTERS = "@%=?&#_~"


def _split_url(url: str):
    """Split a URL, accepting a bare hostname as an authority for analysis."""
    value = url.strip()
    if not value:
        return urlsplit("")
    if "://" not in value and not value.startswith("//"):
        value = f"//{value}"
    return urlsplit(value)


def extract_url_features(url: str) -> dict[str, float]:
    """Extract stable numeric features without resolving or fetching the URL."""
    if not isinstance(url, str):
        raise TypeError("URL must be a string")

    parts = _split_url(url)
    host = (parts.hostname or "").rstrip(".").lower()
    host_for_count = host[4:] if host.startswith("www.") else host
    try:
        ipaddress.ip_address(host.strip("[]"))
        ip_host = 1.0
    except ValueError:
        ip_host = 0.0
    domain_parts = _DOMAIN_EXTRACTOR(host_for_count)
    subdomain_count = len([label for label in domain_parts.subdomain.split(".") if label]) if domain_parts.suffix else 0

    host_alphanumeric = [character for character in host if character.isalnum()]
    all_alphanumeric = [character for character in url if character.isalnum()]
    lowered = url.lower()
    keyword_count = sum(lowered.count(keyword) for keyword in SUSPICIOUS_KEYWORDS)
    try:
        port = parts.port
    except ValueError:
        port = None

    return {
        "url_length": float(len(url)),
        "hostname_length": float(len(host)),
        "hostname_dot_count": float(host.count(".")),
        "subdomain_count": float(0 if ip_host else subdomain_count),
        "path_length": float(len(parts.path)),
        "path_segment_count": float(len([segment for segment in parts.path.split("/") if segment])),
        "query_length": float(len(parts.query)),
        "query_parameter_count": float(sum(1 for item in parts.query.split("&") if item)),
        "fragment_present": float(bool(parts.fragment)),
        "https_present": float(parts.scheme.lower() == "https"),
        "ip_address_host": ip_host,
        "host_has_punycode": float("xn--" in host),
        "suspicious_character_count": float(sum(url.count(character) for character in SUSPICIOUS_CHARACTERS)),
        "at_sign_count": float(url.count("@")),
        "hyphen_count": float(url.count("-")),
        "host_hyphen_count": float(host.count("-")),
        "digit_count": float(sum(character.isdigit() for character in url)),
        "digit_ratio": float(sum(character.isdigit() for character in url) / max(1, len(url))),
        "host_digit_ratio": float(sum(character.isdigit() for character in host) / max(1, len(host_alphanumeric))),
        "suspicious_keyword_count": float(keyword_count),
        "shortener_host": float(host in SHORTENER_HOSTS or any(host.endswith(f".{shortener}") for shortener in SHORTENER_HOSTS)),
        "nonstandard_port": float(port is not None and port not in (80, 443)),
        "userinfo_present": float(parts.username is not None or parts.password is not None),
    }


def extract_heuristic_indicators(url: str) -> list[dict[str, str]]:
    """Describe observable URL traits; these are not model feature attributions."""
    features = extract_url_features(url)
    indicators: list[dict[str, str]] = []
    if features["ip_address_host"]:
        indicators.append({"name": "IP address used as host", "description": "The address uses a numeric IP host rather than a conventional domain name."})
    if not features["https_present"]:
        indicators.append({"name": "HTTPS not present", "description": "The URL does not specify HTTPS. Encryption alone does not determine whether a site is trustworthy."})
    if features["shortener_host"]:
        indicators.append({"name": "URL shortener", "description": "The host matches a commonly used URL-shortening service, which obscures the destination."})
    if features["userinfo_present"] or features["at_sign_count"]:
        indicators.append({"name": "At-sign or user-info syntax", "description": "The URL contains user-info or @ syntax that can make the displayed destination confusing."})
    if features["host_has_punycode"]:
        indicators.append({"name": "Punycode hostname", "description": "The hostname contains an IDN punycode label; inspect the rendered domain carefully."})
    if features["suspicious_keyword_count"]:
        indicators.append({"name": "Sensitive-action wording", "description": "The URL contains terms commonly used in account, credential, billing, or verification lures."})
    if features["hyphen_count"] >= 3:
        indicators.append({"name": "Several hyphens", "description": "The URL contains multiple hyphens, which can occur in deceptive lookalike domains."})
    if features["subdomain_count"] >= 3:
        indicators.append({"name": "Many subdomain labels", "description": "The hostname has multiple labels before its final two labels; this can obscure the registered destination."})
    if features["suspicious_character_count"] >= 4:
        indicators.append({"name": "Unusual URL punctuation", "description": "The URL contains several punctuation characters often used in complex or obfuscated links."})
    if features["url_length"] >= 120:
        indicators.append({"name": "Unusually long URL", "description": "Long URLs can hide the actual destination or include opaque tracking and redirect parameters."})
    if features["nonstandard_port"]:
        indicators.append({"name": "Non-standard port", "description": "The URL specifies a port other than the usual HTTP or HTTPS ports."})
    return indicators


class URLFeatureTransformer(TransformerMixin, BaseEstimator):
    """Scikit-learn transformer that converts URL strings into numeric feature rows."""

    def fit(self, X: Iterable[str], y: Any = None) -> URLFeatureTransformer:
        del X, y
        return self

    def transform(self, X: Iterable[str]) -> np.ndarray:
        rows = [extract_url_features(str(value)) for value in X]
        if not rows:
            return np.empty((0, len(FEATURE_NAMES)), dtype=np.float64)
        return np.asarray([[row[name] for name in FEATURE_NAMES] for row in rows], dtype=np.float64)

    def get_feature_names_out(self, input_features: Any = None) -> np.ndarray:
        del input_features
        return np.asarray(FEATURE_NAMES, dtype=object)


INPUT_SCOPES = ("url", "hostname", "registered_domain")

FEATURE_LABELS = {
    "url_length": "Input length",
    "hostname_length": "Hostname length",
    "hostname_dot_count": "Dots in hostname",
    "subdomain_count": "Subdomain labels",
    "path_length": "Path length",
    "path_segment_count": "Path segments",
    "query_length": "Query length",
    "query_parameter_count": "Query parameters",
    "fragment_present": "Fragment present",
    "https_present": "HTTPS scheme",
    "ip_address_host": "IP address host",
    "host_has_punycode": "Punycode hostname",
    "suspicious_character_count": "Unusual punctuation",
    "at_sign_count": "At-sign count",
    "hyphen_count": "Hyphens",
    "host_hyphen_count": "Hyphens in hostname",
    "digit_count": "Digits",
    "digit_ratio": "Digit ratio",
    "host_digit_ratio": "Digit ratio in hostname",
    "suspicious_keyword_count": "Sensitive-action keywords",
    "shortener_host": "URL-shortener host",
    "nonstandard_port": "Non-standard port",
    "userinfo_present": "User-info syntax",
}


def scope_url(url: str, scope: str) -> str:
    """Reduce a URL to the part the model is allowed to see.

    PhiUSIIL's legitimate URLs are all ``https://www.<domain>`` homepages, so scheme, path and
    the ``www.`` label are label shortcuts in that dataset. ``hostname`` drops scheme, port,
    path, query and a leading ``www.``; ``registered_domain`` keeps only the domain under the
    public suffix (or the IP address).
    """
    if scope == "url":
        return url
    if scope not in INPUT_SCOPES:
        raise ValueError(f"Unknown URL input scope {scope!r}; expected one of {INPUT_SCOPES}.")
    host = (_split_url(url).hostname or "").rstrip(".").lower()
    if host.startswith("www."):
        host = host[4:]
    if scope == "registered_domain":
        try:
            ipaddress.ip_address(host.strip("[]"))
            return host
        except ValueError:
            return _DOMAIN_EXTRACTOR(host).top_domain_under_public_suffix or host
    return host


class URLScopeTransformer(TransformerMixin, BaseEstimator):
    """Pipeline step applying :func:`scope_url` so training and inference see identical input."""

    def __init__(self, scope: str = "hostname") -> None:
        self.scope = scope

    def fit(self, X: Iterable[str], y: Any = None) -> URLScopeTransformer:
        del X, y
        if self.scope not in INPUT_SCOPES:
            raise ValueError(f"Unknown URL input scope {self.scope!r}; expected one of {INPUT_SCOPES}.")
        return self

    def transform(self, X: Iterable[str]) -> list[str]:
        return [scope_url(str(value), self.scope) for value in X]
