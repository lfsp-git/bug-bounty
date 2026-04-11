"""Comprehensive tests for core/ml_filter.py — all helper methods and fallback behavior."""
import sys
import os
import numbers
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch
from core.ml_filter import MLFilter, _ML_DEPS_AVAILABLE


# ── Dependency availability ───────────────────────────────────────────────────

class TestMLDepsAvailable:
    def test_ml_deps_flag_is_bool(self):
        assert isinstance(_ML_DEPS_AVAILABLE, bool)

    def test_numpy_pandas_installed_in_venv(self):
        """numpy and pandas are in requirements.txt — flag must be True in .venv."""
        assert _ML_DEPS_AVAILABLE, (
            "_ML_DEPS_AVAILABLE is False — numpy/pandas may not be installed. "
            "Run: pip install numpy pandas"
        )


# ── score_finding — no model fallback ────────────────────────────────────────

class TestScoreFindingNoModel:
    def setup_method(self):
        # Patch the model path to not exist so load_model() returns False
        self._patcher = patch.object(MLFilter, "MODEL_PATH", "/nonexistent/model.pkl")
        self._patcher.start()
        MLFilter._model = None
        MLFilter._label_encoders = None

    def teardown_method(self):
        self._patcher.stop()
        MLFilter._model = None
        MLFilter._label_encoders = None
        # Re-load the real model for subsequent tests
        MLFilter.load_model()

    def test_no_model_returns_not_fp(self):
        is_fp, conf = MLFilter.score_finding({"severity": "high"})
        assert is_fp is False

    def test_no_model_returns_zero_confidence(self):
        _, conf = MLFilter.score_finding({"severity": "critical"})
        assert conf == 0.0

    def test_empty_finding_no_crash(self):
        is_fp, conf = MLFilter.score_finding({})
        assert is_fp is False
        assert conf == 0.0


# ── _detect_content_type ──────────────────────────────────────────────────────

class TestDetectContentType:
    def test_json_content_type(self):
        resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
        assert MLFilter._detect_content_type(resp) == "json"

    def test_html_content_type(self):
        resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html>"
        assert MLFilter._detect_content_type(resp) == "html"

    def test_plain_text_content_type(self):
        resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"
        assert MLFilter._detect_content_type(resp) == "text"

    def test_xml_content_type(self):
        resp = "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\r\n<root/>"
        assert MLFilter._detect_content_type(resp) == "xml"

    def test_image_content_type(self):
        resp = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n"
        assert MLFilter._detect_content_type(resp) == "image"

    def test_unknown_content_type(self):
        resp = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n"
        assert MLFilter._detect_content_type(resp) == "unknown"

    def test_empty_response_unknown(self):
        assert MLFilter._detect_content_type("") == "unknown"

    def test_none_response_unknown(self):
        assert MLFilter._detect_content_type(None) == "unknown"

    def test_case_insensitive_match(self):
        resp = "HTTP/1.1 200 OK\r\ncontent-type: Application/JSON\r\n\r\n{}"
        assert MLFilter._detect_content_type(resp) == "json"


# ── _detect_host_type ─────────────────────────────────────────────────────────

class TestDetectHostType:
    def test_wordpress_host(self):
        assert MLFilter._detect_host_type("https://example.com/wp-admin") == "wordpress"

    def test_wordpress_wp_prefix(self):
        assert MLFilter._detect_host_type("https://wp-staging.example.com") == "wordpress"

    def test_aws_amazonaws(self):
        assert MLFilter._detect_host_type("https://bucket.s3.amazonaws.com") == "aws"

    def test_aws_ec2(self):
        assert MLFilter._detect_host_type("https://ec2-54-123.compute.amazonaws.com") == "aws"

    def test_azure_host(self):
        assert MLFilter._detect_host_type("https://app.azurewebsites.net") == "azure"

    def test_github_host(self):
        assert MLFilter._detect_host_type("https://github.com/repo") == "github"

    def test_api_host(self):
        assert MLFilter._detect_host_type("https://api.example.com") == "api"

    def test_admin_host(self):
        assert MLFilter._detect_host_type("https://admin.example.com") == "admin"

    def test_dev_host(self):
        assert MLFilter._detect_host_type("https://app.dev") == "dev"

    def test_local_host(self):
        assert MLFilter._detect_host_type("https://service.local") == "dev"

    def test_docker_host(self):
        assert MLFilter._detect_host_type("https://docker.internal.example.com") == "docker"

    def test_standard_host(self):
        assert MLFilter._detect_host_type("https://www.example.com") == "standard"

    def test_empty_host(self):
        assert MLFilter._detect_host_type("") == "standard"

    def test_none_host(self):
        assert MLFilter._detect_host_type(None) == "standard"


# ── _extract_status_code ──────────────────────────────────────────────────────

class TestExtractStatusCode:
    def test_200_from_valid_response(self):
        resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        assert MLFilter._extract_status_code(resp) == "200"

    def test_404_status(self):
        resp = "HTTP/1.1 404 Not Found\r\n"
        assert MLFilter._extract_status_code(resp) == "404"

    def test_500_status(self):
        resp = "HTTP/1.1 500 Internal Server Error\r\n"
        assert MLFilter._extract_status_code(resp) == "500"

    def test_302_redirect(self):
        resp = "HTTP/1.1 302 Found\r\nLocation: https://other.com\r\n"
        assert MLFilter._extract_status_code(resp) == "302"

    def test_http2_response(self):
        resp = "HTTP/2 200\r\ncontent-type: text/html\r\n"
        assert MLFilter._extract_status_code(resp) == "200"

    def test_empty_response_defaults_200(self):
        assert MLFilter._extract_status_code("") == "200"

    def test_none_response_defaults_200(self):
        assert MLFilter._extract_status_code(None) == "200"

    def test_no_http_prefix_defaults_200(self):
        assert MLFilter._extract_status_code("just some text") == "200"


# ── _extract_features ─────────────────────────────────────────────────────────

class TestExtractFeatures:
    def _sample_finding(self):
        return {
            "response": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
            "request": "GET / HTTP/1.1\r\nHost: example.com\r\n",
            "extracted-results": ["result1", "result2"],
            "host": "https://api.example.com",
            "info": {"severity": "high", "tags": ["sqli", "cve"]},
        }

    def test_returns_list_of_8_features(self):
        features = MLFilter._extract_features(self._sample_finding())
        assert features is not None
        assert len(features) == 8

    def test_response_len_is_first_feature(self):
        finding = self._sample_finding()
        features = MLFilter._extract_features(finding)
        assert features[0] == len(finding["response"])

    def test_request_len_is_second_feature(self):
        finding = self._sample_finding()
        features = MLFilter._extract_features(finding)
        assert features[1] == len(finding["request"])

    def test_empty_finding_returns_8_features(self):
        features = MLFilter._extract_features({})
        assert features is not None
        assert len(features) == 8

    def test_all_features_are_numeric(self):
        features = MLFilter._extract_features(self._sample_finding())
        for i, feat in enumerate(features):
            assert isinstance(feat, numbers.Number), f"Feature {i} is not numeric: {feat!r}"


# ── _encode_categorical ───────────────────────────────────────────────────────

class TestEncodeCategorical:
    def setup_method(self):
        self._orig_encoders = MLFilter._label_encoders
        MLFilter._label_encoders = None

    def teardown_method(self):
        MLFilter._label_encoders = self._orig_encoders

    def test_no_encoders_returns_0(self):
        assert MLFilter._encode_categorical("severity", "high") == 0

    def test_encoder_not_found_returns_0(self):
        MLFilter._label_encoders = {}
        assert MLFilter._encode_categorical("severity", "high") == 0

    def test_value_not_in_encoder_classes_returns_0(self):
        class FakeEncoder:
            classes_ = ["low", "info"]
            def transform(self, vals):
                return [0]
        MLFilter._label_encoders = {"severity": FakeEncoder()}
        assert MLFilter._encode_categorical("severity", "critical") == 0
