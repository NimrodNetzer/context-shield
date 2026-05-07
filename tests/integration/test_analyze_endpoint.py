"""
Integration tests for POST /analyze.

Tests the full pipeline: request validation → sanitization → heuristics →
LLM (mocked) → response. Verifies that the endpoint behaves correctly
end-to-end without making real external API calls.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../backend'))

import json
import pytest
from unittest.mock import patch


class TestAnalyzeEndpoint:
    def test_health_check(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_analyze_clean_email_heuristics_only(self, client, sample_email):
        with patch("analyzer.call_llm", side_effect=Exception("Groq down")):
            resp = client.post("/analyze", json=sample_email)
        assert resp.status_code == 200
        data = resp.json()
        assert data["analysis_source"] == "heuristics_only"
        assert "score" in data
        assert "verdict" in data
        assert isinstance(data["reasoning"], list)

    def test_analyze_with_llm_response(self, client, sample_email):
        from models import Verdict
        mock_return = (15, Verdict.SAFE, ["SPF and DKIM pass", "Known sender domain"])
        with patch("analyzer.call_llm", return_value=mock_return):
            with patch("heuristics.check_urls", return_value=[]):
                resp = client.post("/analyze", json=sample_email)
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "SAFE"
        assert data["score"] == 15
        assert data["analysis_source"] == "heuristics+llm"

    def test_analyze_phishing_email_high_score(self, client, phishing_email):
        from models import Verdict
        mock_return = (95, Verdict.MALICIOUS, ["Multiple spoofing signals detected"])
        with patch("analyzer.call_llm", return_value=mock_return):
            with patch("heuristics.check_urls", return_value=[]):
                resp = client.post("/analyze", json=phishing_email)
        assert resp.status_code == 200
        data = resp.json()
        assert data["score"] >= 65   # score_floor from heuristics
        assert data["verdict"] in ("SUSPICIOUS", "MALICIOUS")
        assert len(data["signals"]) > 0

    def test_analyze_rejects_extra_fields(self, client, sample_email):
        payload = {**sample_email, "injected": "evil"}
        resp = client.post("/analyze", json=payload)
        assert resp.status_code == 422

    def test_analyze_rejects_missing_message_id(self, client):
        resp = client.post("/analyze", json={"sender": "test@example.com"})
        assert resp.status_code == 422

    def test_analyze_rejects_oversized_body(self, client, sample_email):
        payload = {**sample_email, "body_plain": "x" * 20_000}
        resp = client.post("/analyze", json=payload)
        assert resp.status_code == 422

    def test_analyze_dkim_fail_sets_score_floor(self, client, sample_email):
        payload = {**sample_email, "headers": {"spf": "pass", "dkim": "fail", "dmarc": "pass"}}
        with patch("analyzer.call_llm", side_effect=Exception("Groq down")):
            resp = client.post("/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["score"] >= 40   # DKIM fail floor
        assert any(s["type"] == "dkim_fail" for s in data["signals"])

    def test_analyze_dangerous_attachment_in_signals(self, client, sample_email):
        payload = {**sample_email, "attachment_names": ["payload.exe"]}
        with patch("analyzer.call_llm", side_effect=Exception("Groq down")):
            resp = client.post("/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        signal_types = [s["type"] for s in data["signals"]]
        assert "dangerous_attachment" in signal_types

    def test_analyze_safe_browsing_hit_critical(self, client, sample_email):
        payload = {**sample_email, "body_plain": "Click: https://evil-phishing-site.com"}
        sb_match = [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "https://evil-phishing-site.com"}}]
        mock_return = (90, __import__('models').Verdict.MALICIOUS, ["Known phishing URL detected"])
        with patch("heuristics.check_urls", return_value=sb_match):
            with patch("analyzer.call_llm", return_value=mock_return):
                resp = client.post("/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert any(s["type"] == "safe_browsing_hit" for s in data["signals"])

    def test_analyze_returns_correct_response_shape(self, client, sample_email):
        with patch("analyzer.call_llm", side_effect=Exception("Groq down")):
            resp = client.post("/analyze", json=sample_email)
        data = resp.json()
        assert "score" in data
        assert "verdict" in data
        assert "reasoning" in data
        assert "signals" in data
        assert "analysis_source" in data
        assert isinstance(data["score"], int)
        assert 0 <= data["score"] <= 100
