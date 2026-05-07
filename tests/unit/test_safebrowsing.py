"""
Unit tests for the Safe Browsing API client.

All tests mock the HTTP call — no real API requests.
Tests verify that the client handles success, empty results,
API errors, and missing keys gracefully.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../backend'))

from unittest.mock import patch, MagicMock
import safebrowsing


class TestCheckUrls:
    def test_returns_empty_when_no_api_key(self):
        with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_KEY": ""}):
            result = safebrowsing.check_urls(["https://evil.com"])
            assert result == []

    def test_returns_empty_for_empty_url_list(self):
        with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_KEY": "test-key"}):
            result = safebrowsing.check_urls([])
            assert result == []

    def test_caps_urls_at_20(self):
        captured = []
        def mock_post(url, params, json, timeout):
            captured.append(json["threatInfo"]["threatEntries"])
            mock_resp = MagicMock()
            mock_resp.json.return_value = {}
            mock_resp.raise_for_status.return_value = None
            return mock_resp

        with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_KEY": "test-key"}):
            with patch("safebrowsing.requests.post", side_effect=mock_post):
                urls = ["https://example.com/" + str(i) for i in range(30)]
                safebrowsing.check_urls(urls)
                assert len(captured[0]) == 20

    def test_returns_matches_from_api(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "matches": [
                {"threatType": "MALWARE", "threat": {"url": "https://evil.com"}}
            ]
        }
        mock_resp.raise_for_status.return_value = None

        with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_KEY": "test-key"}):
            with patch("safebrowsing.requests.post", return_value=mock_resp):
                result = safebrowsing.check_urls(["https://evil.com"])
                assert len(result) == 1
                assert result[0]["threatType"] == "MALWARE"

    def test_returns_empty_on_api_error(self):
        with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_KEY": "test-key"}):
            with patch("safebrowsing.requests.post", side_effect=Exception("Network error")):
                result = safebrowsing.check_urls(["https://example.com"])
                assert result == []

    def test_returns_empty_when_no_matches(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {}  # no "matches" key = clean
        mock_resp.raise_for_status.return_value = None

        with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_KEY": "test-key"}):
            with patch("safebrowsing.requests.post", return_value=mock_resp):
                result = safebrowsing.check_urls(["https://safe-site.com"])
                assert result == []


import os
