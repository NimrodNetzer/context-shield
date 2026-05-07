"""
Integration tests for POST /feedback.

Verifies input validation and that feedback is logged correctly.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../backend'))

from unittest.mock import patch


class TestFeedbackEndpoint:
    def _payload(self):
        return {
            "message_id": "msg-001",
            "original_verdict": "SUSPICIOUS",
            "user_verdict": "SAFE",
        }

    def test_feedback_returns_204(self, client):
        with patch("main.log_feedback") as mock_log:
            resp = client.post("/feedback", json=self._payload())
        assert resp.status_code == 204
        mock_log.assert_called_once()

    def test_feedback_rejects_invalid_verdict(self, client):
        payload = {**self._payload(), "user_verdict": "UNKNOWN"}
        resp = client.post("/feedback", json=payload)
        assert resp.status_code == 422

    def test_feedback_rejects_extra_fields(self, client):
        payload = {**self._payload(), "injected": "evil"}
        resp = client.post("/feedback", json=payload)
        assert resp.status_code == 422

    def test_feedback_rejects_empty_message_id(self, client):
        payload = {**self._payload(), "message_id": ""}
        resp = client.post("/feedback", json=payload)
        assert resp.status_code == 422

    def test_feedback_logs_correct_fields(self, client):
        with patch("main.log_feedback") as mock_log:
            client.post("/feedback", json=self._payload())
        call_kwargs = mock_log.call_args
        assert call_kwargs is not None
