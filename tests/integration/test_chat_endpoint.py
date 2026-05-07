"""
Integration tests for POST /chat.

Verifies the chat endpoint handles questions correctly,
enforces input limits, and fails gracefully when Groq is unavailable.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../backend'))

from unittest.mock import patch


class TestChatEndpoint:
    def _payload(self, question="Is this email safe?"):
        return {
            "question": question,
            "sender": "test@example.com",
            "subject": "Test email",
            "body_snippet": "Click here to verify your account.",
            "verdict": "SUSPICIOUS",
            "score": 55,
            "signals": [{"type": "urgency_language", "severity": "medium", "value": None}],
        }

    def test_chat_returns_answer(self, client):
        with patch("main.answer_question", return_value="This email looks suspicious due to urgency language."):
            resp = client.post("/chat", json=self._payload())
        assert resp.status_code == 200
        assert "answer" in resp.json()
        assert len(resp.json()["answer"]) > 0

    def test_chat_rejects_empty_question(self, client):
        resp = client.post("/chat", json=self._payload(question=""))
        assert resp.status_code == 422

    def test_chat_rejects_oversized_question(self, client):
        resp = client.post("/chat", json=self._payload(question="x" * 501))
        assert resp.status_code == 422

    def test_chat_rejects_extra_fields(self, client):
        payload = {**self._payload(), "injected": "evil"}
        resp = client.post("/chat", json=payload)
        assert resp.status_code == 422

    def test_chat_returns_500_when_groq_fails(self, client):
        with patch("main.answer_question", side_effect=Exception("Groq error")):
            resp = client.post("/chat", json=self._payload())
        assert resp.status_code == 500
