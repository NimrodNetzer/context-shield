"""
Shared fixtures for all tests.

Sets environment variables before any module import so the backend
initializes correctly in test mode (no real API keys needed).
"""

import os
import pytest

os.environ.setdefault("GROQ_API_KEY", "test-key")
os.environ.setdefault("GOOGLE_SAFE_BROWSING_KEY", "")
os.environ.setdefault("SERVICE_URL", "")        # empty = local dev mode, no OIDC
os.environ.setdefault("ALLOWED_SA_EMAILS", "")

from fastapi.testclient import TestClient
from main import app


@pytest.fixture
def client():
    """FastAPI test client with auth bypassed (SERVICE_URL is empty)."""
    return TestClient(app)


@pytest.fixture
def sample_email():
    """A minimal benign email payload."""
    return {
        "message_id": "test-msg-001",
        "sender": "newsletter@example.com",
        "reply_to": None,
        "subject": "Weekly digest",
        "body_plain": "Here is your weekly digest. Click here to read more.",
        "headers": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "attachment_names": [],
    }


@pytest.fixture
def phishing_email():
    """A clearly suspicious email payload that should trigger multiple signals."""
    return {
        "message_id": "test-msg-002",
        "sender": '"PayPal" <security@paypa1-verify.com>',
        "reply_to": "attacker@evil.com",
        "subject": "Urgent: verify your account now or it will be suspended",
        "body_plain": (
            "Your PayPal account has been suspended. "
            "Verify immediately: http://192.168.1.1/login or your account will be closed. "
            "Act now to avoid permanent suspension."
        ),
        "headers": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        "attachment_names": ["invoice.exe"],
    }
