"""
Unit tests for Pydantic request/response models.

Tests the strict schema validation that is our first line of defense
against malformed or oversized input from the add-on.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../backend'))

import pytest
from pydantic import ValidationError
from models import AnalyzeRequest, AnalyzeResponse, EmailHeaders, Verdict, Severity, Signal


class TestAnalyzeRequest:
    def test_valid_minimal_request(self):
        req = AnalyzeRequest(message_id="msg-001", sender="test@example.com")
        assert req.message_id == "msg-001"
        assert req.body_plain == ""
        assert req.attachment_names == []

    def test_rejects_extra_fields(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(
                message_id="msg-001",
                sender="test@example.com",
                injected_field="evil",
            )

    def test_rejects_empty_message_id(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(message_id="", sender="test@example.com")

    def test_rejects_oversized_message_id(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(message_id="x" * 65, sender="test@example.com")

    def test_rejects_oversized_sender(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(message_id="msg-001", sender="a" * 321)

    def test_truncates_attachment_names(self):
        req = AnalyzeRequest(
            message_id="msg-001",
            sender="test@example.com",
            attachment_names=["file_" + str(i) + ".pdf" for i in range(25)],
        )
        assert len(req.attachment_names) == 20

    def test_rejects_oversized_body(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(
                message_id="msg-001",
                sender="test@example.com",
                body_plain="x" * 16_001,
            )


class TestEmailHeaders:
    def test_valid_pass_values(self):
        h = EmailHeaders(spf="pass", dkim="pass", dmarc="pass")
        assert h.spf == "pass"

    def test_valid_fail_values(self):
        h = EmailHeaders(spf="fail", dkim="fail", dmarc="fail")
        assert h.spf == "fail"

    def test_rejects_invalid_spf_value(self):
        with pytest.raises(ValidationError):
            EmailHeaders(spf="invalid_value")

    def test_none_values_allowed(self):
        h = EmailHeaders()
        assert h.spf is None
        assert h.dkim is None
        assert h.dmarc is None

    def test_ignores_unknown_fields(self):
        # EmailHeaders uses extra="ignore"
        h = EmailHeaders(spf="pass", unknown_header="value")
        assert not hasattr(h, "unknown_header")


class TestVerdictEnum:
    def test_valid_verdicts(self):
        assert Verdict("SAFE") == Verdict.SAFE
        assert Verdict("SUSPICIOUS") == Verdict.SUSPICIOUS
        assert Verdict("MALICIOUS") == Verdict.MALICIOUS

    def test_invalid_verdict_raises(self):
        with pytest.raises(ValueError):
            Verdict("UNKNOWN")


class TestSignal:
    def test_signal_without_value(self):
        s = Signal(type="dkim_fail", severity=Severity.HIGH)
        assert s.value is None

    def test_signal_with_value(self):
        s = Signal(type="reply_to_mismatch", severity=Severity.HIGH, value="evil.com")
        assert s.value == "evil.com"


class TestAnalyzeResponse:
    def test_score_clamped_to_100(self):
        with pytest.raises(ValidationError):
            AnalyzeResponse(score=101, verdict=Verdict.MALICIOUS, reasoning=["test"])

    def test_score_cannot_be_negative(self):
        with pytest.raises(ValidationError):
            AnalyzeResponse(score=-1, verdict=Verdict.SAFE, reasoning=["test"])

    def test_reasoning_must_not_be_empty(self):
        with pytest.raises(ValidationError):
            AnalyzeResponse(score=50, verdict=Verdict.SUSPICIOUS, reasoning=[])
