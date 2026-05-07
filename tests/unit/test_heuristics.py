"""
Unit tests for the heuristic signal extraction engine.

These are the most important tests in the suite — heuristics are the primary
security layer. Every test uses a known, deterministic input and asserts the
exact signals and score_floor produced.

The false positive regression tests (e.g. legitimate Google subdomains) are
here to prevent regressions after bug fixes.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../backend'))

from unittest.mock import patch
from models import EmailHeaders, Severity
from heuristics import run_heuristics


def _run(sender="test@example.com", reply_to=None, subject="",
         body="", spf="pass", dkim="pass", dmarc="pass", attachments=None):
    headers = EmailHeaders(spf=spf, dkim=dkim, dmarc=dmarc)
    with patch("heuristics.check_urls", return_value=[]):
        return run_heuristics(
            sender=sender,
            reply_to=reply_to,
            subject=subject,
            body=body,
            headers=headers,
            attachment_names=attachments or [],
        )


def _signal_types(result):
    return [s.type for s in result.signals]


# ---------------------------------------------------------------------------
# Auth headers
# ---------------------------------------------------------------------------

class TestAuthHeaders:
    def test_all_pass_no_signals(self):
        result = _run(spf="pass", dkim="pass", dmarc="pass")
        assert "dkim_fail" not in _signal_types(result)
        assert "spf_fail" not in _signal_types(result)
        assert "dmarc_fail" not in _signal_types(result)
        assert result.score_floor == 0

    def test_dkim_fail_signal(self):
        result = _run(dkim="fail")
        assert "dkim_fail" in _signal_types(result)
        assert result.score_floor >= 40

    def test_spf_fail_signal(self):
        result = _run(spf="fail")
        assert "spf_fail" in _signal_types(result)
        assert result.score_floor >= 35

    def test_spf_softfail_signal(self):
        result = _run(spf="softfail")
        assert "spf_fail" in _signal_types(result)

    def test_dmarc_fail_signal(self):
        result = _run(dmarc="fail")
        assert "dmarc_fail" in _signal_types(result)
        assert result.score_floor >= 35

    def test_all_three_fail_high_floor(self):
        result = _run(spf="fail", dkim="fail", dmarc="fail")
        assert result.score_floor >= 75


# ---------------------------------------------------------------------------
# Reply-To mismatch
# ---------------------------------------------------------------------------

class TestReplyToMismatch:
    def test_same_domain_no_signal(self):
        result = _run(
            sender="support@company.com",
            reply_to="help@company.com",
        )
        assert "reply_to_mismatch" not in _signal_types(result)

    def test_different_domain_signal(self):
        result = _run(
            sender="support@company.com",
            reply_to="attacker@evil.com",
        )
        assert "reply_to_mismatch" in _signal_types(result)
        assert result.score_floor >= 40

    def test_no_reply_to_no_signal(self):
        result = _run(sender="test@example.com", reply_to=None)
        assert "reply_to_mismatch" not in _signal_types(result)


# ---------------------------------------------------------------------------
# Display name spoofing
# ---------------------------------------------------------------------------

class TestDisplayNameSpoofing:
    def test_legit_sender_no_signal(self):
        result = _run(sender='"Google" <noreply@google.com>')
        assert "display_name_spoofing" not in _signal_types(result)

    def test_spoofed_display_name(self):
        result = _run(sender='"PayPal" <noreply@attacker.com>')
        assert "display_name_spoofing" in _signal_types(result)
        assert result.score_floor >= 70

    def test_google_subdomain_not_spoofing(self):
        # Regression: accounts.google.com should NOT be flagged
        result = _run(sender='"Google" <no-reply@accounts.google.com>')
        assert "display_name_spoofing" not in _signal_types(result)

    def test_amazon_subdomain_not_spoofing(self):
        result = _run(sender='"Amazon" <noreply@email.amazon.com>')
        assert "display_name_spoofing" not in _signal_types(result)


# ---------------------------------------------------------------------------
# Homoglyph domain
# ---------------------------------------------------------------------------

class TestHomoglyphDomain:
    def test_legit_google_no_signal(self):
        result = _run(sender="test@google.com")
        assert "homoglyph_domain" not in _signal_types(result)

    def test_legit_google_subdomain_no_signal(self):
        # Regression: accounts.google.com was falsely flagged before the fix
        result = _run(sender="no-reply@accounts.google.com")
        assert "homoglyph_domain" not in _signal_types(result)

    def test_homoglyph_paypal(self):
        # paypa1.com — digit 1 instead of l
        result = _run(sender="support@paypa1.com")
        assert "homoglyph_domain" in _signal_types(result)
        assert result.score_floor >= 75


# ---------------------------------------------------------------------------
# Attachments
# ---------------------------------------------------------------------------

class TestAttachments:
    def test_safe_pdf_no_signal(self):
        result = _run(attachments=["document.pdf"])
        assert "dangerous_attachment" not in _signal_types(result)

    def test_exe_attachment_critical(self):
        result = _run(attachments=["invoice.exe"])
        assert "dangerous_attachment" in _signal_types(result)
        signal = next(s for s in result.signals if s.type == "dangerous_attachment")
        assert signal.severity == Severity.CRITICAL
        assert result.score_floor >= 65

    def test_ps1_attachment(self):
        result = _run(attachments=["setup.ps1"])
        assert "dangerous_attachment" in _signal_types(result)

    def test_macro_office_attachment(self):
        result = _run(attachments=["budget.xlsm"])
        assert "dangerous_attachment" in _signal_types(result)

    def test_multiple_attachments_one_dangerous(self):
        result = _run(attachments=["report.pdf", "invoice.exe", "notes.txt"])
        types = _signal_types(result)
        assert "dangerous_attachment" in types


# ---------------------------------------------------------------------------
# URL checks
# ---------------------------------------------------------------------------

class TestURLChecks:
    def test_private_ip_url_ssrf(self):
        result = _run(body="Click here: http://192.168.1.1/login")
        assert "ssrf_risk_url" in _signal_types(result)
        assert result.score_floor >= 80

    def test_localhost_url_ssrf(self):
        result = _run(body="Visit http://127.0.0.1/admin")
        assert "ssrf_risk_url" in _signal_types(result)

    def test_suspicious_tld(self):
        result = _run(body="Win a prize at https://winner.xyz/claim")
        assert "suspicious_tld" in _signal_types(result)

    def test_url_shortener(self):
        result = _run(body="Click: https://bit.ly/abc123")
        assert "url_shortener" in _signal_types(result)

    def test_ip_as_hostname(self):
        result = _run(body="Login at http://123.456.789.0/login")
        assert "ip_as_hostname" in _signal_types(result)

    def test_normal_https_url_no_signal(self):
        result = _run(body="Visit https://www.google.com for more info")
        types = _signal_types(result)
        assert "ssrf_risk_url" not in types
        assert "ip_as_hostname" not in types


# ---------------------------------------------------------------------------
# Urgency language
# ---------------------------------------------------------------------------

class TestUrgencyLanguage:
    def test_no_urgency_no_signal(self):
        result = _run(body="Here is your monthly newsletter.")
        assert "urgency_language" not in _signal_types(result)

    def test_single_urgency_pattern_low(self):
        result = _run(body="Please verify your account to continue.")
        assert "urgency_language" in _signal_types(result)
        signal = next(s for s in result.signals if s.type == "urgency_language")
        assert signal.severity == Severity.LOW

    def test_multiple_urgency_patterns_medium(self):
        result = _run(body=(
            "Your account has been suspended. "
            "Verify your account now or it will be closed. "
            "Act immediately to avoid suspension."
        ))
        assert "urgency_language" in _signal_types(result)
        signal = next(s for s in result.signals if s.type == "urgency_language")
        assert signal.severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Score floor accumulation
# ---------------------------------------------------------------------------

class TestScoreFloor:
    def test_clean_email_zero_floor(self):
        result = _run(
            sender="newsletter@company.com",
            spf="pass", dkim="pass", dmarc="pass",
            body="Your weekly digest is ready.",
        )
        assert result.score_floor == 0

    def test_multiple_signals_highest_floor_wins(self):
        # DKIM fail (40) + dangerous attachment (65) → floor should be 65
        result = _run(dkim="fail", attachments=["malware.exe"])
        assert result.score_floor >= 65

    def test_all_signals_fires_high_floor(self):
        result = _run(
            sender='"PayPal" <support@paypa1.com>',
            reply_to="attacker@evil.com",
            spf="fail", dkim="fail", dmarc="fail",
            body="Verify your account now: http://192.168.0.1/login",
            attachments=["payload.exe"],
        )
        assert result.score_floor >= 75
        assert len(result.signals) >= 4
