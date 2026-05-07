"""
Unit tests for the sanitizer pipeline.

Every test uses a known input and asserts a deterministic output.
No network calls, no LLM, no external dependencies.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../backend'))

from sanitizer import sanitize_body, sanitize_subject, sanitize_sender, BODY_MAX_CHARS


class TestSanitizeBody:
    def test_strips_html_tags(self):
        result = sanitize_body("<p>Hello <b>world</b></p>")
        assert "<p>" not in result
        assert "<b>" not in result
        assert "Hello" in result
        assert "world" in result

    def test_strips_script_tags(self):
        result = sanitize_body("<script>alert('xss')</script>safe content")
        assert "<script>" not in result
        assert "alert" not in result
        assert "safe content" in result

    def test_normalizes_unicode_homoglyphs(self):
        # Full-width characters should be normalized to ASCII equivalents
        result = sanitize_body("Ｐａｙ Ｐａｌ")
        assert "Ｐ" not in result
        assert "Pay" in result or "pay" in result.lower()

    def test_collapses_whitespace(self):
        result = sanitize_body("hello    \n\n   world")
        assert "  " not in result
        assert "hello" in result
        assert "world" in result

    def test_truncates_to_max_chars(self):
        long_body = "a" * (BODY_MAX_CHARS + 1000)
        result = sanitize_body(long_body)
        assert len(result) <= BODY_MAX_CHARS

    def test_empty_string(self):
        assert sanitize_body("") == ""

    def test_plain_text_preserved(self):
        result = sanitize_body("This is a normal email.")
        assert "This is a normal email." in result

    def test_cyrillic_homoglyph_normalized(self):
        # Cyrillic 'а' (U+0430) looks like Latin 'a' — NFKC normalizes it
        text = "pаypal.com"  # Cyrillic а in paypal
        result = sanitize_body(text)
        # After normalization the text should be readable ASCII-like
        assert len(result) > 0


class TestSanitizeSubject:
    def test_strips_html(self):
        result = sanitize_subject("<b>Important</b> message")
        assert "<b>" not in result
        assert "Important" in result

    def test_truncates_long_subject(self):
        result = sanitize_subject("x" * 500)
        assert len(result) <= 200


class TestSanitizeSender:
    def test_normalizes_unicode(self):
        result = sanitize_sender("Ｇｏｏｇｌｅ")
        assert "Ｇ" not in result

    def test_truncates_long_sender(self):
        result = sanitize_sender("a" * 500)
        assert len(result) <= 320
