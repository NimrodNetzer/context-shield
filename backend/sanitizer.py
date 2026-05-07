"""
Input sanitization pipeline.

Every field that originated from an email (untrusted external input) passes
through here before touching heuristics or the LLM prompt. The goal is to
normalize and bound the data so downstream code operates on a predictable,
safe surface.

Stages:
  1. Strip HTML tags
  2. NFKC Unicode normalization  — defeats homoglyph confusion in body text
  3. Collapse whitespace
  4. Hard truncation to LLM-safe length
"""

import re
import unicodedata
from html.parser import HTMLParser

BODY_MAX_CHARS = 4_000
SUBJECT_MAX_CHARS = 200
SENDER_MAX_CHARS = 320


_SKIP_TAGS = {"script", "style", "head", "noscript"}


class _HTMLStripper(HTMLParser):
    """Extract plain text from HTML, skipping script/style content."""

    def __init__(self) -> None:
        super().__init__()
        self._parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() in _SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in _SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0:
            self._parts.append(data)

    def get_text(self) -> str:
        return " ".join(self._parts)


def _strip_html(text: str) -> str:
    stripper = _HTMLStripper()
    stripper.feed(text)
    return stripper.get_text()


def _normalize_unicode(text: str) -> str:
    # NFKC folds compatibility characters (e.g. ＰａｙＰａｌ → PayPal)
    return unicodedata.normalize("NFKC", text)


def _collapse_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _truncate(text: str, max_chars: int) -> str:
    return text[:max_chars]


def sanitize_body(raw: str) -> str:
    text = _strip_html(raw)
    text = _normalize_unicode(text)
    text = _collapse_whitespace(text)
    text = _truncate(text, BODY_MAX_CHARS)
    return text


def sanitize_subject(raw: str) -> str:
    text = _strip_html(raw)
    text = _normalize_unicode(text)
    text = _collapse_whitespace(text)
    text = _truncate(text, SUBJECT_MAX_CHARS)
    return text


def sanitize_sender(raw: str) -> str:
    text = _normalize_unicode(raw)
    text = _collapse_whitespace(text)
    text = _truncate(text, SENDER_MAX_CHARS)
    return text
