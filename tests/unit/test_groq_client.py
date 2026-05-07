"""
Unit tests for the Groq LLM client.

Tests focus on:
  1. Output parsing and validation (score clamping, verdict enforcement)
  2. Prompt injection defense (score_floor cannot be overridden)
  3. Malformed LLM output rejection
  4. Score-verdict consistency enforcement

No real Groq API calls are made — all LLM responses are mocked.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../backend'))

import json
import pytest
from unittest.mock import MagicMock, patch
from models import Verdict
import groq_client


def _parse(raw: str, floor: int = 0):
    return groq_client._parse_llm_response(raw, floor)


class TestParseLLMResponse:
    def test_valid_safe_response(self):
        raw = json.dumps({
            "score": 10,
            "verdict": "SAFE",
            "reasoning": ["SPF and DKIM pass", "Known sender"],
        })
        score, verdict, reasoning = _parse(raw, 0)
        assert score == 10
        assert verdict == Verdict.SAFE
        assert len(reasoning) == 2

    def test_valid_malicious_response(self):
        raw = json.dumps({
            "score": 90,
            "verdict": "MALICIOUS",
            "reasoning": ["Homoglyph domain", "DKIM fail"],
        })
        score, verdict, _ = _parse(raw, 0)
        assert score == 90
        assert verdict == Verdict.MALICIOUS

    def test_score_floor_enforced(self):
        # LLM returns 10 but floor is 75 — floor must win
        raw = json.dumps({
            "score": 10,
            "verdict": "SAFE",
            "reasoning": ["Looks clean"],
        })
        score, verdict, _ = _parse(raw, floor=75)
        assert score == 75
        # Verdict must be adjusted to match clamped score
        assert verdict != Verdict.SAFE

    def test_score_clamped_to_100(self):
        raw = json.dumps({
            "score": 150,
            "verdict": "MALICIOUS",
            "reasoning": ["Very suspicious"],
        })
        score, _, _ = _parse(raw, 0)
        assert score == 100

    def test_score_cannot_go_below_floor(self):
        raw = json.dumps({
            "score": 0,
            "verdict": "SAFE",
            "reasoning": ["Clean"],
        })
        score, _, _ = _parse(raw, floor=60)
        assert score == 60

    def test_rejects_non_json(self):
        with pytest.raises(ValueError):
            _parse("This is not JSON", 0)

    def test_rejects_invalid_verdict(self):
        raw = json.dumps({
            "score": 50,
            "verdict": "DEFINITELY_EVIL",
            "reasoning": ["Bad"],
        })
        with pytest.raises(ValueError):
            _parse(raw, 0)

    def test_rejects_empty_reasoning(self):
        raw = json.dumps({
            "score": 50,
            "verdict": "SUSPICIOUS",
            "reasoning": [],
        })
        with pytest.raises(ValueError):
            _parse(raw, 0)

    def test_reasoning_capped_at_5(self):
        raw = json.dumps({
            "score": 50,
            "verdict": "SUSPICIOUS",
            "reasoning": ["r1", "r2", "r3", "r4", "r5", "r6", "r7"],
        })
        _, _, reasoning = _parse(raw, 0)
        assert len(reasoning) <= 5

    def test_reasoning_strings_capped_at_120_chars(self):
        raw = json.dumps({
            "score": 50,
            "verdict": "SUSPICIOUS",
            "reasoning": ["x" * 200],
        })
        _, _, reasoning = _parse(raw, 0)
        assert all(len(r) <= 120 for r in reasoning)

    def test_score_verdict_consistency_high_score_forces_malicious(self):
        # Score 80 but verdict says SAFE — must be corrected
        raw = json.dumps({
            "score": 80,
            "verdict": "SAFE",
            "reasoning": ["Looks fine"],
        })
        _, verdict, _ = _parse(raw, 0)
        assert verdict == Verdict.MALICIOUS

    def test_score_verdict_consistency_mid_score_not_safe(self):
        # Score 55 but verdict says SAFE — must be corrected to SUSPICIOUS
        raw = json.dumps({
            "score": 55,
            "verdict": "SAFE",
            "reasoning": ["Borderline"],
        })
        _, verdict, _ = _parse(raw, 0)
        assert verdict == Verdict.SUSPICIOUS


class TestSystemPromptContent:
    def test_system_prompt_contains_score_floor(self):
        from models import Signal, Severity
        signals = [Signal(type="dkim_fail", severity=Severity.HIGH)]
        prompt = groq_client._build_system_prompt(signals, score_floor=75)
        assert "75" in prompt

    def test_system_prompt_warns_about_adversarial_input(self):
        prompt = groq_client._build_system_prompt([], score_floor=0)
        assert "adversarial" in prompt.lower() or "untrusted" in prompt.lower()

    def test_user_message_wraps_content_in_xml_delimiters(self):
        msg = groq_client._build_user_message(
            sender="test@example.com",
            subject="Test",
            body="body content",
            reply_to=None,
        )
        assert "<untrusted_email_content>" in msg
        assert "</untrusted_email_content>" in msg

    def test_system_prompt_includes_signal_info(self):
        from models import Signal, Severity
        signals = [Signal(type="spf_fail", severity=Severity.HIGH)]
        prompt = groq_client._build_system_prompt(signals, score_floor=0)
        assert "spf_fail" in prompt
