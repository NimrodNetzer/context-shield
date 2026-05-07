"""
Analyzer orchestrator.

Runs the two-stage pipeline and merges results:
  Stage 1: Heuristics  (fast, deterministic, no network)
  Stage 2: LLM         (Groq — synthesis and explanation)

Fallback: if Groq fails for any reason, the response is built from heuristics
alone. The service never returns a 500 to the add-on due to an LLM outage.
"""

import logging

from groq_client import call_llm
from heuristics import run_heuristics
from models import AnalyzeRequest, AnalyzeResponse, Verdict
from sanitizer import sanitize_body, sanitize_sender, sanitize_subject

logger = logging.getLogger(__name__)


def _heuristic_verdict(score: int) -> Verdict:
    if score >= 70:
        return Verdict.MALICIOUS
    if score >= 40:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE


def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    # ------------------------------------------------------------------
    # Stage 0: Sanitize all untrusted string fields
    # ------------------------------------------------------------------
    sender = sanitize_sender(request.sender)
    reply_to = sanitize_sender(request.reply_to) if request.reply_to else None
    subject = sanitize_subject(request.subject)
    body = sanitize_body(request.body_plain)

    # ------------------------------------------------------------------
    # Stage 1: Heuristics — primary security layer
    # ------------------------------------------------------------------
    heuristic_result = run_heuristics(
        sender=sender,
        reply_to=reply_to,
        subject=subject,
        body=body,
        headers=request.headers,
        attachment_names=request.attachment_names,
    )

    score_floor = heuristic_result.score_floor
    signals = heuristic_result.signals

    # ------------------------------------------------------------------
    # Stage 2: LLM synthesis — explanation layer
    # Falls back gracefully if Groq is unavailable.
    # ------------------------------------------------------------------
    try:
        score, verdict, reasoning = call_llm(
            sender=sender,
            reply_to=reply_to,
            subject=subject,
            body=body,
            signals=signals,
            score_floor=score_floor,
        )
        source = "heuristics+llm"
    except Exception as exc:
        logger.warning("LLM call failed, falling back to heuristics-only: %s", exc)
        score = max(score_floor, 10)   # baseline if no signals
        verdict = _heuristic_verdict(score)
        reasoning = [
            "Analysis based on email metadata and header checks.",
            *(
                f"{s.type.replace('_', ' ').capitalize()}: {s.value or ''}"
                for s in signals[:4]
            ),
        ] or ["No signals detected."]
        source = "heuristics_only"

    return AnalyzeResponse(
        score=score,
        verdict=verdict,
        reasoning=reasoning,
        signals=signals,
        analysis_source=source,
    )
