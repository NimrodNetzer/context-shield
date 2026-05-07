from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Verdict(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Inbound request — strict schema, no extra fields allowed
# ---------------------------------------------------------------------------

class EmailHeaders(BaseModel):
    model_config = {"extra": "ignore"}

    spf: Literal["pass", "fail", "softfail", "neutral", "none"] | None = None
    dkim: Literal["pass", "fail", "none"] | None = None
    dmarc: Literal["pass", "fail", "none"] | None = None


class AnalyzeRequest(BaseModel):
    """
    Everything the add-on sends. Fields are strictly bounded — oversized or
    unexpected input is rejected before it touches any analysis logic.
    """
    model_config = {"extra": "forbid"}

    message_id: str = Field(..., min_length=1, max_length=64)
    sender: str = Field(..., min_length=1, max_length=320)
    reply_to: str | None = Field(default=None, max_length=320)
    subject: str = Field(default="", max_length=998)
    body_plain: str = Field(default="", max_length=16_000)
    headers: EmailHeaders = Field(default_factory=EmailHeaders)
    attachment_names: list[str] = Field(default_factory=list)

    @field_validator("attachment_names")
    @classmethod
    def validate_attachment_names(cls, v: list[str]) -> list[str]:
        # Silently truncate list and individual names rather than rejecting
        return [name[:255] for name in v[:20]]


# ---------------------------------------------------------------------------
# Signal — produced by heuristics, consumed by LLM prompt + UI
# ---------------------------------------------------------------------------

class Signal(BaseModel):
    type: str
    severity: Severity
    value: str | None = None


# ---------------------------------------------------------------------------
# Outbound response
# ---------------------------------------------------------------------------

class AnalyzeResponse(BaseModel):
    score: int = Field(..., ge=0, le=100)
    verdict: Verdict
    reasoning: list[str] = Field(..., min_length=1, max_length=5)
    signals: list[Signal] = Field(default_factory=list)
    analysis_source: Literal["heuristics_only", "heuristics+llm"] = "heuristics+llm"


# ---------------------------------------------------------------------------
# Internal: heuristic result passed to the analyzer
# ---------------------------------------------------------------------------

class HeuristicResult(BaseModel):
    signals: list[Signal] = Field(default_factory=list)
    score_floor: int = Field(default=0, ge=0, le=100)
