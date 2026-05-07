"""
ContextShield — FastAPI backend entry point.

Exposes three endpoints:
  POST /analyze   — authenticated, rate-limited email analysis
  POST /feedback  — authenticated, user verdict correction logging
  GET  /health    — unauthenticated liveness probe for Cloud Run

Security headers are added to every response via middleware.
Errors never leak internal details to the caller.
"""

import logging
import time

from dotenv import load_dotenv
load_dotenv()  # loads .env when running locally; no-op in production

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from analyzer import analyze
from auth import verify_oidc_token
from feedback import log_feedback
from models import AnalyzeRequest, AnalyzeResponse
from pydantic import BaseModel, Field
from typing import Literal

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="ContextShield",
    docs_url=None,    # disable Swagger UI in production
    redoc_url=None,
)

# ---------------------------------------------------------------------------
# CORS — allow only the Google Workspace add-on origin
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://mail.google.com"],
    allow_methods=["POST", "GET"],
    allow_headers=["Authorization", "Content-Type"],
)


# ---------------------------------------------------------------------------
# Security response headers middleware
# ---------------------------------------------------------------------------
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------------------
# Request timing middleware (logged, not exposed to client)
# ---------------------------------------------------------------------------
@app.middleware("http")
async def log_timing(request: Request, call_next):
    start = time.monotonic()
    response = await call_next(request)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        "method=%s path=%s status=%d duration_ms=%d",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    return response


# ---------------------------------------------------------------------------
# Global exception handler — never leak stack traces to the client
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_email(
    request: AnalyzeRequest,
    _caller: str = Depends(verify_oidc_token),
):
    """
    Analyzes a Gmail message and returns a maliciousness score, verdict,
    reasoning, and typed signals.

    Authentication: Google OIDC Bearer token required.
    Rate limit: 30 requests / 60 seconds per caller identity.
    """
    try:
        result = analyze(request)
    except Exception:
        logger.exception("Analysis failed for message_id=%s", request.message_id)
        raise HTTPException(status_code=500, detail="Analysis failed")

    # Log verdict (no email content — only identifiers and outcome)
    logger.info(
        "analyzed message_id=%s verdict=%s score=%d source=%s signals=%d",
        request.message_id,
        result.verdict,
        result.score,
        result.analysis_source,
        len(result.signals),
    )

    return result


class FeedbackRequest(BaseModel):
    model_config = {"extra": "forbid"}
    message_id: str = Field(..., min_length=1, max_length=64)
    original_verdict: Literal["SAFE", "SUSPICIOUS", "MALICIOUS"]
    user_verdict: Literal["SAFE", "MALICIOUS"]


@app.post("/feedback", status_code=204)
async def submit_feedback(
    request: FeedbackRequest,
    caller: str = Depends(verify_oidc_token),
):
    """
    Records a user correction to a verdict.
    Used to flag false positives and false negatives.
    """
    log_feedback(
        message_id=request.message_id,
        original_verdict=request.original_verdict,
        user_verdict=request.user_verdict,
        caller=caller,
    )
