"""
Authentication and rate limiting.

Every request to /analyze must carry a Google-signed OIDC identity token in
the Authorization header (Bearer <token>). The token is issued by the Apps
Script runtime via ScriptApp.getIdentityToken().

Verification steps:
  1. Token must be signed by Google (fetched certs, RS256)
  2. issuer must be accounts.google.com
  3. audience must match our Cloud Run service URL exactly
  4. subject (sub) must be in the allowlist of permitted service accounts

Rate limiting is per-identity (keyed on token sub), not per-IP, so it cannot
be bypassed by rotating IPs while reusing the same credential.
"""

import os
import time
from collections import defaultdict
from threading import Lock

from fastapi import HTTPException, Request
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

# ---------------------------------------------------------------------------
# Configuration (injected from Secret Manager / env at runtime)
# ---------------------------------------------------------------------------

# The exact Cloud Run service URL — used as the expected OIDC audience.
# Must match what Apps Script sends as the target URL.
_EXPECTED_AUDIENCE = os.environ.get("SERVICE_URL", "")

# Comma-separated list of allowed Apps Script service account emails.
_ALLOWED_SUBJECTS_RAW = os.environ.get("ALLOWED_SA_EMAILS", "")
_ALLOWED_SUBJECTS: set[str] = {
    s.strip() for s in _ALLOWED_SUBJECTS_RAW.split(",") if s.strip()
}

_GOOGLE_ISSUER = "https://accounts.google.com"

# ---------------------------------------------------------------------------
# In-process rate limiter (token-bucket per identity)
# Swap for Redis if you ever run multiple Cloud Run instances.
# ---------------------------------------------------------------------------

_RATE_LIMIT_WINDOW = 60      # seconds
_RATE_LIMIT_MAX = 30         # requests per window per identity

_rate_store: dict[str, list[float]] = defaultdict(list)
_rate_lock = Lock()


def _check_rate_limit(subject: str) -> None:
    now = time.monotonic()
    with _rate_lock:
        timestamps = _rate_store[subject]
        # Evict entries outside the current window
        _rate_store[subject] = [t for t in timestamps if now - t < _RATE_LIMIT_WINDOW]
        if len(_rate_store[subject]) >= _RATE_LIMIT_MAX:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        _rate_store[subject].append(now)


# ---------------------------------------------------------------------------
# Public dependency — inject into FastAPI route
# ---------------------------------------------------------------------------

def verify_oidc_token(request: Request) -> str:
    """
    Validates the Bearer OIDC token and returns the subject (service account email).
    Raises HTTPException on any validation failure.

    In local dev mode (SERVICE_URL not set), authentication is bypassed entirely
    so the backend can be tested without a Google service account.
    """
    if not _EXPECTED_AUDIENCE:
        # Local dev mode — no OIDC verification
        return "local-dev"

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    token = auth_header.removeprefix("Bearer ").strip()

    try:
        claims = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            audience=_EXPECTED_AUDIENCE,
        )
    except Exception:
        # Intentionally opaque — don't leak why verification failed
        raise HTTPException(status_code=401, detail="Invalid token")

    if claims.get("iss") != _GOOGLE_ISSUER:
        raise HTTPException(status_code=401, detail="Invalid token")

    subject: str = claims.get("email") or claims.get("sub", "")

    if _ALLOWED_SUBJECTS and subject not in _ALLOWED_SUBJECTS:
        raise HTTPException(status_code=403, detail="Caller not permitted")

    _check_rate_limit(subject)
    return subject
