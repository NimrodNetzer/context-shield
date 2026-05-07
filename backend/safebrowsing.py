"""
Google Safe Browsing API v4 client.

Checks extracted URLs against Google's threat intelligence database —
the same database used by Chrome, Firefox, and Safari to block malicious sites.

This transforms URL analysis from pattern-matching (suspicious TLD, IP hostname)
to ground-truth threat intelligence. A URL that looks syntactically clean but is
known-malicious will be caught here.

Security design:
- Only URLs already extracted and sanitized by heuristics.py are passed here
- Maximum 20 URLs per request (API limit and DoS prevention)
- 2-second timeout on the API call
- If the API is unavailable, returns empty list (fail open — heuristics still run)
- API key never logged
"""

import logging
import os

import requests

logger = logging.getLogger(__name__)

_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_TIMEOUT = 2  # seconds

_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",   # phishing
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

_PLATFORM_TYPES = ["ANY_PLATFORM"]
_THREAT_ENTRY_TYPES = ["URL"]


def check_urls(urls: list[str]) -> list[dict]:
    """
    Checks up to 20 URLs against Google Safe Browsing.
    Returns a list of threat match dicts for any flagged URLs.
    Returns empty list if API key is not set or call fails.
    """
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "")
    if not api_key or not urls:
        return []

    urls = urls[:20]

    payload = {
        "client": {
            "clientId": "contextshield",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": _THREAT_TYPES,
            "platformTypes": _PLATFORM_TYPES,
            "threatEntryTypes": _THREAT_ENTRY_TYPES,
            "threatEntries": [{"url": url} for url in urls],
        },
    }

    try:
        response = requests.post(
            _SAFE_BROWSING_URL,
            params={"key": api_key},
            json=payload,
            timeout=_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        return data.get("matches", [])
    except Exception as exc:
        logger.warning("Safe Browsing API call failed: %s", exc)
        return []
