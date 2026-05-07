"""
User feedback logging.

When a user marks a verdict as wrong (false positive or false negative),
we log the correction to a JSONL file. In production this would feed a
retraining pipeline — for the demo it demonstrates the feedback loop concept.

Privacy: only message_id, verdicts, and timestamp are stored — no email content.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

_FEEDBACK_FILE = Path(os.environ.get("FEEDBACK_LOG_PATH", "feedback_log.jsonl"))


def log_feedback(
    message_id: str,
    original_verdict: str,
    user_verdict: str,
    caller: str,
) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message_id": message_id,
        "original_verdict": original_verdict,
        "user_verdict": user_verdict,
        "caller": caller,
    }
    try:
        with _FEEDBACK_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        logger.info(
            "feedback logged message_id=%s original=%s user=%s",
            message_id,
            original_verdict,
            user_verdict,
        )
    except Exception as exc:
        logger.warning("Failed to write feedback: %s", exc)
