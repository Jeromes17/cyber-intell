# utils/alert_push.py
import os
import requests
import logging
from typing import Dict, Any

logger = logging.getLogger("c0r3_alert_push")

ALERTS_API = os.getenv(
    "ALERTS_API",
    "http://localhost:5002/api/alerts/push"
)


def push_alert(event: Dict[str, Any], score: float, email=None, slack=True):
    """
    Synchronously POST to alerting service.
    Returns (ok: bool, info: str)
    """
    payload = {
        "event": event,
        "ml_score": score,
        "notify": {
            "email": email or [],
            "slack": bool(slack)
        }
    }
    try:
        r = requests.post(ALERTS_API, json=payload, timeout=5)
        if r.ok:
            return True, "ok"
        else:
            return False, f"status:{r.status_code} body:{r.text}"
    except Exception as e:
        logger.exception("push_alert exception")
        return False, str(e)


def push_alert_task(event: Dict[str, Any], score: float, email=None, slack=True):
    """
    Intended to be enqueued to RQ (non-blocking). This simply calls push_alert.
    Keep it here so worker can call it as a job: utils.alert_push.push_alert_task
    """
    ok, info = push_alert(event, score, email=email, slack=slack)
    # Optionally, return something useful for retries/audit logs
    return {"ok": ok, "info": info}
