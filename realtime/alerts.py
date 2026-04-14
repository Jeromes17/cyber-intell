# realtime/alerts.py

import time
import threading
from collections import defaultdict, deque

# In-memory rate limiter storage
_rate_limits = defaultdict(lambda: deque())
_rate_lock = threading.Lock()


def rate_limit(key: str, limit: int = 60, window: int = 60):
    """
    Simple per-minute rate limiter.
    key = unique identifier (e.g. severity or webhook URL)
    limit = number allowed in the window
    window = seconds (default 60)
    """
    now = time.time()
    dq = _rate_limits[key]

    with _rate_lock:
        # remove old timestamps
        while dq and dq[0] < now - window:
            dq.popleft()

        if len(dq) >= limit:
            return False

        dq.append(now)
        return True


def severity_from_score(score: float):
    """
    Convert ML score (0.0 - 1.0) into severity label.
    """
    if score >= 0.90:
        return "critical"
    if score >= 0.75:
        return "high"
    if score >= 0.50:
        return "medium"
    return "low"


def build_alert(event: dict, ml_score: float = None):
    """
    Normalize event into alert object.
    """
    ts = int(time.time())

    alert = {
        "alert_id": f"alrt-{ts}",
        "timestamp": ts,
        "event": event,
        "ml_score": ml_score,
        "severity": severity_from_score(ml_score or 0.0),
        "host": event.get("host"),
        "agent_id": event.get("agent_id"),
        "type": event.get("type")
    }
    return alert
