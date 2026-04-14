# detectors/beaconing.py

import time
from collections import defaultdict, deque
from statistics import pstdev

# Store last N network activity timestamps per (agent, process)
MAX_SAMPLES = 10
MIN_SAMPLES = 5
VARIANCE_THRESHOLD = 3.0  # seconds (low variance = suspicious)

_activity = defaultdict(lambda: deque(maxlen=MAX_SAMPLES))


def record_network_activity(agent_id, process_name, ts=None):
    """
    Record timestamp of network activity for a process.
    """
    if not agent_id or not process_name:
        return

    if ts is None:
        ts = time.time()

    key = (agent_id, process_name)
    _activity[key].append(ts)


def detect_beaconing(agent_id, process_name):
    """
    Detect periodic beaconing based on interval variance.
    Returns (is_beaconing: bool, details: dict | None)
    """
    key = (agent_id, process_name)
    timestamps = list(_activity.get(key, []))

    if len(timestamps) < MIN_SAMPLES:
        return False, None

    # Calculate inter-arrival intervals
    intervals = [
        timestamps[i] - timestamps[i - 1]
        for i in range(1, len(timestamps))
    ]

    variance = pstdev(intervals)

    if variance <= VARIANCE_THRESHOLD:
        return True, {
            "intervals": intervals,
            "variance": round(variance, 2)
        }

    return False, None
