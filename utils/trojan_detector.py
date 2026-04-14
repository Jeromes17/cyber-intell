# utils/trojan_detector.py
from collections import Counter
from datetime import datetime
import math

HIGH_RISK_PARENTS = {
    "winword.exe",
    "excel.exe",
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "mshta.exe"
}

def _parse_ts(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None

def detect_beaconing(connections):
    """
    Detect periodic beaconing behavior.
    """
    if not connections or len(connections) < 3:
        return 0.0

    times = []
    dst_ips = []

    for c in connections:
        t = _parse_ts(c.get("timestamp", ""))
        if t:
            times.append(t)
            dst_ips.append(c.get("dst_ip"))

    if len(times) < 3:
        return 0.0

    times.sort()
    intervals = [
        (times[i] - times[i - 1]).total_seconds()
        for i in range(1, len(times))
    ]

    if not intervals:
        return 0.0

    mean = sum(intervals) / len(intervals)
    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    std = math.sqrt(variance)

    most_common_ip, count = Counter(dst_ips).most_common(1)[0]

    if mean >= 20 and std <= 2 and count >= 3:
        return 1.0

    return 0.0

def compute_trojan_score(proc):
    """
    Returns (score 0-100, reasons[])
    """
    reasons = []

    age = float(proc.get("process_start_age_seconds") or 0)
    cpu = float(proc.get("cpu_percent") or 0)
    mem = float(proc.get("mem_percent") or 0)
    parent = (proc.get("parent_process") or "").lower()
    connections = proc.get("connections", [])

    longevity = 1.0 if age > 3600 else 0.5 if age > 600 else 0.0
    if longevity > 0:
        reasons.append("long_lived_process")

    cpu_stealth = 1.0 if cpu < 5 else 0.5 if cpu < 10 else 0.0
    mem_stealth = 1.0 if mem < 10 else 0.5 if mem < 20 else 0.0

    if cpu_stealth:
        reasons.append("low_cpu_usage")
    if mem_stealth:
        reasons.append("low_memory_usage")

    beacon_score = detect_beaconing(connections)
    if beacon_score:
        reasons.append("periodic_beaconing")

    unique_ips = {c.get("dst_ip") for c in connections if c.get("dst_ip")}
    dst_concentration = 1.0 if len(unique_ips) == 1 else 0.5 if len(unique_ips) <= 2 else 0.0
    if dst_concentration:
        reasons.append("limited_destination_ips")

    lineage_score = 1.0 if parent in HIGH_RISK_PARENTS else 0.0
    if lineage_score:
        reasons.append(f"suspicious_parent:{parent}")

    trojan_score = (
        0.20 * longevity +
        0.15 * cpu_stealth +
        0.10 * mem_stealth +
        0.25 * beacon_score +
        0.15 * dst_concentration +
        0.15 * lineage_score
    ) * 100

    return round(trojan_score, 2), reasons
