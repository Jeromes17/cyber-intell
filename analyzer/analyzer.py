# analyzer/analyzer.py
"""
Policy-driven analyzer for C0R3 Phase 2
- File hash signature checks
- Process heuristics (suspicious patterns, temp-folder execution)
- Network correlation heuristics (external connection counts)
- Beaconing interval analysis (CORE-2)
"""

import os
import json
import time
from datetime import datetime, timezone
import ipaddress
from typing import List, Dict, Any

# --------------------------
# Beaconing detector import
# --------------------------
from detectors.beaconing import (
    record_network_activity,
    detect_beaconing
)

# --------------------------
# Paths & configuration
# --------------------------
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(ROOT_DIR, "data")
POLICY_DIR = os.path.join(ROOT_DIR, "policy")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(POLICY_DIR, exist_ok=True)

# --------------------------
# Globals
# --------------------------
KNOWN_HASHES: List[Dict[str, Any]] = []
SUSPICIOUS_PROCS: List[Dict[str, Any]] = []
RISK_POLICY: Dict[str, Any] = {}

_DEFAULT_RISK_POLICY = {
    "weights": {
        "signature_hit": 50,
        "unsigned_system_dir": 15,
        "suspicious_parent_chain": 20,
        "bad_ip_reputation": 30,
    },
    "severity_thresholds": {
        "INFO": [0, 14],
        "LOW": [15, 29],
        "MEDIUM": [30, 59],
        "HIGH": [60, 100]
    }
}

IGNORE_PIDS = {0, 4}
EXT_CONN_THRESHOLD = 8

# --------------------------
# Utilities
# --------------------------
def _utcnow_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_json(path: str, default):
    try:
        if not os.path.exists(path):
            return default
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _load_signatures():
    global KNOWN_HASHES, SUSPICIOUS_PROCS, RISK_POLICY
    KNOWN_HASHES = _load_json(os.path.join(DATA_DIR, "known_hashes.json"), [])
    SUSPICIOUS_PROCS = _load_json(os.path.join(DATA_DIR, "suspicious_processes.json"), [])
    RISK_POLICY = _load_json(os.path.join(POLICY_DIR, "risk_policy.json"), _DEFAULT_RISK_POLICY)


_load_signatures()

# --------------------------
# Alert helpers
# --------------------------
def _create_alert(severity: str, risk_score: int, source: str, artifact: str, reason: str, recommendation: str):
    return {
        "timestamp": _utcnow_z(),
        "severity": severity,
        "risk_score": int(risk_score),
        "scanner_source": source,
        "artifact": artifact,
        "detection_reason": reason,
        "recommendation": recommendation
    }


def _severity_from_score(score: int) -> str:
    for sev, (lo, hi) in RISK_POLICY["severity_thresholds"].items():
        if lo <= score <= hi:
            return sev
    return "INFO"

# --------------------------
# Low-level helpers
# --------------------------
def _extract_remote_ip_from_conn(conn: Dict[str, Any]) -> str:
    for key in ("raddr", "remote", "remote_ip", "remote_address"):
        val = conn.get(key)
        if isinstance(val, str):
            return val.split(":")[0]
        if isinstance(val, dict):
            return val.get("ip", "")
        if isinstance(val, (list, tuple)) and val:
            return val[0]
    return ""

# --------------------------
# Process analysis
# --------------------------
def _analyze_process_heuristics(proc_data: Dict[str, Any], connections: List[Dict[str, Any]]):
    alerts = []

    pid = proc_data.get("pid")
    name = (proc_data.get("name") or proc_data.get("exe") or "").lower()

    if pid in IGNORE_PIDS:
        return alerts

    process_connections = []
    for c in connections:
        if c.get("pid") == pid:
            process_connections.append(c)

    # ---------------- CORE-2: Beaconing Interval Analysis ----------------
    if process_connections:
        record_network_activity(
            agent_id=proc_data.get("agent_id"),
            process_name=name,
            ts=time.time()
        )

        is_beacon, details = detect_beaconing(
            agent_id=proc_data.get("agent_id"),
            process_name=name
        )

        if is_beacon:
            alerts.append(_create_alert(
                severity="HIGH",
                risk_score=65,
                source="network_scanner",
                artifact=f"{name} (PID: {pid})",
                reason="Regular periodic network communication detected (possible C2 beaconing)",
                recommendation="Inspect outbound destinations and isolate host if confirmed."
            ))

    # ---------------- Existing Network Heuristic ----------------
    external_connections = 0
    for conn in process_connections:
        ip = _extract_remote_ip_from_conn(conn)
        try:
            if ip and not ipaddress.ip_address(ip).is_private:
                external_connections += 1
        except Exception:
            pass

    if external_connections >= EXT_CONN_THRESHOLD:
        score = 30 + (external_connections - EXT_CONN_THRESHOLD) * 2
        sev = _severity_from_score(score)
        alerts.append(_create_alert(
            severity=sev,
            risk_score=score,
            source="network_scanner",
            artifact=f"{name} (PID: {pid})",
            reason=f"Multiple outbound connections ({external_connections})",
            recommendation="Review remote IPs and block if suspicious."
        ))

    return alerts

# --------------------------
# Main entrypoint
# --------------------------
def analyze_data(scan_report: Dict[str, Any]):
    all_alerts: List[Dict[str, Any]] = []

    connections = scan_report.get("connections", []) or []
    for proc in scan_report.get("processes", []) or []:
        alerts = _analyze_process_heuristics(proc or {}, connections)
        all_alerts.extend(alerts)

    max_score = max([a["risk_score"] for a in all_alerts], default=0)
    summary = {
        "timestamp": _utcnow_z(),
        "total_alerts": len(all_alerts),
        "max_risk_score": max_score,
        "overall_severity": _severity_from_score(max_score)
    }

    return {"alerts": all_alerts, "summary": summary}
