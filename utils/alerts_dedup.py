# utils/alerts_dedup.py
import hashlib

def generate_alert_fingerprint(agent_id, process_name, detection_type):
    raw = f"{agent_id}|{process_name}|{detection_type}"
    return hashlib.sha256(raw.encode()).hexdigest()
