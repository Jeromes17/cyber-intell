# scanner/agent_light.py
"""
Lightweight C0R3 agent (low-resource)
- Sends telemetry to server /api/v1/events
- Polls /api/v1/actions/<agent_id> for queued actions and ACKs them
- Uses timezone-aware ISO timestamps (no DeprecationWarning)
"""
import os
import time
import json
import sqlite3
import requests
from datetime import datetime, timezone
from typing import Optional

# optional dependency; helpful but agent works without psutil if not installed
try:
    import psutil
except Exception:
    psutil = None

# Configuration via env vars
AGENT_ID = os.environ.get("AGENT_ID", "agent-01")
SERVER_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:5000/api/v1/events")
ACTIONS_BASE = os.environ.get("ACTIONS_BASE", "http://127.0.0.1:5000/api/v1")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "45"))  # seconds
SCAN_PATHS = os.environ.get("SCAN_PATHS", "")  # comma-separated paths for sampling

BASE_DIR = os.path.dirname(__file__)
RETRY_DB = os.path.join(BASE_DIR, f"{AGENT_ID}_outbox.sqlite")

# ---------- Utilities ----------
def utc_z():
    """Return ISO8601 UTC timestamp with trailing Z (timezone-aware)."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def init_db():
    conn = sqlite3.connect(RETRY_DB, timeout=5)
    conn.execute("CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT, ts TEXT)")
    conn.commit()
    conn.close()

def enqueue(payload):
    conn = sqlite3.connect(RETRY_DB, timeout=5)
    conn.execute("INSERT INTO outbox(payload, ts) VALUES (?, ?)", (json.dumps(payload), utc_z()))
    conn.commit()
    conn.close()

def flush_outbox():
    conn = sqlite3.connect(RETRY_DB, timeout=5)
    cur = conn.cursor()
    cur.execute("SELECT id, payload FROM outbox ORDER BY id LIMIT 5")
    rows = cur.fetchall()
    for rid, payload_text in rows:
        payload = json.loads(payload_text)
        if send(payload):
            cur.execute("DELETE FROM outbox WHERE id=?", (rid,))
            conn.commit()
        else:
            break
    conn.close()

# ---------- Telemetry ----------
def minimal_scan():
    """Collect small telemetry sample (lightweight)."""
    cpu = 0.0
    mem = 0.0
    proc_sample = []
    net_sample = []
    if psutil:
        try:
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory().percent
            for i, p in enumerate(psutil.process_iter(["pid", "name"])):
                proc_sample.append({"pid": p.info.get("pid"), "name": p.info.get("name")})
                if i >= 6:
                    break
            # net connections (first few)
            conns = psutil.net_connections(kind="inet")
            for c in conns[:6]:
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                net_sample.append({"laddr": laddr, "raddr": raddr, "status": c.status})
        except Exception:
            cpu, mem, proc_sample, net_sample = 0.0, 0.0, [], []
    # light file sampling (no hashing)
    files = []
    if SCAN_PATHS:
        for p in SCAN_PATHS.split(","):
            p = p.strip()
            if not p or not os.path.exists(p):
                continue
            try:
                for root, dirs, filenames in os.walk(p):
                    for fname in filenames[:5]:
                        files.append({"path": os.path.join(root, fname)})
                    break
            except Exception:
                continue

    event = {
        "agent_id": AGENT_ID,
        "timestamp": utc_z(),
        "type": "telemetry",
        "payload": {
            "cpu_pct": cpu,
            "mem_pct": mem,
            "proc_sample": proc_sample,
            "net_sample": net_sample,
            "files_sample": files,
        },
    }
    return event

# ---------- Networking ----------
def send(payload) -> bool:
    """Send event to server; return True on success."""
    try:
        headers = {"Content-Type": "application/json", "X-Agent-ID": AGENT_ID}
        r = requests.post(SERVER_URL, json=payload, headers=headers, timeout=6)
        r.raise_for_status()
        return True
    except Exception as e:
        # print minimal error so console stays clean but informative
        print(f"[{AGENT_ID}] send failed: {e}")
        return False

# ---------- Action handling ----------
def poll_actions():
    """Poll server for pending actions for this agent, execute safe demo actions, and ACK."""
    try:
        url = f"{ACTIONS_BASE}/actions/{AGENT_ID}"
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        data = r.json()
        for act in data.get("actions", []):
            act_id = act.get("id")
            action_name = act.get("action")
            params = act.get("params", {}) or {}
            print(f"[{AGENT_ID}] received action {action_name} (id={act_id}) params={params}")

            # SAFE demo handlers
            try:
                if action_name == "run_scan":
                    # If scanner.file_scanner exists, call scan_directory, else do a light sample and send
                    path = params.get("path", "")
                    result_payload = {
                        "agent_id": AGENT_ID,
                        "timestamp": utc_z(),
                        "type": "scan_result",
                        "payload": {"scanned_path": path, "files": []},
                    }
                    try:
                        # try to import your scan function
                        from scanner.file_scanner import scan_directory
                        if path and os.path.isdir(path):
                            files = scan_directory(path)
                            result_payload["payload"]["files"] = files
                    except Exception:
                        # fallback: include sampled file list if path was in SCAN_PATHS
                        result_payload["payload"]["files"] = minimal_scan().get("payload", {}).get("files_sample", [])
                    # send result back to server
                    send(result_payload)

                elif action_name == "quarantine_file":
                    src = params.get("path")
                    if src and os.path.exists(src):
                        qdir = os.path.join(BASE_DIR, ".quarantine")
                        os.makedirs(qdir, exist_ok=True)
                        try:
                            dest = os.path.join(qdir, os.path.basename(src))
                            os.replace(src, dest)
                            print(f"[{AGENT_ID}] quarantined {src} -> {dest}")
                        except Exception as e:
                            print(f"[{AGENT_ID}] quarantine error: {e}")

                # other safe demo actions can go here (no destructive ops)

            except Exception as e:
                print(f"[{AGENT_ID}] action handler error: {e}")

            # ACK the action to server
            try:
                ack_url = f"{ACTIONS_BASE}/actions/{act_id}/ack"
                requests.post(ack_url, timeout=4)
            except Exception as e:
                print(f"[{AGENT_ID}] ack failed: {e}")

    except Exception:
        # silent fail (server down or no actions) — nothing to do
        pass

# ---------- Main loop ----------
def main_loop():
    print(f"[{AGENT_ID}] starting, server -> {SERVER_URL}")
    init_db()
    while True:
        evt = minimal_scan()
        if not send(evt):
            enqueue(evt)
        # try to flush a few queued events
        flush_outbox()
        # poll for actions and handle them
        poll_actions()
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main_loop()
