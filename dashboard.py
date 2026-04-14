# dashboard.py (Fixed: push_alert signature + indentation + worker import clarity)
import os
import json
import sqlite3
import time
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from flask import Flask, render_template, jsonify, request, send_file
from utils.trojan_detector import compute_trojan_score


# -------- Optional RQ imports --------
try:
    import redis
    from rq import Queue
    RQ_AVAILABLE = True
except Exception:
    RQ_AVAILABLE = False

# Redis config (env override)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# -------- Alert push helper -------- 
# ✅ FIX #1: Unified fallback signature matching all call sites
try:
    from utils.alert_push import push_alert
except Exception:
    def push_alert(event_doc, ml_score, email=None, slack=True):
        return False, "alert_push_not_configured"

# ----------------- load schema -----------------
with open("agent_schema.json", "r") as f:
    AGENT_SCHEMA = json.load(f)

# -------- Legacy compatibility -------- #
try:
    from utils.logger import ALERT_LOG_PATH, log_alerts as legacy_log_alerts
except Exception:
    ALERT_LOG_PATH = os.path.join(os.path.dirname(__file__), "output", "alerts.json")

    def legacy_log_alerts(alerts):
        os.makedirs(os.path.dirname(ALERT_LOG_PATH), exist_ok=True)
        try:
            existing = []
            if os.path.exists(ALERT_LOG_PATH):
                with open(ALERT_LOG_PATH, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            existing.extend(alerts)
            with open(ALERT_LOG_PATH, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2)
        except:
            pass

# -------- Export fallback -------- #
try:
    from utils.exporter import export_alerts_to_csv, export_to_json
except Exception:
    def export_alerts_to_csv():
        import csv
        os.makedirs("output/reports", exist_ok=True)
        csv_path = os.path.join("output/reports", f"alerts_{int(datetime.now(timezone.utc).timestamp())}.csv")
        alerts = []
        if os.path.exists(ALERT_LOG_PATH):
            try:
                with open(ALERT_LOG_PATH, "r", encoding="utf-8") as f:
                    alerts = json.load(f)
            except:
                pass
        if alerts:
            keys = sorted({k for a in alerts for k in a.keys()})
            with open(csv_path, "w", newline="", encoding="utf-8") as cf:
                w = csv.DictWriter(cf, fieldnames=keys)
                w.writeheader()
                for a in alerts:
                    w.writerow({k: a.get(k, "") for k in keys})
        return csv_path

    def export_to_json(data, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

# -------- Analyzer Hook -------- #
try:
    from analyzer.analyzer import analyze_event
except Exception:
    analyze_event = None

# -------- Attempt to load inferencer (optional) -------- #
try:
    from infer_iso import Inferencer
    _inferencer = Inferencer()
except Exception:
    _inferencer = None

# -------- Logging -------- #
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("c0r3_dashboard")

app = Flask(__name__, template_folder="templates", static_folder="static")

# -------- DB -------- #
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "c0r3_events.sqlite")
os.makedirs(os.path.dirname(ALERT_LOG_PATH), exist_ok=True)

# simple API key map (in production, move to secure store)
API_KEYS = {
    "agent-key-abc-123": "host-001",
    "agent-key-demo-456": "host-002"
}

# Rate limiter store (per-process, per-key). Replace with Redis for prod.
_RATE_STORE: Dict[str, Dict[str, Any]] = {}  # {api_key: {"window_start": ts, "count": n}}
RATE_LIMIT_RPM = int(os.environ.get("RATE_LIMIT_RPM", "120"))  # requests per minute

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    # existing tables
    c.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT, ts TEXT, payload TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT, ts TEXT, severity TEXT, reason TEXT, meta TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT, ts_requested TEXT,
        action TEXT, params TEXT, status TEXT DEFAULT 'PENDING')""")

    # new tables for Section A
    c.execute("""CREATE TABLE IF NOT EXISTS agents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT UNIQUE NOT NULL,
        registered_at TEXT DEFAULT (datetime('now')),
        last_seen TEXT DEFAULT (datetime('now')),
        api_key TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS telemetry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT NOT NULL,
        record_id TEXT NOT NULL,
        ts TEXT,
        process_name TEXT,
        parent_process TEXT,
        cpu_percent REAL,
        mem_percent REAL,
        net_bytes_sent_per_s REAL,
        net_bytes_recv_per_s REAL,
        num_child_processes INTEGER,
        process_start_age_seconds REAL,
        raw_json TEXT,
        processed INTEGER DEFAULT 0,
        UNIQUE(agent_id, record_id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS ml_scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telemetry_id INTEGER,
        anomaly_score REAL,
        decision_value REAL,
        is_anomaly INTEGER,
        created_at TEXT DEFAULT (datetime('now'))
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS zt_scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telemetry_id INTEGER,
        zt_score REAL,
        decision TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS ti_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telemetry_id INTEGER,
        provider TEXT,
        result TEXT,
        score REAL,
        fetched_at TEXT DEFAULT (datetime('now'))
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS idempotency_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        agent_id TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        response_code INTEGER,
        response_body TEXT
    )""")
    conn.commit(); conn.close()

init_db()

# -------- Helpers -------- #

def _utcnow_z():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _parse_ts(ts: str):
    """Safe, timezone-aware timestamp parser (fixes aware/naive crash)."""
    if not ts:
        return datetime.now(timezone.utc)
    try:
        ts = ts.strip()
        if ts.endswith("Z"):
            ts = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except:
        return datetime.now(timezone.utc)

def load_alerts_from_json():
    if not os.path.exists(ALERT_LOG_PATH): return []
    try:
        with open(ALERT_LOG_PATH, "r", encoding="utf-8") as f:
            d = json.load(f)
            return d if isinstance(d, list) else []
    except:
        return []

def append_to_json_alert_log(new):
    try:
        existing = load_alerts_from_json()
        existing.extend(new)
        with open(ALERT_LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)
    except:
        pass

def save_event_to_db(agent_id, ts, payload):
    conn = get_db_connection(); c = conn.cursor()
    c.execute("INSERT INTO events(agent_id, ts, payload) VALUES (?, ?, ?)",
              (agent_id, ts, json.dumps(payload)))
    conn.commit(); conn.close()

def save_alert_to_db(agent_id, severity, reason, meta=None):
    ts = _utcnow_z()
    conn = get_db_connection(); c = conn.cursor()
    c.execute("""
        INSERT INTO alerts(agent_id, ts, severity, reason, meta)
        VALUES (?, ?, ?, ?, ?)""",
        (agent_id, ts, severity, reason, json.dumps(meta or {})))
    conn.commit(); conn.close()
    

def list_agents():
    conn = get_db_connection(); c = conn.cursor()
    c.execute("SELECT agent_id, MAX(ts) AS last_seen, COUNT(*) AS events_count FROM events GROUP BY agent_id")
    rows = c.fetchall(); conn.close()
    return [{"agent_id": r["agent_id"], "last_seen": r["last_seen"], "events_count": r["events_count"]} for r in rows]

def list_alerts(limit=100):
    conn = get_db_connection(); c = conn.cursor()
    c.execute(
        "SELECT id, agent_id, ts, severity, reason, meta FROM alerts ORDER BY id DESC LIMIT ?",
        (limit,)
    )

    alerts = []
    for r in c.fetchall():
        d = dict(r)
        try:
            d["meta"] = json.loads(d["meta"]) if isinstance(d.get("meta"), str) else {}
        except:
            d["meta"] = {}
        alerts.append(d)

    conn.close()
    return alerts



def queue_action_for_agent(agent_id, action, params=None):
    conn = get_db_connection(); c = conn.cursor()
    ts = _utcnow_z()
    c.execute("INSERT INTO actions(agent_id, ts_requested, action, params, status) VALUES (?, ?, ?, ?, 'PENDING')",
              (agent_id, ts, action, json.dumps(params or {}),))
    conn.commit(); conn.close()
    return {"status": "queued", "agent_id": agent_id, "action": action, "params": params or {}}

def get_pending_actions_for_agent(agent_id):
    conn = get_db_connection(); c = conn.cursor()
    c.execute("SELECT id, ts_requested, action, params FROM actions WHERE agent_id=? AND status='PENDING' ORDER BY id ASC",
              (agent_id,))
    rows = c.fetchall(); conn.close()
    return [{"id": r["id"], "ts_requested": r["ts_requested"], "action": r["action"], "params": json.loads(r["params"])} for r in rows]

def mark_action_as_acked(action_id):
    conn = get_db_connection(); c = conn.cursor()
    c.execute("UPDATE actions SET status='ACKED' WHERE id=?", (action_id,))
    conn.commit(); conn.close()

# ---------- Enqueue helper ----------
# ✅ FIX #3: Added comment clarifying worker startup requirement
def enqueue_processing_job(telemetry_id: int, proc: Dict[str, Any]):
    """
    Enqueue a job to run dashboard.process_telemetry(telemetry_id, proc) asynchronously.
    Returns job_id (str) on success, or False on failure.
    
    IMPORTANT: Worker must be started from the same directory as dashboard.py:
        $ rq worker default
    """
    if not RQ_AVAILABLE:
        logger.debug("RQ not available, enqueue skipped")
        return False

    try:
        # import Retry in a compatibility-safe way
        try:
            from rq import Retry  # rq >= 1.x
            retry_obj = Retry(max=3)
        except Exception:
            # older/newer versions may expose Retry differently
            try:
                from rq.job import Retry as RetryJob
                retry_obj = RetryJob(max=3)
            except Exception:
                retry_obj = None

        redis_conn = redis.from_url(REDIS_URL)
        q = Queue("default", connection=redis_conn)

        if retry_obj is not None:
            job = q.enqueue("dashboard.process_telemetry", telemetry_id, proc, retry=retry_obj, ttl=300)
        else:
            # fallback: call without retry param
            job = q.enqueue("dashboard.process_telemetry", telemetry_id, proc, ttl=300)

        job_id = getattr(job, "id", None)
        logger.info("Enqueued telemetry %s as job %s", telemetry_id, job_id)
        return str(job_id) if job_id else True
    except Exception as e:
        logger.exception("Failed to enqueue job to Redis: %s", e)
        return False


# ---------- New helpers for Section A ----------
def normalize_parent(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    return name.strip().lower()

def preprocess_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(rec)
    out["agent_id"] = rec.get("agent_id")

    ts = rec.get("ts") or rec.get("timestamp")
    try:
        if ts:
            out["ts"] = _parse_ts(ts).isoformat()
        else:
            out["ts"] = _utcnow_z()
    except:
        out["ts"] = _utcnow_z()

    # normalize text fields
    if out.get("process_name"):
        out["process_name"] = str(out["process_name"]).strip().lower()

    out["parent_process"] = normalize_parent(out.get("parent_process"))

    # coerce numeric
    for k in [
        "cpu_percent",
        "mem_percent",
        "net_bytes_sent_per_s",
        "net_bytes_recv_per_s",
        "num_child_processes",
        "process_start_age_seconds"
    ]:
        v = rec.get(k)
        try:
            out[k] = float(v) if v is not None else None
        except:
            out[k] = None

    # Required for Trojan / Beaconing detection
    if "connections" in rec and isinstance(rec["connections"], list):
        out["connections"] = rec["connections"]
    else:
        out["connections"] = []

    return out


def check_rate_limit(api_key: str) -> bool:
    now = int(time.time())
    window = 60
    limit = RATE_LIMIT_RPM
    entry = _RATE_STORE.get(api_key)
    if not entry or now - entry["window_start"] >= window:
        _RATE_STORE[api_key] = {"window_start": now, "count": 1}
        return True
    else:
        if entry["count"] >= limit:
            return False
        entry["count"] += 1
        return True

def mark_idempotency(key: str, agent_id: str, response_obj: Dict = None, response_code: int = None):
    if not key:
        return
    conn = get_db_connection(); c = conn.cursor()
    try:
        c.execute("INSERT OR IGNORE INTO idempotency_keys(key, agent_id, created_at) VALUES (?, ?, ?)",
                  (key, agent_id, _utcnow_z()))
        if response_obj is not None:
            c.execute("UPDATE idempotency_keys SET response_code=?, response_body=? WHERE key=?",
                      (response_code, json.dumps(response_obj), key))
        conn.commit()
    except Exception as e:
        logger.exception("idempotency mark failed: %s", e)
        conn.rollback()
    finally:
        conn.close()

def get_idempotency(key: str):
    if not key:
        return None
    conn = get_db_connection(); c = conn.cursor()
    c.execute("SELECT response_code, response_body FROM idempotency_keys WHERE key=?", (key,))
    r = c.fetchone()
    conn.close()
    if not r:
        return None
    return {"response_code": r["response_code"], "response_body": r["response_body"]}

def save_telemetry(agent_id: str, record_id: str, proc: Dict[str, Any]) -> int:
    conn = get_db_connection(); c = conn.cursor()
    try:
        c.execute("""INSERT INTO telemetry(agent_id, record_id, ts, process_name, parent_process,
            cpu_percent, mem_percent, net_bytes_sent_per_s, net_bytes_recv_per_s,
            num_child_processes, process_start_age_seconds, raw_json, processed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
            (agent_id, record_id, proc.get("ts"),
             proc.get("process_name"), proc.get("parent_process"),
             proc.get("cpu_percent"), proc.get("mem_percent"),
             proc.get("net_bytes_sent_per_s"), proc.get("net_bytes_recv_per_s"),
             int(proc.get("num_child_processes") or 0),
             proc.get("process_start_age_seconds"),
             json.dumps(proc)))
        conn.commit()
        tid = c.lastrowid
    except sqlite3.IntegrityError:
        # duplicate (agent_id, record_id) constraint -> fetch existing id
        conn.rollback()
        c.execute("SELECT id FROM telemetry WHERE agent_id=? AND record_id=?", (agent_id, record_id))
        r = c.fetchone()
        tid = r["id"] if r else None
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return int(tid) if tid else None

def save_ml_score(telemetry_id: int, anomaly_score: float, decision_value: float, is_anomaly: bool):
    conn = get_db_connection(); c = conn.cursor()
    c.execute("INSERT INTO ml_scores(telemetry_id, anomaly_score, decision_value, is_anomaly, created_at) VALUES (?, ?, ?, ?, ?)",
              (telemetry_id, anomaly_score, decision_value, int(is_anomaly), _utcnow_z()))
    conn.commit(); conn.close()

def save_zt_score(telemetry_id: int, zt_score: float, decision: str):
    conn = get_db_connection(); c = conn.cursor()
    c.execute("INSERT INTO zt_scores(telemetry_id, zt_score, decision, created_at) VALUES (?, ?, ?, ?)",
              (telemetry_id, zt_score, decision, _utcnow_z()))
    conn.commit(); conn.close()

def save_ti_report(telemetry_id: int, provider: str, result: Dict[str, Any], score: Optional[float] = None):
    conn = get_db_connection(); c = conn.cursor()
    c.execute("INSERT INTO ti_reports(telemetry_id, provider, result, score, fetched_at) VALUES (?, ?, ?, ?, ?)",
              (telemetry_id, provider, json.dumps(result), score, _utcnow_z()))
    conn.commit(); conn.close()

# Very small ZT scoring function (weights)
ZT_WEIGHTS = {"ml": 0.6, "ti": 0.3, "priv": 0.1}
THRESH_ISOLATE = 0.95
THRESH_ALERT = 0.45

def compute_zt_and_store(telemetry_id: int, anomaly_score: float):
    # anomaly_score: 0..1 (higher = more anomalous)
    # ml_contrib: 0..1 (higher = more trusted) = 1 - anomaly
    ml_contrib = max(0.0, 1.0 - anomaly_score)
    # placeholder TI and priv scores (TI async later)
    ti_score = 0.0
    priv_score = 1.0
    final_ratio = (ZT_WEIGHTS["ml"] * ml_contrib +
                   ZT_WEIGHTS["ti"] * ti_score +
                   ZT_WEIGHTS["priv"] * priv_score)
    zt_score = float(final_ratio * 100.0)  # 0..100 (higher = more trusted)
    decision = "ALLOW"
    if anomaly_score >= THRESH_ISOLATE:
        decision = "ISOLATE"
    elif anomaly_score >= THRESH_ALERT:
        decision = "ALERT"
    save_zt_score(telemetry_id, zt_score, decision)
    return {"zt_score": zt_score, "decision": decision}

from datetime import datetime, timezone
from typing import Dict, Any

def run_ml_inference_and_store(telemetry_id: int, proc: Dict[str, Any]) -> Dict[str, Any]:
    try:
        if _inferencer:
            r = _inferencer.score_record(proc)
            anomaly_score = float(r.get("anomaly_score", 0.0))
            decision_val = float(r.get("decision_function", 0.0))
            is_anom = bool(r.get("is_anomaly", False))
        else:
            # Fallback heuristic
            cpu = float(proc.get("cpu_percent") or 0.0)
            mem = float(proc.get("mem_percent") or 0.0)
            net = float(proc.get("net_bytes_sent_per_s") or 0.0)

            anomaly_score = min(
                1.0,
                max(cpu / 100.0, mem / 100.0, net / 100000.0)
            )
            decision_val = -anomaly_score
            is_anom = anomaly_score > 0.85

    except Exception:
        logger.exception("ML inference failed; using fallback zero")
        anomaly_score = 0.0
        decision_val = 0.0
        is_anom = False

    # ---------------- STORE ML SCORE ----------------
    save_ml_score(telemetry_id, anomaly_score, decision_val, is_anom)

    # ---------------- ZERO TRUST DECISION ----------------
    zt_res = compute_zt_and_store(telemetry_id, anomaly_score)
    decision = zt_res.get("decision")

    # ================= RULE-BASED OVERRIDE (Option A) =================
    if (
        proc.get("process_name") == "powershell.exe"
        and proc.get("parent_process") == "winword.exe"
    ):
        decision = "ALERT"
        zt_res["decision"] = "ALERT" 
    # =================================================================

   
    # ---------------- ALERT PERSISTENCE ----------------

    return {
        "anomaly_score": anomaly_score,
        "is_anomaly": is_anom,
        "zt": zt_res,
    }



def process_telemetry(telemetry_id: int, proc: Dict[str, Any]):
    try:
        conn = get_db_connection()
        c = conn.cursor()

        c.execute("SELECT processed FROM telemetry WHERE id=?", (telemetry_id,))
        r = c.fetchone()
        if not r or int(r["processed"] or 0) == 1:
            conn.close()
            return {"ok": True, "skipped": True}
        
        # Run ML + ZT ONCE and capture result
        res = run_ml_inference_and_store(telemetry_id, proc)

        # Initialize alert state
        alert_reason = None
        alert_severity = None
        alert_meta = {}
        trojan_score = None


        # 2️⃣ RULE-BASED (highest priority)
        if proc.get("process_name") == "powershell.exe" and proc.get("parent_process") == "winword.exe":
            alert_reason = "Suspicious PowerShell launched from WinWord"
            alert_severity = "HIGH"
            alert_meta = {
                "telemetry_id": telemetry_id,
                "artifact": f"{proc.get('process_name')} (parent: {proc.get('parent_process')})",
                "rule": "powershell_from_office"
            }

        # 3️⃣ TROJAN / BEACONING
        if not alert_reason:
            trojan_score, trojan_reasons = compute_trojan_score(proc)
            if trojan_score >= 25:
                alert_reason = "Potential Trojan / Backdoor detected"
                alert_severity = "HIGH"
                alert_meta = {
                    "telemetry_id": telemetry_id,
                    "trojan_score": trojan_score,
                    "signals": trojan_reasons,
                    "artifact": f"{proc.get('process_name')} (parent: {proc.get('parent_process')})"
                }

        # 4️⃣ ML / ZT (last fallback)
        if not alert_reason:
            decision = res.get("zt", {}).get("decision")
            if decision in ("ALERT", "ISOLATE"):
                alert_reason = "ML / Behavioral Detection"
                alert_severity = "CRITICAL" if decision == "ISOLATE" else "HIGH"
                alert_meta = {
                    "telemetry_id": telemetry_id,
                    "anomaly_score": res.get("anomaly_score"),
                    "decision": decision,
                    "artifact": f"{proc.get('process_name')} (parent: {proc.get('parent_process')})"
                }

        # 5️⃣ SINGLE ALERT WRITE (ONLY PLACE)
        if alert_reason:
            save_alert_to_db(
                agent_id=proc.get("agent_id", "unknown"),
                severity=alert_severity,
                reason=alert_reason,
                meta=alert_meta
            )

            score_for_push = (
                trojan_score / 100.0
                if trojan_score is not None
                else res.get("anomaly_score", 0.0)
            )

            push_alert(proc, score_for_push, slack=True)


        # mark processed
        c.execute("UPDATE telemetry SET processed=1 WHERE id=?", (telemetry_id,))
        conn.commit()
        conn.close()

        return {"ok": True}

    except Exception:
        logger.exception("process_telemetry failed")
        return {"ok": False}


# ---------- UI Routes (unchanged) ----------
@app.route("/")
def overview():
    alerts = list_alerts(limit=50)

    # Sort alerts by time (latest first)
    alerts_sorted = sorted(
        alerts,
        key=lambda a: _parse_ts(a.get("ts") or a.get("timestamp")),
        reverse=True
    )

    last_alert_time = (
        alerts_sorted[0].get("ts") or alerts_sorted[0].get("timestamp")
        if alerts_sorted else None
    )

    high = [
        a for a in alerts
        if str(a.get("severity", "")).upper() in ("CRITICAL", "HIGH")
    ]

    health = "Infected" if high else "Secure"

    recent = alerts_sorted

    last_alert_time = None
    if alerts:
        ts = alerts[0].get("timestamp") or alerts[0].get("ts")
        if ts:
            last_alert_time = ts[:19]


    return render_template(
        "overview.html",
        health=health,
        total_threats=len(high),
        total_alerts=len(alerts),
        current_time=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        recent_alerts=recent,
        last_alert_time=last_alert_time,
        agents=list_agents()
    )

@app.route("/api/alerts")
def api_alerts():
    return jsonify(list_alerts(limit=500))

# -------- Scan Route (unchanged) -------- #
@app.route("/scan", methods=["POST"])
def run_scan():
    try:
        from scanner.process_scanner import get_all_processes
        from scanner.network_scanner import get_all_connections
        from scanner.file_scanner import scan_directory
        from analyzer.analyzer import analyze_data
        from utils.logger import log_alerts as logger_log_alerts
        from utils.exporter import export_to_json as exporter_export_to_json
    except Exception as e:
        return jsonify({"message": "Scan failed", "error": "Scanner modules missing"}), 500

    try:
        body = request.get_json(silent=True) or {}
        path = (body.get("path") or "").strip()
        procs, conns, files = get_all_processes(), get_all_connections(), []

        if path:
            import os
            if not os.path.isdir(path):
                return jsonify({"message": "Invalid directory"}), 400
            files = scan_directory(path)

        report = {"processes": procs, "connections": conns, "files": files}
        results = analyze_data(report)
        alerts, summary = results.get("alerts", []), results.get("summary", {})

        for a in alerts:
            save_alert_to_db(a.get("agent_id","local"), a.get("severity","INFO"), a.get("reason",""), a.get("meta",{}))

        try: logger_log_alerts(alerts)
        except: append_to_json_alert_log(alerts)

        try: exporter_export_to_json(summary, "output/reports/summary.json")
        except: pass

        return jsonify({
            "message":"Scan completed",
            "alerts_detected":len(alerts),
            "overall_severity":summary.get("overall_severity","INFO"),
            "scanned_files":len(files),"scanned_path":path
        })
    except Exception as e:
        return jsonify({"message":"Scan error","error":str(e)}), 500

# -------- CSV Export (unchanged) ----------
@app.route("/export/csv")
def export_csv():
    try: return send_file(export_alerts_to_csv(), as_attachment=True)
    except Exception as e: return jsonify({"message":"Export failed","error":str(e)}), 500

# -------- UPDATED Ingestion API (SECTION A) -------- #
@app.route("/api/v1/events", methods=["POST"])
def ingest_event():
    # Basic JSON parsing
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error":"invalid json"}), 400

    # Determine API key (X-API-KEY header) and enforce rate limit if provided.
    api_key = (request.headers.get("X-API-KEY") or "").strip()
    if api_key:
        if not check_rate_limit(api_key):
            return jsonify({"error":"rate_limit_exceeded"}), 429

    # Idempotency header handling
    idem_key = request.headers.get("Idempotency-Key")

    # If idempotency key provided and we've seen it before, return cached response
    if idem_key:
        existing = get_idempotency(idem_key)
        if existing and existing.get("response_code") is not None:
            # response_body was stored as JSON string
            body = existing.get("response_body") or "{}"
            try:
                return (body, existing.get("response_code"), {"Content-Type":"application/json"})
            except:
                return jsonify({"status":"ok","cached":True}), existing.get("response_code")

    # Validate schema (batch or single)
    payload = data
    # Support older single-payload style: wrap if not 'records'
    if "records" not in payload and any(k in payload for k in ("process_name","cpu_percent")):
        # single-record style -> convert into batch
        payload = {
            "agent_id": payload.get("agent_id") or request.headers.get("X-Agent-ID") or "unknown",
            "records": [payload]
        }

    # Basic schema validation (best-effort)
    try:
        from jsonschema import validate, ValidationError
        validate(instance=payload, schema=AGENT_SCHEMA)
    except Exception as e:
        # If schema fails, return a readable error
        msg = str(e)
        return jsonify({"error":"schema_validation_failed", "details": msg}), 400

    # Resolve agent identity: header X-Agent-ID or mapped API key or payload agent_id
    agent_id = (request.headers.get("X-Agent-ID") or payload.get("agent_id") or API_KEYS.get(api_key) or "unknown").strip()

    # Register/update agent in agents table
    try:
        conn = get_db_connection(); c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO agents(agent_id, registered_at, api_key) VALUES (?, ?, ?)",
                  (agent_id, _utcnow_z(), api_key or None))
        c.execute("UPDATE agents SET last_seen=? WHERE agent_id=?", (_utcnow_z(), agent_id))
        conn.commit(); conn.close()
    except Exception as e:
        logger.exception("agent register/update failed: %s", e)

    # iterate records
    results = []
    records = payload.get("records", []) or []
    stored = 0
    for rec in records:
        alert_already_pushed = False
        # create deterministic record_id if client didn't provide
        client_rid = rec.get("client_record_id") or f"{agent_id}:{rec.get('ts') or ''}:{rec.get('process_name') or ''}:{uuid.uuid4().hex[:8]}"

        # preprocess
        proc = preprocess_record(rec)

        # save raw event (legacy)
        try:
            save_event_to_db(agent_id, proc.get("ts") or _utcnow_z(), rec)
        except Exception as e:
            logger.exception("save_event_to_db failed: %s", e)

        # store telemetry & get telemetry_id
        try:
            tid = save_telemetry(agent_id, client_rid, proc)
        except Exception as e:
            logger.exception("save_telemetry failed: %s", e)
            tid = None

        # Try analyzer hook (legacy) — keep existing behavior
        #try:
           # if analyze_event:
               # alert = analyze_event(rec)
               # if alert:
                #    sev, rea, meta = alert.get("severity","MEDIUM"), alert.get("reason","auto"), alert.get("meta",{})
                 #   save_alert_to_db(agent_id, sev, rea, meta)
                 #   try:
                 #       legacy_log_alerts([{
                  #          "timestamp": _utcnow_z(),
                   #         "agent_id": agent_id, "severity": sev,
                    #        "reason": rea, "meta": meta
                     #   }])
                    #except:
                     #   append_to_json_alert_log([{
                      #      "timestamp": _utcnow_z(),
                       #     "agent_id": agent_id, "severity": sev,
                        #    "reason": rea, "meta": meta
                        #}])
        #except Exception:
         #   logger.exception("legacy analyzer failed")

        # Async: enqueue processing job (returns job_id or False)
        ml_result = {}
        if tid:
            try:
                enq = enqueue_processing_job(tid, proc)
                if enq:
                    # enqueue returned job id (string) or True-like value
                    ml_result = {"enqueued": True, "job_id": str(enq)}
                else:
                    # fallback: run synchronously to preserve behavior
                    logger.info("enqueue failed or disabled; running ML synchronously for telemetry %s", tid)
                    ml_result = run_ml_inference_and_store(tid, proc)

                    # --- PUSH ALERT (synchronous fallback path) --

                    decision = ml_result.get("zt", {}).get("decision")

                    # 🔒 HARD GATE — only real alerts are pushed
                    if decision in ("ALERT", "ISOLATE") and not alert_already_pushed:
                        try:
                            anomaly_score = float(ml_result.get("anomaly_score", 0.0))
                            ok, info = push_alert(proc, anomaly_score, email=None, slack=True)

                            if not ok:
                                logger.warning(
                                    "push_alert returned not-ok for telemetry %s: %s",
                                    tid, info
                                )

                        except Exception as e:
                            logger.exception(
                                "Exception while pushing alert for telemetry %s: %s",
                                tid, e
                            ) 

            except Exception as e:
                logger.exception("enqueue exception; running ML synchronously: %s", e)
                try:
                    ml_result = run_ml_inference_and_store(tid, proc)
                except Exception as e2:
                    logger.exception("synchronous ML fallback failed: %s", e2)
                    save_ml_score(tid, 0.0, 0.0, False)
                    zres = compute_zt_and_store(tid, 0.0)
                    ml_result = {"anomaly_score": 0.0, "is_anomaly": False, "zt": zres}
        else:
            ml_result = {}

        results.append({"record_id": client_rid, "telemetry_id": tid, "ml": ml_result})
        stored += 1

    resp = {"status":"ok", "stored": stored, "results": results}

    # Save idempotency response if header provided
    if idem_key:
        try:
            mark_idempotency(idem_key, agent_id, response_obj=resp, response_code=200)
        except Exception:
            logger.exception("mark_idempotency failed")

    return jsonify(resp), 200

# -------- Agent Actions (unchanged) -------- #
@app.route("/api/v1/agents")
def api_agents():
    return jsonify({"agents": list_agents()})

@app.route("/api/v1/agents/<agent>/action", methods=["POST"])
def api_agent_action(agent):
    try:
        body = request.get_json(force=True) or {}
        action = body.get("action")
        params = body.get("params", {})
        if not action:
            return jsonify({"error":"missing action"}), 400
        return jsonify(queue_action_for_agent(agent, action, params)), 201
    except Exception as e:
        return jsonify({"error":str(e)}), 500

@app.route("/api/v1/actions/<agent>", methods=["GET"])
def api_agent_poll(agent):
    try: return jsonify({"actions": get_pending_actions_for_agent(agent)})
    except Exception as e: return jsonify({"error":str(e)}), 500

@app.route("/api/v1/actions/<int:aid>/ack", methods=["POST"])
def api_action_ack(aid):
    try: mark_action_as_acked(aid); return jsonify({"status":"acked","action_id":aid})
    except Exception as e: return jsonify({"error":str(e)}), 500

# -------- Run App -------- #
if __name__ == "__main__":
    print("Starting Flask Dashboard on http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, threaded=True)