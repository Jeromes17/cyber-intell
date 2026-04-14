# app.py
"""
Cyber Sentinel - Ingestion + lightweight ML wiring (Section A implementation)

Features implemented:
- POST /api/v1/events with API-key auth
- JSON Schema validation (agent_schema.json expected in same folder)
- Idempotency using Idempotency-Key header
- Lightweight in-memory rate limiting (per API key)
- Parent process normalization + preprocessing hook
- DB models for telemetry, ml_scores, zt_scores, ti_reports, agents
- WAL mode suggestion (enabled on DB connect)
- ML inference integration via infer_iso.score_record()
- Simple async-work queue stub (replace with Redis/RQ/Celery easily)
- Structured logging
"""
import os
import json
import uuid
import time
import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Any, Optional

from flask import Flask, request, jsonify, g
from sqlalchemy import (create_engine, Column, Integer, String, DateTime,
                        Float, Text, ForeignKey, UniqueConstraint, Boolean)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session, relationship
from jsonschema import validate, ValidationError

# Optional: if infer_iso not present it'll fallback gracefully
try:
    from infer_iso import Inferencer
    inferencer = Inferencer()  # loads model if found
except Exception as e:
    inferencer = None
    # We'll still allow server to run; fallback scoring used

# ---------- CONFIG ----------
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///cs_v2.db")
JSON_SCHEMA_PATH = os.environ.get("AGENT_SCHEMA_PATH", "agent_schema.json")
API_KEYS = {
    # In production, don't hardcode; load from env / vault / DB
    "agent-key-abc-123": "host-001",
    "agent-key-demo-456": "host-002"
}
# Rate limit: requests per minute per API key
RATE_LIMIT_RPM = int(os.environ.get("RATE_LIMIT_RPM", 120))  # 120 req/min default

# ZT scoring weights (configurable)
ZT_WEIGHTS = {
    "ml": 0.6,
    "ti": 0.3,
    "priv": 0.1
}

# ML thresholds
THRESH_ISOLATE = 0.95
THRESH_ALERT = 0.7

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("cs_ingest")

# ---------- DB Setup ----------
# Enable WAL for SQLite by adding connect args and setting PRAGMAs after connect
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
# If using SQLite, enable WAL mode at connection time:
if DATABASE_URL.startswith("sqlite"):
    def _enable_wal(dbapi_conn, conn_record):
        try:
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.close()
            logger.info("SQLite WAL mode enabled")
        except Exception as e:
            logger.exception("Failed to set WAL mode: %s", e)

    from sqlalchemy import event
    event.listen(engine, "connect", _enable_wal)

Base = declarative_base()
Session = scoped_session(sessionmaker(bind=engine))

# ---------- DB Models ----------
class Agent(Base):
    __tablename__ = "agents"
    id = Column(Integer, primary_key=True)
    agent_id = Column(String, unique=True, nullable=False)  # e.g., host-001
    registered_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    api_key = Column(String, nullable=True)

class Telemetry(Base):
    __tablename__ = "telemetry"
    id = Column(Integer, primary_key=True)
    agent_id = Column(String, ForeignKey("agents.agent_id"), index=True, nullable=False)
    record_id = Column(String, index=True, nullable=False)
    ts = Column(DateTime, index=True)
    process_name = Column(String)
    parent_process = Column(String)
    cpu_percent = Column(Float)
    mem_percent = Column(Float)
    net_bytes_sent_per_s = Column(Float)
    net_bytes_recv_per_s = Column(Float)
    num_child_processes = Column(Integer)
    process_start_age_seconds = Column(Float, nullable=True)
    raw_json = Column(Text)
    processed = Column(Boolean, default=False)  # marks if processed by pipeline

    __table_args__ = (UniqueConstraint('agent_id', 'record_id', name='_agent_record_uc'),)

class MLScore(Base):
    __tablename__ = "ml_scores"
    id = Column(Integer, primary_key=True)
    telemetry_id = Column(Integer, ForeignKey("telemetry.id"), index=True)
    anomaly_score = Column(Float)  # normalized 0..1 (higher -> more anomalous)
    decision_value = Column(Float)  # decision_function if available (signed)
    is_anomaly = Column(Boolean)
    created_at = Column(DateTime, default=datetime.utcnow)

class ZTScore(Base):
    __tablename__ = "zt_scores"
    id = Column(Integer, primary_key=True)
    telemetry_id = Column(Integer, ForeignKey("telemetry.id"), index=True)
    zt_score = Column(Float)  # 0..100 (higher -> more trusted)
    decision = Column(String)  # ALLOW | ALERT | ISOLATE
    created_at = Column(DateTime, default=datetime.utcnow)

class TIReport(Base):
    __tablename__ = "ti_reports"
    id = Column(Integer, primary_key=True)
    telemetry_id = Column(Integer, ForeignKey("telemetry.id"), index=True)
    provider = Column(String)  # e.g., VirusTotal
    result = Column(Text)      # raw JSON string
    score = Column(Float, nullable=True)
    fetched_at = Column(DateTime, default=datetime.utcnow)

class IdempotencyKey(Base):
    __tablename__ = "idempotency_keys"
    id = Column(Integer, primary_key=True)
    key = Column(String, unique=True, nullable=False)
    agent_id = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    response_code = Column(Integer, nullable=True)
    response_body = Column(Text, nullable=True)

# Create tables if not present
Base.metadata.create_all(engine)

# Load JSON schema
if not os.path.exists(JSON_SCHEMA_PATH):
    logger.error("Agent JSON schema not found at %s", JSON_SCHEMA_PATH)
    AGENT_SCHEMA = None
else:
    with open(JSON_SCHEMA_PATH, "r") as f:
        AGENT_SCHEMA = json.load(f)

app = Flask(__name__)

# ---------- Lightweight in-memory rate limiter ----------
# note: this is per-process; for multi-instance use Redis-based limiter (e.g., Flask-Limiter)
_rate_store: Dict[str, Dict[str, Any]] = {}  # {api_key: {"window_start": ts, "count": n}}

def rate_limited(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get("X-API-KEY") or request.args.get("api_key") or "anon"
        now = int(time.time())
        window = 60  # seconds
        limit = RATE_LIMIT_RPM
        entry = _rate_store.get(api_key)
        if not entry or now - entry["window_start"] >= window:
            _rate_store[api_key] = {"window_start": now, "count": 1}
        else:
            if entry["count"] >= limit:
                return jsonify({"error": "rate_limit_exceeded"}), 429
            entry["count"] += 1
        return f(*args, **kwargs)
    return wrapper

# ---------- Auth decorator ----------
def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get("X-API-KEY") or request.args.get("api_key")
        if not api_key or api_key not in API_KEYS:
            return jsonify({"error":"Unauthorized"}), 401
        g.api_key = api_key
        g.agent_id_from_key = API_KEYS[api_key]
        return f(*args, **kwargs)
    return wrapper

# ---------- Helpers ----------
def normalize_parent(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    # simple normalization: strip, lower, remove extension duplicates
    n = name.strip().lower()
    return n

def preprocess_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clean fields, normalize parent_process, ensure numeric types.
    Returns processed dict ready for ML or DB storage.
    """
    out = dict(rec)  # shallow copy
    # normalize timestamp
    ts = rec.get("ts")
    try:
        if ts:
            # support ISO Z
            out["ts"] = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        else:
            out["ts"] = datetime.utcnow()
    except Exception:
        out["ts"] = datetime.utcnow()

    # normalize parent_process and process_name
    out["parent_process"] = normalize_parent(rec.get("parent_process"))
    if out.get("process_name"):
        out["process_name"] = rec.get("process_name").strip().lower()

    # coerce numeric fields
    for k in ["cpu_percent", "mem_percent", "net_bytes_sent_per_s", "net_bytes_recv_per_s", "num_child_processes", "process_start_age_seconds"]:
        v = rec.get(k)
        try:
            out[k] = float(v) if v is not None else None
        except Exception:
            out[k] = None
    return out

# ---------- Simple async queue stub ----------
# Replace this with Redis/RQ or Celery producer
_async_queue = []

def push_to_queue(func, *args, **kwargs):
    """Push a job to the in-memory queue (for demo). Real use: push to Redis/RQ."""
    _async_queue.append((func, args, kwargs))
    logger.debug("Pushed job to in-memory queue. queue_size=%d", len(_async_queue))

def process_async_queue_once():
    """
    Process a single job from the in-memory queue.
    Run periodically or in separate process during dev to emulate worker.
    """
    if not _async_queue:
        return
    func, args, kwargs = _async_queue.pop(0)
    try:
        func(*args, **kwargs)
    except Exception:
        logger.exception("Async job failed")

# ---------- Pipeline functions ----------
def run_ml_and_store(sess, telemetry_row: Telemetry, record_dict: Dict[str, Any]):
    """
    Run ML inference (sync) and store MLScore + ZTScore.
    For heavy load, push this to worker instead.
    """
    # Attempt to infer using inferencer if available, else fallback rule
    try:
        if inferencer:
            r = inferencer.score_record(record_dict)
            anomaly_score = float(r.get("anomaly_score", 0.0))  # higher -> more anomalous
            decision_value = float(r.get("decision_function", 0.0))
            is_anomaly = bool(r.get("is_anomaly", False))
        else:
            # Fallback simple heuristic: cpu>90 or mem>90 or net spike
            cpu = record_dict.get("cpu_percent") or 0.0
            mem = record_dict.get("mem_percent") or 0.0
            net_out = record_dict.get("net_bytes_sent_per_s") or 0.0
            # create simple anomaly score 0..1
            anomaly_score = min(1.0, (max(cpu/100.0, mem/100.0, net_out/100000.0)))
            decision_value = -anomaly_score
            is_anomaly = anomaly_score > 0.85
    except Exception:
        logger.exception("ML inference error; applying fallback")
        anomaly_score = 0.0
        decision_value = 0.0
        is_anomaly = False

    # store MLScore
    ml = MLScore(telemetry_id=telemetry_row.id,
                 anomaly_score=anomaly_score,
                 decision_value=decision_value,
                 is_anomaly=is_anomaly)
    sess.add(ml)
    sess.commit()

    # compute a basic TI score placeholder (0..1) (real TI runs async)
    ti_score = 0.0  # 0 means unknown/low trust, 1 high-reputation (we'll make low baseline)

    # compute priv score placeholder (0..1) (depends on privileges, here static)
    priv_score = 1.0  # assume low privilege by default

    # combine into ZT score (0..100, higher -> more trusted)
    # anomaly_score higher -> more anomalous -> reduce trust
    ml_contrib = max(0.0, (1.0 - anomaly_score))  # 1-anomaly -> 1 normal, 0 anomalous
    final_score_ratio = (ZT_WEIGHTS["ml"] * ml_contrib +
                         ZT_WEIGHTS["ti"] * ti_score +
                         ZT_WEIGHTS["priv"] * priv_score)
    zt_score = float(final_score_ratio * 100.0)

    # decide action
    decision = "ALLOW"
    if anomaly_score >= THRESH_ISOLATE:
        decision = "ISOLATE"
    elif anomaly_score >= THRESH_ALERT:
        decision = "ALERT"

    z = ZTScore(telemetry_id=telemetry_row.id,
                zt_score=zt_score,
                decision=decision)
    sess.add(z)
    sess.commit()

    logger.info("Processed telemetry id=%s anomaly=%.3f zt_score=%.2f decision=%s",
                telemetry_row.id, anomaly_score, zt_score, decision)

def async_worker_process_queued():
    """Call this from separate process or periodically to drain queue."""
    while _async_queue:
        func, args, kwargs = _async_queue.pop(0)
        try:
            func(*args, **kwargs)
        except Exception:
            logger.exception("Async job failed")

# ---------- Idempotency helper ----------
def check_and_mark_idempotency(sess, key: str, agent_id: str, response_obj: Optional[Dict]=None, response_code: Optional[int]=None):
    if not key:
        return None
    existing = sess.query(IdempotencyKey).filter_by(key=key).first()
    if existing:
        return existing
    new = IdempotencyKey(key=key, agent_id=agent_id)
    if response_obj is not None:
        new.response_body = json.dumps(response_obj)
    if response_code is not None:
        new.response_code = response_code
    sess.add(new)
    sess.commit()
    return new

# ---------- Ingestion endpoint ----------
@app.route("/api/v1/events", methods=["POST"])
@require_api_key
@rate_limited
def ingest_events():
    sess = Session()
    try:
        idem_key = request.headers.get("Idempotency-Key")
        if idem_key:
            existing = sess.query(IdempotencyKey).filter_by(key=idem_key).first()
            if existing and existing.response_code is not None:
                # return cached response
                return (existing.response_body, existing.response_code, {"Content-Type":"application/json"})

        # raw JSON parsing & validation
        try:
            payload = request.get_json(force=True)
        except Exception as e:
            return jsonify({"error":"Invalid JSON", "details": str(e)}), 400

        if AGENT_SCHEMA:
            try:
                validate(instance=payload, schema=AGENT_SCHEMA)
            except ValidationError as e:
                return jsonify({"error":"Schema validation failed", "message": e.message}), 400

        agent_id = payload.get("agent_id") or g.agent_id_from_key

        # register/update agent
        agent_row = sess.query(Agent).filter_by(agent_id=agent_id).first()
        if not agent_row:
            agent_row = Agent(agent_id=agent_id, api_key=g.api_key)
            sess.add(agent_row)
        agent_row.last_seen = datetime.utcnow()
        sess.commit()

        # mark idempotency placeholder (prevents duplicate work from multiple requests)
        if idem_key:
            check_and_mark_idempotency(sess, idem_key, agent_id)

        records = payload.get("records", [])
        stored = 0
        per_record_results = []
        for rec in records:
            # ensure client_record_id or deterministic record id
            if "client_record_id" in rec:
                rec_record_id = rec["client_record_id"]
            else:
                rec_record_id = f"{agent_id}:{rec.get('ts')}:{rec.get('process_name')}:{uuid.uuid4().hex[:8]}"

            # preprocess / normalize
            proc = preprocess_record(rec)
            # store telemetry
            t = Telemetry(agent_id=agent_id,
                          record_id=rec_record_id,
                          ts=proc["ts"],
                          process_name=proc.get("process_name"),
                          parent_process=proc.get("parent_process"),
                          cpu_percent=proc.get("cpu_percent"),
                          mem_percent=proc.get("mem_percent"),
                          net_bytes_sent_per_s=proc.get("net_bytes_sent_per_s"),
                          net_bytes_recv_per_s=proc.get("net_bytes_recv_per_s"),
                          num_child_processes=int(proc.get("num_child_processes") or 0),
                          process_start_age_seconds=proc.get("process_start_age_seconds"),
                          raw_json=json.dumps(rec))
            sess.add(t)
            try:
                sess.commit()
            except Exception:
                sess.rollback()
                # could be duplicate due to unique constraint
                existing = sess.query(Telemetry).filter_by(agent_id=agent_id, record_id=rec_record_id).first()
                if existing:
                    t = existing
                else:
                    raise

            # For now we process ML synchronously but we push to async queue in background variant
            # Option A: synchronous
            try:
                run_ml_and_store(sess, t, proc)
            except Exception:
                # on heavy loads, push to async worker instead
                push_to_queue(run_ml_and_store, sess, t, proc)

            stored += 1
            per_record_results.append({"record_id": rec_record_id, "ts": proc["ts"].isoformat()})

        resp = {"status":"ok", "stored": stored, "records": per_record_results}

        # save idempotency response
        if idem_key:
            existing = sess.query(IdempotencyKey).filter_by(key=idem_key).first()
            if existing:
                existing.response_code = 200
                existing.response_body = json.dumps(resp)
                sess.commit()

        return jsonify(resp), 200

    except Exception as e:
        sess.rollback()
        logger.exception("Ingestion error")
        return jsonify({"error":"Internal Server Error", "details": str(e)}), 500
    finally:
        Session.remove()

# ---------- Small admin endpoints (health, queue) ----------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status":"ok", "time": datetime.utcnow().isoformat()}), 200

@app.route("/admin/drain-queue", methods=["POST"])
def drain_queue():
    # convenience endpoint to process in-memory queue once (dev only)
    async_worker_process_queued()
    return jsonify({"status":"drained"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
