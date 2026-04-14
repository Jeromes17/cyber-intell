# realtime/server.py
"""
Realtime Alert Streaming Server (READ-ONLY)

Responsibilities:
- Stream existing alerts to clients in realtime
- No ML
- No DB writes
- No alert creation
"""

import json
import time
import sqlite3
from flask import Flask, Response

# ---------------- CONFIG ----------------

DB_PATH = r"D:\Cyber Intelligence\data\c0r3_events.sqlite"
POLL_INTERVAL = 2  # seconds

# ---------------- APP ----------------

app = Flask(__name__)

# ---------------- DB HELPERS ----------------

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def fetch_new_alerts(last_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, agent_id, ts, severity, reason, meta
        FROM alerts
        WHERE id > ?
        ORDER BY id ASC
        """,
        (last_id,)
    )
    rows = cur.fetchall()
    conn.close()
    return rows

# ---------------- SSE STREAM ----------------

def alert_stream():
    last_seen_id = 0

    while True:
        try:
            alerts = fetch_new_alerts(last_seen_id)

            for a in alerts:
                last_seen_id = a["id"]

                meta = {}
                try:
                    meta = json.loads(a["meta"]) if a["meta"] else {}
                except Exception:
                    pass

                payload = {
                    "id": a["id"],
                    "timestamp": a["ts"],
                    "agent_id": a["agent_id"],
                    "severity": a["severity"],
                    "reason": a["reason"],
                    "artifact": meta.get("artifact"),
                    "meta": meta
                }

                yield f"data: {json.dumps(payload)}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

        time.sleep(POLL_INTERVAL)

# ---------------- ROUTES ----------------

@app.route("/stream/alerts")
def stream_alerts():
    return Response(
        alert_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )

@app.route("/health")
def health():
    return {"status": "ok", "service": "realtime-stream"}, 200

# ---------------- MAIN ----------------

if __name__ == "__main__":
    print("Realtime server running on http://127.0.0.1:5002")
    app.run(host="0.0.0.0", port=5002, threaded=True)
