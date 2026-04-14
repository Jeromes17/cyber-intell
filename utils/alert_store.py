# utils/alert_store.py

from datetime import datetime, timedelta
from utils.alerts_dedup import generate_alert_fingerprint

# Deduplication window (seconds)
DEDUP_WINDOW_SECONDS = 600  # 10 minutes


def _ensure_alerts_schema(conn):
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(alerts)")
    cols = {row[1] for row in cur.fetchall()}

    required_cols = {
        "alert_fingerprint": "TEXT",
        "first_seen": "DATETIME",
        "last_seen": "DATETIME",
        "count": "INTEGER DEFAULT 1",
        "process_name": "TEXT",
        "detection_type": "TEXT",
        "telemetry_id": "INTEGER",
        "score": "REAL",
        "metadata": "TEXT",
    }

    for col, ddl in required_cols.items():
        if col not in cols:
            cur.execute(f"ALTER TABLE alerts ADD COLUMN {col} {ddl}")

    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_alert_dedup
        ON alerts (alert_fingerprint, last_seen)
    """)
    conn.commit()


def upsert_alert(
    conn,
    agent_id,
    telemetry_id,
    process_name,
    detection_type,
    severity,
    reason,
    score,
    metadata
):
    # 🚫 HARD GUARD — reject malformed alerts
    if not agent_id or not process_name or not detection_type:
        return

    now = datetime.utcnow()
    fingerprint = generate_alert_fingerprint(
        agent_id, process_name, detection_type
    )

    window_start = now - timedelta(seconds=DEDUP_WINDOW_SECONDS)
    cur = conn.cursor()

    cur.execute("""
        SELECT id, count, severity
        FROM alerts
        WHERE alert_fingerprint = ?
          AND last_seen >= ?
        ORDER BY last_seen DESC
        LIMIT 1
    """, (fingerprint, window_start))

    row = cur.fetchone()

    if row:
        alert_id, count, existing_severity = row
        final_severity = "critical" if severity == "critical" else existing_severity

        cur.execute("""
            UPDATE alerts
            SET count = count + 1,
                last_seen = ?,
                severity = ?,
                score = ?
            WHERE id = ?
        """, (now, final_severity, score, alert_id))
    else:
        cur.execute("""
            INSERT INTO alerts (
                agent_id,
                telemetry_id,
                process_name,
                detection_type,
                severity,
                reason,
                score,
                metadata,
                alert_fingerprint,
                first_seen,
                last_seen,
                count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (
            agent_id,
            telemetry_id,
            process_name,
            detection_type,
            severity,
            reason,
            score,
            metadata,
            fingerprint,
            now,
            now
        ))

    conn.commit()
