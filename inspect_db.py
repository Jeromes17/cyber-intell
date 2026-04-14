#inspect_db.py

import sqlite3

conn = sqlite3.connect(r".\data\c0r3_events.sqlite")
cur = conn.cursor()

print("\n--- TELEMETRY (latest 5) ---")
for row in cur.execute("SELECT id, agent_id, record_id, ts, cpu_percent, mem_percent FROM telemetry ORDER BY id DESC LIMIT 5;"):
    print(row)

print("\n--- ML SCORES (latest 5) ---")
for row in cur.execute("SELECT id, telemetry_id, anomaly_score, is_anomaly, decision_value, created_at FROM ml_scores ORDER BY id DESC LIMIT 5;"):
    print(row)

print("\n--- ZT SCORES (latest 5) ---")
for row in cur.execute("SELECT id, telemetry_id, zt_score, decision, created_at FROM zt_scores ORDER BY id DESC LIMIT 5;"):
    print(row)

conn.close()
