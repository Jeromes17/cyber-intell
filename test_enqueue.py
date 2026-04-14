# test_enqueue.py
import sqlite3, json, os
import dashboard

# fetch last telemetry id & raw_json
db = sqlite3.connect(os.path.join(os.path.dirname(__file__), "data", "c0r3_events.sqlite"))
cur = db.cursor()
cur.execute("SELECT id, raw_json FROM telemetry ORDER BY id DESC LIMIT 1")
row = cur.fetchone()
if not row:
    print("no telemetry rows found")
else:
    tid = row[0]
    proc = json.loads(row[1])
    print("Calling enqueue_processing_job for telemetry", tid)
    res = dashboard.enqueue_processing_job(tid, proc)
    print("enqueue result:", res)
db.close()
