import sqlite3
conn = sqlite3.connect("data/c0r3_events.sqlite")
cur = conn.cursor()
cur.execute("DELETE FROM alerts")
conn.commit()
conn.close()
print("SQLite alerts cleared")
