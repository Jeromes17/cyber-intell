PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT UNIQUE NOT NULL,
    registered_at DATETIME DEFAULT (datetime('now')),
    last_seen DATETIME DEFAULT (datetime('now')),
    api_key TEXT
);

CREATE TABLE IF NOT EXISTS telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    ts DATETIME,
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
    FOREIGN KEY(agent_id) REFERENCES agents(agent_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_record ON telemetry(agent_id, record_id);

CREATE TABLE IF NOT EXISTS ml_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telemetry_id INTEGER,
    anomaly_score REAL,
    decision_value REAL,
    is_anomaly INTEGER,
    created_at DATETIME DEFAULT (datetime('now')),
    FOREIGN KEY(telemetry_id) REFERENCES telemetry(id)
);

CREATE TABLE IF NOT EXISTS zt_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telemetry_id INTEGER,
    zt_score REAL,
    decision TEXT,
    created_at DATETIME DEFAULT (datetime('now')),
    FOREIGN KEY(telemetry_id) REFERENCES telemetry(id)
);

CREATE TABLE IF NOT EXISTS ti_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telemetry_id INTEGER,
    provider TEXT,
    result TEXT,
    score REAL,
    fetched_at DATETIME DEFAULT (datetime('now')),
    FOREIGN KEY(telemetry_id) REFERENCES telemetry(id)
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    agent_id TEXT,
    created_at DATETIME DEFAULT (datetime('now')),
    response_code INTEGER,
    response_body TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    telemetry_id INTEGER,
    process_name TEXT,
    detection_type TEXT,
    severity TEXT,
    reason TEXT,
    score REAL,
    metadata TEXT,

    alert_fingerprint TEXT,
    first_seen DATETIME,
    last_seen DATETIME,
    count INTEGER DEFAULT 1,

    created_at DATETIME DEFAULT (datetime('now')),
    FOREIGN KEY(agent_id) REFERENCES agents(agent_id),
    FOREIGN KEY(telemetry_id) REFERENCES telemetry(id)
);


CREATE INDEX IF NOT EXISTS idx_alert_dedup
ON alerts (alert_fingerprint, last_seen);

