# train_iso.py
import os, joblib, json, numpy as np, pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime

os.makedirs("models", exist_ok=True)
MODEL_PATH = "models/iso_forest_v1.joblib"
SCALER_PATH = "models/scaler_v1.joblib"

# Minimal feature set (must match infer_iso fallback expectations)
feat_cols = ["cpu_percent", "mem_percent", "net_bytes_sent_per_s", "net_bytes_recv_per_s", "num_child_processes"]

# Generate synthetic "normal" telemetry
rng = np.random.RandomState(42)
n_normal = 5000
cpu = rng.normal(loc=15, scale=8, size=n_normal).clip(0, 100)
mem = rng.normal(loc=20, scale=10, size=n_normal).clip(0, 100)
net_out = rng.exponential(scale=2000, size=n_normal)  # bytes/sec
net_in = rng.exponential(scale=1500, size=n_normal)
children = rng.poisson(lam=1.2, size=n_normal)

df_norm = pd.DataFrame({
    "cpu_percent": cpu,
    "mem_percent": mem,
    "net_bytes_sent_per_s": net_out,
    "net_bytes_recv_per_s": net_in,
    "num_child_processes": children
})

# Add a small set of anomalies
n_anom = 100
cpu_a = rng.normal(loc=90, scale=5, size=n_anom).clip(0,100)
mem_a = rng.normal(loc=85, scale=5, size=n_anom).clip(0,100)
net_out_a = rng.exponential(scale=200000, size=n_anom)
net_in_a = rng.exponential(scale=150000, size=n_anom)
children_a = rng.poisson(lam=10, size=n_anom)

df_anom = pd.DataFrame({
    "cpu_percent": cpu_a,
    "mem_percent": mem_a,
    "net_bytes_sent_per_s": net_out_a,
    "net_bytes_recv_per_s": net_in_a,
    "num_child_processes": children_a
})

df = pd.concat([df_norm, df_anom], ignore_index=True)
X = df[feat_cols].astype(float).fillna(0.0)

# scale
scaler = StandardScaler()
Xs = scaler.fit_transform(X)

# train IsolationForest
clf = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
clf.fit(Xs)

# Save model + scaler + feature list
joblib.dump({"model": clf, "feature_columns": feat_cols}, MODEL_PATH)
joblib.dump({"scaler": scaler}, SCALER_PATH)

print(f"Saved model to {MODEL_PATH} and scaler to {SCALER_PATH} at {datetime.utcnow().isoformat()}")

# Optional: quick sanity check
scores = clf.decision_function(Xs)
pred = clf.predict(Xs)
n_flagged = (pred == -1).sum()
print("Flagged anomalies (train):", int(n_flagged))
