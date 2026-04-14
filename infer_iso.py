# infer_iso.py
"""
Lightweight inferencer wrapper.
- Loads joblib model file if present (models/iso_forest_v1.joblib)
- Exposes score_record(record_dict) -> dict with anomaly_score, decision_function, is_anomaly
- If model missing, uses a simple heuristic fallback.
"""

import os
import joblib
import numpy as np

MODEL_PATH = os.environ.get("ISO_MODEL_PATH", "models/iso_forest_v1.joblib")
SCALER_PATH = os.environ.get("SCALER_PATH", "models/scaler_v1.joblib")

class Inferencer:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_columns = None
        if os.path.exists(MODEL_PATH):
            data = joblib.load(MODEL_PATH)
            # We expect dictionary saved earlier with model & feature list
            if isinstance(data, dict) and "model" in data:
                self.model = data["model"]
                self.feature_columns = data.get("feature_columns")
            else:
                self.model = data  # legacy save
        if os.path.exists(SCALER_PATH):
            sdata = joblib.load(SCALER_PATH)
            # scaler might be saved as dict earlier
            if isinstance(sdata, dict) and "scaler" in sdata:
                self.scaler = sdata["scaler"]
            else:
                self.scaler = sdata

    def _build_feature_vector(self, record):
        """
        Build a feature vector from the minimal feature set used in training.
        If feature_columns exist, pick them; otherwise expect numeric keys.
        """
        if self.feature_columns:
            vec = []
            for c in self.feature_columns:
                vec.append(float(record.get(c, 0.0)))
            return np.array(vec).reshape(1, -1)
        # fallback minimal features
        features = ["cpu_percent", "mem_percent", "net_bytes_sent_per_s", "net_bytes_recv_per_s", "num_child_processes"]
        vec = [float(record.get(f, 0.0) or 0.0) for f in features]
        return np.array(vec).reshape(1, -1)

    def score_record(self, record: dict) -> dict:
        """
        Returns:
         - decision_function: float (higher -> normal for scikit IF)
         - is_anomaly: bool
         - anomaly_score: normalized 0..1 where higher -> more anomalous
        """
        try:
            X = self._build_feature_vector(record)
            if self.scaler:
                Xs = self.scaler.transform(X)
            else:
                Xs = X
            if self.model:
                # scikit-learn IsolationForest: decision_function (higher -> more normal)
                df = float(self.model.decision_function(Xs)[0])
                pred = int(self.model.predict(Xs)[0])  # -1 anomaly, 1 normal
                is_anom = (pred == -1)
                # normalize anomaly_score: map decision_function to 0..1 roughly
                # decision_function typically ranges between -0.5..0.5 roughly, but can vary.
                anomaly_score = max(0.0, min(1.0, (0.5 - df)))  # heuristic mapping
                return {"decision_function": df, "is_anomaly": is_anom, "anomaly_score": anomaly_score}
            else:
                # fallback
                cpu = float(record.get("cpu_percent") or 0.0)
                mem = float(record.get("mem_percent") or 0.0)
                net = float(record.get("net_bytes_sent_per_s") or 0.0)
                score = min(1.0, max(cpu/100.0, mem/100.0, net/100000.0))
                is_anom = score > 0.85
                return {"decision_function": -score, "is_anomaly": is_anom, "anomaly_score": score}
        except Exception as e:
            # safe fallback
            return {"decision_function": 0.0, "is_anomaly": False, "anomaly_score": 0.0}
