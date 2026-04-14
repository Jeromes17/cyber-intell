# Cyber Intelligence/utils/exporter.py
import os
import csv
import json
from datetime import datetime
from typing import List, Dict, Any

# Pulls the runtime alerts path; logger.py does NOT import exporter, so no circular import.
try:
    from utils.logger import ALERT_LOG_PATH
except Exception:
    ALERT_LOG_PATH = os.path.join("output", "alerts", "alerts.json")

# Try to use fpdf2 if available (PDF export is optional)
try:
    from fpdf import FPDF  # fpdf2
except Exception:
    FPDF = None


# -------------------------
# Generic JSON / CSV Export
# -------------------------

def export_to_json(data: Any, path: str) -> None:
    """
    Export any dict/list to a pretty JSON file.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"JSON saved: {path}")


def export_to_csv(rows: List[Dict[str, Any]], path: str) -> None:
    """
    Export a list[dict] to CSV.
    Example: rows = [{"severity":"HIGH","risk_score":80,...}, ...]
    Uses a union of all keys across rows for the header.
    """
    if not rows:
        print("No rows to export to CSV.")
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    headers = sorted({k for r in rows for k in r.keys()})
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        w.writerows(rows)
    print(f"CSV saved: {path}")


# -------------------------
# Convenience Exporters
# -------------------------

def _load_alerts() -> List[Dict[str, Any]]:
    """
    Load alerts from ALERT_LOG_PATH, returning a list.
    Gracefully handles missing/corrupt files.
    """
    if not os.path.exists(ALERT_LOG_PATH):
        return []
    try:
        with open(ALERT_LOG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def export_alerts_to_csv(dest_path: str | None = None) -> str:
    """
    Read alerts from output/alerts/alerts.json and export to CSV.
    Includes a 1-row summary header with CRITICAL/HIGH/MEDIUM/LOW counts.

    Returns the final CSV path.
    """
    alerts = _load_alerts()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if dest_path is None:
        dest_path = os.path.join("output", "reports", f"alerts_{ts}.csv")
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

    # Quick counts
    sev_levels = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    counts = {k: 0 for k in sev_levels}
    for a in alerts:
        sev = a.get("severity", "")
        if sev in counts:
            counts[sev] += 1

    # Union header of all alert keys (for the table part)
    table_headers = sorted({k for a in alerts for k in a.keys()}) if alerts else [
        "timestamp", "severity", "risk_score", "scanner_source", "artifact",
        "detection_reason", "recommendation", "log_time_saved"
    ]

    with open(dest_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        # Summary block
        w.writerow(["SUMMARY", "CRITICAL", "HIGH", "MEDIUM", "LOW", "TOTAL"])
        w.writerow(["", counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"], len(alerts)])
        w.writerow([])  # spacer

        # Table header + rows
        w = csv.DictWriter(f, fieldnames=table_headers)
        w.writeheader()
        for a in alerts:
            # Make sure we only write keys that are present in header
            row = {k: a.get(k, "") for k in table_headers}
            w.writerow(row)

    print(f"CSV exported: {dest_path}")
    return dest_path


def export_summary_to_csv(summary: Dict[str, Any], dest_path: str | None = None) -> str:
    """
    Write a tiny one-line summary CSV (useful if you want a separate summary artifact).
    Returns the final CSV path.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if dest_path is None:
        dest_path = os.path.join("output", "reports", f"summary_{ts}.csv")
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

    # Flatten 1-level summary dict into two rows: header + values
    headers = list(summary.keys())
    with open(dest_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerow([summary.get(h, "") for h in headers])

    print(f"Summary CSV exported: {dest_path}")
    return dest_path


# -------------------------
# Optional PDF Export
# -------------------------

def export_to_pdf(summary: Dict[str, Any], path: str) -> None:
    """
    Export a simple summary dict to PDF.
    Expects keys like: total_alerts, max_risk_score, overall_severity, timestamp

    Note: Requires 'fpdf2'. If you see a warning about both PyFPDF & fpdf2 being
    installed, uninstall the legacy package:
        pip uninstall --yes pypdf
        pip install --upgrade fpdf2
    """
    if FPDF is None:
        raise RuntimeError("fpdf2 is not installed. Run: pip install fpdf2")

    os.makedirs(os.path.dirname(path), exist_ok=True)
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=16)
    pdf.cell(0, 10, "Cyber Sentinel - Security Summary", ln=True, align="C")
    pdf.ln(6)
    pdf.set_font("Arial", size=12)
    for k, v in summary.items():
        pdf.multi_cell(0, 8, f"{k}: {v}")
    pdf.output(path)
    print(f"PDF saved: {path}")
