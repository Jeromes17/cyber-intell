import json
import os
from scanner.process_scanner import get_all_processes as list_processes
from scanner.network_scanner import get_all_connections as list_connections
from scanner.file_scanner import scan_directory
from analyzer.analyzer import analyze_data 
from utils.logger import log_alerts
from utils.exporter import export_to_json


def pretty_write(path, data):
    """Helper function to write JSON files with formatting."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    print("Starting Cyber Sentinel Local Scan...\n")

    # 1. Process Scanning
    print("Scanning processes...")
    procs = list_processes()
    print(f"Found {len(procs)} processes.")
    pretty_write("output/reports/processes.json", procs)

    # 2. Network Scanning
    print("\nScanning network connections...")
    conns = list_connections()
    print(f"Found {len(conns)} connections.")
    pretty_write("output/reports/connections.json", conns)

    # 3. File Scanning
    print("\nEnter directory to scan (example: C:\\Users\\<YourName>\\Downloads) or press Enter to skip:")
    test_dir = input("> ").strip()
    files = []

    if test_dir:
        print(f"Scanning files under {test_dir} ...")
        files = scan_directory(test_dir)
        print(f"Scanned {len(files)} files.")
        pretty_write("output/reports/files_sample.json", files)

    # 4. Combine scan data
    scan_report = {
        "processes": procs,
        "connections": conns,
        "files": files
    }

    # 5. Analysis Phase
    print("\nPerforming threat analysis...")
    analysis_results = analyze_data(scan_report)

    alerts = analysis_results["alerts"]
    summary = analysis_results["summary"]

    # ---- NEW: Handle safe vs. alert output cleanly ----
    if not alerts:
        print("\nAnalysis Engine: No suspicious events detected.")
        print("System status: SECURE")
    else:
        print(f"\nAlerts generated: {len(alerts)}")
        print(f"Overall Severity: {summary['overall_severity']} (Score: {summary['max_risk_score']})")
    # ---------------------------------------------------

    # 6. Save Alerts
    alert_path = "output/alerts/alerts.json"
    os.makedirs(os.path.dirname(alert_path), exist_ok=True)
    log_alerts(alerts)
    print(f"Alerts saved to {alert_path}")

    # 7. Save Analysis Report
    report_path = "output/reports/analysis_report.json"
    pretty_write(report_path, analysis_results)
    print(f"Full analysis report saved to {report_path}")

    # 8. Export Summary
    export_to_json(summary, "output/reports/summary.json")
    print("Summary exported to 'output/reports/summary.json'")

    print("\nScan complete. Reports available in 'output/reports/' directory.")
