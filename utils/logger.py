# utils/logger.py

import json
import os
import datetime

# Define the file where all analyzed alerts will be stored
ALERT_LOG_PATH = "output/alerts/alerts.json"

def log_alerts(new_alerts):
    """
    Appends a list of newly generated alert dictionaries to the persistent log file.
    
    Args:
        new_alerts (list): A list of structured alert dictionaries from the Analysis Engine.
    """
    if not new_alerts:
        print("Logger: No new alerts to record.")
        return

    # 1. Ensure the output directory exists
    output_dir = os.path.dirname(ALERT_LOG_PATH)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    existing_alerts = []
    
    # 2. Read existing logs if the file exists
    if os.path.exists(ALERT_LOG_PATH):
        try:
            with open(ALERT_LOG_PATH, 'r', encoding='utf-8') as f:
                existing_alerts = json.load(f)
        except json.JSONDecodeError:
            # Handle case where file is empty or corrupted by starting fresh
            print("Logger: WARNING - Existing alert log corrupted. Starting fresh.")
            existing_alerts = []
            
    # 3. Append new alerts
    # Add a final log time stamp for when the entry was officially saved
    log_time = datetime.datetime.now().isoformat()
    for alert in new_alerts:
        # Prevent errors if log_time was already set by analysis engine
        alert['log_time_saved'] = log_time 
        existing_alerts.append(alert)
        
    # 4. Write all logs back to the file
    with open(ALERT_LOG_PATH, 'w', encoding='utf-8') as f:
        json.dump(existing_alerts, f, indent=2, ensure_ascii=False)
    
    print(f"Logger: Successfully saved {len(new_alerts)} new alert(s) to {ALERT_LOG_PATH}")
    
# You can test this module by running it directly if needed:
if __name__ == '__main__':
    test_alert = {
        "timestamp": datetime.datetime.now().isoformat(),
        "severity": "TEST",
        "risk_score": 1.0,
        "scanner_source": "TEST_MODULE",
        "artifact": "C:\\test\\file.txt",
        "detection_reason": "Test entry for logger functionality",
        "recommendation": "Ignore this alert"
    }
    log_alerts([test_alert])