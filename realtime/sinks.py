# realtime/sinks.py

import os
import json
import smtplib
import requests
from email.message import EmailMessage
from realtime.alerts import rate_limit

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")

SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")


# ---------------- EMAIL ------------------

def send_email(alert: dict, recipients: list):
    if not recipients or not SMTP_HOST:
        return False, "email-not-configured"

    key = f"email:{alert['severity']}"
    if not rate_limit(key, 30):
        return False, "rate-limited"

    msg = EmailMessage()
    msg["From"] = SMTP_USER
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = f"[{alert['severity'].upper()}] Alert: {alert['type']}"

    msg.set_content(
        json.dumps(alert, indent=2)
    )

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.starttls()
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        return True, "sent"
    except Exception as e:
        return False, str(e)


# ---------------- WEBHOOK HELPERS ------------------

def send_webhook(url: str, alert: dict):
    if not url:
        return False, "no-url"

    key = f"webhook:{url}:{alert['severity']}"
    if not rate_limit(key, 60):
        return False, "rate-limited"

    try:
        r = requests.post(url, json=alert, timeout=5)
        return r.ok, f"{r.status_code}"
    except Exception as e:
        return False, str(e)


def send_slack(alert: dict):
    return send_webhook(SLACK_WEBHOOK, alert)


def send_discord(alert: dict):
    return send_webhook(DISCORD_WEBHOOK, alert)
