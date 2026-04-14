# realtime/test_alerts.py

from realtime.alerts import severity_from_score, build_alert, rate_limit

def test_severity():
    assert severity_from_score(0.9) == "critical"
    assert severity_from_score(0.8) == "high"
    assert severity_from_score(0.6) == "medium"
    assert severity_from_score(0.2) == "low"


def test_build_alert():
    evt = {"host": "pc1", "agent_id": "A1", "type": "proc.scan"}
    a = build_alert(evt, 0.88)
    assert a["severity"] == "high"
    assert a["host"] == "pc1"


def test_rate_limit():
    key = "test123"
    # allow first few
    assert rate_limit(key, limit=3)
    assert rate_limit(key, limit=3)
    assert rate_limit(key, limit=3)
    # block next
    assert not rate_limit(key, limit=3)
