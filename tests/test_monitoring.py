"""Security Information Management layer: logging, detection, alerting."""

import json
from datetime import datetime, timedelta, timezone

from security import alerts, detector, events

SQLI_USERNAME = "' OR '1'='1' /*"


def post(client, endpoint, username, password):
    return client.post(endpoint, data={"username": username, "password": password})


# --- detector ---------------------------------------------------------------

def test_detector_flags_demo_input():
    hits = detector.inspect(SQLI_USERNAME, "test")
    assert "quote_then_boolean" in hits
    assert "comment_sequence" in hits


def test_detector_does_not_flag_ordinary_input():
    for text in ("omm", "O'Brien", "Anne-Marie", "password123", "it's me"):
        assert detector.inspect(text) == [], text


def test_severity_scales_with_indicator_count():
    assert detector.severity_for([]) == "none"
    assert detector.severity_for(["a"]) == "medium"
    assert detector.severity_for(["a", "b"]) == "high"


# --- event log --------------------------------------------------------------

def test_every_attempt_is_logged_with_expected_fields(client):
    post(client, "/secure-login", "omm", "password123")
    event = events.read_all()[-1]
    for field in ("timestamp", "event_id", "source_ip", "endpoint",
                  "username", "outcome", "indicators", "severity"):
        assert field in event
    assert event["outcome"] == "success"
    assert event["endpoint"] == "/secure-login"


def test_passwords_are_never_written_to_the_log(client):
    secret = "Sup3r-Secret-Value-123"
    post(client, "/secure-login", "omm", secret)
    post(client, "/vulnerable-login", "omm", secret)
    raw = events.log_path().read_text()
    assert secret not in raw


def test_log_lines_are_valid_json(client):
    post(client, "/secure-login", "omm", "x")
    for line in events.log_path().read_text().splitlines():
        json.loads(line)


def test_blocked_secure_attempt_is_still_visible_in_log(client):
    post(client, "/secure-login", SQLI_USERNAME, "test")
    event = events.read_all()[-1]
    assert event["outcome"] == "failure"
    assert event["indicators"]  # blocked by the query, still *seen* by SIM


# --- alerts -----------------------------------------------------------------

def _fake_event(ip, seconds, outcome="failure", indicators=None, endpoint="/secure-login"):
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return {
        "timestamp": (base + timedelta(seconds=seconds)).isoformat(),
        "source_ip": ip,
        "endpoint": endpoint,
        "username": "x",
        "outcome": outcome,
        "indicators": indicators or [],
        "severity": "none",
    }


def test_successful_attack_raises_critical_alert(client):
    post(client, "/vulnerable-login", SQLI_USERNAME, "test")
    result = alerts.evaluate(events.read_all())
    assert any(a["rule"] == "suspicious_login_succeeded" and a["severity"] == "critical"
               for a in result)


def test_blocked_attack_alone_is_not_critical(client):
    post(client, "/secure-login", SQLI_USERNAME, "test")
    result = alerts.evaluate(events.read_all())
    assert not any(a["severity"] == "critical" for a in result)


def test_repeated_flagged_inputs_raise_high_alert():
    evs = [_fake_event("10.0.0.9", s, indicators=["comment_sequence"]) for s in (0, 10, 20)]
    result = alerts.evaluate(evs)
    assert any(a["rule"] == "repeated_sqli_indicators" for a in result)


def test_flagged_inputs_spread_over_time_do_not_alert():
    evs = [_fake_event("10.0.0.9", s, indicators=["comment_sequence"]) for s in (0, 300, 600)]
    assert not any(a["rule"] == "repeated_sqli_indicators" for a in alerts.evaluate(evs))


def test_failed_login_burst_raises_medium_alert():
    evs = [_fake_event("10.0.0.7", s) for s in (0, 5, 10, 15, 20)]
    assert any(a["rule"] == "failed_login_burst" for a in alerts.evaluate(evs))


def test_alerts_are_per_source():
    evs = [_fake_event(f"10.0.0.{i}", i) for i in range(5)]  # 5 different IPs
    assert alerts.evaluate(evs) == []


def test_monitor_page_shows_alert(client):
    post(client, "/vulnerable-login", SQLI_USERNAME, "test")
    page = client.get("/monitor").get_data(as_text=True)
    assert "CRITICAL" in page
