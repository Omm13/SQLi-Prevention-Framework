"""Correlation rules: turn many small events into one meaningful alert.

A single flagged login is a data point. Several in a short time from one
source is an incident. These rules read the event log and produce alerts.
"""

from datetime import datetime, timedelta

# Tunable thresholds (kept as plain constants so they are easy to explain).
FLAGGED_BURST_COUNT = 3        # flagged attempts ...
FLAGGED_BURST_WINDOW_S = 60    # ... within this many seconds -> alert
FAILED_BURST_COUNT = 5         # failed logins ...
FAILED_BURST_WINDOW_S = 60     # ... within this many seconds -> alert


def _parse(ts):
    return datetime.fromisoformat(ts)


def _within(events, window_s):
    """Return True if the events' span is no longer than window_s seconds."""
    times = sorted(_parse(e["timestamp"]) for e in events)
    return times[-1] - times[0] <= timedelta(seconds=window_s)


def _sliding_window_hit(events, count, window_s):
    """True if any `count` consecutive events fit inside window_s seconds."""
    events = sorted(events, key=lambda e: e["timestamp"])
    for i in range(len(events) - count + 1):
        if _within(events[i:i + count], window_s):
            return events[i:i + count]
    return None


def evaluate(events):
    """Return a list of alert dicts for the given event list."""
    alerts = []
    by_ip = {}
    for event in events:
        by_ip.setdefault(event["source_ip"], []).append(event)

    for ip, ip_events in by_ip.items():
        # Rule 1: repeated SQLi indicators from the same source.
        flagged = [e for e in ip_events if e["indicators"]]
        hit = _sliding_window_hit(flagged, FLAGGED_BURST_COUNT, FLAGGED_BURST_WINDOW_S)
        if hit:
            alerts.append({
                "rule": "repeated_sqli_indicators",
                "severity": "high",
                "source_ip": ip,
                "summary": (
                    f"{FLAGGED_BURST_COUNT}+ SQL-injection-style inputs from "
                    f"{ip} within {FLAGGED_BURST_WINDOW_S}s"
                ),
                "first_seen": hit[0]["timestamp"],
                "last_seen": hit[-1]["timestamp"],
            })

        # Rule 2: burst of failed logins (guessing or probing).
        failures = [e for e in ip_events if e["outcome"] == "failure"]
        hit = _sliding_window_hit(failures, FAILED_BURST_COUNT, FAILED_BURST_WINDOW_S)
        if hit:
            alerts.append({
                "rule": "failed_login_burst",
                "severity": "medium",
                "source_ip": ip,
                "summary": (
                    f"{FAILED_BURST_COUNT}+ failed logins from {ip} "
                    f"within {FAILED_BURST_WINDOW_S}s"
                ),
                "first_seen": hit[0]["timestamp"],
                "last_seen": hit[-1]["timestamp"],
            })

        # Rule 3: a successful login that carried SQLi indicators.
        # On the vulnerable endpoint this is the sign the attack worked.
        for event in ip_events:
            if event["outcome"] == "success" and event["indicators"]:
                alerts.append({
                    "rule": "suspicious_login_succeeded",
                    "severity": "critical",
                    "source_ip": ip,
                    "summary": (
                        f"Login SUCCEEDED on {event['endpoint']} with "
                        f"SQL-injection indicators ({', '.join(event['indicators'])})"
                    ),
                    "first_seen": event["timestamp"],
                    "last_seen": event["timestamp"],
                })

    order = {"critical": 0, "high": 1, "medium": 2}
    alerts.sort(key=lambda a: (order.get(a["severity"], 9), a["first_seen"]))
    return alerts
