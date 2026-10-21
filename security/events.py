"""Structured security event log (JSON Lines).

One line per login attempt. JSON Lines is easy to read by eye, easy to parse
in Python, and can be ingested as-is by SIEM tools such as Wazuh, Elastic or
Splunk.

Privacy rule: passwords are never written to the log, in any form. The
username is stored (truncated) because it is needed to investigate an
incident.
"""

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "security_events.jsonl"
MAX_USERNAME_LENGTH = 80

_lock = threading.Lock()


def log_path():
    return Path(os.environ.get("SQLI_LOG_PATH", DEFAULT_LOG_PATH))


def record(*, source_ip, endpoint, username, outcome, indicators, severity):
    """Append one event and return it."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "event_id": uuid.uuid4().hex[:12],
        "event_type": "login_attempt",
        "source_ip": source_ip,
        "endpoint": endpoint,
        "username": (username or "")[:MAX_USERNAME_LENGTH],
        "outcome": outcome,  # "success" or "failure"
        "indicators": list(indicators),
        "severity": severity,  # "none", "medium" or "high"
    }
    path = log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event) + "\n")
    return event


def read_all():
    """Return every event in the log, oldest first. Skips damaged lines."""
    path = log_path()
    if not path.exists():
        return []
    events = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def clear():
    """Delete the log (used by tests and the lab reset button)."""
    path = log_path()
    if path.exists():
        path.unlink()
