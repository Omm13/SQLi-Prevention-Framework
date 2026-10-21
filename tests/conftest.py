"""Test setup: isolated temporary database and log, no running server needed."""

import os
import sys
import tempfile
from pathlib import Path

# Point the app at throw-away files BEFORE it is imported.
_TMP = tempfile.mkdtemp(prefix="sqli_tests_")
os.environ["SQLI_DB_PATH"] = str(Path(_TMP) / "test.db")
os.environ["SQLI_LOG_PATH"] = str(Path(_TMP) / "events.jsonl")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

from app import app as flask_app  # noqa: E402
from security import events  # noqa: E402


@pytest.fixture()
def client():
    flask_app.config.update(TESTING=True)
    events.clear()
    os.environ["SQLI_LAB_MODE"] = "1"
    with flask_app.test_client() as test_client:
        yield test_client
    events.clear()
