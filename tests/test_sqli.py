"""Behavior of the two login implementations (vulnerable vs parameterized)."""

import os
import sqlite3

from security import events

# The single controlled demo input used throughout this project.
SQLI_USERNAME = "' OR '1'='1' /*"
SQLI_PASSWORD = "test"


def post(client, endpoint, username, password):
    return client.post(endpoint, data={"username": username, "password": password})


def test_vulnerable_endpoint_accepts_sqli(client):
    response = post(client, "/vulnerable-login", SQLI_USERNAME, SQLI_PASSWORD)
    assert response.status_code == 200


def test_secure_endpoint_rejects_sqli(client):
    response = post(client, "/secure-login", SQLI_USERNAME, SQLI_PASSWORD)
    assert response.status_code == 401


def test_valid_login_works_on_both(client):
    assert post(client, "/vulnerable-login", "omm", "password123").status_code == 200
    assert post(client, "/secure-login", "omm", "password123").status_code == 200


def test_wrong_password_fails_on_both(client):
    assert post(client, "/vulnerable-login", "omm", "wrong").status_code == 401
    assert post(client, "/secure-login", "omm", "wrong").status_code == 401


def test_secure_endpoint_does_not_break_on_apostrophe(client):
    """Control case: ordinary names containing quotes must not crash."""
    response = post(client, "/secure-login", "O'Brien", "x")
    assert response.status_code == 401
    event = events.read_all()[-1]
    assert event["indicators"] == []  # not a false positive


def test_secure_table_stores_hashes_not_plaintext():
    from database.database import get_connection

    connection = get_connection()
    row = connection.execute(
        "SELECT password_hash FROM secure_users WHERE username = 'omm'"
    ).fetchone()
    connection.close()
    assert row["password_hash"] != "password123"
    assert "password123" not in row["password_hash"]


def test_malformed_input_on_vulnerable_endpoint_does_not_crash(client):
    response = post(client, "/vulnerable-login", "'", "x")
    assert response.status_code == 401


def test_lab_mode_off_disables_vulnerable_endpoint(client):
    os.environ["SQLI_LAB_MODE"] = "0"
    assert post(client, "/vulnerable-login", "omm", "password123").status_code == 404
    assert post(client, "/secure-login", "omm", "password123").status_code == 200


def test_pages_render_and_stylesheet_is_served(client):
    for path in ("/", "/vulnerable-login", "/secure-login", "/monitor", "/benchmark"):
        assert client.get(path).status_code == 200
    assert client.get("/static/style.css").status_code == 200


def test_stacked_statements_are_not_executed_by_sqlite_driver(client):
    """sqlite3's execute() refuses multiple statements, so this must not
    modify data. (Documented as a driver safety net, not a defense.)"""
    post(client, "/vulnerable-login", "x'; DELETE FROM users; --", "x")
    assert post(client, "/vulnerable-login", "omm", "password123").status_code == 200


def test_unknown_user_still_costs_a_hash_check(client, monkeypatch):
    """Timing safety: an unknown username must trigger the same password-hash
    verification as a known one, so response time cannot reveal which
    usernames exist."""
    import app as app_module

    calls = []
    real = app_module.check_password_hash

    def counting(stored, password):
        calls.append(1)
        return real(stored, password)

    monkeypatch.setattr(app_module, "check_password_hash", counting)
    post(client, "/secure-login", "no-such-user", "whatever")
    assert len(calls) == 1
    post(client, "/secure-login", "omm", "wrong")
    assert len(calls) == 2
