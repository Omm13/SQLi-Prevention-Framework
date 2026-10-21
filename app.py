import csv
import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from werkzeug.security import check_password_hash, generate_password_hash

from database.database import get_connection, initialize_database
from security import alerts, detector, events

app = Flask(__name__)

# Initialize the database when the application starts
initialize_database()

# Verified against when the username does not exist, so that "unknown user"
# takes as long as "wrong password". Without this, response time would reveal
# which usernames are registered (user enumeration via timing).
_DUMMY_HASH = generate_password_hash("not-a-real-password")

# The vulnerable endpoint exists only for the lab. Set SQLI_LAB_MODE=0 to
# switch it off (for example if the app is ever shown on a shared network).
LAB_MODE_ENV = "SQLI_LAB_MODE"


def lab_mode_enabled():
    return os.environ.get(LAB_MODE_ENV, "1") != "0"


def _log_attempt(endpoint, username, password, succeeded):
    """Inspect the input, write a security event, and return the event."""
    indicators = detector.inspect(username, password)
    return events.record(
        source_ip=request.remote_addr or "unknown",
        endpoint=endpoint,
        username=username,
        outcome="success" if succeeded else "failure",
        indicators=indicators,
        severity=detector.severity_for(indicators),
    )


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    connection = get_connection()
    result = connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()
    connection.close()
    return {"status": "ok", "database": "connected", "users": result["count"]}


@app.route("/vulnerable-login", methods=["GET", "POST"])
def vulnerable_login():
    if not lab_mode_enabled():
        return jsonify({"error": "vulnerable lab endpoint is disabled"}), 404

    if request.method == "GET":
        return render_template("vulnerable_login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    connection = get_connection()

    # INTENTIONALLY VULNERABLE:
    # User input is directly inserted into the SQL query.
    query = f"""
        SELECT id, username, role
        FROM users
        WHERE username = '{username}'
        AND password = '{password}'
    """

    try:
        result = connection.execute(query).fetchone()
    except Exception:
        # Malformed input can break the query. Treat as a failed login but
        # keep the event so the attempt is still visible in the log.
        result = None
    finally:
        connection.close()

    _log_attempt("/vulnerable-login", username, password, result is not None)

    if result:
        return jsonify({
            "login": "successful",
            "username": result["username"],
            "role": result["role"],
        })

    return jsonify({"login": "failed"}), 401


@app.route("/secure-login", methods=["GET", "POST"])
def secure_login():
    if request.method == "GET":
        return render_template("secure_login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    connection = get_connection()

    # SECURE:
    # 1. User input is passed separately from the SQL statement
    #    (parameterized query), so it can never change the query's structure.
    # 2. Passwords are stored as salted hashes and verified with
    #    check_password_hash, never compared as plaintext.
    row = connection.execute(
        "SELECT id, username, role, password_hash "
        "FROM secure_users WHERE username = ?",
        (username,),
    ).fetchone()

    connection.close()

    stored_hash = row["password_hash"] if row is not None else _DUMMY_HASH
    password_ok = check_password_hash(stored_hash, password)
    succeeded = row is not None and password_ok

    _log_attempt("/secure-login", username, password, succeeded)

    if succeeded:
        return jsonify({
            "login": "successful",
            "username": row["username"],
            "role": row["role"],
        })

    return jsonify({"login": "failed"}), 401


@app.route("/monitor")
def monitor():
    all_events = events.read_all()
    recent = list(reversed(all_events))[:50]
    return render_template(
        "monitor.html",
        events=recent,
        alerts=alerts.evaluate(all_events),
        total=len(all_events),
        flagged=sum(1 for e in all_events if e["indicators"]),
        rules=detector.RULES,
    )


@app.route("/benchmark")
def benchmark():
    results_file = Path(__file__).parent / "benchmark" / "results.csv"

    results = []
    if results_file.exists():
        with open(results_file, newline="") as file:
            results = list(csv.DictReader(file))

    return render_template("benchmark.html", results=results)


if __name__ == "__main__":
    # debug=True exposes an interactive debugger; keep it off unless needed.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
