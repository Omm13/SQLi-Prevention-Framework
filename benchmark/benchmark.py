"""Benchmark: security outcome and cost of each implementation.

Run:  python benchmark/benchmark.py        (no server needs to be running)

What is measured, and why it is measured this way
-------------------------------------------------
Layer "database":
    Only the SQL call. String-built query vs parameterized query. This is the
    cost that actually differs between the two designs, so it is timed in
    isolation (no HTTP, no Flask, no network noise).

Layer "application":
    The full login request through Flask's in-process test client (no network).
    Includes input inspection, event logging and, for the secure endpoint,
    password-hash verification.

Layer "monitoring":
    The per-request cost of the SIM layer on its own (inspect + log write).

Statistics: warm-up runs are discarded; we report the median (robust to
outliers), the 95th percentile (worst typical case), the mean and the standard
deviation. Timings are in microseconds.
"""

import csv
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

# Use a private database and log so benchmarking never touches real data.
_TMP = tempfile.mkdtemp(prefix="sqli_bench_")
os.environ["SQLI_DB_PATH"] = str(Path(_TMP) / "bench.db")
os.environ["SQLI_LOG_PATH"] = str(Path(_TMP) / "bench_events.jsonl")
os.environ["SQLI_LAB_MODE"] = "1"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import app  # noqa: E402
from database.database import get_connection  # noqa: E402
from security import detector, events  # noqa: E402

RESULTS_FILE = Path(__file__).parent / "results.csv"

WARMUP = 200
DB_ITERATIONS = 5000
MONITOR_ITERATIONS = 2000
APP_ITERATIONS = 300       # lower: password hashing is deliberately slow

VALID = ("omm", "password123")
SQLI = ("' OR '1'='1' /*", "test")   # the project's single controlled demo input

FIELDS = [
    "layer", "implementation", "test_case", "iterations", "result",
    "median_us", "p95_us", "mean_us", "stdev_us",
]


def summarize(samples_ns):
    us = sorted(s / 1000 for s in samples_ns)
    p95 = us[int(0.95 * (len(us) - 1))]
    return {
        "median_us": round(statistics.median(us), 1),
        "p95_us": round(p95, 1),
        "mean_us": round(statistics.fmean(us), 1),
        "stdev_us": round(statistics.pstdev(us), 1),
    }


def time_calls(func, iterations, warmup=WARMUP):
    for _ in range(warmup):
        func()
    samples = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        func()
        samples.append(time.perf_counter_ns() - start)
    return samples


# --- database layer ---------------------------------------------------------

def db_string_built(connection, username, password):
    query = (
        "SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    return connection.execute(query).fetchone()


def db_parameterized(connection, username, password):
    return connection.execute(
        "SELECT id, username, role FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()


def bench_database(rows):
    connection = get_connection()
    for impl, func in (("String-built (vulnerable)", db_string_built),
                       ("Parameterized (secure)", db_parameterized)):
        for case, (user, pwd) in (("Valid Login", VALID), ("SQL Injection", SQLI)):
            returned = func(connection, user, pwd) is not None
            if case == "Valid Login":
                result = "PASS" if returned else "FAILED"
            else:
                result = "VULNERABLE" if returned else "BLOCKED"
            samples = time_calls(lambda: func(connection, user, pwd), DB_ITERATIONS)
            rows.append({"layer": "database", "implementation": impl,
                         "test_case": case, "iterations": DB_ITERATIONS,
                         "result": result, **summarize(samples)})
    connection.close()


# --- monitoring layer -------------------------------------------------------

def bench_monitoring(rows):
    def inspect_only():
        detector.inspect(*SQLI)

    def inspect_and_log():
        hits = detector.inspect(*SQLI)
        events.record(source_ip="127.0.0.1", endpoint="/bench", username=SQLI[0],
                      outcome="failure", indicators=hits,
                      severity=detector.severity_for(hits))

    for impl, func in (("Input inspection", inspect_only),
                       ("Inspection + event log write", inspect_and_log)):
        samples = time_calls(func, MONITOR_ITERATIONS)
        rows.append({"layer": "monitoring", "implementation": impl,
                     "test_case": "SQL Injection", "iterations": MONITOR_ITERATIONS,
                     "result": "n/a", **summarize(samples)})


# --- application layer ------------------------------------------------------

def bench_application(rows):
    client = app.test_client()
    for impl, endpoint in (("Vulnerable endpoint", "/vulnerable-login"),
                           ("Secure endpoint", "/secure-login")):
        for case, (user, pwd) in (("Valid Login", VALID), ("SQL Injection", SQLI)):
            def request_once():
                return client.post(endpoint, data={"username": user, "password": pwd})

            status = request_once().status_code
            if case == "Valid Login":
                result = "PASS" if status == 200 else "FAILED"
            else:
                result = "VULNERABLE" if status == 200 else "BLOCKED"
            samples = time_calls(request_once, APP_ITERATIONS, warmup=10)
            rows.append({"layer": "application", "implementation": impl,
                         "test_case": case, "iterations": APP_ITERATIONS,
                         "result": result, **summarize(samples)})


def run_benchmark():
    rows = []
    print("Benchmarking database layer ...")
    bench_database(rows)
    print("Benchmarking monitoring layer ...")
    bench_monitoring(rows)
    print("Benchmarking application layer ...")
    bench_application(rows)

    with open(RESULTS_FILE, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print()
    print(f"{'layer':<12}{'implementation':<30}{'test case':<15}{'result':<11}"
          f"{'median':>10}{'p95':>10}{'stdev':>10}  (us)")
    print("-" * 100)
    for r in rows:
        print(f"{r['layer']:<12}{r['implementation']:<30}{r['test_case']:<15}"
              f"{r['result']:<11}{r['median_us']:>10}{r['p95_us']:>10}{r['stdev_us']:>10}")
    print(f"\nSaved: {RESULTS_FILE}")


if __name__ == "__main__":
    run_benchmark()
