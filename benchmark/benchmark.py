import time
import csv
from pathlib import Path

import requests


BASE_URL = "http://127.0.0.1:5000"

VALID_USERNAME = "omm"
VALID_PASSWORD = "password123"

SQLI_USERNAME = "' OR '1'='1' /*"
SQLI_PASSWORD = "test"

NUMBER_OF_RUNS = 20

RESULTS_FILE = Path(__file__).parent / "results.csv"


def test_login(endpoint, username, password):
    start_time = time.perf_counter()

    response = requests.post(
        f"{BASE_URL}{endpoint}",
        data={
            "username": username,
            "password": password
        }
    )

    end_time = time.perf_counter()

    response_time = (end_time - start_time) * 1000

    return response.status_code, response_time


def run_test(implementation, endpoint, test_name, username, password):
    response_times = []
    status_codes = []

    for _ in range(NUMBER_OF_RUNS):

        status_code, response_time = test_login(
            endpoint,
            username,
            password
        )

        status_codes.append(status_code)
        response_times.append(response_time)

    average_time = sum(response_times) / len(response_times)
    minimum_time = min(response_times)
    maximum_time = max(response_times)

    if test_name == "SQL Injection":
        blocked_count = status_codes.count(401)
        result = (
            "BLOCKED"
            if blocked_count == NUMBER_OF_RUNS
            else "VULNERABLE"
        )
    else:
        successful_count = status_codes.count(200)
        result = (
            "PASS"
            if successful_count == NUMBER_OF_RUNS
            else "FAILED"
        )

    print(
        f"{implementation:<12} "
        f"{test_name:<18} "
        f"Result: {result:<10} "
        f"Avg: {average_time:.2f} ms  "
        f"Min: {minimum_time:.2f} ms  "
        f"Max: {maximum_time:.2f} ms"
    )

    return {
        "implementation": implementation,
        "test_case": test_name,
        "runs": NUMBER_OF_RUNS,
        "result": result,
        "average_response_time_ms": round(average_time, 2),
        "minimum_response_time_ms": round(minimum_time, 2),
        "maximum_response_time_ms": round(maximum_time, 2)
    }


def run_benchmark():

    test_cases = [
        ("Valid Login", VALID_USERNAME, VALID_PASSWORD),
        ("SQL Injection", SQLI_USERNAME, SQLI_PASSWORD)
    ]

    endpoints = {
        "Vulnerable": "/vulnerable-login",
        "Secure": "/secure-login"
    }

    results = []

    print("\nSQL Injection Prevention Benchmark")
    print("=" * 85)
    print(f"Runs per test: {NUMBER_OF_RUNS}")
    print("-" * 85)

    for implementation, endpoint in endpoints.items():

        for test_name, username, password in test_cases:

            result = run_test(
                implementation,
                endpoint,
                test_name,
                username,
                password
            )

            results.append(result)

    with open(RESULTS_FILE, "w", newline="") as file:

        fieldnames = [
            "implementation",
            "test_case",
            "runs",
            "result",
            "average_response_time_ms",
            "minimum_response_time_ms",
            "maximum_response_time_ms"
        ]

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(results)

    print("-" * 85)
    print(f"Results saved to: {RESULTS_FILE}")


if __name__ == "__main__":
    run_benchmark()