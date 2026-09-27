import time
import csv
from pathlib import Path

import requests


BASE_URL = "http://127.0.0.1:5000"

VALID_USERNAME = "omm"
VALID_PASSWORD = "password123"

SQLI_USERNAME = "' OR '1'='1' /*"
SQLI_PASSWORD = "test"

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
    print("=" * 60)

    for implementation, endpoint in endpoints.items():

        print(f"\n{implementation} Implementation")
        print("-" * 60)

        for test_name, username, password in test_cases:

            status_code, response_time = test_login(
                endpoint,
                username,
                password
            )

            if test_name == "SQL Injection":
                result = "BLOCKED" if status_code == 401 else "VULNERABLE"
            else:
                result = "PASS" if status_code == 200 else "FAILED"

            print(
                f"{test_name:<20} "
                f"Status: {status_code:<3} "
                f"Result: {result:<10} "
                f"Time: {response_time:.2f} ms"
            )

            results.append({
                "implementation": implementation,
                "test_case": test_name,
                "status_code": status_code,
                "result": result,
                "response_time_ms": round(response_time, 2)
            })

    with open(RESULTS_FILE, "w", newline="") as file:

        fieldnames = [
            "implementation",
            "test_case",
            "status_code",
            "result",
            "response_time_ms"
        ]

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(results)

    print("\nResults saved to:")
    print(RESULTS_FILE)


if __name__ == "__main__":
    run_benchmark()