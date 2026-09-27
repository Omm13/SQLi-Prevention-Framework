import csv
from pathlib import Path

import matplotlib.pyplot as plt


RESULTS_FILE = Path(__file__).parent / "results.csv"
OUTPUT_FILE = Path(__file__).parent / "benchmark_results.png"


def load_results():
    with open(RESULTS_FILE, newline="") as file:
        return list(csv.DictReader(file))


def create_plot():
    results = load_results()

    labels = [
        f"{row['implementation']}\n{row['test_case']}"
        for row in results
    ]

    average_times = [
        float(row["average_response_time_ms"])
        for row in results
    ]

    plt.figure(figsize=(10, 6))

    plt.bar(labels, average_times)

    plt.title("SQL Injection Prevention Benchmark")
    plt.xlabel("Implementation and Test Case")
    plt.ylabel("Average Response Time (ms)")

    plt.tight_layout()

    plt.savefig(OUTPUT_FILE, dpi=300)
    plt.show()

    print(f"Graph saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    create_plot()