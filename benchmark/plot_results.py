"""Plot median timings (with 95th percentile marker) for each layer.

Run:  python benchmark/plot_results.py   (after benchmark/benchmark.py)
"""

import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # write a file; no window needed
import matplotlib.pyplot as plt  # noqa: E402

RESULTS_FILE = Path(__file__).parent / "results.csv"
OUTPUT_FILE = Path(__file__).parent / "benchmark_results.png"

LAYER_TITLES = {
    "database": "Database layer (query only)",
    "monitoring": "Monitoring layer (SIM cost per request)",
    "application": "Application layer (full login request)",
}


def load_results():
    with open(RESULTS_FILE, newline="") as file:
        return list(csv.DictReader(file))


def create_plot():
    rows = load_results()
    layers = [layer for layer in LAYER_TITLES if any(r["layer"] == layer for r in rows)]

    fig, axes = plt.subplots(1, len(layers), figsize=(6 * len(layers), 5))
    if len(layers) == 1:
        axes = [axes]

    for ax, layer in zip(axes, layers):
        subset = [r for r in rows if r["layer"] == layer]
        labels = [f"{r['implementation']}\n{r['test_case']}" for r in subset]
        medians = [float(r["median_us"]) for r in subset]
        p95 = [float(r["p95_us"]) for r in subset]

        positions = range(len(subset))
        ax.barh(positions, medians, color="#4c78a8", label="median")
        ax.plot(p95, positions, "k|", markersize=14, label="95th percentile")
        ax.set_yticks(list(positions))
        ax.set_yticklabels(labels, fontsize=8)
        ax.invert_yaxis()
        ax.set_xlabel("Time per call (microseconds)")
        ax.set_title(LAYER_TITLES[layer], fontsize=10)

    handles, names = axes[0].get_legend_handles_labels()
    fig.legend(handles, names, loc="lower center", ncol=2, fontsize=9)
    fig.suptitle("SQL Injection Prevention Benchmark")
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.savefig(OUTPUT_FILE, dpi=200)
    print(f"Graph saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    create_plot()
