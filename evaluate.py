import csv
import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

QRELS_FILENAME = "qrels_template.csv"
RUNS_DIR = Path("runs")
FIGURE_PATH = Path("figures") / "pr_curves.png"
SETUPS = ["simple", "advanced"]
K = 10
RECALL_LEVELS = np.linspace(0.0, 1.0, 11)


def load_qrels(path):
    qrels = {}
    missing = 0
    with open(path, newline="", encoding="utf-8") as csv_file:
        for row in csv.DictReader(csv_file):
            label = row["relevant"].strip()
            if label == "":
                missing += 1
                continue
            qrels.setdefault(row["query"], {})[row["document id"]] = int(label) > 0
    return qrels, missing


def load_run(setup):
    with open(RUNS_DIR / f"{setup}.json", encoding="utf-8") as run_file:
        return json.load(run_file)


def precision_at_k(ranking, relevant, k=K):
    return sum(doc in relevant for doc in ranking[:k]) / k


def average_precision(ranking, relevant):
    if not relevant:
        return 0.0
    hits = 0
    total = 0.0
    for rank, doc in enumerate(ranking, start=1):
        if doc in relevant:
            hits += 1
            total += hits / rank
    return total / len(relevant)


def interpolated_pr(ranking, relevant):
    """11-point interpolated precision, using the judged pool as the recall base."""
    if not relevant:
        return np.zeros(len(RECALL_LEVELS))

    precisions, recalls = [], []
    hits = 0
    for rank, doc in enumerate(ranking, start=1):
        hits += doc in relevant
        precisions.append(hits / rank)
        recalls.append(hits / len(relevant))

    precisions = np.array(precisions)
    recalls = np.array(recalls)
    return np.array([
        precisions[recalls >= level].max() if (recalls >= level).any() else 0.0
        for level in RECALL_LEVELS
    ])


def evaluate():
    qrels, missing = load_qrels(QRELS_FILENAME)
    if missing:
        sys.exit(f"{missing} documents in '{QRELS_FILENAME}' are not judged yet.")
    if not qrels:
        sys.exit(f"No judgments found in '{QRELS_FILENAME}'.")

    runs = {setup: load_run(setup) for setup in SETUPS}
    queries = sorted(qrels, key=int)
    results = {setup: {} for setup in SETUPS}

    for setup in SETUPS:
        for q_id in queries:
            relevant = {doc for doc, is_rel in qrels[q_id].items() if is_rel}
            ranking = runs[setup].get(q_id, [])
            results[setup][q_id] = {
                "p10": precision_at_k(ranking, relevant),
                "ap": average_precision(ranking, relevant),
                "pr": interpolated_pr(ranking, relevant),
                "relevant": len(relevant),
            }

    return queries, results


def print_results(queries, results):
    header = f"{'Query':<7}{'Rel':>5}" + "".join(
        f"{f'P@{K} ' + s:>16}{'AP ' + s:>16}" for s in SETUPS
    )
    print(header)
    print("-" * len(header))
    for q_id in queries:
        line = f"Q{q_id:<6}{results[SETUPS[0]][q_id]['relevant']:>5}"
        for setup in SETUPS:
            r = results[setup][q_id]
            line += f"{r['p10']:>16.2f}{r['ap']:>16.2f}"
        print(line)

    print()
    for setup in SETUPS:
        mean_ap = np.mean([results[setup][q]["ap"] for q in queries])
        mean_p10 = np.mean([results[setup][q]["p10"] for q in queries])
        print(f"{setup:<9} MAP = {mean_ap:.2f}   mean P@{K} = {mean_p10:.2f}")

    print("\nLaTeX rows:")
    for q_id in queries:
        s, a = results["simple"][q_id], results["advanced"][q_id]
        print(f"Q{q_id} & {s['p10']:.2f} & {a['p10']:.2f} & {s['ap']:.2f} & {a['ap']:.2f} \\\\")
    maps = [np.mean([results[setup][q]["ap"] for q in queries]) for setup in SETUPS]
    print(f"\\textbf{{MAP}} & & & {maps[0]:.2f} & {maps[1]:.2f} \\\\")


def plot_pr_curves(queries, results):
    fig, axes = plt.subplots(1, len(queries) + 1, figsize=(4 * (len(queries) + 1), 4), sharey=True)
    styles = {"simple": ("#475467", "--"), "advanced": ("#1F4FD8", "-")}

    for ax, q_id in zip(axes, queries):
        for setup in SETUPS:
            color, line = styles[setup]
            ax.plot(RECALL_LEVELS, results[setup][q_id]["pr"], line, color=color, marker="o", label=setup)
        ax.set_title(f"Q{q_id}")
        ax.set_xlabel("Recall")

    for setup in SETUPS:
        color, line = styles[setup]
        mean_curve = np.mean([results[setup][q]["pr"] for q in queries], axis=0)
        axes[-1].plot(RECALL_LEVELS, mean_curve, line, color=color, marker="o", label=setup)
    axes[-1].set_title("Average")
    axes[-1].set_xlabel("Recall")

    axes[0].set_ylabel("Interpolated precision")
    axes[0].set_ylim(0, 1.05)
    axes[-1].legend()
    fig.tight_layout()

    FIGURE_PATH.parent.mkdir(exist_ok=True)
    fig.savefig(FIGURE_PATH, dpi=200)
    print(f"\nSaved precision-recall curves to '{FIGURE_PATH}'")


def main():
    queries, results = evaluate()
    print_results(queries, results)
    plot_pr_curves(queries, results)


if __name__ == "__main__":
    main()
