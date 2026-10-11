import json
import os
import re
from collections import Counter

import pandas as pd
import matplotlib.pyplot as plt

OUTPUT_DIR = "figures"

# Common words we don't want to count
STOP_WORDS = {
    "a", "an", "and", "are", "as", "at", "be", "been", "being", "by",
    "can", "could", "for", "from", "has", "have", "in", "into", "is",
    "it", "its", "may", "might", "of", "on", "or", "should", "that",
    "the", "their", "there", "these", "this", "to", "was", "were",
    "which", "will", "with", "would",
}

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_COLORS = {
    "LOW": "#4caf50",
    "MEDIUM": "#ffc107",
    "HIGH": "#ff7043",
    "CRITICAL": "#c62828",
    "UNKNOWN": "#9e9e9e",
}


def get_words(text):
    if not isinstance(text, str):
        return []
    return re.findall(r"[a-z0-9]+(?:[._+-][a-z0-9]+)*", text.lower())


# ----------------------------------------------------------------- analyses

def missing_values(data):
    # treats empty strings like missing values
    cleaned = data.replace(r"^\s*$", pd.NA, regex=True)
    missing = pd.DataFrame()
    missing["missing_count"] = cleaned.isna().sum()
    missing["missing_percent"] = missing["missing_count"] / len(data) * 100
    return missing


def cvss_analysis(data):
    """Summarize CVSS scores and count CVEs per severity level."""
    scores = pd.to_numeric(data["cvss_score"], errors="coerce").dropna()
    score_summary = scores.describe()

    severity = data.loc[scores.index, "cvss_severity"]
    severity = severity.fillna("Unknown").str.strip().str.upper()
    severity_counts = severity.value_counts().to_frame("count")
    severity_counts["percent"] = severity_counts["count"] / len(scores) * 100

    return score_summary, severity_counts


def status_counts(data, column="status"):
    """Count how many CVEs have each status."""
    counts = data[column].fillna("Unknown").value_counts().to_frame("count")
    counts["percent"] = counts["count"] / len(data) * 100
    return counts


def cves_per_year(data):
    published = pd.to_datetime(data["published"], errors="coerce", utc=True).dt.year
    modified = pd.to_datetime(data["modified"], errors="coerce", utc=True).dt.year

    counts = pd.DataFrame({
        "published": published.value_counts(),
        "modified": modified.value_counts(),
    })

    all_years = range(int(counts.index.min()), int(counts.index.max()) + 1)
    counts = counts.reindex(all_years, fill_value=0).fillna(0).astype(int)
    counts.index.name = "year"
    return counts


def top_cwes_vendors_products(data, top_n=10):
    """Find the most common CWEs, vendors and products.

    Each one is counted once per CVE, even if it shows up several times.
    """
    cwe_counts = Counter()
    vendor_counts = Counter()
    product_counts = Counter()

    for _, row in data.iterrows():
        if isinstance(row["cwe"], str):
            cwes = {c.strip() for c in row["cwe"].split(";") if c.strip()}
            cwe_counts.update(cwes)

        if not isinstance(row["affected"], str):
            continue
        affected = json.loads(row["affected"])

        vendors = set()
        products = set()
        for item in affected:
            if not isinstance(item, dict):
                continue
            vendor = item.get("vendor")
            product = item.get("product")
            if isinstance(vendor, str):
                vendors.add(vendor.strip())
            if isinstance(product, str):
                products.add(product.strip())

        vendor_counts.update(vendors)
        product_counts.update(products)

    results = {}
    for name, counter in [("cwe", cwe_counts),
                          ("vendor", vendor_counts),
                          ("product", product_counts)]:
        table = pd.DataFrame(counter.most_common(top_n), columns=[name, "cve_count"])
        table["percent"] = table["cve_count"] / len(data) * 100
        results[name] = table
    return results


def text_analysis(data, top_n=15):

    text = data[["summary", "description"]].fillna("").astype(str)
    text = text.apply(lambda col: col.str.strip())

    stats = {}
    common_words = {}
    common_phrases = {}
    word_counts = {}

    for column in ["summary", "description"]:
        nonempty = text[column][text[column] != ""]

        lengths = nonempty.apply(
            lambda t: len([w for w in get_words(t) if w not in STOP_WORDS])
        )
        word_counts[column] = lengths

        stats[column] = {
            "non_empty": len(nonempty),
            "unique_texts": nonempty.nunique(),
            "median_words": lengths.median(),
            "mean_words": lengths.mean(),
            "min_words": lengths.min(),
            "max_words": lengths.max(),
        }

        word_counter = Counter()
        phrase_counter = Counter()
        for doc in nonempty:
            words = get_words(doc)
            word_counter.update({w for w in words if w not in STOP_WORDS})

            phrases = set()
            for first, second in zip(words, words[1:]):
                if first not in STOP_WORDS and second not in STOP_WORDS:
                    phrases.add(first + " " + second)
            phrase_counter.update(phrases)

        common_words[column] = pd.DataFrame(
            word_counter.most_common(top_n), columns=["term", "documents"]
        )
        common_phrases[column] = pd.DataFrame(
            phrase_counter.most_common(top_n), columns=["phrase", "documents"]
        )

    return pd.DataFrame(stats).T, common_words, common_phrases, word_counts



def save(fig, name):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    fig.tight_layout()
    fig.savefig(f"{OUTPUT_DIR}/{name}.png", dpi=160)
    plt.close(fig)


def plot_missing_values(missing):
    """Horizontal bars: one per column, easy to read long column names."""
    missing = missing.sort_values("missing_percent")
    fig, ax = plt.subplots(figsize=(8, max(4, 0.35 * len(missing))))
    ax.barh(missing.index, missing["missing_percent"], color="#5c6bc0")
    ax.set_xlim(0, 100)
    ax.set_xlabel("Missing values (%)")
    ax.set_title("Missing values per column")
    save(fig, "missing_values")


def plot_cvss(data, severity_counts):
    """Histogram for the score distribution, bars for the severity categories."""
    scores = pd.to_numeric(data["cvss_score"], errors="coerce").dropna()

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

    ax1.hist(scores, bins=20, range=(0, 10), color="#5c6bc0", edgecolor="white")
    ax1.axvline(scores.median(), color="black", linestyle="--",
                label=f"Median: {scores.median():.1f}")
    ax1.set_xlabel("CVSS score")
    ax1.set_ylabel("Number of CVEs")
    ax1.set_title("CVSS score distribution")
    ax1.legend()

    order = [s for s in SEVERITY_ORDER if s in severity_counts.index]
    order += [s for s in severity_counts.index if s not in order]
    counts = severity_counts.loc[order, "count"]
    ax2.bar(counts.index, counts.values,
            color=[SEVERITY_COLORS.get(s, "#9e9e9e") for s in counts.index])
    ax2.set_ylabel("Number of CVEs")
    ax2.set_title("CVEs per severity level")

    save(fig, "cvss")


def plot_status(status):
    """Bar chart of the status categories (sorted by count)."""
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(status.index.astype(str), status["count"], color="#26a69a")
    ax.set_ylabel("Number of CVEs")
    ax.set_title("CVE status distribution")
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
    save(fig, "status")


def plot_cves_per_year(counts):
    """Line chart: best for a trend over time."""
    fig, ax = plt.subplots(figsize=(11, 5))
    ax.plot(counts.index, counts["published"], marker="o", label="Published")
    ax.plot(counts.index, counts["modified"], marker="s", label="Modified")
    ax.set_xlabel("Year")
    ax.set_ylabel("Number of CVEs")
    ax.set_title("CVEs per year")
    ax.grid(alpha=0.3)
    ax.legend()
    save(fig, "cves_per_year")


def plot_top_tables(top):
    """One horizontal bar chart per category (labels are often long)."""
    for name, table in top.items():
        table = table.iloc[::-1]  # biggest bar on top
        fig, ax = plt.subplots(figsize=(9, max(5, 0.3 * len(table))))
        ax.barh(table[name], table["cve_count"], color="#5c6bc0")
        ax.set_xlabel("Number of CVEs")
        ax.set_title(f"Most frequent {name}s")
        save(fig, f"top_{name}s")


def plot_text_analysis(word_counts, common_words, common_phrases):
    # Box plot: compares the length distribution of the two text fields
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.boxplot(
        [word_counts["summary"], word_counts["description"]],
        tick_labels=["Summary", "Description"],
        showfliers=False,
    )
    ax.set_ylabel("Words per document")
    ax.set_title("Text length distribution (outliers hidden)")
    save(fig, "text_length_distribution")

    # Horizontal bars for the most common words and phrases
    for kind, tables, label in [("words", common_words, "term"),
                                ("phrases", common_phrases, "phrase")]:
        fig, axes = plt.subplots(1, 2, figsize=(14, 6))
        for ax, column in zip(axes, ["summary", "description"]):
            table = tables[column].sort_values("documents")
            ax.barh(table[label], table["documents"], color="#26a69a")
            ax.set_title(f"Common {kind} in {column}s")
            ax.set_xlabel(f"Documents containing {label}")
        save(fig, f"common_text_{kind}")



def main():
    cves = pd.read_csv("final_cves.csv")
    print(f"Nr of cves: {cves["cve_id"].unique().size}")
    print("Missing values:")
    missing = missing_values(cves)
    print(missing)
    plot_missing_values(missing)

    score_summary, severity_counts = cvss_analysis(cves)
    print("\nCVSS score summary:")
    print(score_summary)
    print("\nCVSS severity distribution:")
    print(severity_counts)
    plot_cvss(cves, severity_counts)

    print("\nCVE status distribution:")
    status = status_counts(cves)
    print(status)
    plot_status(status)

    print("\nCVEs per year:")
    per_year = cves_per_year(cves)
    print(per_year)
    plot_cves_per_year(per_year)

    top = top_cwes_vendors_products(cves)
    for name, table in top.items():
        print(f"\nMost frequent {name}s:")
        print(table.to_string(index=False))
    plot_top_tables(top)

    stats, words, phrases, word_counts = text_analysis(cves)
    print("\nText field stats:")
    print(stats)

    for column in ["summary", "description"]:
        print(f"\nMost common words in {column}:")
        print(words[column].to_string(index=False))
        print(f"\nMost common two-word phrases in {column}:")
        print(phrases[column].to_string(index=False))
    plot_text_analysis(word_counts, words, phrases)

    print(f"\nCharts saved to the '{OUTPUT_DIR}' folder.")


if __name__ == "__main__":
    main()