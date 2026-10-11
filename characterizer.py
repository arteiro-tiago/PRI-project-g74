import json
import re
from collections import Counter

import pandas as pd
import matplotlib.pyplot as plt

# Common words we don't want to count
STOP_WORDS = {
    "a", "an", "and", "are", "as", "at", "be", "been", "being", "by",
    "can", "could", "for", "from", "has", "have", "in", "into", "is",
    "it", "its", "may", "might", "of", "on", "or", "should", "that",
    "the", "their", "there", "these", "this", "to", "was", "were",
    "which", "will", "with", "would",
}


def get_words(text):
    if not isinstance(text, str):
        return []
    return re.findall(r"[a-z0-9]+(?:[._+-][a-z0-9]+)*", text.lower())


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


def top_cwes_vendors_products(data, top_n=30):
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


def plot_text_analysis(word_counts, common_phrases, output_dir="figures"):
    import os
    os.makedirs(output_dir, exist_ok=True)

    plt.figure(figsize=(8, 5))
    plt.boxplot(
        [word_counts["summary"], word_counts["description"]],
        tick_labels=["Summary", "Description"],
        showfliers=False,
    )
    plt.ylabel("Words per document")
    plt.title("Text length distribution (outliers hidden)")
    plt.tight_layout()
    plt.savefig(f"{output_dir}/text_length_distribution.png", dpi=160)
    plt.close()

    # Common phrases bar charts
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    for ax, column in zip(axes, ["summary", "description"]):
        phrases = common_phrases[column].sort_values("documents")
        ax.barh(phrases["phrase"], phrases["documents"])
        ax.set_title(f"Common phrases in {column}s")
        ax.set_xlabel("Documents containing phrase")
    plt.tight_layout()
    plt.savefig(f"{output_dir}/common_text_phrases.png", dpi=160)
    plt.close()


def main():
    cves = pd.read_csv("final_cves.csv")
    print(f"Nr of cves: {cves["cve_id"].unique().size}")
    print("Missing values:")
    print(missing_values(cves))

    score_summary, severity_counts = cvss_analysis(cves)
    print("\nCVSS score summary:")
    print(score_summary)
    print("\nCVSS severity distribution:")
    print(severity_counts)

    print("\nCVEs per year:")
    print(cves_per_year(cves))

    top = top_cwes_vendors_products(cves)
    for name, table in top.items():
        print(f"\nMost frequent {name}s:")
        print(table.to_string(index=False))

    stats, words, phrases, word_counts = text_analysis(cves)
    print("\nText field stats:")
    print(stats)

    for column in ["summary", "description"]:
        print(f"\nMost common words in {column}:")
        print(words[column].to_string(index=False))
        print(f"\nMost common two-word phrases in {column}:")
        print(phrases[column].to_string(index=False))

    plot_text_analysis(word_counts, phrases)
    print("\nCharts saved to the 'figures' folder.")


if __name__ == "__main__":
    main()