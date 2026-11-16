import csv
import json
import urllib.parse
import urllib.request
from pathlib import Path

SOLR_URLS = {
    "simple": "http://localhost:8983/solr/cves_simple/select",
    "advanced": "http://localhost:8983/solr/cves_advanced/select",
}

CSV_FILENAME = "qrels_template.csv"
RUNS_DIR = Path("runs")
ROWS_TO_FETCH = 30

QUERIES = {
    "1": "XSS dashboard administration panel",
    "2": "unauthenticated remote code execution framework",
    "3": "privilege escalation Linux kernel",
    "4": "memory corruption buffer overflow denial of service code execution network services protocols"
}

SETUPS = {
    "simple": {
        "defType": "edismax",
        "qf": "description summary affected cve_id",
    },
    "advanced": {
        "defType": "edismax",
        "qf": "cve_id^10 summary^5 description^3 affected^2 text_all^1",
        "pf": "summary^10 description^5",
        "bq": "cvss_severity:CRITICAL^3 cvss_severity:HIGH^1.5",
    }
}

FIELDNAMES = ["query", "iteration", "document id", "relevant"]


def get_solr_doc_ids(solr_endpoint, query_text, setup_params):
    params = {"q": query_text, "rows": ROWS_TO_FETCH, "fl": "cve_id", "wt": "json"}
    params.update(setup_params)

    url = f"{solr_endpoint}?{urllib.parse.urlencode(params)}"

    with urllib.request.urlopen(url) as response:
        data = json.loads(response.read().decode("utf-8"))

    docs = data.get("response", {}).get("docs", [])
    return [doc["cve_id"] for doc in docs if doc.get("cve_id")]


def load_existing_judgments(path):
    """Keep relevance labels already filled in, so re-running never erases them."""
    if not Path(path).exists():
        return {}

    with open(path, newline="", encoding="utf-8") as csv_file:
        return {
            (row["query"], row["document id"]): row["relevant"]
            for row in csv.DictReader(csv_file)
            if row.get("relevant", "").strip()
        }


def main():
    RUNS_DIR.mkdir(exist_ok=True)
    judgments = load_existing_judgments(CSV_FILENAME)
    pooled_docs = {q_id: set() for q_id in QUERIES}

    for setup_name, endpoint in SOLR_URLS.items():
        run = {}
        for q_id, q_text in QUERIES.items():
            print(f"Running query [{q_id}] on '{setup_name}' core")
            doc_ids = get_solr_doc_ids(endpoint, q_text, SETUPS[setup_name])
            run[q_id] = doc_ids
            pooled_docs[q_id].update(doc_ids)

        run_path = RUNS_DIR / f"{setup_name}.json"
        with open(run_path, "w", encoding="utf-8") as run_file:
            json.dump(run, run_file, indent=4)
        print(f"Saved ranking to '{run_path}'")

    with open(CSV_FILENAME, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=FIELDNAMES)
        writer.writeheader()
        for q_id, doc_ids in pooled_docs.items():
            for doc_id in sorted(doc_ids):
                writer.writerow({
                    "query": q_id,
                    "iteration": 0,
                    "document id": doc_id,
                    "relevant": judgments.get((q_id, doc_id), ""),
                })

    kept = sum(1 for key in judgments if key[1] in pooled_docs.get(key[0], set()))
    print(f"File '{CSV_FILENAME}' generated ({kept} existing judgments kept)")


if __name__ == "__main__":
    main()
