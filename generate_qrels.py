import csv
import json
import urllib.parse
import urllib.request

SOLR_URLS = {
    "simple": "http://localhost:8983/solr/cves_simple/select",
    "advanced": "http://localhost:8983/solr/cves_advanced/select",
}

CSV_FILENAME = "qrels_template.csv"
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


def get_solr_doc_ids(solr_endpoint, query_text, setup_params):
  
  params = {"q": query_text, "rows": ROWS_TO_FETCH, "wt": "json"}
  params.update(setup_params)

  url = f"{solr_endpoint}?{urllib.parse.urlencode(params)}"

  with urllib.request.urlopen(url) as response:
    data = json.loads(response.read().decode("utf-8"))
    docs = data.get("response", {}).get("docs", [])

    doc_ids = []
    for doc in docs:
      doc_id = doc.get("cve_id") or doc.get("id")
      if doc_id:
        doc_ids.append(doc_id)
    return doc_ids


def main():

  pooled_docs = {q_id: set() for q_id in QUERIES.keys()}

  for q_id, q_text in QUERIES.items():
    for setup_name, endpoint in SOLR_URLS.items():
      print(f"Running Query [{q_id}] on '{setup_name}' core")
      setup_params = SETUPS[setup_name]
      doc_ids = get_solr_doc_ids(endpoint, q_text, setup_params)

      for doc_id in doc_ids:
        pooled_docs[q_id].add(doc_id)

  rows_to_write = []
  for q_id, unique_doc_ids in pooled_docs.items():
    for doc_id in unique_doc_ids:
      rows_to_write.append({
          "query": q_id,
          "iteration": 0,
          "document id": doc_id,
          "relevant": "",
      })

  with open(CSV_FILENAME, mode="w", newline="", encoding="utf-8") as csv_file:
    fieldnames = ["query", "iteration", "document id", "relevant"]
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

    writer.writeheader()
    for row in rows_to_write:
      writer.writerow(row)


if __name__ == "__main__":
  main()