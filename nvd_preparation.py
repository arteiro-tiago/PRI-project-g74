import json
import pandas as pd
from pathlib import Path

REPO_NAME = "nvd-json-data-feeds"

def extract_cvss(data):
    """Prefer CVSS 4.0, then 3.1, then 3.0, then 2.0."""
    metrics = data.get("metrics", {})
    metric_priority = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]

    for metric_name in metric_priority:
        metrics_list = metrics.get(metric_name, [])
        if not metrics_list:
            continue

        metric = metrics_list[0]
        cvss_data = metric.get("cvssData", {})

        return {
            "version": cvss_data.get("version"),
            "score": cvss_data.get("baseScore"),
            "severity": cvss_data.get("baseSeverity"),
            "vector": cvss_data.get("vectorString"),
        }

    return {"version": None, "score": None, "severity": None, "vector": None}


def extract_cwe(data):
    """Extract CWE identifiers from the NVD weaknesses section."""
    cwes = []
    for weakness in data.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value")
            if value and value not in cwes:
                cwes.append(value)
    return cwes


def extract_affected(data):
    """Normalize NVD affected product/version information."""
    affected = []
    for affected_entry in data.get("affected", []):
        for product_data in affected_entry.get("affectedData", []):
            vendor = product_data.get("vendor")
            product = product_data.get("product")

            for version in product_data.get("versions", []):
                affected.append({
                    "vendor": vendor,
                    "product": product,
                    "version": version.get("version"),
                    "less_than": version.get("lessThan"),
                    "version_type": version.get("versionType"),
                    "status": version.get("status"),
                })
    return affected


def create_csv_with_pandas(csv_filename, repo_name):
    """Parse NVD JSON feeds into a single Pandas DataFrame and save as CSV."""
    path = Path(repo_name)
    all_data = []
    
    print("extracting jsons")

    for json_file in path.rglob("*.json"):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            cve_id = data.get("id")
            descriptions = data.get("descriptions", [])
            description = next(
                (item.get("value") for item in descriptions if item.get("lang") == "en"),
                None
            )

            cvss = extract_cvss(data)
            cwe = extract_cwe(data)
            affected = extract_affected(data)

            references = [
                ref.get("url") for ref in data.get("references", []) if ref.get("url")
            ]

            record = {
                "cve_id": cve_id,
                "description": description,
                "published": data.get("published"),
                "modified": data.get("lastModified"),
                "status": data.get("vulnStatus"),
                "cvss_version": cvss.get("version"),
                "cvss_score": cvss.get("score"),
                "cvss_severity": cvss.get("severity"),
                "cvss_vector": cvss.get("vector"),
                "cwe": ";".join(cwe),
                "affected": json.dumps(affected, ensure_ascii=False),
                "references": ";".join(references),
            }

            all_data.append(record)

        except (json.JSONDecodeError, OSError) as e:
            print(f"Could not process {json_file}: {e}")

    df = pd.DataFrame(all_data)
    df = df.dropna(subset=["cve_id"])

    df.to_csv(csv_filename, index=False, encoding="utf-8")

    print("finished creating CSV :)")
    print(f"CVEs extracted: {len(df)}")


if __name__ == "__main__":
    create_csv_with_pandas("selected_cves.csv", REPO_NAME)