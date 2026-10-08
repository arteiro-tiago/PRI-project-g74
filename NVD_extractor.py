import subprocess
import shutil
import random
import json
import csv
import pandas as pd
from pathlib import Path

nPerYear = 300
repo_name = "nvd-json-data-feeds"
ghad_repo_name = "github-advisory-database"

def cloneRepo():
    path = Path(repo_name)

    if path.exists():
        print("deleting existing copy")
        shutil.rmtree(path)

    print("CLONE")
    subprocess.run(["git", "clone", "--depth", "1", f"https://github.com/fkie-cad/{repo_name}.git"])


def clone_ghad_repo():
    path = Path(ghad_repo_name)

    if path.exists():
        print("deleting existing GHAD copy")
        shutil.rmtree(path)

    print("CLONE GHAD")
    subprocess.run([
        "git",
        "clone",
        "--depth",
        "1",
        "https://github.com/github/advisory-database.git",
        ghad_repo_name,
    ], check=True)


def filter_cve_data(start_year, end_year, nPerYear):
    root = Path(repo_name)
    
    if not root.exists():
        print(f"Directory {repo_name} not found.")
        return

    for item in root.iterdir():
        
        if item.is_dir() and item.name.startswith("CVE"):
            year_str = item.name[4:8]
        
            year = int(year_str)
            
            if  year < start_year or year > end_year:
                shutil.rmtree(item)
            else:
                
                json_files = sorted(item.rglob("*.json")) #retorna todos os jsons dentro desta pasta
                
                random.shuffle(json_files)
                files_to_delete = json_files[nPerYear:]
                for file_path in files_to_delete:
                    file_path.unlink()
            
def create_csv_with_pandas(csv_filename):
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
                (
                    item.get("value")
                    for item in descriptions
                    if item.get("lang") == "en"
                ),
                None
            )

            def extract_cvss(data):
                """
                Prefer CVSS 4.0, then 3.1, then 3.0, then 2.0.
                """

                metrics = data.get("metrics", {})

                metric_priority = [
                    "cvssMetricV40",
                    "cvssMetricV31",
                    "cvssMetricV30",
                    "cvssMetricV2",
                ]

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

                return {
                    "version": None,
                    "score": None,
                    "severity": None,
                    "vector": None,
                }

            def extract_cwe(data):
                """
                Extract CWE identifiers from the NVD weaknesses section.
                """

                cwes = []

                for weakness in data.get("weaknesses", []):
                    for description in weakness.get("description", []):
                        value = description.get("value")

                        if value and value not in cwes:
                            cwes.append(value)

                return cwes

            def extract_affected(data):
                """
                Normalize NVD affected product/version information.
                """

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
            
            cvss = extract_cvss(data)
            cwe = extract_cwe(data)
            affected = extract_affected(data)

            references = [
                ref.get("url")
                for ref in data.get("references", [])
                if ref.get("url")
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

                "affected": json.dumps(
                    affected,
                    ensure_ascii=False
                ),

                "references": ";".join(references),
            }

            all_data.append(record)

        except (json.JSONDecodeError, OSError) as e:
            print(f"Could not process {json_file}: {e}")

    df = pd.DataFrame(all_data)

    df = df.dropna(subset=["cve_id"]) # For some unknown reason, 8 empty rows are being created

    df.to_csv(
        csv_filename,
        index=False,
        encoding="utf-8"
    )

    print(f"finished creating CSV :)")
    print(f"CVEs extracted: {len(df)}")


def _unique_values(values):
    return list(dict.fromkeys(value for value in values if value))


def _unique_json_objects(values):
    unique = []
    seen = set()

    for value in values:
        key = json.dumps(value, sort_keys=True, ensure_ascii=False)
        if key not in seen:
            seen.add(key)
            unique.append(value)

    return unique


def _ghad_references(advisory):
    references = []

    for reference in advisory.get("references", []):
        if isinstance(reference, str):
            references.append(reference)
        elif isinstance(reference, dict):
            references.append(reference.get("url"))

    return _unique_values(references)


def _ghad_cwes(advisory):
    database_specific = advisory.get("database_specific", {})
    cwes = database_specific.get("cwe_ids", [])
    return cwes if isinstance(cwes, list) else [cwes]


def _ghad_cvss(advisory):
    cvss = advisory.get("cvss", {})
    if not isinstance(cvss, dict):
        return {}

    return {
        "score": cvss.get("score"),
        "vector": cvss.get("vector_string") or cvss.get("vectorString"),
        "version": cvss.get("version"),
    }


def _ghad_affected(advisory):
    affected = []

    for entry in advisory.get("affected", []):
        package = entry.get("package", {})
        affected.append({
            "ecosystem": package.get("ecosystem"),
            "name": package.get("name"),
            "ranges": entry.get("ranges", []),
            "versions": entry.get("versions", []),
            "source": "GHAD",
        })

    return affected


def index_ghad_advisories(ghad_path):
    advisories_by_cve = {}

    for json_file in Path(ghad_path).rglob("*.json"):
        try:
            with json_file.open("r", encoding="utf-8") as file:
                advisory = json.load(file)
        except (json.JSONDecodeError, OSError) as error:
            print(f"Could not process {json_file}: {error}")
            continue

        advisory_id = advisory.get("id")
        aliases = advisory.get("aliases", [])
        if not advisory_id or not isinstance(aliases, list):
            continue

        for alias in aliases:
            if isinstance(alias, str) and alias.startswith("CVE-"):
                advisories_by_cve.setdefault(alias, []).append(advisory)

    return advisories_by_cve


def _merge_ghad_advisories(nvd_record, advisories):
    ghsa_ids = []
    summaries = []
    details = []
    cwes = [value.strip() for value in nvd_record.get("cwe", "").split(";")]
    references = [value.strip() for value in nvd_record.get("references", "").split(";")]

    try:
        affected = json.loads(nvd_record.get("affected", "[]"))
    except json.JSONDecodeError:
        affected = []

    ghad_cvss = {}
    ghad_severity = None
    ghad_published = []
    ghad_modified = []

    for advisory in advisories:
        ghsa_ids.append(advisory.get("id"))
        summaries.append(advisory.get("summary"))
        details.append(advisory.get("details"))
        cwes.extend(_ghad_cwes(advisory))
        references.extend(_ghad_references(advisory))
        affected.extend(_ghad_affected(advisory))

        advisory_cvss = _ghad_cvss(advisory)
        if not ghad_cvss and advisory_cvss:
            ghad_cvss = advisory_cvss
        ghad_severity = ghad_severity or advisory.get("severity")
        ghad_published.append(advisory.get("published"))
        ghad_modified.append(advisory.get("modified"))

    nvd_record["ghsa_id"] = ";".join(_unique_values(ghsa_ids))
    nvd_record["summary"] = "\n\n".join(_unique_values(summaries))
    nvd_record["details"] = "\n\n".join(_unique_values(details))
    nvd_record["cwe"] = ";".join(_unique_values(cwes))
    nvd_record["references"] = ";".join(_unique_values(references))
    nvd_record["affected"] = json.dumps(
        _unique_json_objects(affected),
        ensure_ascii=False,
    )

    if nvd_record.get("details"):
        nvd_record["description"] = nvd_record["details"]
    if not nvd_record.get("published"):
        nvd_record["published"] = next((value for value in ghad_published if value), "")
    if not nvd_record.get("modified"):
        nvd_record["modified"] = next((value for value in ghad_modified if value), "")
    if not nvd_record.get("cvss_score") and ghad_cvss:
        nvd_record["cvss_score"] = ghad_cvss.get("score")
        nvd_record["cvss_vector"] = ghad_cvss.get("vector")
        nvd_record["cvss_version"] = ghad_cvss.get("version")
    if not nvd_record.get("cvss_severity"):
        nvd_record["cvss_severity"] = ghad_severity or ""

    nvd_record.drop("details")

    return nvd_record


def merge_ghad_with_nvd(nvd_filename, ghad_path, output_filename):
    advisories_by_cve = index_ghad_advisories(ghad_path)

    with open(nvd_filename, "r", encoding="utf-8", newline="") as file:
        records = list(csv.DictReader(file))

    fieldnames = list(records[0].keys()) if records else []
    for field in ["ghsa_id", "summary", "details"]:
        if field not in fieldnames:
            fieldnames.append(field)

    matched = 0
    for record in records:
        advisories = advisories_by_cve.get(record.get("cve_id"), [])
        if advisories:
            matched += 1
        _merge_ghad_advisories(record, advisories)

    with open(output_filename, "w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    print(f"GHAD advisories indexed: {len(advisories_by_cve)} CVE aliases")
    print(f"NVD records enriched: {matched}/{len(records)}")
    print(f"finished creating {output_filename}")

if __name__ == "__main__":
    #cloneRepo()
    #filter_cve_data(2017, 2026, nPerYear)
    #create_csv_with_pandas("selected_cves.csv")
    #clone_ghad_repo()
    merge_ghad_with_nvd(
        "selected_cves.csv",
        ghad_repo_name,
        "final_cves.csv",
    )
