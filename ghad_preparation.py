import csv
import json
from pathlib import Path

GHAD_REPO_NAME = "github-advisory-database"

def unique_values(values):
    return list(dict.fromkeys(value for value in values if value))


def unique_json_objects(values):
    unique = []
    seen = set()

    for value in values:
        key = json.dumps(value, sort_keys=True, ensure_ascii=False)
        if key not in seen:
            seen.add(key)
            unique.append(value)

    return unique


def ghad_references(advisory):
    references = []
    for reference in advisory.get("references", []):
        if isinstance(reference, str):
            references.append(reference)
        elif isinstance(reference, dict):
            references.append(reference.get("url"))
    return unique_values(references)


def ghad_cwes(advisory):
    database_specific = advisory.get("database_specific", {})
    cwes = database_specific.get("cwe_ids", [])
    return cwes if isinstance(cwes, list) else [cwes]


def ghad_cvss(advisory):
    cvss = advisory.get("cvss", {})
    if not isinstance(cvss, dict):
        return {}

    return {
        "score": cvss.get("score"),
        "vector": cvss.get("vector_string") or cvss.get("vectorString"),
        "version": cvss.get("version"),
    }


def ghad_affected(advisory):
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
    """Index GHAD advisory records by CVE alias."""
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


def merge_ghad_advisories(nvd_record, advisories):
    """Enrich an NVD record dictionary with matched GHAD advisories."""
    ghsa_ids = []
    aliases = []
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
        aliases.extend(advisory.get("aliases", []))
        summaries.append(advisory.get("summary"))
        details.append(advisory.get("details"))
        cwes.extend(ghad_cwes(advisory))
        references.extend(ghad_references(advisory))
        affected.extend(ghad_affected(advisory))

        advisory_cvss = ghad_cvss(advisory)
        if not ghad_cvss and advisory_cvss:
            ghad_cvss = advisory_cvss
        ghad_severity = ghad_severity or advisory.get("severity")
        ghad_published.append(advisory.get("published"))
        ghad_modified.append(advisory.get("modified"))

    nvd_record["ghsa_id"] = ";".join(unique_values(ghsa_ids))
    nvd_record["aliases"] = ";".join(unique_values(aliases))
    nvd_record["summary"] = "\n\n".join(unique_values(summaries))
    nvd_record["details"] = "\n\n".join(unique_values(details))
    nvd_record["cwe"] = ";".join(unique_values(cwes))
    nvd_record["references"] = ";".join(unique_values(references))
    nvd_record["affected"] = json.dumps(
        unique_json_objects(affected),
        ensure_ascii=False,
    )

    if not nvd_record.get("description"):
        nvd_record["description"] = nvd_record["details"] or nvd_record["summary"]
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

    return nvd_record


def merge_ghad_with_nvd(nvd_filename, ghad_path, output_filename):
    """Combine NVD CSV records with indexed GHAD data and write output."""
    advisories_by_cve = index_ghad_advisories(ghad_path)

    with open(nvd_filename, "r", encoding="utf-8", newline="") as file:
        records = list(csv.DictReader(file))

    fieldnames = list(records[0].keys()) if records else []
    for field in ["ghsa_id", "aliases", "summary", "details"]:
        if field not in fieldnames:
            fieldnames.append(field)

    matched = 0
    for record in records:
        advisories = advisories_by_cve.get(record.get("cve_id"), [])
        if advisories:
            matched += 1
        merge_ghad_advisories(record, advisories)

    with open(output_filename, "w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    print(f"GHAD advisories indexed: {len(advisories_by_cve)} CVE aliases")
    print(f"NVD records enriched: {matched}/{len(records)}")
    print(f"finished creating {output_filename}")


if __name__ == "__main__":
    merge_ghad_with_nvd(
        "selected_cves.csv",
        GHAD_REPO_NAME,
        "final_cves.csv",
    )