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

def ghad_affected(advisory):
    """Map GHAD affected packages to match NVD structure as dictionaries."""
    affected = []
    for entry in advisory.get("affected", []):
        package = entry.get("package", {})
        ecosystem = package.get("ecosystem")
        name = package.get("name")
        
        # Map version ranges
        for rng in entry.get("ranges", []):
            events = rng.get("events", [])
            introduced = next((e.get("introduced") for e in events if "introduced" in e), "0")
            fixed = next((e.get("fixed") for e in events if "fixed" in e), None)
            
            affected.append({
                "vendor": ecosystem,
                "product": name,
                "version": introduced,
                "less_than": fixed,
                "version_type": rng.get("type"),
                "status": "affected",
            })
            
        # Map specific versions
        for version in entry.get("versions", []):
            affected.append({
                "vendor": ecosystem,
                "product": name,
                "version": version,
                "less_than": None,
                "version_type": "semver",
                "status": "affected",
            })
            
    return affected

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

def index_ghad_advisories(ghad_path):
    """Index GHAD advisory records by CVE alias."""
    advisories_by_cve = {}
    path = Path(ghad_path)
    if not path.exists():
        return advisories_by_cve

    for json_file in path.rglob("*.json"):
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
    summaries = []
    details = []
    
    cwes = list(nvd_record.get("cwe", []))
    references = list(nvd_record.get("references", []))
    affected = list(nvd_record.get("affected", []))
    
    for advisory in advisories:
        ghsa_ids.append(advisory.get("id"))
        summaries.append(advisory.get("summary"))
        details.append(advisory.get("details"))
        cwes.extend(ghad_cwes(advisory))
        references.extend(ghad_references(advisory))
        affected.extend(ghad_affected(advisory))

    ghsa_list = unique_values(ghsa_ids)
    nvd_record["ghsa_id"] = ";".join(ghsa_list) if ghsa_list else ""
    
    nvd_record["summary"] = "\n\n".join(unique_values(summaries))
    nvd_record["details"] = "\n\n".join(unique_values(details))
    nvd_record["cwe"] = unique_values(cwes)
    nvd_record["references"] = unique_values(references)
    nvd_record["affected"] = unique_json_objects(affected)

    if nvd_record.get("details"):
        nvd_record["description"] = nvd_record["details"]
    
    ghad_published = [a.get("published") for a in advisories]
    ghad_modified = [a.get("modified") for a in advisories]
    ghad_cvss_data = next((ghad_cvss(a) for a in advisories if ghad_cvss(a)), {})
    ghad_severity = next((a.get("severity") for a in advisories if a.get("severity")), None)

    if not nvd_record.get("published"):
        nvd_record["published"] = next((value for value in ghad_published if value), "")
    if not nvd_record.get("modified"):
        nvd_record["modified"] = next((value for value in ghad_modified if value), "")
    if not nvd_record.get("cvss_score") and ghad_cvss_data:
        nvd_record["cvss_score"] = ghad_cvss_data.get("score")
        nvd_record["cvss_vector"] = ghad_cvss_data.get("vector")
        nvd_record["cvss_version"] = ghad_cvss_data.get("version")
    if not nvd_record.get("cvss_severity"):
        nvd_record["cvss_severity"] = ghad_severity or ""

    return nvd_record

def merge_ghad_with_nvd(nvd_filename, ghad_path, output_filename):
    """Combine NVD JSON records with indexed GHAD data and write output using pure JSON."""
    advisories_by_cve = index_ghad_advisories(ghad_path)

    with open(nvd_filename, "r", encoding="utf-8") as file:
        records = json.load(file)

    matched = 0
    for record in records:
        advisories = advisories_by_cve.get(record.get("cve_id"), [])
        if advisories:
            matched += 1
        merge_ghad_advisories(record, advisories)

        # Remove unwanted fields (details, aliases) directly from dictionary records
        for col in ["details", "aliases"]:
            record.pop(col, None)

    with open(output_filename, "w", encoding="utf-8") as file:
        json.dump(records, file, ensure_ascii=False, indent=4)

    print(f"GHAD advisories indexed: {len(advisories_by_cve)} CVE aliases")
    print(f"NVD records enriched: {matched}/{len(records)}")
    print(f"finished creating {output_filename}")

if __name__ == "__main__":
    merge_ghad_with_nvd(
        "selected_cves.json",
        GHAD_REPO_NAME,
        "final_cves.json",
    )