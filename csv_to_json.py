import csv
import json
import sys

# Set maximum allowed CSV field size limit to handle large rows
max_int = sys.maxsize
while True:
    try:
        csv.field_size_limit(max_int)
        break
    except OverflowError:
        max_int = int(max_int / 10)

def parse_semicolon_list(value):
    """Parse semicolon-separated strings (e.g., CWE, references)."""
    if not value:
        return []
    return [v.strip() for v in value.split(";") if v.strip()]

def parse_nvd_affected(value):
    """Parse semicolon-separated JSON strings into native dictionary objects."""
    if not value:
        return []
    affected = []
    for item in value.split(";"):
        if item.strip():
            try:
                parsed = json.loads(item)
                if isinstance(parsed, dict):
                    affected.append(parsed)
            except (json.JSONDecodeError, TypeError):
                continue
    return affected

def convert_csv_to_json(csv_filename="final_cves.csv", json_filename="final_cves.json"):
    records = []
    
    with open(csv_filename, "r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            # Convert multi-valued fields into native JSON arrays & objects
            row["affected"] = parse_nvd_affected(row.get("affected", ""))
            row["cwe"] = parse_semicolon_list(row.get("cwe", ""))
            row["references"] = parse_semicolon_list(row.get("references", ""))
            
            # Convert numeric CVSS score to float if present
            if row.get("cvss_score"):
                try:
                    row["cvss_score"] = float(row["cvss_score"])
                except ValueError:
                    pass

            records.append(row)

    with open(json_filename, "w", encoding="utf-8") as file:
        json.dump(records, file, ensure_ascii=False, indent=2)

    print(f"Successfully converted {len(records)} records from {csv_filename} to {json_filename}")

if __name__ == "__main__":
    convert_csv_to_json()