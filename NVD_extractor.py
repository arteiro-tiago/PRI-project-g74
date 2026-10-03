import subprocess
import shutil
import random
import json
import csv
import pandas as pd
from pathlib import Path

nPerYear = 300
repo_name = "nvd-json-data-feeds"

def cloneRepo():
    path = Path(repo_name)

    if path.exists():
        print("deleting existing copy")
        shutil.rmtree(path)

    print("CLONE")
    subprocess.run(["git", "clone", "--depth", "1", f"https://github.com/fkie-cad/{repo_name}.git"])


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
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            all_data.append(data)

    df = pd.json_normalize(all_data)

    df.to_csv(csv_filename, index=False) 
    
    print("finished creating csv :)")


cloneRepo()
filter_cve_data(2017, 2026, nPerYear)
create_csv_with_pandas("selected_cves.csv")