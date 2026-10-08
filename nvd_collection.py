import shutil
import subprocess
import random
from pathlib import Path

REPO_NAME = "nvd-json-data-feeds"

def clone_nvd_repo(repo_name):
    """Clone or refresh the local copy of the NVD repository."""
    path = Path(repo_name)

    if path.exists():
        print("deleting existing copy")
        shutil.rmtree(path)

    print("CLONE")
    subprocess.run(["git", "clone", "--depth", "1", f"https://github.com/fkie-cad/{repo_name}.git"])


def filter_cve_data(start_year, end_year, n_per_year, repo_name):
    """Filter JSON files by year range and randomly sample up to `n_per_year` per year."""
    root = Path(repo_name)
    
    if not root.exists():
        print(f"Directory {repo_name} not found.")
        return

    for item in root.iterdir():
        if item.is_dir() and item.name.startswith("CVE"):
            year_str = item.name[4:8]
            year = int(year_str)
            
            if year < start_year or year > end_year:
                shutil.rmtree(item)
            else:
                json_files = sorted(item.rglob("*.json"))
                random.shuffle(json_files)
                files_to_delete = json_files[n_per_year:]
                for file_path in files_to_delete:
                    file_path.unlink()


if __name__ == "__main__":
    N_PER_YEAR = 300
    clone_nvd_repo(REPO_NAME)
    filter_cve_data(2017, 2026, N_PER_YEAR, REPO_NAME)