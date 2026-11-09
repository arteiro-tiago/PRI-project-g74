import shutil
import subprocess
from pathlib import Path

GHAD_REPO_NAME = "github-advisory-database"

def clone_ghad_repo(ghad_repo_name):
    """Clone or refresh the local copy of the GHAD repository."""
    path = Path(ghad_repo_name)

    if path.exists():
        print("deleting existing GHAD copy")
        shutil.rmtree(path)

    print("Cloning reviewed GitHub Advisory Database advisories")
    subprocess.run([
        "git",
        "clone",
        "--depth",
        "1",
        "https://github.com/github/advisory-database.git",
        ghad_repo_name,
    ], check=True)


if __name__ == "__main__":
    clone_ghad_repo(GHAD_REPO_NAME)