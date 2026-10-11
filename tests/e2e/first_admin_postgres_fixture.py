"""Run the maintained isolated PostgreSQL first-administrator integration suite."""

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]


if __name__ == "__main__":
    verifier = str(ROOT / "scripts" / "verify_public_knowledge_postgres.py")
    for options in (
        ["--suite", "administration"],
        ["--suite", "administration", "--local-admin-bootstrap"],
    ):
        result = subprocess.call([sys.executable, verifier, *options], cwd=ROOT)
        if result:
            raise SystemExit(result)
