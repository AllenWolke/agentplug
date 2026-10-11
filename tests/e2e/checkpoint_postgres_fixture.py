"""Run the maintained isolated PostgreSQL Python SDK checkpoint integration suite."""

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]


if __name__ == "__main__":
    raise SystemExit(subprocess.call([
        sys.executable,
        str(ROOT / "scripts" / "verify_public_knowledge_postgres.py"),
        "--suite",
        "checkpoint",
        "--sdk-full",
    ], cwd=ROOT))
