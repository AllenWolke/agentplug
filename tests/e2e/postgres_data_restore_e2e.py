"""Run the maintained isolated PostgreSQL backup and data-restore integration suite."""

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]


if __name__ == "__main__":
    raise SystemExit(subprocess.call([
        sys.executable,
        str(ROOT / "scripts" / "verify_postgres_backup_isolated.py"),
    ], cwd=ROOT))
