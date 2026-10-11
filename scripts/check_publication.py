"""Audit actual Git publication candidates, including tracked ignored files.

This does not stage, commit, push, or modify Git metadata. A content manifest
can be written outside the candidate set (for example under ignored .tmp/).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BLOCKED_COMPONENTS = {".git", ".claude", ".trae", ".codex", ".cursor", ".windsurf", ".gemini", ".tools", ".vscode", ".idea", ".local-secrets", ".local-build", "secrets", "credentials", "backups", "node_modules", "__pycache__", ".cache", ".next"}
BLOCKED_SUFFIXES = {".jar", ".class", ".pyc", ".exe", ".dll", ".so", ".db", ".sqlite", ".sqlite3", ".key", ".pem", ".p12", ".pfx", ".jks", ".keystore", ".secret", ".har", ".gz", ".zip", ".pgdump", ".dump", ".backup"}
PRIVATE_FILE_NAMES = {".DS_Store", "Thumbs.db", "desktop.ini"}
ENV_EXAMPLES = {".env.example", ".env.sample", ".env.template"}
PRIVATE_MATERIAL_PREFIXES = ("docs/八股文背诵/", "docs/面试题/", "docs/面试冲刺/", "面试冲刺手册/", "docs/新增需求/")
PRIVATE_MATERIAL_FILES = {"docs/1、4小时速通Agent面试.docx"}


def candidates(root: Path) -> list[str]:
    result = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                            cwd=root, capture_output=True, check=False)
    if result.returncode:
        raise ValueError("cannot enumerate Git publication candidates")
    return sorted({item.decode("utf-8") for item in result.stdout.split(b"\0") if item})


def audit(root: Path, paths: list[str]) -> tuple[list[dict], list[str]]:
    entries, failures = [], []
    for relative in paths:
        path = root / relative
        parts = Path(relative).parts
        reason = None
        if Path(relative).is_absolute() or ".." in parts:
            reason = "invalid repository path"
        elif path.is_symlink():
            reason = "symbolic links require explicit publication review"
        elif any(part in BLOCKED_COMPONENTS or part.startswith((".tmp", ".gocache")) for part in parts):
            reason = "private state or dependency cache"
        elif path.name.startswith(".env") and path.name not in ENV_EXAMPLES:
            reason = "runtime environment file"
        elif path.suffix.lower() in BLOCKED_SUFFIXES:
            reason = "compiled artifact, archive, key or runtime database"
        elif path.name in PRIVATE_FILE_NAMES or any(marker in path.name.lower() for marker in (".db-", ".sqlite-", ".sqlite3-")):
            reason = "desktop metadata or runtime database sidecar"
        elif relative.startswith(("cli/agentctl/out/", "artifacts/pprof/")):
            reason = "generated workspace or raw profile"
        elif relative.startswith(PRIVATE_MATERIAL_PREFIXES) or relative in PRIVATE_MATERIAL_FILES:
            reason = "local history, requirements or personal material outside source release"
        else:
            # A Go package named internal/target is source, not a Maven build directory.
            for index, part in enumerate(parts):
                if part == "target" and (root.joinpath(*parts[:index]) / "pom.xml").is_file():
                    reason = "Maven build output"
                    break
        if reason is not None:
            failures.append(f"{relative}: {reason}")
            continue
        if not path.is_file():
            failures.append(f"{relative}: missing or non-file publication candidate")
            continue
        size = path.stat().st_size
        # Project policy, not a claim about a hosting provider's current maximum.
        if size > 50 * 1024 * 1024:
            failures.append(f"{relative}: exceeds project 50 MiB per-file publication limit")
            continue
        with path.open("rb") as stream:
            checksum = hashlib.file_digest(stream, "sha256").hexdigest()
        entries.append({"path": relative, "bytes": size, "sha256": checksum})
    if not paths:
        failures.append("publication candidate set is empty")
    for required in ("LICENSE", "THIRD_PARTY_NOTICES.md", "README.md", ".env.example", "compose.yaml"):
        if required not in paths:
            failures.append(f"required publication file missing: {required}")
    return entries, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    try:
        paths = candidates(ROOT)
        if args.manifest is not None and args.manifest.resolve() in {(ROOT / path).resolve() for path in paths}:
            raise ValueError("manifest output must be outside the publication candidate set")
        entries, failures = audit(ROOT, paths)
        if failures:
            print("publication audit failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        encoded = json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        summary = {"publication": "PASS", "file_count": len(entries),
                   "total_bytes": sum(entry["bytes"] for entry in entries),
                   "candidate_sha256": hashlib.sha256(encoded).hexdigest()}
        if args.manifest is not None:
            args.manifest.parent.mkdir(parents=True, exist_ok=True)
            args.manifest.write_text(json.dumps({**summary, "files": entries}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(summary))
        return 0
    except (OSError, ValueError, UnicodeError):
        print("publication audit could not inspect the complete candidate set", file=sys.stderr)
        return 2


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
