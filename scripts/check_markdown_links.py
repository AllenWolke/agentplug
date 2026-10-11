"""Validate Markdown links against the actual Git publication candidate set.

--include-local inspects retained local reports too; it is a separate diagnostic
and never substitutes for the public source check.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
CANONICAL_INPUTS = ("README.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md",
                    "docs", "deploy", "sdk", "agents", "templates", "cli", "frontend")
SKIP_PARTS = {".git", "node_modules", "__pycache__", "target", "dist", ".cache", ".tmp", ".venv"}
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")


def publication_paths(root: Path) -> list[str]:
    result = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                            cwd=root, capture_output=True, check=False)
    if result.returncode:
        raise ValueError("cannot enumerate complete Git publication candidates")
    return sorted({part.decode("utf-8") for part in result.stdout.split(b"\0") if part})


def markdown_files(path: Path) -> list[Path]:
    if not path.is_dir():
        return [path]
    with os.scandir(path) as entries:
        next(entries, None)
    files = []
    def fail(error: OSError) -> None:
        raise error
    for current, directories, names in os.walk(path, onerror=fail):
        directories[:] = [name for name in directories if name not in SKIP_PARTS]
        files.extend(Path(current) / name for name in names if name.endswith(".md"))
    return sorted(files)


def target_path(source: Path, raw: str) -> Path | None:
    value = raw.strip()
    if value.startswith("<"):
        end = value.find(">")
        value = value[1:end] if end > 0 else value
    else:
        value = value.split(maxsplit=1)[0] if value else ""
    if not value or value.startswith(("#", "http://", "https://", "mailto:")):
        return None
    value = unquote(value.split("#", 1)[0])
    if value.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", value):
        return source.parent / "__INVALID_ABSOLUTE_LINK__"
    return (source.parent / value).resolve()


def inspect_links(root: Path, paths: list[str], *, public_only: bool = True) -> tuple[int, list[str]]:
    root = root.resolve()
    allowed = {(root / name).resolve() for name in paths}
    checked, failures = 0, []
    for name in paths:
        if not name.endswith(".md"):
            continue
        source = root / name
        try:
            if not source.resolve().is_relative_to(root):
                raise ValueError("source outside repository")
            content = source.read_text(encoding="utf-8")
            in_fence = False
            for line_number, line in enumerate(content.splitlines(), 1):
                if line.lstrip().startswith(("```", "~~~")):
                    in_fence = not in_fence
                    continue
                if in_fence:
                    continue
                for match in LINK.finditer(re.sub(r"`[^`]*`", "", line)):
                    checked += 1
                    target = target_path(source, match.group(1))
                    if target is None:
                        continue
                    visible = target in allowed or (target.is_dir() and any(item.is_relative_to(target) for item in allowed))
                    if not target.is_relative_to(root) or not target.exists() or (public_only and not visible):
                        failures.append(f"{name}:{line_number}: missing or non-public target {match.group(1)!r}")
        except (OSError, UnicodeError, ValueError) as error:
            failures.append(f"{name}: unreadable Markdown input ({type(error).__name__})")
    return checked, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--include-local", action="store_true")
    args = parser.parse_args()
    try:
        if args.include_local:
            paths = sorted({path.relative_to(ROOT).as_posix() for name in CANONICAL_INPUTS
                            for path in markdown_files(ROOT / name)})
        else:
            paths = publication_paths(ROOT)
            for name in ("README.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md"):
                if name not in paths:
                    raise ValueError("required canonical Markdown input missing")
        checked, failures = inspect_links(ROOT, paths, public_only=not args.include_local)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Markdown candidate inspection failed ({type(error).__name__})", file=sys.stderr)
        return 2
    if failures:
        print("Markdown link check failed:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    scope = "local-inclusive" if args.include_local else "public Git candidates"
    print(f"Markdown link check passed ({scope}; {checked} links inspected)")
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
