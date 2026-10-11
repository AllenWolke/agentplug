"""Fail the local/CI quality gate when repository files contain likely credentials."""

from __future__ import annotations

import math
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRECTORIES = {
    ".git",
    ".next",
    ".cache",
    ".codex-cache",
    ".mypy_cache",
    ".npm-cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tmp",
    # Config-probe GOCACHE has the standard Go cache README and binary objects.
    # 配置探针专用GOCACHE包含标准Go缓存说明和二进制对象；仅排除此明确目录。
    ".tmp-config-gocache",
    ".verify-work",
    ".frontend-work",
    "_audit-v3",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    "tmp",
    "venv",
    ".venv",
    "uploads",
    # macOS archive metadata is binary and never part of an Agent artifact.
    # 明确忽略 macOS 压缩包元数据；这些二进制文件不是 Agent 制品内容。
    "__MACOSX",
}
SKIP_DIRECTORY_PREFIXES = (
    ".tmp-go-cache",
    # GOTMP/GOMODCACHE are intentionally redirected into the workspace by the
    # Windows/POSIX gates. Module downloads contain binary corpus and checksum
    # tiles, never deployable source or credentials; scanning them as UTF-8
    # would fail closed for the wrong reason.
    # Windows/POSIX 门禁会把 GOTMP/GOMODCACHE 定向到工作区；模块缓存含二进制
    # corpus/checksum tile，不是源码或部署配置，按 UTF-8 扫描会产生错误阻断。
    ".tmp-go-modcache",
    # The full quality gate may use a module-local cache name to isolate
    # concurrent/race builds. These directories contain compiled objects, not
    # source or deployable configuration, and must be excluded as a family.
    # 全量门禁会使用模块级缓存名隔离并发/race 构建；这些目录仅含编译产物，
    # 不属于源码或可部署配置，应按前缀整体排除。
    ".tmp-go-build-cache",
    ".go-build-cache",
    ".gocache",
    # Go build caches emitted by the audit tooling. They hold compiled binary
    # objects that are never part of an Agent artifact and cannot be decoded as
    # text. 审查工具产生的 Go 构建缓存，内含二进制对象，不属于制品内容。
    ".audit-gocache",
)
ALLOWED_ENV_FILES = {
    ".env.example",
    ".env.template",
    ".env.sample",
}
SKIP_FILE_NAMES = {".DS_Store"}
# These are private operator directories, not a blanket source exclusion.
# They are pruned only after Git proves that no publication candidate is inside.
PRIVATE_DIRECTORIES = {".local-secrets", ".local-build"}
TEXT_SUFFIXES = {
    "",
    ".conf",
    ".env",
    ".go",
    ".ini",
    ".js",
    ".json",
    ".jsx",
    ".md",
    ".mjs",
    ".py",
    ".ps1",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}
PLACEHOLDER_PARTS = {
    "changeme",
    "dummy",
    "example",
    "fake",
    "mock",
    "placeholder",
    "replace",
    "sample",
    "test",
    "your",
}
PROVIDER_PATTERNS = {
    "Feishu App ID": re.compile(r"\bcli_[A-Za-z0-9]{12,}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}
ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|app[_-]?secret|access[_-]?token|auth[_-]?token|"
    r"master[_-]?key|salt[_-]?key|client[_-]?secret|password)\b\s*[:=]\s*"
    r"[\"']([A-Za-z0-9_./+=:@-]{16,})[\"']"
)
GENERIC_ASSIGNMENT_SUFFIXES = {
    ".conf",
    ".go",
    ".ini",
    ".js",
    ".jsx",
    ".mjs",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}


def entropy(value: str) -> float:
    counts = Counter(value)
    size = len(value)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def looks_real(value: str) -> bool:
    lowered = value.lower()
    if any(part in lowered for part in PLACEHOLDER_PARTS):
        return False
    if "${" in value or "$(" in value or "getenv" in lowered:
        return False
    return len(value) >= 20 and entropy(value) >= 3.5


def is_git_ignored(relative: str) -> bool:
    """Report whether Git ignores a path.

    Git-ignored `.env*` files are local runtime state that can never be
    committed, so the unified gate skips them — matching `scripts/unit.ps1`
    and Docker build context ignores. A tracked `.env*` file is still scanned
    and reported as a real leak. If Git is unavailable the scan stays
    conservative and reports the file rather than silently passing.
    被 Git 忽略的 `.env*` 属于本地运行时文件，不可能被提交，因此统一门禁跳过它们，
    与 unit.ps1 及 Docker 构建上下文忽略规则保持一致；被跟踪的 `.env*` 仍会被扫描
    并报告。若 Git 不可用则保守处理为“未忽略”，避免静默放行。
    """
    try:
        result = subprocess.run(
            ["git", "check-ignore", "-q", "--", relative],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, ValueError):
        return False
    return result.returncode == 0


def iter_files() -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    errors: list[str] = []

    def record_walk_error(error: OSError) -> None:
        errors.append(f"directory unreadable: {error.filename or '<unknown>'}: {error}")

    for current, directories, names in os.walk(
        ROOT, topdown=True, onerror=record_walk_error
    ):
        directories[:] = [
            name
            for name in directories
            if name not in SKIP_DIRECTORIES
            and not name.startswith(SKIP_DIRECTORY_PREFIXES)
        ]
        parent = Path(current)
        directories[:] = [
            name for name in directories
            if name not in PRIVATE_DIRECTORIES
            or not private_directory_outside_publication((parent / name).relative_to(ROOT).as_posix())
        ]
        for name in names:
            path = parent / name
            if path == Path(__file__).resolve():
                continue
            if path.name in SKIP_FILE_NAMES or path.name.startswith("._"):
                continue
            if path.name.startswith(".env"):
                relative = path.relative_to(ROOT).as_posix()
                if is_git_ignored(relative):
                    continue
            try:
                if path.stat().st_size > 2 * 1024 * 1024:
                    continue
            except OSError:
                errors.append(f"file metadata unreadable: {path}")
                continue
            if path.suffix.lower() in TEXT_SUFFIXES or path.name.startswith(".env"):
                files.append(path)
    return files, errors


def scan(path: Path) -> tuple[list[tuple[int, str]], list[str]]:
    relative = path.relative_to(ROOT)
    findings: list[tuple[int, str]] = []
    if path.name.startswith(".env") and path.name not in ALLOWED_ENV_FILES:
        findings.append((1, "tracked or copied environment file"))
    try:
        lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError) as exc:
        return findings, [f"file content unreadable: {relative}: {exc}"]
    for line_number, line in enumerate(lines, 1):
        if "secret-scan: allow" in line:
            continue
        for name, pattern in PROVIDER_PATTERNS.items():
            if pattern.search(line):
                findings.append((line_number, name))
        if path.suffix.lower() in GENERIC_ASSIGNMENT_SUFFIXES or path.name in ALLOWED_ENV_FILES:
            for match in ASSIGNMENT.finditer(line):
                if looks_real(match.group(1)):
                    findings.append((line_number, "high-entropy credential assignment"))
    return [(line, f"{relative}: {kind}") for line, kind in findings], []


def private_directory_outside_publication(relative: str) -> bool:
    if not is_git_ignored(relative + "/"):
        return False
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", relative + "/"],
            cwd=str(ROOT), capture_output=True, check=False,
        )
    except (OSError, ValueError):
        return False
    # A force-added file inside an ignored directory must still be inspected.
    return result.returncode == 0 and not result.stdout


def main() -> int:
    findings: list[tuple[int, str]] = []
    files, scan_errors = iter_files()
    for path in files:
        file_findings, file_errors = scan(path)
        findings.extend(file_findings)
        scan_errors.extend(file_errors)
    if scan_errors:
        print("secret scan failed because repository content was not fully scanned:")
        for message in scan_errors:
            print(f"- {message}")
        return 2
    if findings:
        print("secret scan failed; rotate exposed credentials and replace literals with Secret/env references:")
        for line, message in findings:
            print(f"- {message} (line {line})")
        return 1
    print("secret scan passed")
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
