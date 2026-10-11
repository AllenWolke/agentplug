from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ALLOWLIST = ROOT / "scripts" / "legacy_architecture_allowlist.json"
SOURCE_ROOTS = (
    "go-backend",
    "go-harness",
    "agents",
    "adapters",
    "sdk",
    "frontend",
    "tests",
    "scripts",
    "deploy",
)
ROOT_CONFIGS = (
    ".env.example",
    "compose.yaml",
)
SELF_EXCLUSIONS = {
    "scripts/check_removed_architecture.py",
    # This pre-test gate intentionally mentions legacy route needles in its
    # own source; do not report the scanner's vocabulary as an application
    # route. / 逐卡门禁自身包含检测字符串，不应被当成生产路由命中。
    "scripts/verify_ar_tasks.py",
    "tests/release-validation/legacy_architecture_forbidden_test.py",
}
TEXT_SUFFIXES = {
    ".go",
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".sql",
    ".ps1",
    ".sh",
    ".env",
}
IGNORED_PARTS = {
    ".git",
    ".cache",
    ".tmp",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    # macOS Finder metadata is binary and is never application source.
    # macOS Finder 元数据是二进制文件，不属于应用源码。
    "__MACOSX",
}


@dataclass(frozen=True)
class ForbiddenPattern:
    code: str
    needle: str
    description: str


FORBIDDEN_PATTERNS = (
    ForbiddenPattern(
        "COMBINED_CAPABILITY_REGISTRATION",
        "AGENT_CAPABILITIES=check,qa",
        "固定校验/口径双能力注册仍然存在",
    ),
    ForbiddenPattern(
        "LEGACY_ORCHESTRATOR_ASK",
        "/internal/orchestrator/ask",
        "旧融合问答执行 API 仍然存在",
    ),
    ForbiddenPattern(
        "LEGACY_RUNTIME_RUN",
        "/internal/runtime/run",
        "旧融合异步运行 API 仍然存在",
    ),
    # The Harness exposes the same legacy endpoints below /internal.  Keep
    # short-path detection separate so a clean-cut scan cannot miss route
    # registration merely because the router group supplies the prefix.
    # Harness 路由组会自动补上 /internal 前缀；这里同时检查短路径，避免
    # 只扫描调用方 URL 而漏掉真实的路由注册。
    ForbiddenPattern(
        "LEGACY_ORCHESTRATOR_ASK_SHORT",
        '"/orchestrator/ask"',
        "旧融合问答路由注册仍然存在",
    ),
    ForbiddenPattern(
        "LEGACY_RUNTIME_RUN_SHORT",
        '"/runtime/run"',
        "旧融合运行路由注册仍然存在",
    ),
)


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    line: int
    detail: str

    @property
    def key(self) -> str:
        return f"{self.code}:{self.path}:{self.line}"


def _relative(path: Path, root: Path = ROOT) -> str:
    return path.relative_to(root).as_posix()


def _iter_source_files(root: Path):
    """Yield controlled source files and fail on unreadable traversal.

    只遍历受控生产源码；读取或遍历失败由调用者按失败关闭处理。
    """

    for name in SOURCE_ROOTS:
        source_root = root / name
        if not source_root.exists():
            continue
        for path in source_root.rglob("*"):
            # Compare only repository-relative components.  Checking the
            # absolute path would incorrectly ignore every fixture rooted
            # under a directory named `.tmp` (including the gate's own
            # failure-closed tests).
            relative_parts = path.relative_to(root).parts
            if any(part in IGNORED_PARTS for part in relative_parts):
                continue
            if path.is_file() and (path.name == ".DS_Store" or path.name.startswith("._")):
                continue
            if path.is_file() and (path.suffix.lower() in TEXT_SUFFIXES or path.name == "Dockerfile"):
                yield path
    for name in ROOT_CONFIGS:
        path = root / name
        if path.is_file():
            yield path


def scan_repository(root: Path = ROOT) -> tuple[list[Finding], list[str]]:
    """Return forbidden architecture findings and all scan failures.

    返回旧架构命中项和所有扫描失败；调用方不得静默忽略失败。
    """

    findings: list[Finding] = []
    errors: list[str] = []
    legacy_root = root / "py-ai"
    if legacy_root.exists():
        findings.append(
            Finding(
                "FUSED_RUNTIME_DIRECTORY",
                "py-ai",
                0,
                "根目录融合 Agent Runtime 尚未删除",
            )
        )

    try:
        paths = list(_iter_source_files(root))
    except OSError as exc:
        return findings, [f"source traversal failed: {exc}"]

    for path in paths:
        if _relative(path, root) in SELF_EXCLUSIONS:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            errors.append(f"{_relative(path, root)}: {exc}")
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for pattern in FORBIDDEN_PATTERNS:
                if pattern.needle in line:
                    findings.append(
                        Finding(pattern.code, _relative(path, root), line_no, pattern.description)
                    )
    return sorted(findings, key=lambda item: item.key), sorted(errors)


def load_allowlist(path: Path) -> set[str]:
    if not path.exists():
        return set()
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
        raise ValueError("allowlist must be an object with a findings array")
    if not all(isinstance(value, str) for value in payload["findings"]):
        raise ValueError("allowlist findings must contain strings only")
    return set(payload["findings"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reject removed Agent architecture")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="ignore the migration allowlist; required by AR-21",
    )
    args = parser.parse_args(argv)

    findings, errors = scan_repository(args.root.resolve())
    if errors:
        for error in errors:
            print(f"SCAN_ERROR {error}", file=sys.stderr)
        return 2

    try:
        allowed = set() if args.strict else load_allowlist(args.allowlist)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"invalid migration allowlist: {exc}", file=sys.stderr)
        return 2

    unexpected = [finding for finding in findings if finding.key not in allowed]
    stale = sorted(allowed - {finding.key for finding in findings})
    for finding in findings:
        state = "ALLOWED_TEMPORARILY" if finding.key in allowed else "FORBIDDEN"
        print(f"{state} {finding.key} {finding.detail}")
    for key in stale:
        print(f"STALE_ALLOWLIST {key}", file=sys.stderr)

    if unexpected or stale:
        return 1
    print(f"removed architecture gate passed ({len(findings)} temporary findings)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
