#!/usr/bin/env python3
"""Verify the modular-monolith baseline without consulting Git.

This check is intentionally repository-local and deterministic.  It records
the current cross-module HTTP calls, SQL write ownership, and forbidden domain
imports so MM-P-00 has executable evidence instead of a hand-maintained list.
本检查只读取当前工作区，不依赖 Git；把跨模块调用、SQL 写入所有权和
禁止的领域依赖变成可重复执行的 MM-P-00 证据。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ast
import io
import tokenize
from dataclasses import asdict, dataclass
from pathlib import Path

from modular_table_owners import TABLE_OWNERS, module_for
from sql_read_projections import permits_projection, read_only_query


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = ("platform", "workers", "agents", "examples", "templates", "sdk", "adapters", "cli", "frontend")
SKIP_PARTS = {".git", ".tmp", "node_modules", "__pycache__", ".venv", ".pytest_cache"}
# agentctl's documented output is an ignored business workspace, not platform
# source. Its vendored SDK retains SDK table ownership in its own repository.
GENERATED_SOURCE_ROOTS = {"cli/agentctl/out"}

FORBIDDEN_IMPORTS = (
    ("platform/internal", "go-harness/internal"),
    ("platform/internal", "go-backend/internal"),
    ("agents", "go-backend/internal"),
    ("agents", "go-harness/internal"),
)


@dataclass(frozen=True)
class SqlWrite:
    file: str
    operation: str
    table: str
    expected_owner: str
    actual_owner: str = "unclassified"


@dataclass(frozen=True)
class CallEdge:
    file: str
    target: str


def iter_source_files() -> list[Path]:
    files: list[Path] = []
    for root_name in SOURCE_ROOTS:
        root = ROOT / root_name
        if not root.exists():
            continue

        def fail_walk(error: OSError) -> None:
            raise error

        for directory, directories, names in os.walk(root, onerror=fail_walk):
            directories[:] = [name for name in directories if name not in SKIP_PARTS
                              and (Path(directory) / name).relative_to(ROOT).as_posix() not in GENERATED_SOURCE_ROOTS]
            for name in names:
                path = Path(directory) / name
                if path.suffix.lower() in {".go", ".py", ".sql", ".yaml", ".yml"}:
                    files.append(path)
    return files


def owner_for(table: str) -> str:
    normalized = table.lower().strip('`"')
    return TABLE_OWNERS.get(normalized.removeprefix("public."), "unclassified")


def go_raw_constants(path: Path) -> dict[str, str]:
    """Resolve only literal constants from production files of one Go package."""
    text = path.read_text(encoding="utf-8")
    package = re.search(r"^\s*package\s+([A-Za-z_]\w*)", text, re.MULTILINE)
    if not package:
        return {}
    constants: dict[str, str] = {}
    ambiguous: set[str] = set()
    for sibling in path.parent.glob("*.go"):
        if sibling.name.endswith("_test.go"):
            continue
        source = sibling.read_text(encoding="utf-8")
        candidate = re.search(r"^\s*package\s+([A-Za-z_]\w*)", source, re.MULTILINE)
        if not candidate or candidate.group(1) != package.group(1):
            continue
        for token in re.finditer(r'//[^\n]*|/\*[\s\S]*?\*/|`[^`]*`|"(?:\\.|[^"\\])*"', source):
            if not token.group().startswith("`"):
                continue
            declaration = re.search(r"\bconst\s+([A-Za-z_]\w*)\s*=\s*$", source[:token.start()])
            if not declaration:
                continue
            name, value = declaration.group(1), token.group()[1:-1]
            if name in constants and constants[name] != value:
                ambiguous.add(name)
            constants[name] = value
    return {name: value for name, value in constants.items() if name not in ambiguous}


def sql_literals(path: Path, go_constants: dict[str, str] | None = None) -> list[str]:
    """Ignore source comments; include multiline SQL and fail on unreadable input.
    忽略源码注释，覆盖多行 SQL；不可读文件不得静默通过。
    """
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".sql":
        return [text]
    if path.suffix == ".py":
        values = [
            ast.literal_eval(token.string)
            for token in tokenize.generate_tokens(io.StringIO(text).readline)
            if token.type == tokenize.STRING
            and not token.string.lower().startswith("f")
        ]
        return [value for value in values if isinstance(value, str)]
    tokens = re.finditer(r'//[^\n]*|/\*[\s\S]*?\*/|`[^`]*`|"(?:\\.|[^"\\])*"', text)
    constants = go_constants if go_constants is not None else go_raw_constants(path)
    values = []
    for token in tokens:
        if not token.group().startswith(('"', "`")):
            continue
        value = token.group()[1:-1]
        # Resolve only an adjacent named raw-string constant, never variables.
        prefix = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*$", text[:token.start()])
        if prefix and prefix.group(1) in constants:
            value = constants[prefix.group(1)] + value
        values.append(value)
    return values


def cte_names(statement: str) -> dict[str, int]:
    """Recognize top-level WITH aliases; underlying queries are still scanned."""
    start = re.match(r"\s*WITH\s+(?:RECURSIVE\s+)?", statement, re.IGNORECASE)
    if not start:
        return {}
    names: dict[str, int] = {}
    offset = start.end()
    header = re.compile(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^()]*\)\s*)?AS\s+(?:(?:NOT\s+)?MATERIALIZED\s+)?\(', re.IGNORECASE)
    while match := header.match(statement, offset):
        name = match.group(1).lower()
        offset, depth, quote = match.end(), 1, ""
        while offset < len(statement) and depth:
            char = statement[offset]
            if quote:
                if char == quote:
                    if offset + 1 < len(statement) and statement[offset + 1] == quote:
                        offset += 2
                        continue
                    quote = ""
            elif char in {"'", '"'}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            offset += 1
        if depth:
            break
        names[name] = offset
        separator = re.match(r"\s*,", statement[offset:])
        if not separator:
            break
        offset += separator.end()
    return names


def scan_sql_writes(files: list[Path]) -> list[SqlWrite]:
    """Retain the report field name, now inspect writes AND table reads/JOINs.
    保留报告字段名，但同时检查写入和跨模块读取/JOIN。
    """
    writes: list[SqlWrite] = []
    package_constants: dict[Path, dict[str, str]] = {}
    pattern = re.compile(
        r"\b(?P<op>INSERT\s+(?:IGNORE\s+)?INTO|UPDATE|DELETE\s+FROM|REPLACE\s+INTO|FROM|JOIN|CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?|ALTER\s+TABLE|DROP\s+TABLE(?:\s+IF\s+EXISTS)?)\s+(?:LATERAL\s+)?[`\"]?(?P<table>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)[`\"]?",
        re.IGNORECASE,
    )
    for path in files:
        relative = str(path.relative_to(ROOT)).replace("\\", "/")
        # Tests and schema migrations are evidence/setup, not runtime table
        # owners.  Including their SQL would make the ownership report noisy
        # and could hide a real production writer.
        if (
            path.name.endswith("_test.go")
            or "/tests/" in f"/{relative}/"
            or "/migrations/" in f"/{relative}/"
            or relative.startswith("platform/cmd/migrate/")
        ):
            continue
        if path.suffix.lower() not in {".go", ".py", ".sql"}:
            continue
        constants = None
        if path.suffix.lower() == ".go":
            if path.parent not in package_constants:
                package_constants[path.parent] = go_raw_constants(path)
            constants = package_constants[path.parent]
        for statement in sql_literals(path, constants):
            if not re.match(
                r"\s*(?:SELECT\b|INSERT\s+(?:IGNORE\s+)?INTO\b|UPDATE\s+[`\"]?[\w.]+[`\"]?\s+SET\b|DELETE\s+FROM\b|REPLACE\s+INTO\b|CREATE\s+TABLE\b|ALTER\s+TABLE\b|DROP\s+TABLE\b|WITH\b)",
                statement,
                re.IGNORECASE,
            ):
                continue
            aliases = cte_names(statement)
            for match in pattern.finditer(statement):
                if match.group("table").upper() in {"SET", "SELECT"}:
                    continue
                operation = re.sub(r"\s+", " ", match.group("op").upper()).strip()
                if operation == "UPDATE" and not re.match(
                    r"\s+SET\b", statement[match.end() :], re.IGNORECASE
                ):
                    continue
                # System metadata reads are explicit shared infrastructure,
                # not a blanket exemption for arbitrary schema-qualified SQL.
                # 仅列明的系统元数据读取允许共享；写入仍拒绝。
                relation = match.group("table").lower()
                if operation == "FROM" and re.search(r"\bIS\s+(?:NOT\s+)?DISTINCT\s+$", statement[:match.start()], re.IGNORECASE):
                    continue
                if relation == "lateral" and operation in {"FROM", "JOIN"} and re.match(r"\s*\(", statement[match.end():]):
                    continue
                metadata_owner = module_for(relative) in {"compensation", "notification", "schemaversion"}
                if operation in {"FROM", "JOIN"} and metadata_owner and read_only_query(statement):
                    if relation in {"pg_class", "pg_namespace", "pg_roles", "pg_auth_members", "pg_proc"}:
                        continue
                    if relation in {"aclexplode", "pg_catalog.aclexplode"} and re.match(r"\s*\(", statement[match.end():]):
                        continue
                if permits_projection(path, module_for(relative), relation, statement, operation):
                    continue
                if operation in {"FROM", "JOIN"} and relation in aliases and match.start() >= aliases[relation]:
                    continue
                if operation in {"FROM", "JOIN"} and relation in {"jsonb_to_recordset", "unnest"} and re.match(r"\s*\(", statement[match.end():]):
                    continue
                if operation in {"FROM", "JOIN"} and relation in {
                    "information_schema.columns",
                    "information_schema.tables",
                    "information_schema.statistics",
                    "pg_catalog.pg_class", "pg_catalog.pg_namespace",
                    "pg_catalog.pg_roles", "pg_catalog.pg_auth_members",
                    "pg_catalog.pg_proc", "pg_catalog.pg_index",
                    "pg_catalog.pg_attribute",
                }:
                    continue
                writes.append(
                    SqlWrite(
                        str(path.relative_to(ROOT)),
                        operation,
                        match.group("table"),
                        owner_for(match.group("table")),
                        module_for(relative),
                    )
                )
    return writes


def scan_calls(files: list[Path]) -> list[CallEdge]:
    edges: list[CallEdge] = []
    patterns = (
        re.compile(r"https?://[^\s\"'`]+"),
        re.compile(
            r"(?:http\.NewRequest|httpx\.(?:get|post|AsyncClient)|requests\.(?:get|post))[^\n]*"
        ),
        re.compile(r"grpc(?:\.Dial|\.insecure_channel)[^\n]*"),
    )
    for path in files:
        if path.name.endswith("_test.go") or path.name.endswith("_pb.go"):
            continue
        if path.suffix.lower() not in {".go", ".py"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in patterns:
            for match in pattern.finditer(text):
                edges.append(
                    CallEdge(str(path.relative_to(ROOT)), match.group(0).strip())
                )
    return edges


def scan_forbidden_imports(files: list[Path] | None = None) -> list[dict[str, str]]:
    violations: list[dict[str, str]] = []
    for path in files if files is not None else iter_source_files():
        relative = path.relative_to(ROOT).as_posix()
        if not relative.startswith(
            ("platform/", "agents/", "examples/", "templates/")
        ) or path.suffix.lower() not in {".go", ".py"}:
            continue
        text = path.read_text(encoding="utf-8")
        for owner_root, forbidden in FORBIDDEN_IMPORTS:
            if relative.startswith(owner_root) and forbidden in text:
                violations.append({"file": relative, "forbidden": forbidden})
    return violations


def scan_agent_database_ownership(files: list[Path]) -> list[dict[str, str]]:
    """Reject database ownership from business Agent packages.

    Agents may call the SDK capability/checkpoint ports, but they must not own
    a SQL client or execute write statements.  This is intentionally narrower
    than a generic ``.execute`` search so domain set operations and comments do
    not produce false positives. / Agent 只能通过 SDK Port 访问公共能力。
    """

    violations: list[dict[str, str]] = []
    import_pattern = re.compile(
        r"^\s*(?:from|import)\s+(?:aiomysql|asyncmy|sqlalchemy|sqlite3|mysql\.connector|psycopg)\b",
        re.IGNORECASE | re.MULTILINE,
    )
    sql_write_pattern = re.compile(
        r"\b(?:INSERT\s+INTO|UPDATE\s+[A-Za-z_][A-Za-z0-9_]*|DELETE\s+FROM|REPLACE\s+INTO)\b",
        re.IGNORECASE,
    )
    for path in files:
        relative = str(path.relative_to(ROOT)).replace("\\", "/")
        if not relative.startswith(("agents/", "examples/", "templates/")) or "/tests/" in f"/{relative}/":
            continue
        # Vendored SDK code owns shared persistence ports, not business data.
        # The canonical SDK copy is checked separately under sdk/.
        if "/agent_platform_sdk/" in relative or path.name.startswith("test_") or path.name.endswith("_test.py"):
            continue
        if path.suffix.lower() != ".py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if import_pattern.search(text):
            violations.append(
                {"file": relative, "reason": "Agent imports a database client"}
            )
            continue
        if sql_write_pattern.search(text):
            violations.append(
                {"file": relative, "reason": "Agent contains a SQL write statement"}
            )
    return violations


def render_report(
    writes: list[SqlWrite],
    calls: list[CallEdge],
    violations: list[dict[str, str]],
    agent_db_ownership: list[dict[str, str]],
) -> str:
    owners: dict[str, set[str]] = {}
    for write in writes:
        owners.setdefault(write.table.lower(), set()).add(write.actual_owner)
    conflicts = {
        table: sorted(values) for table, values in owners.items() if len(values) > 1
    }
    lines = [
        "# MM-P-00 可执行边界检查报告",
        "",
        "> 生成方式：`python scripts/verify_modular_boundaries.py --report ...`；只读取当前工作区，不读取 Git。",
        "",
        f"- SQL 静态访问命中（含读/写/DDL）：{len(writes)}",
        f"- 跨模块调用命中：{len(calls)}",
        f"- 禁止依赖：{len(violations)}",
        f"- Agent 数据库越权：{len(agent_db_ownership)}",
        f"- 写入所有权冲突：{len(conflicts)}",
        "",
        "## SQL 写入所有权",
        "",
        "| 文件 | 操作 | 表 | 期望所有者 | 实际所有者 |",
        "|---|---|---|---|---|",
    ]
    for write in writes:
        lines.append(
            f"| `{write.file}` | `{write.operation}` | `{write.table}` | `{write.expected_owner}` | `{write.actual_owner}` |"
        )
    lines.extend(["", "## 所有权冲突", ""])
    for write in writes:
        if (
            write.expected_owner == "unclassified"
            or write.actual_owner != write.expected_owner
        ):
            lines.append(
                f"- 访问越界/未知表：`{write.file}` / `{write.table}`：`{write.actual_owner}` != `{write.expected_owner}`"
            )
    if conflicts:
        for table, owners_for_table in sorted(conflicts.items()):
            lines.append(f"- `{table}`: {', '.join(owners_for_table)}")
    else:
        lines.append("无。")
    lines.extend(["", "## 跨模块调用边", "", "| 文件 | 调用表达式 |", "|---|---|"])
    for edge in calls:
        lines.append(f"| `{edge.file}` | `{edge.target.replace('|', '\\|')}` |")
    lines.extend(["", "## 禁止依赖", ""])
    if violations:
        for violation in violations:
            lines.append(f"- `{violation['file']}` 引用了 `{violation['forbidden']}`")
    else:
        lines.append("无。")
    lines.extend(["", "## Agent 数据库所有权越权", ""])
    if agent_db_ownership:
        for finding in agent_db_ownership:
            lines.append(f"- `{finding['file']}`：{finding['reason']}")
    else:
        lines.append("无。Agent 业务包不持有数据库客户端或 SQL 写入。")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    files = iter_source_files()
    writes = scan_sql_writes(files)
    calls = scan_calls(files)
    violations = scan_forbidden_imports(files)
    agent_db_ownership = scan_agent_database_ownership(files)
    owners: dict[str, set[str]] = {}
    for write in writes:
        owners.setdefault(write.table.lower(), set()).add(write.actual_owner)
    conflicts = {
        table: sorted(values) for table, values in owners.items() if len(values) > 1
    }
    mismatches = [
        asdict(item)
        for item in writes
        if item.expected_owner == "unclassified"
        or item.actual_owner != item.expected_owner
    ]
    payload = {
        "source_files": len(files),
        "sql_writes": [asdict(item) for item in writes],
        "call_edges": [asdict(item) for item in calls],
        "forbidden_imports": violations,
        "agent_database_ownership": agent_db_ownership,
        "ownership_conflicts": conflicts,
        "ownership_mismatches": mismatches,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            render_report(writes, calls, violations, agent_db_ownership),
            encoding="utf-8",
        )
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    print(
        json.dumps(
            {
                "source_files": len(files),
                "sql_writes": len(writes),
                "call_edges": len(calls),
                "forbidden_imports": len(violations),
                "agent_database_ownership": len(agent_db_ownership),
                "ownership_conflicts": len(conflicts),
                "ownership_mismatches": len(mismatches),
            },
            ensure_ascii=False,
        )
    )
    for item in mismatches:
        print(
            f"SQL owner mismatch: {item['file']} / {item['table']} / {item['actual_owner']} != {item['expected_owner']}"
        )
    return 1 if violations or agent_db_ownership or conflicts or mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
