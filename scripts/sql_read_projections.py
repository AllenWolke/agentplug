"""Source- and query-bound read projections, never cross-module writes."""

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECTIONS = json.loads(
    (ROOT / "contracts/architecture/sql-read-projections.json").read_text(encoding="utf-8")
)


def read_only_query(query: str) -> bool:
    if not re.match(r"\s*(SELECT|WITH)\b", query, re.IGNORECASE):
        return False
    # Positional bound parameters are not dollar-quoted SQL bodies.
    syntax = re.sub(r"\$[1-9][0-9]*\b", "?", query)
    if any(token in syntax for token in (";", "--", "/*", "$")):
        return False
    sanitized = re.sub(r"'(?:''|[^'])*'", "''", query)
    return not re.search(
        r"\b(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|COPY|CALL|DO)\b",
        sanitized, re.IGNORECASE,
    )


def permits_projection(path: Path, owner: str, table: str, query: str, operation: str) -> bool:
    if operation not in {"FROM", "JOIN"} or not read_only_query(query):
        return False
    if not path.is_relative_to(ROOT):
        return False
    relative = path.relative_to(ROOT).as_posix()
    source_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    query_digest = hashlib.sha256(" ".join(query.split()).encode()).hexdigest()
    return any(
        record.get("file") == relative
        and record.get("owner") == owner
        and record.get("table") == table
        and record.get("source_sha256") == source_digest
        and record.get("query_sha256") == query_digest
        and bool(record.get("reason", "").strip())
        for record in PROJECTIONS
    )
