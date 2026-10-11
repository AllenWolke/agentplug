"""Common E2E transport, projection and isolated SQL failure assertions."""
from __future__ import annotations
import json
import os
import re
import subprocess
import time
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def assert_no_platform_mutations(run_id: str, *, require_absent_run: bool = False) -> dict[str, int]:
    """Prove no notification or mutating tool receipt in isolated PostgreSQL.

    This does not assert the state of a business provider's separate database.
    """
    dsn = os.getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN", "").strip()
    if not re.fullmatch(r"machine-e2e-[a-f0-9]{20}", run_id):
        raise RuntimeError("negative E2E requires a generated Run ID")
    try:
        parsed = urlsplit(dsn)
        password = unquote(parsed.password or "")
        username = unquote(parsed.username or "")
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError("negative E2E requires an isolated PostgreSQL runtime DSN") from exc
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    query_options = dict(query_items)
    if (parsed.scheme not in {"postgres", "postgresql"}
            or parsed.hostname != "127.0.0.1"
            or parsed.path != "/knowledge_test"
            or not port or not username or not password
            or any(key.lower() != "sslmode" for key, _ in query_items)
            or len(query_options) != len(query_items)
            or query_options.get("sslmode", "disable") not in
            {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}
            or any(character in password for character in "\r\n\0")):
        raise RuntimeError("negative E2E requires an isolated PostgreSQL runtime DSN")
    safe_netloc = f"{quote(username, safe='')}@{parsed.hostname}:{port}"
    safe_dsn = urlunsplit((parsed.scheme, safe_netloc, parsed.path, urlencode(query_options), ""))
    statement = (
        "SELECT "
        "(SELECT COUNT(*) FROM platform_notification_outbox "
        "WHERE payload_json::jsonb ->> 'run_id' = :'run_id'), "
        "(SELECT COUNT(*) FROM platform_tool_invocation "
        "WHERE recovery_query IS NOT NULL "
        "AND recovery_query::jsonb #>> '{Scope,RunID}' = :'run_id' "
        "AND (recovery_query::jsonb ->> 'Name' IS NULL "
        "OR recovery_query::jsonb ->> 'Name' NOT IN "
        "('runtime.inspect','json.validate','clock.now'))), "
        "(SELECT COUNT(*) FROM platform_execution_run WHERE run_id = :'run_id');\n"
    )
    environment = os.environ.copy()
    environment["PGPASSWORD"] = password
    environment["PGOPTIONS"] = "-c default_transaction_read_only=on"
    try:
        result = subprocess.run(
            ["psql", "--no-psqlrc", "--set=ON_ERROR_STOP=1", "--set", f"run_id={run_id}",
             "--tuples-only", "--no-align", "--field-separator", "\t", f"--dbname={safe_dsn}"],
            input=statement.encode("utf-8"), env=environment,
            capture_output=True, timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("isolated PostgreSQL SQL check failed; no PASS evidence") from exc
    if result.returncode != 0:
        raise RuntimeError("isolated negative E2E SQL check failed; no PASS evidence")
    counts = result.stdout.decode("utf-8").strip().split("\t")
    if len(counts) != 3 or counts[:2] != ["0", "0"]:
        raise RuntimeError("failed Run left a notification or mutating tool receipt")
    if require_absent_run and counts[2] != "0":
        raise RuntimeError("preflight rejection nevertheless created a platform Run")
    if not require_absent_run and counts[2] != "1":
        raise RuntimeError("terminal failure did not preserve exactly one platform Run")
    return {"notification_rows": 0, "mutation_ledger_rows": 0}

def _wait_assistant_projection(url: str, headers: dict, timeout: float = 10) -> list:
    """Bound async projection lag; never bypass evidence checks. / 有界等待异步投影。"""
    deadline = time.monotonic() + timeout
    while True:
        status, page = _http("GET", url, headers=headers)
        if status != 200 or not isinstance(page, dict):
            raise RuntimeError("Agent conversation message projection unavailable")
        items = page.get("items")
        if not isinstance(items, list):
            raise RuntimeError("Agent conversation message projection has no items")
        assistant = [
            i for i in items if isinstance(i, dict) and i.get("role") == "assistant"
        ]
        if assistant:
            return assistant
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "successful Agent Run did not project an assistant message before deadline"
            )
        time.sleep(0.2)


def _http(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    *,
    expected_error_statuses: set[int] | None = None,
) -> tuple[int, dict[str, Any]]:
    data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode()
    request = Request(
        url,
        method=method,
        data=data,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    for attempt in range(4):
        try:
            with urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            # A restarted single-instance container may briefly expose a 502/503
            # while the durable Run remains intact; retry only these transport
            # gateway statuses, never business 4xx responses.
            # 单实例容器重启期间可能短暂返回 502/503；只重试传输层状态，
            # 业务 4xx 绝不重试，避免掩盖真实契约错误。
            if exc.code in {502, 503, 504} and attempt < 3:
                time.sleep(0.2 * (attempt + 1))
                continue
            raw = exc.read().decode("utf-8", errors="replace")
            if expected_error_statuses and exc.code in expected_error_statuses:
                try:
                    return exc.code, json.loads(raw)
                except json.JSONDecodeError:
                    return exc.code, {}
            raise RuntimeError(
                f"{method} {url} -> HTTP {exc.code}: {raw[:512]}"
            ) from exc
        except (
            ConnectionResetError,
            ConnectionAbortedError,
            TimeoutError,
            URLError,
            OSError,
        ) as exc:
            if attempt == 3:
                raise RuntimeError(f"{method} {url} -> transport error: {exc}") from exc
            time.sleep(0.2 * (attempt + 1))
    raise RuntimeError(f"{method} {url} -> transport retry exhausted")


