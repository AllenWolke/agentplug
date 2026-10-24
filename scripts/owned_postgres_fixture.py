"""Readiness and redacted setup diagnostics for disposable SQL fixtures."""
from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path


def safe_diagnostic(raw: bytes, secrets: tuple[str, ...]) -> str:
    text = raw.decode("utf-8", errors="replace")
    for value in sorted((v for v in secrets if v), key=len, reverse=True):
        text = text.replace(value, "<redacted>")
    text = re.sub(r"(?i)postgres(?:ql)?://[^\s\"']+", "<redacted-dsn>", text)
    text = re.sub(r"(?i)((?:password|token|secret|authorization)\s*[=:]\s*)[^\s,;\"']+", r"\1<redacted>", text)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    return text[-4000:].strip()


def fixture_command(arguments: list[str], *, record: dict, stage: str,
                    private: Path, secrets: tuple[str, ...],
                    data: bytes | None = None, timeout: int = 60) -> bytes:
    record["fixture_stage"] = stage
    result = subprocess.run(arguments, input=data, capture_output=True, timeout=timeout)
    if result.returncode:
        summary = safe_diagnostic(result.stdout + b"\n" + result.stderr, secrets)
        record["fixture_exit_code"] = result.returncode
        record["fixture_error_summary"] = summary
        # Only redacted diagnostics are retained; never serialize arguments or
        # the environment, which may contain an ephemeral database credential.
        log = private / "setup-failure.log"
        log.write_text(summary + "\n", encoding="utf-8")
        raise RuntimeError(f"fixture {stage} failed (exit {result.returncode}): {summary}")
    return result.stdout


def wait_for_postgres(name: str, database: str, *, timeout: float = 45) -> dict:
    """Wait for the final TCP server and the target database, not initdb's socket.

    The official image temporarily starts a Unix-socket-only server before
    creating POSTGRES_DB. A socket pg_isready success is not application
    readiness. Both probes here are read-only and safe to repeat.
    """
    deadline = time.monotonic() + timeout
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        ready = subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1",
                                "-p", "5432", "-U", "postgres", "-d", database],
                               capture_output=True, timeout=5)
        if ready.returncode == 0:
            query = subprocess.run(["docker", "exec", name, "psql", "-X", "--no-password",
                                    "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database,
                                    "-t", "-A", "-c", "SELECT 1"],
                                   capture_output=True, timeout=5)
            if query.returncode == 0 and query.stdout.strip() == b"1":
                return {"ready_over_tcp": True, "database_query_confirmed": True, "attempts": attempts}
        time.sleep(0.25)
    raise RuntimeError("owned PostgreSQL final TCP server and target database readiness timed out")
