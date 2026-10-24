"""A bootstrap socket or an unrelated test must not decide a CI SQL result."""
import ast
import importlib.util
from pathlib import Path
import re
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("owned_pg", ROOT / "scripts/owned_postgres_fixture.py")
owned_pg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owned_pg)


def test_bootstrap_socket_is_not_ready_and_target_database_must_exist(monkeypatch):
    calls = []
    tcp_attempts, query_attempts = 0, 0

    def execute(args, **kwargs):
        nonlocal tcp_attempts, query_attempts
        calls.append(args)
        if "pg_isready" in args:
            # initdb's socket reports ready before the final server exists.
            if "-h" not in args:
                return subprocess.CompletedProcess(args, 0, b"accepting", b"")
            tcp_attempts += 1
            return subprocess.CompletedProcess(args, 1 if tcp_attempts == 1 else 0, b"", b"")
        query_attempts += 1
        return subprocess.CompletedProcess(args, 1 if query_attempts == 1 else 0,
                                           b"1\n" if query_attempts > 1 else b"", b"database unavailable")

    monkeypatch.setattr(owned_pg.subprocess, "run", execute)
    monkeypatch.setattr(owned_pg.time, "sleep", lambda _: None)
    result = owned_pg.wait_for_postgres("owned-test", "conditional_test")
    assert result["ready_over_tcp"] and result["database_query_confirmed"]
    assert tcp_attempts == 3 and query_attempts == 2
    assert all("127.0.0.1" in command for command in calls if "pg_isready" in command)
    assert all("SELECT 1" in command and "conditional_test" in command for command in calls if "psql" in command)


def test_permanent_readiness_failure_is_bounded(monkeypatch):
    ticks = iter([0, 0, 2])
    monkeypatch.setattr(owned_pg.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(owned_pg.time, "sleep", lambda _: None)
    monkeypatch.setattr(owned_pg.subprocess, "run", lambda args, **kwargs: subprocess.CompletedProcess(args, 1, b"", b"not ready"))
    with pytest.raises(RuntimeError, match="final TCP server and target database"):
        owned_pg.wait_for_postgres("owned-test", "conditional_test", timeout=1)


def test_setup_failure_preserves_stage_and_redacts_diagnostics(monkeypatch, tmp_path):
    secret = "random-fixture-password"
    diagnostic = f"connection refused postgres://postgres:{secret}@127.0.0.1/db TOKEN=another-secret".encode()
    monkeypatch.setattr(owned_pg.subprocess, "run", lambda args, **kwargs: subprocess.CompletedProcess(args, 2, b"", diagnostic))
    record = {}
    with pytest.raises(RuntimeError, match="cache-schema failed") as error:
        owned_pg.fixture_command(["docker", "exec"], record=record, stage="cache-schema",
                                 private=tmp_path, secrets=(secret,))
    assert record["fixture_exit_code"] == 2 and record["fixture_stage"] == "cache-schema"
    assert "connection refused" in record["fixture_error_summary"]
    for text in (str(error.value), (tmp_path / "setup-failure.log").read_text(), record["fixture_error_summary"]):
        assert secret not in text and "another-secret" not in text and "postgres://" not in text


def test_knowledge_selection_keeps_all_domain_cases_and_leaves_compensation_to_its_fixture():
    tree = ast.parse((ROOT / "scripts/verify_public_knowledge_postgres.py").read_text(encoding="utf-8"))
    definition = next(n for n in tree.body if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == "KNOWLEDGE_GO_TEST_PATTERN" for t in n.targets))
    pattern = ast.literal_eval(definition.value)
    previous = r"TestBM25|TestDenied|TestChinese|TestHybrid|TestPostgres|TestVectorLiteral|TestCurrentKnowledgeSource|TestStageCache|TestCachedQueryModels|TestIndexEmbeddings|TestIndexEmbeddingWorker"
    names = {m[1] for folder in (ROOT / "platform/internal/knowledge", ROOT / "platform/cmd/platform")
             for path in folder.glob("*_test.go")
             for m in re.finditer(r"^func (Test\w+)\(", path.read_text(encoding="utf-8"), re.M)}
    old = {name for name in names if re.search(previous, name)}
    new = {name for name in names if re.search(pattern, name)}
    unrelated = "TestPostgresCancellationProgressCompositionDoesNotReadFrozenToolHistory"
    assert old - new == {unrelated}
    assert new - old == set()
    assert len(new) == 54
    dedicated = (ROOT / "docs/developer/zh/github-actions-verification-20261023.json").read_text(encoding="utf-8")
    assert unrelated in dedicated
    assert not re.search(pattern, "TestPostgresUnrelatedFutureFixture")
