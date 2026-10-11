"""PostgreSQL acceptance plumbing tests; actual SQL evidence uses the isolated fixture."""

from types import SimpleNamespace

import pytest

import run_assertions as probe


RUN = "machine-e2e-" + "a" * 20
DSN = "postgresql://fixture_user:fixture-not-a-secret@127.0.0.1:5432/knowledge_test?sslmode=disable"


def fixture_environment(monkeypatch):
    monkeypatch.setenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN", DSN)


def test_read_only_postgres_query_keeps_password_out_of_argv(monkeypatch):
    fixture_environment(monkeypatch)

    def execute(argv, **kwargs):
        joined = " ".join(argv)
        assert "fixture-not-a-secret" not in joined
        assert "--dbname=postgresql://fixture_user@127.0.0.1:5432/knowledge_test?sslmode=disable" in argv
        assert argv[argv.index("--set") + 1] == f"run_id={RUN}"
        assert kwargs["env"]["PGPASSWORD"] == "fixture-not-a-secret"
        assert kwargs["env"]["PGOPTIONS"] == "-c default_transaction_read_only=on"
        query = kwargs["input"].decode()
        assert query.startswith("SELECT ")
        assert "platform_notification_outbox" in query
        assert "payload_json::jsonb" in query
        assert "platform_tool_invocation" in query
        assert "recovery_query::jsonb" in query
        assert "platform_execution_run" in query
        assert ":'run_id'" in query
        assert kwargs["timeout"] == 20
        return SimpleNamespace(returncode=0, stdout=b"0\t0\t1\n", stderr=b"")

    monkeypatch.setattr(probe.subprocess, "run", execute)
    assert probe.assert_no_platform_mutations(RUN)["mutation_ledger_rows"] == 0


@pytest.mark.parametrize("output", [b"1\t0\t1", b"0\t1\t1", b"0\t0\t2", b"0\t0\t1\t0", b"0\t0\t0", b"", b"0\t0"])
def test_missing_or_nonzero_counts_never_pass(monkeypatch, output):
    fixture_environment(monkeypatch)
    monkeypatch.setattr(probe.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=0, stdout=output, stderr=b""))
    with pytest.raises(RuntimeError):
        probe.assert_no_platform_mutations(RUN)


def test_sql_failure_is_explicit_and_diagnostic_is_not_leaked(monkeypatch):
    fixture_environment(monkeypatch)
    monkeypatch.setattr(probe.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=1, stdout=b"", stderr=b"fixture-sensitive-diagnostic"))
    with pytest.raises(RuntimeError, match="no PASS evidence") as caught:
        probe.assert_no_platform_mutations(RUN)
    assert "fixture-sensitive-diagnostic" not in str(caught.value)


def test_no_sql_without_isolated_postgres_credentials(monkeypatch):
    monkeypatch.delenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN", raising=False)
    called = []
    monkeypatch.setattr(probe.subprocess, "run", lambda *a, **k: called.append(a))
    with pytest.raises(RuntimeError, match="isolated PostgreSQL"):
        probe.assert_no_platform_mutations(RUN)
    assert called == []


@pytest.mark.parametrize("dsn", [
    "mysql://user:password@127.0.0.1:3306/knowledge_test",
    "postgresql://user:password@127.0.0.1:5432/knowledge_test?%70assword=leak",
    "postgresql://user:password@127.0.0.1:5432/knowledge_test?options=-c%20application_name=leak",
    "postgresql://user:password@db.example.test:5432/knowledge_test",
    "postgresql://user:password@127.0.0.1:5432/agentplug",
    "postgresql://user@127.0.0.1:5432/knowledge_test",
])
def test_nonisolated_or_credentialless_dsn_never_runs_sql(monkeypatch, dsn):
    monkeypatch.setenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN", dsn)
    called = []
    monkeypatch.setattr(probe.subprocess, "run", lambda *a, **k: called.append(a))
    with pytest.raises(RuntimeError, match="isolated PostgreSQL"):
        probe.assert_no_platform_mutations(RUN)
    assert called == []


def test_preflight_rejection_must_not_create_run(monkeypatch):
    fixture_environment(monkeypatch)
    monkeypatch.setattr(probe.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=0, stdout=b"0\t0\t0", stderr=b""))
    assert probe.assert_no_platform_mutations(RUN, require_absent_run=True)["notification_rows"] == 0
    with pytest.raises(RuntimeError, match="exactly one platform Run"):
        probe.assert_no_platform_mutations(RUN)
