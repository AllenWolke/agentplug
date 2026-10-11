"""A reviewed snapshot join cannot authorize another query, file or write."""

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import sql_read_projections as projections
import verify_modular_boundaries as gate


def test_projection_is_bound_to_source_query_owner_and_read(tmp_path, monkeypatch):
    path = tmp_path / "platform/internal/audit/projection.go"
    path.parent.mkdir(parents=True)
    query = "SELECT id FROM platform_execution_run"
    path.write_text("package audit\nvar query = `" + query + "`\n", encoding="utf-8")
    monkeypatch.setattr(projections, "ROOT", tmp_path)
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    record = dict(file=path.relative_to(tmp_path).as_posix(), owner="audit",
                  table="platform_execution_run", reason="reviewed bounded read",
                  source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                  query_sha256=hashlib.sha256(query.encode()).hexdigest())
    monkeypatch.setattr(projections, "PROJECTIONS", [record])
    assert gate.scan_sql_writes([path]) == []
    assert projections.permits_projection(path, "audit", record["table"], query, "FROM")
    assert not projections.permits_projection(path, "identity", record["table"], query, "FROM")
    assert not projections.permits_projection(path, "audit", record["table"], query, "UPDATE")
    assert not projections.permits_projection(path, "audit", record["table"], query + " JOIN secret_table ON true", "FROM")
    other = path.with_name("other.go")
    other.write_bytes(path.read_bytes())
    assert not projections.permits_projection(other, "audit", record["table"], query, "FROM")
    path.write_bytes(path.read_bytes() + b"// changed source\n")
    assert gate.scan_sql_writes([path])[0].actual_owner != gate.scan_sql_writes([path])[0].expected_owner


@pytest.mark.parametrize("query", [
    "UPDATE foreign_table SET id=1",
    "WITH deleted AS (DELETE FROM foreign_table RETURNING *) SELECT * FROM deleted",
    "SELECT * FROM foreign_table; DELETE FROM foreign_table",
    "SELECT * FROM foreign_table FOR UPDATE",
    "SELECT * FROM foreign_table /* hidden */",
    "SELECT $body$DELETE FROM foreign_table$body$",
])
def test_registry_cannot_authorize_a_mutation(query):
    assert not projections.read_only_query(query)


@pytest.mark.parametrize("owner,query,expected", [
    ("compensation", "SELECT c.oid FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a", []),
    ("notification", "SELECT rolname FROM pg_roles WHERE oid=$1", []),
    ("audit", "SELECT * FROM pg_roles", ["pg_roles"]),
    ("notification", "UPDATE pg_roles SET rolname='changed'", ["pg_roles"]),
    ("capability", "CREATE TABLE platform_memory_entry(id int); SELECT x IS NOT DISTINCT FROM OLD.effect_stamp", ["platform_memory_entry"]),
    ("capability", "SELECT * FROM OLD.effect_stamp", ["OLD.effect_stamp"]),
    ("audit", "SELECT a.id FROM LATERAL (SELECT id FROM platform_execution_run) a", ["platform_execution_run"]),
])
def test_metadata_and_sql_grammar_remain_bounded(tmp_path, monkeypatch, owner, query, expected):
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    path = tmp_path / "platform/internal" / owner / "store.go"
    path.parent.mkdir(parents=True)
    path.write_text("package " + owner + "\nvar q = `" + query + "`\n", encoding="utf-8")
    assert [row.table for row in gate.scan_sql_writes([path])] == expected


@pytest.mark.parametrize("prefix", ["sdk/python/", "templates/python-generic/platform_entry/", "templates/python-langgraph/platform_entry/"])
def test_only_reviewed_sdk_generation_module_has_ownership(tmp_path, monkeypatch, prefix):
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    folder = tmp_path / prefix / "agent_platform_sdk"
    folder.mkdir(parents=True)
    path = folder / "generation_exit.py"
    path.write_text("q = 'UPDATE public.sdk_execution_generation SET exited=true'\n")
    row = gate.scan_sql_writes([path])[0]
    assert row.actual_owner == row.expected_owner == "execution-sdk"
    other = path.with_name("other.py")
    other.write_bytes(path.read_bytes())
    row = gate.scan_sql_writes([other])[0]
    assert row.actual_owner != row.expected_owner
