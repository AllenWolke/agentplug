"""Explicit table ownership fixtures / 显式表所有权负向夹具。"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import verify_modular_boundaries as gate


def test_generated_business_workspace_is_excluded_but_platform_and_cli_source_remain(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    generated = tmp_path / "cli/agentctl/out/business/platform_entry/copied_sdk.py"
    cli = tmp_path / "cli/agentctl/cmd/main.go"
    platform = tmp_path / "platform/internal/identity/store.go"
    for path in (generated, cli, platform):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    assert set(gate.iter_source_files()) == {cli, platform}


def test_source_walk_prunes_only_pytest_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    root = tmp_path / "platform"
    root.mkdir()
    visited = []

    def walk(directory, onerror):
        directories = [".pytest_cache", "internal"]
        yield str(directory), directories, []
        visited.extend(directories)

    monkeypatch.setattr(gate.os, "walk", walk)
    assert gate.iter_source_files() == []
    assert visited == ["internal"]


def test_source_walk_permission_failure_still_blocks(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    (tmp_path / "platform").mkdir()

    def walk(directory, onerror):
        onerror(PermissionError("production source inaccessible"))
        yield str(directory), [], []

    monkeypatch.setattr(gate.os, "walk", walk)
    with pytest.raises(PermissionError):
        gate.iter_source_files()


def scan(tmp_path, monkeypatch, module, statement):
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    file = tmp_path / "platform" / "internal" / module / "store.go"
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(
        "package " + module + "\nvar query = `" + statement + "`\n", encoding="utf-8"
    )
    return gate.scan_sql_writes([file])


@pytest.mark.parametrize(
    "statement,expected",
    [
        ("INSERT INTO platform_audit_event(id) VALUES(?)", False),
        ("INSERT INTO platform_notification_outbox(id) VALUES(?)", True),
        ("UPDATE unknown_table SET id=?", True),
        (
            "SELECT a.id FROM platform_audit_event a JOIN platform_execution_run r ON r.run_id=a.id",
            True,
        ),
        (
            "SELECT a.id FROM platform_audit_event a\nJOIN platform_notification_outbox n ON n.event_id=a.id",
            True,
        ),
        ("SELECT id FROM information_schema.tables", False),
        ("DELETE FROM information_schema.tables WHERE id=?", True),
    ],
)
def test_owner_and_join_fail_closed(tmp_path, monkeypatch, statement, expected):
    rows = scan(tmp_path, monkeypatch, "audit", statement)
    invalid = [
        row
        for row in rows
        if row.actual_owner != row.expected_owner
        or row.expected_owner == "unclassified"
    ]
    assert bool(invalid) is expected
    monkeypatch.setattr(sys, "argv", ["boundary-gate"])
    assert gate.main() == int(expected)


def test_two_actual_writers_are_not_expected_owner(tmp_path, monkeypatch):
    a = scan(
        tmp_path, monkeypatch, "audit", "UPDATE platform_audit_event SET summary=?"
    )
    b = scan(
        tmp_path, monkeypatch, "execution", "UPDATE platform_audit_event SET summary=?"
    )
    assert {row.actual_owner for row in a + b} == {"audit", "execution"}
    assert {row.expected_owner for row in a + b} == {"audit"}
    monkeypatch.setattr(sys, "argv", ["boundary-gate"])
    assert gate.main() == 1


def test_checkpoint_schema_is_owned_by_only_the_reviewed_sdk_module(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, 'ROOT', tmp_path)
    sdk = tmp_path / 'sdk/python/agent_platform_sdk'
    sdk.mkdir(parents=True)
    reviewed = sdk / 'checkpoint_schema.py'
    reviewed.write_text("query = 'SELECT v FROM checkpoint_migrations ORDER BY v'\n")
    rows = gate.scan_sql_writes([reviewed])
    assert len(rows) == 1 and rows[0].actual_owner == rows[0].expected_owner == 'checkpoint-sdk'
    unrelated = sdk / 'unreviewed.py'
    unrelated.write_text(reviewed.read_text())
    invalid = gate.scan_sql_writes([unrelated])
    assert invalid[0].actual_owner != invalid[0].expected_owner
    cross_domain = scan(tmp_path, monkeypatch, 'identity', 'DELETE FROM checkpoint_migrations WHERE v=1')
    assert cross_domain[0].actual_owner != cross_domain[0].expected_owner


def test_comments_prose_and_for_update_are_not_tables(tmp_path, monkeypatch):
    rows = scan(
        tmp_path,
        monkeypatch,
        "audit",
        "SELECT id FROM platform_audit_event FOR UPDATE SKIP LOCKED",
    )
    assert [row.table for row in rows] == ["platform_audit_event"]
    assert (
        scan(tmp_path, monkeypatch, "audit", "create grant from access request") == []
    )
    file = tmp_path / "platform/internal/audit/store.go"
    file.write_text(
        'package audit\n// `INSERT INTO secret_table(id) VALUES(?)`\nvar message="update conversation"',
        encoding="utf-8",
    )
    assert gate.scan_sql_writes([file]) == []


def test_invalid_encoding_is_not_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    file = tmp_path / "platform/internal/audit/store.go"
    file.parent.mkdir(parents=True)
    file.write_bytes(b"\xff")
    with pytest.raises(UnicodeDecodeError):
        gate.scan_sql_writes([file])


@pytest.mark.parametrize("statement,expected", [
 ("WITH mine AS MATERIALIZED (SELECT id FROM platform_audit_event) SELECT id FROM mine", False),
 ("WITH mine AS (SELECT id FROM platform_execution_run) SELECT id FROM mine", True),
 ("WITH mine AS (SELECT id FROM platform_audit_event) DELETE FROM mine", True),
 ("SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace", False),
 ("UPDATE pg_catalog.pg_class SET relname='changed'", True),
 ("SELECT * FROM pg_catalog.unknown_metadata", True),
 ("SELECT id FROM public.platform_audit_event", False),
 ("SELECT id FROM foreign_schema.platform_audit_event", True),
 ("SELECT f.id FROM jsonb_to_recordset(?) AS f(id text)", False),
 ("SELECT * FROM unknown_function(?)", True),
 ("SELECT * FROM jsonb_to_recordset", True),
 ("WITH mine AS (SELECT id FROM platform_audit_event), other AS (SELECT id FROM platform_execution_run) SELECT * FROM mine JOIN other ON true", True),
])
def test_postgres_relations_keep_cross_module_checks(tmp_path, monkeypatch, statement, expected):
 rows = scan(tmp_path, monkeypatch, "audit", statement)
 invalid = [row for row in rows if row.actual_owner != row.expected_owner or row.expected_owner == "unclassified"]
 assert bool(invalid) is expected


def test_named_go_cte_constant_is_resolved_but_variable_is_not(tmp_path, monkeypatch):
 monkeypatch.setattr(gate,"ROOT",tmp_path)
 p=tmp_path/"platform/internal/audit/store.go";p.parent.mkdir(parents=True)
 p.write_text("package audit\nconst prefix = `WITH own AS (SELECT id FROM platform_audit_event) `\nvar query=prefix+`SELECT * FROM own`\n")
 rows=gate.scan_sql_writes([p])
 assert rows and all(row.actual_owner==row.expected_owner for row in rows)
 p.write_text(p.read_text().replace("const prefix", "var prefix"))
 rows=gate.scan_sql_writes([p])
 assert any(row.expected_owner=="unclassified" for row in rows)


@pytest.mark.parametrize("table,foreign", [("platform_audit_event", False), ("platform_execution_run", True)])
def test_sibling_go_cte_keeps_underlying_table_boundary(tmp_path, monkeypatch, table, foreign):
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    folder = tmp_path / "platform/internal/audit"
    folder.mkdir(parents=True)
    (folder / "prefix.go").write_text("package audit\nconst prefix = `WITH visible AS (SELECT id FROM " + table + ") `\n", encoding="utf-8")
    caller = folder / "store.go"
    caller.write_text("package audit\nvar query = prefix + `SELECT id FROM visible`\n", encoding="utf-8")
    rows = gate.scan_sql_writes([caller])
    assert rows and all(row.table != "visible" for row in rows)
    assert any(row.actual_owner != row.expected_owner for row in rows) is foreign
    (folder / "prefix.go").write_text("package different\nconst prefix = `WITH visible AS (SELECT id FROM " + table + ") `\n", encoding="utf-8")
    assert any(row.table == "visible" and row.expected_owner == "unclassified" for row in gate.scan_sql_writes([caller]))
