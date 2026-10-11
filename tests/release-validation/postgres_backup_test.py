"""Backup failure, corruption and stale data must not look like success."""

import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("postgres_backup", ROOT / "scripts/postgres_backup.py")
BACKUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BACKUP)
ARCHIVE = b'PGDMP' + b'synthetic archive for checksum/publication tests'
TOC = b'1; 1259 100 TABLE public fixture postgres\n'

@pytest.fixture(autouse=True)
def archive_reader(monkeypatch):
    original = BACKUP.subprocess.run
    def run(command, **kwargs):
        if command and command[0] == 'pg_restore':
            return subprocess.CompletedProcess(command, 0, TOC if '--list' in command else b'')
        return original(command, **kwargs)
    monkeypatch.setattr(BACKUP.subprocess, 'run', run)



def create_backup(folder):
    return BACKUP.write_backup([sys.executable, "-c", f"import sys; sys.stdout.buffer.write({ARCHIVE!r})"],
                               folder, "lexagent", "private-test-password")


def change_manifest(path, **changes):
    data = json.loads(path.read_text())
    data.update(changes)
    path.write_text(json.dumps(data))


def test_streamed_dump_is_compressed_and_verified(tmp_path):
    manifest = create_backup(tmp_path)
    data, backup, _ = BACKUP.verify(manifest, 3600)
    assert data["tables"] == ["public.fixture"]
    assert "private-test-password" not in manifest.read_text()
    assert backup.read_bytes().startswith(b"PGDMP")
    if os.name != "nt":
        assert backup.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("data,exit_code", [(ARCHIVE, 7), (b"", 0), (b"not-a-postgres-archive", 0)])
def test_failed_or_empty_dump_publishes_nothing(tmp_path, data, exit_code):
    with pytest.raises((RuntimeError, ValueError)):
        BACKUP.write_backup([sys.executable, "-c", f"import sys; sys.stdout.buffer.write({data!r}); raise SystemExit({exit_code})"],
                            tmp_path, "lexagent", "private-test-password")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("changes", [
    {"created_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()},
    {"created_at": (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()},
    {"created_at": "2026-01-01T00:00:00"},
    {"backup_file": "../escape.pgdump"},
    {"tables": ["other"]},
    {"archive_sha256": "0" * 64},
])
def test_invalid_manifest_is_rejected(tmp_path, changes):
    manifest = create_backup(tmp_path)
    change_manifest(manifest, **changes)
    with pytest.raises(ValueError):
        BACKUP.verify(manifest, 3600)


def test_corrupt_latest_backup_does_not_fall_back(tmp_path):
    older = create_backup(tmp_path)
    latest = create_backup(tmp_path)
    os.utime(older, (100, 100))
    data = json.loads(latest.read_text())
    (tmp_path / data["backup_file"]).write_bytes(b"corrupted")
    metric = tmp_path / "check.prom"
    assert BACKUP.main(["check", "--output-dir", str(tmp_path), "--metrics-file", str(metric)]) == 1
    assert "agentplug_backup_status 0" in metric.read_text()


def test_missing_backups_and_failed_attempt_are_separate_metrics(tmp_path, monkeypatch):
    check_metric, attempt_metric = tmp_path / "check.prom", tmp_path / "attempt.prom"
    assert BACKUP.main(["check", "--output-dir", str(tmp_path), "--metrics-file", str(check_metric)]) == 1
    monkeypatch.delenv("AGENTPLUG_BACKUP_POSTGRES_PASSWORD", raising=False)
    assert BACKUP.main(["backup", "--output-dir", str(tmp_path), "--database", "lexagent",
                        "--user", "backup", "--metrics-file", str(attempt_metric)]) == 1
    assert "agentplug_backup_status 0" in check_metric.read_text()
    assert "agentplug_backup_attempt_success 0" in attempt_metric.read_text()
    assert "agentplug_backup_status" not in attempt_metric.read_text()


def test_successful_cli_check_and_invalid_age_exit_codes(tmp_path):
    manifest = create_backup(tmp_path)
    assert BACKUP.main(['check', '--manifest', str(manifest)]) == 0
    assert BACKUP.main(['check', '--manifest', str(manifest), '--max-age-seconds', '0']) == 1



@pytest.mark.parametrize("options", [[], ["--docker-source", "postgres", "--host", "remote.example"]])
def test_native_tls_required_and_docker_remote_plaintext_rejected(tmp_path, monkeypatch, options):
    monkeypatch.setenv("AGENTPLUG_BACKUP_POSTGRES_PASSWORD", "private-test-password")
    monkeypatch.setattr(BACKUP, "write_backup", lambda *args, **kwargs: pytest.fail("unsafe connection reached dump"))
    assert BACKUP.main(["backup", "--output-dir", str(tmp_path), "--database", "lexagent",
                        "--user", "backup", *options]) == 1


def test_metrics_cannot_overwrite_credentials_or_non_metric_file(tmp_path):
    secret = tmp_path / "private.prom"
    secret.write_text("private-test-password")
    secret.chmod(0o600)
    assert BACKUP.main(["backup", "--database", "lexagent", "--user", "backup", "--output-dir", str(tmp_path),
                        "--password-file", str(secret), "--metrics-file", str(secret)]) == 1
    assert secret.read_text() == "private-test-password"
    manifest = create_backup(tmp_path)
    original = manifest.read_bytes()
    assert BACKUP.main(["check", "--manifest", str(manifest), "--metrics-file", str(manifest)]) == 1
    assert manifest.read_bytes() == original


def test_corrupt_compressed_data_block_is_rejected_after_readable_toc(tmp_path, monkeypatch):
    manifest = create_backup(tmp_path)
    def decoder(command, **kwargs):
        return subprocess.CompletedProcess(command, 0 if '--list' in command else 1, TOC)
    monkeypatch.setattr(BACKUP.subprocess, 'run', decoder)
    with pytest.raises(RuntimeError, match='data validation'):
        BACKUP.verify(manifest, 3600)


def test_duplicate_toc_inventory_publishes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(BACKUP.subprocess, 'run', lambda command, **kwargs: subprocess.CompletedProcess(command, 0, TOC * 2))
    with pytest.raises(ValueError, match='unique'):
        create_backup(tmp_path)
    assert not list(tmp_path.iterdir())


def test_manifest_write_failure_removes_completed_archive(tmp_path, monkeypatch):
    def fail(*args, **kwargs):raise OSError('test disk failure')
    monkeypatch.setattr(BACKUP, 'atomic_write', fail)
    with pytest.raises(OSError):create_backup(tmp_path)
    assert not list(tmp_path.iterdir())


def test_plain_sql_or_mysql_manifest_is_rejected(tmp_path):
    manifest = create_backup(tmp_path)
    change_manifest(manifest, format_version=1, engine='mysql')
    with pytest.raises(ValueError, match='PostgreSQL'):BACKUP.verify(manifest, 3600)


def test_header_probe_does_not_advance_inherited_archive_descriptor(tmp_path):
    archive = tmp_path / 'stream.pgdump'
    archive.write_bytes(b'PGDMP' + b'x' * 10000)
    code = "import sys; data=sys.stdin.buffer.read(); assert data.startswith(b'PGDMP') and len(data)==10005; print('1; 1259 100 TABLE public fixture postgres') if '--list' in sys.argv else None"
    assert BACKUP.archive_inventory(archive, [sys.executable, '-c', code]) == ['public.fixture']
