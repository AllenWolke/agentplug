"""Verify native PostgreSQL backup/restore against owned disposable databases."""
from __future__ import annotations
import importlib.util
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
NAME = 'agentplug-backup-source-' + uuid4().hex
TEMP = ROOT / '.tmp' / NAME
IMAGE = 'pgvector/pgvector:pg16'
DATABASE = 'agentplug_backup_fixture'
EVIDENCE = ROOT / 'docs/新增需求/github作品改造'
spec = importlib.util.spec_from_file_location('postgres_backup', ROOT / 'scripts/postgres_backup.py')
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, timeout=180, **kwargs)
    if result.returncode:
        raise RuntimeError('isolated backup verification command failed')
    return result.stdout


def query(container, database, sql):
    return run(['docker', 'exec', '--user', 'postgres', container, 'psql', '-X', '-q', '-t', '-A',
                '-v', 'ON_ERROR_STOP=1', '-d', database, '-c', sql]).decode('utf-8').strip()


def data_facts(container, database, tables):
    facts = {}
    for table in tables:
        parts = table.split('.')
        if len(parts) != 2 or not all(backup.IDENTIFIER.fullmatch(part) for part in parts):
            raise ValueError('invalid fixture table')
        relation = '.'.join('"' + part + '"' for part in parts)
        # Canonical JSONB includes every column; only the count and SHA leave
        # the fixture process, never row payloads or credential data.
        sql = "SET TIME ZONE 'UTC'; SELECT COUNT(*)::text||':'||encode(sha256(convert_to(COALESCE(string_agg(to_jsonb(t)::text,E'\\n' ORDER BY to_jsonb(t)::text),''),'UTF8')),'hex') FROM " + relation + ' t'
        facts[table] = query(container, database, sql)
    return facts


def main():
    report = {'complete': False, 'scope': 'isolated PostgreSQL backup/restore only, not complete project',
              'image': IMAGE, 'temporary_images_built': [], 'source_project_database_accessed': False,
              'interview_copy_changed': False, 'cleanup_errors': []}
    try:
        TEMP.mkdir(parents=True, exist_ok=False)
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        password = secrets.token_hex(32)
        read_password = secrets.token_hex(32) + ':$(touch /tmp/agentplug-dump-command-injection)'
        environment_file = TEMP / 'postgres.env'
        environment_file.write_text('POSTGRES_PASSWORD=' + password + '\nPOSTGRES_DB=' + DATABASE + '\nPOSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=trust\n', encoding='utf-8')
        environment_file.chmod(0o600)
        inspection = json.loads(run(['docker', 'image', 'inspect', IMAGE]))[0]
        report['image_id'], report['image_digests'] = inspection['Id'], inspection.get('RepoDigests', [])
        run(['docker', 'run', '--detach', '--name', NAME, '--label', 'agentplug.backup.fixture=' + NAME,
             '--env-file', str(environment_file), '--publish', '127.0.0.1::5432', '--read-only', '--user', 'postgres',
             '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
             '--tmpfs', '/var/lib/postgresql/data:rw,noexec,nosuid,size=512m,uid=999,gid=999,mode=0700',
             '--tmpfs', '/var/run/postgresql:rw,nosuid,uid=999,gid=999,mode=0700',
             '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m', IMAGE])
        for _ in range(120):
            ready = subprocess.run(['docker', 'exec', NAME, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres', '-d', DATABASE], capture_output=True)
            if ready.returncode == 0:break
            time.sleep(0.5)
        else:raise RuntimeError('owned source database readiness failed')
        metadata = json.loads(run(['docker', 'inspect', NAME]))[0]
        binding = metadata['NetworkSettings']['Ports']['5432/tcp'][0]
        assert binding['HostIp'] == '127.0.0.1'
        environment = os.environ.copy()
        environment.update(APP_ENV='test', DB_DRIVER='pgx', DB_DSN=f'postgresql://postgres:{quote(password,safe="")}@127.0.0.1:{binding["HostPort"]}/{DATABASE}?sslmode=disable')
        environment.pop('PLATFORM_DEV_RUNTIME_PASSWORD', None)
        run(['go', 'run', './cmd/migrate'], cwd=ROOT / 'platform', env=environment)
        report['actual_complete_platform_migration'] = True
        sql = """CREATE TABLE public.backup_fixture (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, document jsonb NOT NULL, bytes bytea NOT NULL, embedding vector(3) NOT NULL, updated_at timestamptz NOT NULL);
INSERT INTO public.backup_fixture(document,bytes,embedding,updated_at) VALUES ('{"text":"中文备份数据","principal":"fixture-user"}','\\x00ff01','[1,0,0]','2026-10-02T03:04:05.123456Z'),('{"text":"second","tags":["a","b"]}','\\x0102','[0,1,0]','2026-10-02T03:05:06.123456Z');
CREATE ROLE fixture_backup LOGIN PASSWORD '""" + read_password.replace("'", "''") + """';
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE TEMP ON DATABASE agentplug_backup_fixture FROM PUBLIC;
GRANT USAGE ON SCHEMA public,knowledge TO fixture_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA public,knowledge TO fixture_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public,knowledge TO fixture_backup;
"""
        run(['docker', 'exec', '--interactive', '--user', 'postgres', NAME, 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-d', DATABASE], input=sql.encode('utf-8'))
        report['version'] = query(NAME, DATABASE, "SELECT current_setting('server_version')||' / pgvector '||extversion FROM pg_extension WHERE extname='vector'")
        tables = query(NAME, DATABASE, backup.TABLE_QUERY).splitlines()
        source = data_facts(NAME, DATABASE, tables)
        secret = TEMP / 'backup.password'
        secret.write_text(read_password, encoding='utf-8');secret.chmod(0o600)
        output = TEMP / 'backups'
        export = [sys.executable, str(ROOT / 'scripts/postgres_backup.py'), 'backup', '--database', DATABASE,
                  '--user', 'fixture_backup', '--docker-source', NAME, '--password-file', str(secret),
                  '--output-dir', str(output), '--metrics-file', str(TEMP / 'attempt.prom')]
        completed = subprocess.run(export, capture_output=True, timeout=180)
        if completed.returncode:
            for code in ('dump_failed', 'archive_header', 'archive_inventory', 'archive_identifiers', 'archive_tables', 'archive_data', 'configuration_or_integrity'):
                if ('(' + code + ')').encode() in completed.stderr:
                    report['backup_cli_failure_code'] = code
                    break
        assert completed.returncode == 0, 'actual PostgreSQL backup CLI failed'
        assert read_password.encode() not in completed.stdout + completed.stderr
        run(['docker', 'exec', NAME, 'test', '!', '-e', '/tmp/agentplug-dump-command-injection'])
        report['stdin_password_is_literal_and_not_in_output'] = True
        assert 'agentplug_backup_attempt_success 1' in (TEMP / 'attempt.prom').read_text()
        manifest_path = next(output.glob('*.manifest.json'))
        reader = ['docker', 'exec', '--interactive', NAME, 'pg_restore']
        manifest, archive, _ = backup.verify(manifest_path, 3600, reader, null_device='/dev/null')
        assert manifest['tables'] == tables
        assert read_password not in manifest_path.read_text(encoding='utf-8')
        report['archive_native_full_decode_verified'] = True
        report['table_count'] = len(tables)
        # Mutate only the owned source fixture after the dump. Restored data
        # must match the archive snapshot, not read the live source anew.
        query(NAME, DATABASE, "UPDATE public.backup_fixture SET document='{\"text\":\"after-snapshot\"}' WHERE id=1")
        def inspect_restored(container, database):
            metadata = json.loads(run(['docker', 'inspect', container]))[0]
            assert metadata['HostConfig']['NetworkMode'] == 'none'
            assert not metadata['HostConfig'].get('PortBindings')
            assert data_facts(container, database, tables) == source
            assert query(container, database, "INSERT INTO public.backup_fixture(document,bytes,embedding,updated_at) VALUES ('{}','\\x00','[0,0,1]',clock_timestamp()) RETURNING id") == '3'
            report['all_table_counts_and_full_row_hashes_match'] = True
            report['jsonb_bytea_unicode_vector_timestamp_and_identity_sequence_restored'] = True
            report['restore_network_none_no_published_ports'] = True
        report['restore'] = backup.restore_isolated(manifest, archive, IMAGE, inspect_restored=inspect_restored)
        assert 'after-snapshot' in query(NAME, DATABASE, 'SELECT document::text FROM public.backup_fixture WHERE id=1')
        report['source_post_snapshot_change_preserved'] = True
        cli_check = subprocess.run([sys.executable, str(ROOT / 'scripts/postgres_backup.py'), 'check', '--manifest', str(manifest_path),
                                   '--max-age-seconds', '3600', '--restore-image', IMAGE, '--metrics-file', str(TEMP / 'check.prom')], capture_output=True, timeout=180)
        assert cli_check.returncode == 0, 'actual isolated restore CLI failed'
        assert read_password.encode() not in cli_check.stdout + cli_check.stderr
        report['native_check_and_restore_cli_verified'] = True
        secret.write_text('incorrect-test-password', encoding='utf-8')
        before = sorted(path.name for path in output.iterdir())
        failed = subprocess.run(export, capture_output=True, timeout=180)
        assert failed.returncode != 0 and sorted(path.name for path in output.iterdir()) == before
        assert 'agentplug_backup_attempt_success 0' in (TEMP / 'attempt.prom').read_text()
        assert 'agentplug_backup_status 1' in (TEMP / 'check.prom').read_text()
        report['failed_export_publishes_nothing_and_keeps_check_metric_separate'] = True
        report['tests_passed'] = True
    except Exception as error:
        report['failure_type'] = type(error).__name__
        # Capture a redacted stage only; no client stderr, credentials or rows.
        report['tests_passed'] = False
    finally:
        inspection = subprocess.run(['docker', 'inspect', NAME], capture_output=True)
        if inspection.returncode == 0:
            metadata = json.loads(inspection.stdout)[0]
            if (metadata['Config'].get('Labels') or {}).get('agentplug.backup.fixture') != NAME:
                report['cleanup_errors'].append('source ownership mismatch')
            elif subprocess.run(['docker', 'rm', '--force', '--volumes', NAME], capture_output=True).returncode:
                report['cleanup_errors'].append('source cleanup failed')
        elif b'No such object' not in inspection.stderr and b'No such container' not in inspection.stderr:
            report['cleanup_errors'].append('Docker unavailable; cleanup unverified')
        report['temporary_source_container_removed'] = subprocess.run(['docker', 'inspect', NAME], capture_output=True).returncode != 0 and not report['cleanup_errors']
        if TEMP.exists():
            target = TEMP.resolve()
            if not target.is_relative_to((ROOT / '.tmp').resolve()) or target.name != NAME or TEMP.is_symlink():
                report['cleanup_errors'].append('temporary path ownership mismatch')
            else:shutil.rmtree(TEMP)
        report['temporary_source_files_removed'] = not TEMP.exists()
        report['complete'] = report.get('tests_passed', False) and not report['cleanup_errors'] and report['temporary_source_container_removed'] and report['temporary_source_files_removed']
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        (EVIDENCE / 'T3-04A-PostgreSQL备份恢复实际验证.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['complete'] else 1


if __name__ == '__main__':raise SystemExit(main())
