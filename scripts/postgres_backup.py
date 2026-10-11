"""PostgreSQL custom-archive backup, integrity monitoring and isolated restore.

Credentials never enter command arguments. Native connections verify TLS;
Docker source mode is limited to the selected container's loopback endpoint.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
TABLE_ENTRY = re.compile(r"^\d+; \d+ \d+ TABLE (?!DATA |ATTACH )(.+)$")

def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".backup-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def metrics(path: Path | None, success: bool, timestamp: float, operation: str = "check") -> None:
    if path is not None:
        if operation == "backup":
            atomic_write(path, (
                "# HELP agentplug_backup_attempt_success Most recent backup command result.\n"
                "# TYPE agentplug_backup_attempt_success gauge\n"
                f"agentplug_backup_attempt_success {int(success)}\n"
                "# HELP agentplug_backup_attempt_timestamp_seconds Most recent backup attempt time.\n"
                "# TYPE agentplug_backup_attempt_timestamp_seconds gauge\n"
                f"agentplug_backup_attempt_timestamp_seconds {time.time():.0f}\n"
            ).encode("ascii"))
            return
        atomic_write(path, (
            "# HELP agentplug_backup_status Latest backup/check integrity and age status.\n"
            "# TYPE agentplug_backup_status gauge\n"
            f"agentplug_backup_status {int(success)}\n"
            "# HELP agentplug_backup_last_success_timestamp_seconds Verified backup creation time.\n"
            "# TYPE agentplug_backup_last_success_timestamp_seconds gauge\n"
            f"agentplug_backup_last_success_timestamp_seconds {timestamp:.0f}\n"
            "# HELP agentplug_backup_check_timestamp_seconds Most recent integrity and age check time.\n"
            "# TYPE agentplug_backup_check_timestamp_seconds gauge\n"
            f"agentplug_backup_check_timestamp_seconds {time.time():.0f}\n"
        ).encode("ascii"))


def archive_inventory(path: Path, reader: list[str], *, null_device: str = os.devnull) -> list[str]:
    # The child inherits the OS file offset, not Python's buffered cursor.
    # A buffered header read followed by seek(0) may leave that offset at 4096.
    with path.open('rb', buffering=0) as stream:
        if stream.read(5) != b'PGDMP':
            raise ValueError('backup is not a PostgreSQL custom archive')
        stream.seek(0)
        result = subprocess.run([*reader, '--list'], stdin=stream, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=900, check=False)
    if result.returncode:
        raise RuntimeError('PostgreSQL archive inventory validation failed')
    tables = []
    for line in result.stdout.decode('utf-8').splitlines():
        match = TABLE_ENTRY.match(line)
        if not match:
            continue
        fields = match.group(1).split()
        if len(fields) != 3 or not all(IDENTIFIER.fullmatch(value) for value in fields[:2]):
            raise ValueError('unsupported table identifier in archive')
        tables.append(fields[0] + '.' + fields[1])
    if not tables or len(tables) != len(set(tables)):
        raise ValueError('backup must have a nonempty, unique base-table inventory')
    # Listing alone does not decompress/validate table-data blocks. Render all
    # SQL to the null device without executing it, so damaged blocks fail check.
    with path.open('rb') as stream:
        result = subprocess.run([*reader, '--no-owner', '--no-acl', '--file', null_device],
                                stdin=stream, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=900, check=False)
    if result.returncode:
        raise RuntimeError('PostgreSQL archive data validation failed')
    return sorted(tables)


def write_backup(command: list[str], directory: Path, database: str, password: str, *,
                 docker_source: bool = False, reader: list[str] | None = None,
                 ssl_ca: Path | None = None) -> Path:
    if not IDENTIFIER.fullmatch(database):
        raise ValueError('invalid database name')
    directory.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc)
    stem = database + '-' + started.strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(4)
    final = directory / (stem + '.pgdump')
    descriptor, temporary_name = tempfile.mkstemp(prefix='.backup-', dir=directory)
    temporary = Path(temporary_name)
    raw = os.fdopen(descriptor, 'wb')
    environment = {key: value for key, value in os.environ.items()
                   if not key.upper().startswith('PG') and key != 'AGENTPLUG_BACKUP_POSTGRES_PASSWORD'}
    environment['PGCONNECT_TIMEOUT'] = '15'
    environment['PGSSLMODE'] = 'verify-full'
    if ssl_ca is not None:
        environment['PGSSLROOTCERT'] = str(ssl_ca.resolve())
    try:
        # Native libpq reads an owner-private password file; Docker receives the
        # password via stdin and exports it only in the selected dump process.
        with tempfile.TemporaryDirectory(prefix='agentplug-pgpass-') as credentials:
            if not docker_source:
                password_file = Path(credentials) / 'pgpass'
                escaped = password.replace('\\', '\\\\').replace(':', '\\:')
                password_file.write_text('*:*:*:*:' + escaped + '\n', encoding='utf-8')
                password_file.chmod(0o600)
                environment['PGPASSFILE'] = str(password_file)
            with raw:
                with subprocess.Popen(command, stdin=subprocess.PIPE if docker_source else subprocess.DEVNULL,
                                      stdout=raw, stderr=subprocess.DEVNULL, env=environment) as process:
                    try:
                        if docker_source:
                            assert process.stdin is not None
                            process.stdin.write((password + '\n').encode('utf-8'))
                            process.stdin.close()
                        if process.wait(timeout=900):
                            raise RuntimeError('pg_dump failed; no completed backup was published')
                    except BaseException:
                        process.kill()
                        process.wait()
                        raise
                raw.flush()
                os.fsync(raw.fileno())
        tables = archive_inventory(temporary, reader or ['pg_restore'],
                                   null_device='/dev/null' if docker_source else os.devnull)
        manifest = {'format_version': 2, 'engine': 'postgresql', 'archive_format': 'custom',
                    'database': database, 'backup_file': final.name, 'created_at': started.isoformat(),
                    'archive_sha256': digest(temporary), 'tables': tables,
                    'consistency': 'pg_dump consistent database snapshot; separate databases require coordination',
                    'restore_identity': 'no-owner/no-acl; provision approved roles and grants separately'}
        os.replace(temporary, final)
        manifest_path = directory / (stem + '.manifest.json')
        try:
            atomic_write(manifest_path, (json.dumps(manifest, indent=2) + '\n').encode('utf-8'))
        except BaseException:
            final.unlink(missing_ok=True)
            raise
        return manifest_path
    finally:
        raw.close()
        temporary.unlink(missing_ok=True)


def verify(manifest_path: Path, max_age: int, reader: list[str] | None = None, *,
           isolated_restore: bool = False, null_device: str = os.devnull) -> tuple[dict, Path, float]:
    if manifest_path.is_symlink() or not manifest_path.is_file() or max_age < 1:
        raise ValueError('invalid backup manifest or maximum age')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if (manifest.get('format_version') != 2 or manifest.get('engine') != 'postgresql'
            or manifest.get('archive_format') != 'custom'
            or not IDENTIFIER.fullmatch(manifest.get('database', ''))):
        raise ValueError('invalid PostgreSQL backup manifest')
    filename = manifest.get('backup_file', '')
    if not isinstance(filename, str) or not re.fullmatch(r'[A-Za-z0-9_-]+\.pgdump', filename):
        raise ValueError('invalid backup filename')
    backup = manifest_path.parent / filename
    if backup.is_symlink() or not backup.is_file():
        raise ValueError('backup must be a regular file')
    created = datetime.fromisoformat(manifest['created_at'])
    if created.tzinfo is None or created.utcoffset() is None:
        raise ValueError('backup timestamp must include timezone')
    timestamp = created.timestamp()
    age = time.time() - timestamp
    if age < -300 or age > max_age:
        raise ValueError('backup timestamp is in the future or backup is stale')
    if digest(backup) != manifest.get('archive_sha256'):
        raise ValueError('backup archive checksum mismatch')
    tables = manifest.get('tables')
    if (not isinstance(tables, list) or not tables
            or any(not isinstance(table, str) or len(table.split('.')) != 2
                   or not all(IDENTIFIER.fullmatch(part) for part in table.split('.')) for table in tables)
            or tables != sorted(set(tables))):
        raise ValueError('invalid qualified table inventory')
    with backup.open('rb') as stream:
        if stream.read(5) != b'PGDMP':
            raise ValueError('backup is not a PostgreSQL archive')
    if not isolated_restore and archive_inventory(backup, reader or ['pg_restore'], null_device=null_device) != tables:
        raise ValueError('archive table inventory mismatch')
    return manifest, backup, timestamp


def docker(args: list[str], *, input_file: Path | None = None, input_bytes: bytes | None = None) -> bytes:
    if input_file is not None:
        with input_file.open('rb') as stream:
            result = subprocess.run(['docker', *args], stdin=stream, capture_output=True, timeout=900)
    else:
        result = subprocess.run(['docker', *args], input=input_bytes, capture_output=True, timeout=900)
    if result.returncode:
        raise RuntimeError('PostgreSQL backup Docker operation failed')
    return result.stdout


TABLE_QUERY = "SELECT n.nspname||'.'||c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p') AND left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema' ORDER BY n.nspname,c.relname"


def restore_isolated(manifest: dict, backup: Path, image: str, *,
                     inspect_restored: Callable[[str, str], None] | None = None) -> dict:
    if not image or image.startswith('-') or any(char.isspace() for char in image):
        raise ValueError('invalid restore image')
    docker(['image', 'inspect', image])  # no implicit pull
    name = 'agentplug-backup-restore-' + secrets.token_hex(12)
    database = 'agentplug_restore'
    report = {'isolated_restore': 'PASS', 'table_count': len(manifest['tables']),
              'temporary_container_removed': False, 'temporary_credentials_removed': False}
    with tempfile.TemporaryDirectory(prefix='agentplug-pgrestore-') as credentials:
        environment = Path(credentials) / 'postgres.env'
        environment.write_text('POSTGRES_PASSWORD=' + secrets.token_hex(32) + '\nPOSTGRES_DB=' + database + '\n', encoding='utf-8')
        environment.chmod(0o600)
        try:
            docker(['run', '-d', '--network', 'none', '--name', name, '--label', 'agentplug.backup.owner=' + name,
                    '--tmpfs', '/var/lib/postgresql/data:rw,size=1g', '--env-file', str(environment), image])
            for _ in range(120):
                try:
                    docker(['exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres', '-d', database])
                    break
                except RuntimeError:
                    time.sleep(0.5)
            else:
                raise RuntimeError('isolated PostgreSQL restore readiness timed out')
            reader = ['docker', 'exec', '--interactive', '--user', 'postgres', name, 'pg_restore']
            if archive_inventory(backup, reader, null_device='/dev/null') != manifest['tables']:
                raise ValueError('archive table inventory mismatch')
            docker(['exec', '--interactive', '--user', 'postgres', name, 'pg_restore', '--dbname', database,
                    '--no-owner', '--no-acl', '--exit-on-error', '--single-transaction'], input_file=backup)
            tables = docker(['exec', '--user', 'postgres', name, 'psql', '-X', '-t', '-A', '-v', 'ON_ERROR_STOP=1',
                             '-d', database, '-c', TABLE_QUERY]).decode('utf-8').splitlines()
            if tables != manifest['tables']:
                raise RuntimeError('isolated restore table inventory mismatch')
            if inspect_restored is not None:
                inspect_restored(name, database)
        finally:
            result = subprocess.run(['docker', 'inspect', name], capture_output=True, timeout=30)
            if result.returncode == 0:
                container = json.loads(result.stdout)[0]
                if (container.get('Config', {}).get('Labels') or {}).get('agentplug.backup.owner') != name:
                    raise RuntimeError('restore container ownership mismatch; refusing cleanup')
                docker(['rm', '--force', '--volumes', name])
            elif b'No such object' not in result.stderr and b'No such container' not in result.stderr:
                raise RuntimeError('Docker unavailable; restore cleanup cannot be verified')
            remaining = docker(['ps', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}'])
            if remaining.strip():
                raise RuntimeError('restore container cleanup failed')
            report['temporary_container_removed'] = True
    report['temporary_credentials_removed'] = not Path(credentials).exists()
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    export = actions.add_parser('backup')
    export.add_argument('--output-dir', type=Path, required=True)
    export.add_argument('--database', required=True)
    export.add_argument('--host', default='127.0.0.1')
    export.add_argument('--port', type=int, default=5432)
    export.add_argument('--user', required=True)
    export.add_argument('--password-file', type=Path)
    export.add_argument('--ssl-ca', type=Path)
    export.add_argument('--docker-source')
    export.add_argument('--metrics-file', type=Path)
    check = actions.add_parser('check')
    locations = check.add_mutually_exclusive_group(required=True)
    locations.add_argument('--manifest', type=Path)
    locations.add_argument('--output-dir', type=Path)
    check.add_argument('--max-age-seconds', type=int, default=86400)
    check.add_argument('--reader-container', help='existing trusted PostgreSQL container with pg_restore; no database access')
    check.add_argument('--restore-image', help='locally cached PostgreSQL + pgvector image; network-less temporary restore only')
    check.add_argument('--metrics-file', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.metrics_file is not None:
            if args.metrics_file.suffix != '.prom':
                args.metrics_file = None
                raise ValueError('metrics output must have .prom extension')
            protected = [getattr(args, name, None) for name in ('password_file', 'ssl_ca', 'manifest')]
            if any(path is not None and args.metrics_file.resolve() == path.resolve() for path in protected):
                args.metrics_file = None
                raise ValueError('metrics output cannot overwrite a credential or manifest')
        if args.action == 'backup':
            if (not IDENTIFIER.fullmatch(args.database) or not IDENTIFIER.fullmatch(args.user)
                    or not 1 <= args.port <= 65535 or not args.host.strip() or '\x00' in args.host):
                raise ValueError('invalid PostgreSQL connection target')
            if args.password_file and (args.password_file.is_symlink() or not args.password_file.is_file()
                                       or (os.name != 'nt' and args.password_file.stat().st_mode & 0o077)):
                raise ValueError('password file must be regular and private to its owner')
            password = args.password_file.read_text(encoding='utf-8').rstrip('\r\n') if args.password_file else os.getenv('AGENTPLUG_BACKUP_POSTGRES_PASSWORD', '')
            if not password or any(char in password for char in '\x00\r\n'):
                raise ValueError('backup password is missing or invalid')
            options = ['--format=custom', '--compress=6', '--no-acl', '--no-tablespaces', '--no-password',
                       '--lock-wait-timeout=10s', '--host', args.host, '--port', str(args.port), '--username', args.user,
                       '--dbname', args.database]
            if args.docker_source:
                if args.host != '127.0.0.1' or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', args.docker_source):
                    raise ValueError('Docker source must use container loopback')
                command = ['docker', 'exec', '--interactive', args.docker_source, 'sh', '-c',
                           'IFS= read -r PGPASSWORD; export PGPASSWORD; PGSSLMODE=disable; export PGSSLMODE; PGCONNECT_TIMEOUT=15; export PGCONNECT_TIMEOUT; exec pg_dump "$@"', 'backup', *options]
                reader = ['docker', 'exec', '--interactive', args.docker_source, 'pg_restore']
            else:
                if args.ssl_ca is None or not args.ssl_ca.is_file():
                    raise ValueError('native PostgreSQL backup requires a trusted CA file')
                command, reader = ['pg_dump', *options], ['pg_restore']
            manifest_path = write_backup(command, args.output_dir, args.database, password, docker_source=bool(args.docker_source), reader=reader, ssl_ca=args.ssl_ca)
            _, _, timestamp = verify(manifest_path, 86400, reader, null_device='/dev/null' if args.docker_source else os.devnull)
            metrics(args.metrics_file, True, timestamp, 'backup')
            print(json.dumps({'backup': 'PASS', 'manifest': str(manifest_path)}))
        else:
            if args.max_age_seconds < 1:
                raise ValueError('maximum backup age must be positive')
            if args.reader_container and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', args.reader_container):
                raise ValueError('invalid archive reader container')
            manifest_path = args.manifest
            if manifest_path is None:
                candidates = list(args.output_dir.glob('*.manifest.json'))
                if not candidates:
                    raise ValueError('no completed backup manifests')
                manifest_path = max(candidates, key=lambda path: path.stat().st_mtime_ns)
            reader = ['docker', 'exec', '--interactive', args.reader_container, 'pg_restore'] if args.reader_container else ['pg_restore']
            manifest, backup, timestamp = verify(manifest_path, args.max_age_seconds, reader,
                                                 isolated_restore=bool(args.restore_image), null_device='/dev/null' if args.reader_container else os.devnull)
            if args.restore_image:
                print(json.dumps(restore_isolated(manifest, backup, args.restore_image)))
            metrics(args.metrics_file, True, timestamp)
            print(json.dumps({'check': 'PASS', 'table_count': len(manifest['tables'])}))
        return 0
    except Exception as error:
        try:
            metrics(args.metrics_file, False, 0, args.action)
        except OSError:
            pass
        # Only emit allowlisted failure categories, never a client exception,
        # source DSN, command, password, row value or private-file content.
        codes = {
            'pg_dump failed; no completed backup was published': 'dump_failed',
            'backup is not a PostgreSQL custom archive': 'archive_header',
            'PostgreSQL archive inventory validation failed': 'archive_inventory',
            'unsupported table identifier in archive': 'archive_identifiers',
            'backup must have a nonempty, unique base-table inventory': 'archive_tables',
            'PostgreSQL archive data validation failed': 'archive_data',
        }
        code = codes.get(str(error), 'configuration_or_integrity')
        print('backup/check failed (' + code + '); inspect private configuration, storage, credentials and archive integrity', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())


