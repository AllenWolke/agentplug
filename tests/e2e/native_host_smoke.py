"""Exercise host applications against an owned, disposable Docker PostgreSQL dependency.

Application processes run on the host. This test does not certify Linux sandbox
or a production IdP/TLS environment. Requires local.py build and Agent dependencies.
"""
from __future__ import annotations

import base64
import importlib.util
import http.cookiejar
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.request import Request, build_opener, ProxyHandler, HTTPCookieProcessor
from urllib.error import HTTPError
from urllib.parse import quote

# Owned loopback probes must not traverse workstation HTTP proxies.
urlopen = build_opener(ProxyHandler({})).open

import psycopg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("native", ROOT / "scripts/local.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main() -> int:
    run_id = uuid.uuid4().hex[:12]
    temporary = ROOT / ".tmp" / f"native-host-{run_id}"
    temporary.mkdir(parents=True, mode=0o700)
    container = f"agentplug-native-test-{run_id}"
    processes, files, results = [], [], []
    owned = False
    report = {"application_mode": "host processes", "database_mode": "disposable Docker PostgreSQL16 + pgvector", "checks": results}
    process_identity = {}
    if sys.platform == "linux" and os.geteuid() == 0:
        process_identity = {"user": 65534, "group": 65534, "extra_groups": []}
    report["service_uid"] = process_identity.get("user", os.getuid() if hasattr(os, "getuid") else "Windows user")
    root_password, runtime_password = secrets.token_urlsafe(32) + "@:%", secrets.token_urlsafe(32)
    internal, signing, runner_token, login_password, gateway_token, access_signing = [secrets.token_urlsafe(32) for _ in range(6)]
    db_port, public_port, internal_port, runner_port, frontend_port = [free_port() for _ in range(5)]
    key = Ed25519PrivateKey.generate()
    private = base64.b64encode(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())).decode()
    public = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    substitutions = {"replace-runtime-password": runtime_password, "replace-schema-password": root_password,
                     "replace-internal-token": internal, "replace-with-independent-random-gateway-token": gateway_token, "replace-signing-secret": signing,
                     "replace-runner-token": runner_token, "replace-demo-password": login_password,
                     "replace-ed25519-public-key": public, "replace-ed25519-private-key": private}

    def settings(service):
        text = (ROOT / "deploy/local" / f"{service}.env.example").read_text(encoding="utf-8")
        for original, value in substitutions.items():
            if service == "checkpoint-init" and original == "replace-schema-password":
                value = quote(value, safe="")
            text = text.replace(original, value)
        # URLs use percent-encoded credentials; never shell-expand private values.
        if service in {'migration', 'platform'}:
            user = 'postgres' if service == 'migration' else 'platform_runtime'
            password = root_password if service == 'migration' else runtime_password
            dsn = f'postgresql://{user}:{quote(password, safe="")}@127.0.0.1:{db_port}/agentplug?sslmode=disable'
            text = '\n'.join('DB_DSN=' + dsn if line.startswith('DB_DSN=') else line for line in text.splitlines()) + '\n' 
        if service == 'frontend':
            text = text.replace('ACCESS_TOKEN_SIGNING_KEY=\n', 'ACCESS_TOKEN_SIGNING_KEY=' + access_signing + '\n')
        for original, replacement in [(5432, db_port), (8080, public_port), (8081, internal_port), (8085, runner_port), (33000, frontend_port)]:
            text = text.replace(f"127.0.0.1:{original}", f"127.0.0.1:{replacement}")
        path = temporary / f"{service}.env"
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)
        return native.load_settings(path), path

    def wait_http(name, url, process):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"{name} exited before readiness")
            try:
                with urlopen(url, timeout=2) as response:
                    if response.status == 200:
                        results.append(name + " readiness PASS")
                        print(results[-1], flush=True)
                        return
            except OSError:
                pass
            time.sleep(0.5)
        raise RuntimeError(f"{name} readiness timeout")

    try:
        docker_env = temporary / "postgres.env"
        docker_env.write_text(f"POSTGRES_PASSWORD={root_password}\nPOSTGRES_DB=agentplug\n", encoding="utf-8")
        docker_env.chmod(0o600)
        subprocess.run(["docker", "run", "-d", "--name", container, "--label", f"agentplug.test.owner={container}", "--tmpfs", "/var/lib/postgresql/data:rw,size=512m", "--env-file", str(docker_env),
                        "-p", f"127.0.0.1:{db_port}:5432", "pgvector/pgvector:pg16"], check=True, capture_output=True, timeout=60)
        owned = True
        deadline = time.monotonic() + 90
        while True:
            try:
                connection = psycopg.connect(host="127.0.0.1", port=db_port, user="postgres", password=root_password, dbname="agentplug", connect_timeout=2)
                connection.close()
                break
            except psycopg.Error:
                if time.monotonic() >= deadline:
                    raise RuntimeError("isolated PostgreSQL timeout")
                time.sleep(1)
        for service in ["migrate"]:
            values, config = settings("migration" if service == "migrate" else service)
            log = open(temporary / f"{service}.log", "wb")
            files.append(log)
            subprocess.run([sys.executable, "scripts/local.py", "run", service, "--env-file", str(config)],
                           cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=120)
            results.append(service + " PASS")
            print(results[-1], flush=True)
        platform_values, _ = settings('platform')
        configuration = {
            'version': 1, 'db_dsn': platform_values['DB_DSN'],
            'tenant_id': 'tenant-native', 'tenant_name': 'Native smoke company',
            'department_id': 'dept-native', 'department_name': 'Native smoke department',
            'application_id': 'app-native', 'application_name': 'Native smoke application',
            'principal_id': 'system.admin', 'operator_id': 'native.acceptance.operator',
            'approval_reference': 'isolated-native-smoke', 'local_password': login_password,
        }
        bootstrap_config = temporary / 'first-administrator.json'
        bootstrap_config.write_text(json.dumps(configuration), encoding='utf-8')
        bootstrap_config.chmod(0o600)
        bootstrap_command = [sys.executable, 'scripts/local.py', 'bootstrap-admin', '--config', str(bootstrap_config)]
        with (temporary / 'bootstrap.log').open('wb') as output:
            subprocess.run(bootstrap_command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, check=True, timeout=60)
        repeat = subprocess.run(bootstrap_command, cwd=ROOT, capture_output=True, timeout=60)
        if repeat.returncode == 0:
            raise RuntimeError('first-administrator initialization replaced an existing identity')
        results.append('documented first administrator bootstrap and reinitialization denial PASS')
        print(results[-1], flush=True)
        for service, port, health in [("runner", runner_port, "/readyz"), ("platform", public_port, "/health/ready"),
                                      ("frontend", frontend_port, "/healthz")]:
            values, _ = settings(service)
            arguments, cwd = native.command(service, sys.executable, values)
            log = open(temporary / f"{service}.log", "wb")
            files.append(log)
            process = subprocess.Popen(arguments, cwd=cwd, env=native.environment(service, values), stdout=log, stderr=subprocess.STDOUT, **process_identity)
            processes.append(process)
            wait_http(service, f"http://127.0.0.1:{port}{health}", process)
        with urlopen(f"http://127.0.0.1:{frontend_port}/", timeout=5) as response:
            assert b"<html" in response.read().lower()
        address = f'http://127.0.0.1:{frontend_port}'
        cookies = http.cookiejar.CookieJar()
        client = build_opener(ProxyHandler({}), HTTPCookieProcessor(cookies))

        def call(method, path, body=None):
            request = Request(address + path, method=method,
                              data=json.dumps(body).encode() if body is not None else None,
                              headers={'Content-Type': 'application/json', 'Origin': address})
            with client.open(request, timeout=10) as response:
                assert response.status == 200
                return json.load(response)

        call('POST', '/auth/login', {'username': 'system.admin', 'password': login_password})
        assert any(cookie.name == 'lexagent_session' for cookie in cookies)
        call('GET', '/auth/me')
        call('POST', '/auth/refresh', {})
        call('GET', '/api/modules/identity/principals')
        previous_cookie = '; '.join(cookie.name + '=' + cookie.value for cookie in cookies)
        call('POST', '/auth/logout', {})
        try:
            call('GET', '/auth/me')
        except HTTPError as error:
            if error.code != 401:
                raise
        else:
            raise RuntimeError('logged-out native session was accepted')
        try:
            # Replay the old credential rather than merely checking an empty
            # browser cookie jar, which would not prove server-side revocation.
            urlopen(Request(address + '/auth/me', headers={'Cookie': previous_cookie}), timeout=10)
        except HTTPError as error:
            if error.code != 401:
                raise
        else:
            raise RuntimeError('revoked native session credential was accepted')
        results.append('frontend static page, local login, authenticated management, refresh and logout revocation PASS')
        print(results[-1], flush=True)
        report["status"] = "PASS"
    except Exception as error:
        report["status"] = "FAIL"
        report["error_type"] = type(error).__name__
        if isinstance(error, HTTPError):
            report['http_status'] = error.code
            print('HTTP request failed with status ' + str(error.code), flush=True)
        if owned:
            try:
                with psycopg.connect(host="127.0.0.1", port=db_port, user="postgres", password=root_password, dbname="agentplug", connect_timeout=2) as db:
                    with db.cursor() as cursor:
                        cursor.execute("SELECT event_type, payload->>'code' FROM platform_execution_event ORDER BY seq DESC LIMIT 6")
                        print(str(cursor.fetchall()), flush=True)
            except psycopg.Error:
                pass
        # Output only redacted local diagnostics; never publish private config.
        for log_path in temporary.glob("*.log"):
            diagnostic = log_path.read_text(encoding="utf-8", errors="replace")[-5000:]
            for secret in [root_password, runtime_password, internal, signing, runner_token, login_password, gateway_token, access_signing, private, public]:
                diagnostic = diagnostic.replace(secret, "[REDACTED]").replace(quote(secret, safe=""), "[REDACTED]")
            print(log_path.name + "\n" + diagnostic, flush=True)
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for log in files:
            log.close()
        if owned:
            inspect = subprocess.run(['docker', 'inspect', container], check=True, capture_output=True, timeout=20)
            labels = json.loads(inspect.stdout)[0]['Config']['Labels'] or {}
            if labels.get('agentplug.test.owner') != container:
                raise RuntimeError('refusing to remove a database without the fixture ownership label')
            subprocess.run(["docker", "rm", "-f", "-v", container], check=True, capture_output=True, timeout=30)
            remaining = subprocess.run(["docker", "ps", "-a", "--filter", f"name=^{container}$", "--format", "{{.Names}}"], check=True, capture_output=True, text=True, timeout=20)
            assert not remaining.stdout.strip(), "test database cleanup incomplete"
        assert temporary.resolve().parent == (ROOT / ".tmp").resolve()
        shutil.rmtree(temporary)
        report["cleanup"] = "host processes, owned PostgreSQL container/tmpfs and private temporary files removed"
        report["limits"] = f"{sys.platform} host validation; Docker used only for test PostgreSQL; no real model/IdP/TLS or separate sandbox certification"
        filename = "native-linux-host-smoke-20260930.json" if sys.platform == "linux" else "native-host-smoke-20260930.json"
        output = ROOT / "artifacts/production-review" / filename
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("NATIVE HOST SMOKE " + report["status"], flush=True)
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
