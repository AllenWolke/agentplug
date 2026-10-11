"""Exercise real Compose interpolation under CI and operator shell exports."""
from contextlib import contextmanager
import http.server
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import threading
import urllib.request

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('isolated_public_compose', ROOT / 'tests/e2e/public_project_e2e.py')
E2E = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(E2E)


@pytest.mark.parametrize('scenario', ['reported-compose-job', 'modular-cutover-job', 'operator-shell'])
def test_real_compose_keeps_generated_ports_and_credentials(tmp_path, monkeypatch, scenario):
    exports = {'DB_PASSWORD': 'ci-modular-db-pass'}
    if scenario == 'reported-compose-job':
        exports.update(DB_PASSWORD='ci-platform-db-pass', FRONTEND_HOST_PORT='13000',
                       API_KEY='ci-platform-api-key', COMPOSE_PROJECT_NAME='lexagent-ci-fixture')
    elif scenario == 'operator-shell':
        exports.update(
            APP_ENV='production', FRONTEND_HOST_PORT='13000', PLATFORM_HOST_PORT='13001',
            FRONTEND_HOST_BIND='0.0.0.0', PLATFORM_HOST_BIND='0.0.0.0',
            PLATFORM_DB_DSN='postgresql://operator-only@operator.invalid/private',
            PLATFORM_MIGRATION_DB_DSN='postgresql://operator-only@operator.invalid/private',
            PLATFORM_DEV_RUNTIME_PASSWORD='operator-only',
            PLATFORM_MODEL_SECRET_DIR='/operator-only', PLATFORM_WORKLOAD_SECRET_DIR='/operator-only',
            PLATFORM_MCP_BINDINGS_DIR='/operator-only', FRONTEND_AUTH_MODE='oidc_proxy',
            COOKIE_SECURE='true', PLATFORM_DEMO_IDENTITY_BOOTSTRAP='true',
            BROWSER_GATEWAY_TOKEN='operator-only', INTERNAL_TOKEN='operator-only',
            COMPOSE_FILE='/operator-only.yaml', COMPOSE_PROFILES='full',
            COMPOSE_ENV_FILES='/operator-only.env', COMPOSE_PROJECT_NAME='operator-only',
        )
    for key, value in exports.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv('UNRELATED_FIXTURE', 'kept')
    snapshot = os.environ.copy()
    settings = {key: secrets.token_hex(32) for key in (
        'DB_PASSWORD', 'PLATFORM_RUNTIME_DB_PASSWORD', 'INTERNAL_TOKEN', 'BROWSER_GATEWAY_TOKEN',
        'INTERNAL_SIGNING_SECRET', 'METRIC_RUNNER_TOKEN', 'ACCESS_TOKEN_SIGNING_KEY')}
    secret_directory = tmp_path / 'empty-secrets'
    secret_directory.mkdir()
    settings.update(
        APP_ENV='development', PLATFORM_CONTEXT_PUBLIC_KEY='parser-only-fixture',
        PLATFORM_DEMO_IDENTITY_BOOTSTRAP='false', FRONTEND_AUTH_MODE='local', COOKIE_SECURE='false',
        PLATFORM_MODEL_SECRET_DIR=secret_directory.as_posix(), PLATFORM_WORKLOAD_SECRET_DIR=secret_directory.as_posix(),
        POSTGRES_HOST_PORT='23000', FRONTEND_HOST_PORT='23001', PLATFORM_HOST_PORT='23002',
        PLATFORM_INTERNAL_HOST_PORT='23003', FRONTEND_HOST_BIND='127.0.0.1', PLATFORM_HOST_BIND='127.0.0.1')
    private = tmp_path / 'private.env'
    private.write_text(''.join(f'{key}={value}\n' for key, value in settings.items()), encoding='utf-8')
    private.chmod(0o600)
    environment = E2E.isolated_compose_environment(settings)
    assert os.environ == snapshot, 'creating a test environment must not mutate the operator shell'
    assert environment['UNRELATED_FIXTURE'] == 'kept'
    for key in ('PATH', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'HTTP_PROXY', 'HTTPS_PROXY'):
        if key in snapshot:
            assert environment[key] == snapshot[key]
    result = subprocess.run([
        'docker', 'compose', '--project-name', 'agentplug-test-clean-012345abcdef',
        '--env-file', str(private), '-f', str(ROOT / 'compose.yaml'),
        '-f', str(ROOT / 'deploy/compose/compose.init.yaml'), '--profile', 'modular',
        '--profile', 'init', 'config', '--format', 'json',
    ], env=environment, capture_output=True, timeout=30)
    assert result.returncode == 0, 'real Compose configuration failed; secret-bearing output withheld'
    configuration = json.loads(result.stdout)
    E2E.verify_published_endpoints(configuration, settings)
    assert configuration['name'] == 'agentplug-test-clean-012345abcdef'
    services = configuration['services']
    for name in ('platform-app', 'platform-migrate'):
        assert services[name]['environment']['APP_ENV'] == 'development'
        assert 'operator-only' not in services[name]['environment']['DB_DSN']
    assert settings['PLATFORM_RUNTIME_DB_PASSWORD'] in services['platform-app']['environment']['DB_DSN']
    assert settings['DB_PASSWORD'] in services['platform-migrate']['environment']['DB_DSN']
    assert services['platform-migrate']['environment']['PLATFORM_DEV_RUNTIME_PASSWORD'] == settings['PLATFORM_RUNTIME_DB_PASSWORD']
    assert services['frontend']['environment']['FRONTEND_AUTH_MODE'] == 'local'
    assert str(services['frontend']['environment']['COOKIE_SECURE']).lower() == 'false'
    assert services['frontend']['environment']['PLATFORM_GATEWAY_TOKEN'] == settings['BROWSER_GATEWAY_TOKEN']
    assert all(volume['source'] != '/operator-only' for volume in services['platform-app']['volumes'])


def test_port_mismatch_is_refused_before_credentials_are_sent():
    configuration = {'services': {'frontend': {'ports': [{'target': 80, 'host_ip': '127.0.0.1', 'published': '13000'}]}}}
    with pytest.raises(RuntimeError, match='published port mismatch: frontend/FRONTEND_HOST_PORT'):
        E2E.verify_published_endpoints(configuration, {'FRONTEND_HOST_PORT': '23001'})


@contextmanager
def health_server(statuses):
    calls = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(self.path)
            self.send_response(statuses[min(len(calls)-1, len(statuses)-1)])
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
    thread.start()
    try:
        yield 'http://127.0.0.1:' + str(server.server_port) + '/healthz', calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_host_readiness_accepts_recovery_and_checks_only_health():
    with health_server([503, 200]) as (address, calls):
        E2E.wait_http_ready(urllib.request.build_opener(urllib.request.ProxyHandler({})), address, timeout=2)
    assert calls == ['/healthz', '/healthz']


@pytest.mark.parametrize('condition', ['unhealthy', 'unreachable'])
def test_host_readiness_does_not_silently_accept_failed_services(condition):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    if condition == 'unhealthy':
        with health_server([503]) as (address, calls):
            with pytest.raises(RuntimeError, match='host HTTP readiness failed:.*503'):
                E2E.wait_http_ready(opener, address, timeout=0.08)
        assert calls
    else:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            address = 'http://127.0.0.1:' + str(sock.getsockname()[1]) + '/healthz'
            with pytest.raises(RuntimeError, match='host HTTP readiness failed:'):
                E2E.wait_http_ready(opener, address, timeout=0.08)


def test_failure_receipt_redacts_credentials_but_retains_endpoint_and_stage_details():
    secret = secrets.token_hex(32)
    message = 'frontend 127.0.0.1:23001 refused; password=' + secret
    redacted = E2E.redact_diagnostic(message, {'DB_PASSWORD': secret, 'FRONTEND_HOST_PORT': '23001'}, secret)
    assert secret not in redacted
    assert '127.0.0.1:23001 refused' in redacted


def test_both_workflow_jobs_preserve_the_owned_receipt_without_default_project_cleanup():
    workflow = yaml.load((ROOT / '.github/workflows/three-project-quality.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    artifacts = []
    for name in ('compose-e2e', 'modular-cutover'):
        job = workflow['jobs'][name]
        assert 'FRONTEND_HOST_PORT' not in job.get('env', {})
        assert 'COMPOSE_PROJECT_NAME' not in job.get('env', {})
        assert not any('docker compose' in step.get('run', '') and 'down' in step['run'] for step in job['steps'])
        artifact = next(step for step in job['steps'] if step.get('uses') == 'actions/upload-artifact@v6')
        assert artifact['if'] == 'always()'
        assert artifact['with']['if-no-files-found'] == 'error'
        assert artifact['with']['path'].endswith('T3-11-干净PostgreSQL与五账号初始化实际验收.json')
        artifacts.append(artifact['with']['name'])
    assert len(set(artifacts)) == 2
