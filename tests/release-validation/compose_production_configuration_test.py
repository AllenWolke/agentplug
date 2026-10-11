"""Render production inputs with the real Compose client, without starting services."""

import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def test_compose_preserves_separate_database_roles_oidc_and_loopback_ports(tmp_path):
    docker = shutil.which('docker')
    assert docker, 'Docker Compose is required for supported Docker installation validation'
    password = secrets.token_hex(32)
    settings = {
        'APP_ENV': 'production', 'DB_PASSWORD': password,
        'PLATFORM_RUNTIME_DB_PASSWORD': secrets.token_hex(32),
        'INTERNAL_TOKEN': secrets.token_hex(32), 'INTERNAL_SIGNING_SECRET': secrets.token_hex(32),
        'BROWSER_GATEWAY_TOKEN': secrets.token_hex(32),
        'PLATFORM_CONTEXT_PUBLIC_KEY': 'parser-only-not-a-runtime-key',
        'PLATFORM_CONTEXT_PRIVATE_KEY': 'parser-only-not-a-runtime-key',
        'PLATFORM_DEV_RUNTIME_PASSWORD': '', 'PLATFORM_DEMO_IDENTITY_BOOTSTRAP': 'false',
        'PLATFORM_POLICY_RESOLVER': 'sql',
        'PLATFORM_DB_DSN': f'postgresql://platform_dml:{password}@postgres:5432/agentplug?sslmode=verify-full',
        'PLATFORM_MIGRATION_DB_DSN': f'postgresql://schema_owner:{password}@postgres:5432/agentplug?sslmode=verify-full',
        'FRONTEND_AUTH_MODE': 'oidc', 'OIDC_PROXY_TRUSTED': 'true', 'COOKIE_SECURE': 'true',
        'OIDC_PROXY_AUTH_URL': 'http://oidc-proxy:4180/oauth2/auth',
        'OIDC_ISSUER_URL': 'https://idp.fixture.internal/realm',
        'OIDC_STEP_UP_CLIENT_ID': 'fixture-client',
        'OIDC_STEP_UP_CLIENT_SECRET': secrets.token_hex(32),
        'OIDC_STEP_UP_REDIRECT_URL': 'https://console.fixture.internal/auth/step-up/oidc/callback',
    }
    private = tmp_path / 'private.env'
    private.write_text(''.join(f'{key}={value}\n' for key, value in settings.items()), encoding='utf-8')
    private.chmod(0o600)
    approved = tmp_path / 'approved-images.yaml'
    images = {'platform-app': 'platform', 'platform-migrate': 'platform', 'frontend': 'frontend',
              'metric-runner': 'runner', 'postgres': 'postgres'}
    approved.write_text('services:\n' + ''.join(
        f'  {service}:\n    build: !reset null\n    image: ghcr.io/fixture/{image}@sha256:{"1" * 64}\n'
        for service, image in images.items()), encoding='utf-8')
    env = {key: value for key, value in os.environ.items() if key not in settings and not key.endswith(('_HOST_BIND', '_HOST_PORT'))}
    result = subprocess.run([docker, 'compose', '--env-file', str(private), '--profile', 'modular', '--profile', 'init',
                             '-f', str(ROOT / 'compose.yaml'), '-f', str(ROOT / 'deploy/compose/compose.init.yaml'), '-f', str(approved), 'config', '--format', 'json'],
                            cwd=tmp_path, env=env, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
    assert result.returncode == 0, 'Compose production configuration render failed; raw credential-bearing output withheld'
    services = json.loads(result.stdout)['services']
    assert services['kafka']['restart'] == 'unless-stopped'
    assert services['platform-app']['environment']['EVENT_BUS_MODE'] == 'kafka'
    assert services['platform-app']['environment']['PLATFORM_NOTIFICATION_ADAPTER'] == 'audit'
    assert services['platform-app']['depends_on']['kafka']['condition'] == 'service_healthy'
    assert 'kafka-topic-bootstrap' not in services['platform-app']['depends_on']
    assert services['platform-migrate']['restart'] == 'no'
    assert services['kafka-topic-bootstrap']['restart'] == 'no'
    for service, image in images.items():
        assert 'build' not in services[service]
        assert services[service]['image'] == f'ghcr.io/fixture/{image}@sha256:{"1" * 64}'
    assert 'mysql' not in services
    for service in ('platform-app', 'platform-migrate'):
        assert services[service]['environment']['DB_DRIVER'] == 'pgx'
    assert services['postgres']['environment']['POSTGRES_DB'] == 'agentplug'
    assert all(port['host_ip'] == '127.0.0.1' for port in services['postgres']['ports'])
    for service, setting in (('platform-app', 'PLATFORM_DB_DSN'), ('platform-migrate', 'PLATFORM_MIGRATION_DB_DSN')):
        assert services[service]['environment']['DB_DSN'] == settings[setting]
    assert services['platform-migrate']['environment']['PLATFORM_DEV_RUNTIME_PASSWORD'] == ''
    for key in ('OIDC_PROXY_AUTH_URL', 'OIDC_ISSUER_URL', 'FRONTEND_AUTH_MODE', 'COOKIE_SECURE', 'OIDC_STEP_UP_CLIENT_ID', 'OIDC_STEP_UP_CLIENT_SECRET', 'OIDC_STEP_UP_REDIRECT_URL'):
        assert str(services['frontend']['environment'][key]).lower() == settings[key]
    assert services['frontend']['environment']['PLATFORM_GATEWAY_TOKEN'] == settings['BROWSER_GATEWAY_TOKEN']
    assert services['platform-app']['environment']['BROWSER_GATEWAY_TOKEN'] == settings['BROWSER_GATEWAY_TOKEN']
    assert settings['BROWSER_GATEWAY_TOKEN'] != settings['INTERNAL_TOKEN']
    for service in ('platform-app', 'frontend'):
        assert all(port['host_ip'] == '127.0.0.1' for port in services[service]['ports'])
