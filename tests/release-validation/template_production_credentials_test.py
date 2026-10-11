"""Generated Python Agents must retain production credential rejection."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("template", ["python-generic", "python-langgraph"])
@pytest.mark.parametrize("environment", ["production", "prod"])
def test_template_sdk_rejects_weak_production_credentials(
    template, environment, tmp_path
):
    package_root = ROOT / "templates" / template / "platform_entry"
    environment_values = os.environ.copy()
    environment_values.update(APP_ENV=environment, PYTHONPATH=str(package_root))
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
from agent_platform_sdk.security import internal_token, internal_signing_secret
for resolver in (internal_token, internal_signing_secret):
    for value in ('short', 'x' * 32, '密' * 11, 'changeme-' + '0123456789abcdef' * 3, 'replace-' + '0123456789abcdef' * 3):
        try:
            resolver(value)
        except RuntimeError as error:
            assert value not in str(error)
        else:
            raise AssertionError('template accepted weak production credential')
    strong = 'test-0123456789abcdef0123456789abcdef'
    assert resolver(strong) == strong
""",
        ],
        cwd=tmp_path,
        env=environment_values,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('template', ['python-generic', 'python-langgraph'])
def test_template_checkpoint_rejects_root_and_runtime_schema_setup(template, tmp_path):
    environment_values = os.environ.copy()
    environment_values.update(APP_ENV='production', PYTHONPATH=str(ROOT / 'templates' / template / 'platform_entry'))
    result = subprocess.run([sys.executable, '-c', '''
import asyncio, os
from agent_platform_sdk.checkpoint import PostgresCheckpointProvider
async def verify():
    for dsn, setup in [('postgres://postgres:some-valid-length-password@localhost/db', 'false'),
                       ('postgres://runtime:some-valid-length-password@localhost/db', 'true')]:
        os.environ['CHECKPOINT_SETUP'] = setup
        provider = PostgresCheckpointProvider(dsn)
        async def forbidden(**kwargs):
            raise AssertionError('template reached connection with unsafe runtime configuration')
        provider._connect = forbidden
        try:
            await provider.get()
        except RuntimeError as error:
            assert dsn not in str(error)
        else:
            raise AssertionError('template accepted unsafe checkpoint configuration')
asyncio.run(verify())
'''], cwd=tmp_path, env=environment_values, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
