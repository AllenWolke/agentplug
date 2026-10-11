"""CI must execute its gates under the same security and startup contracts."""
import ast
from pathlib import Path
import re
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_metric_race_gate_executes_all_packages_with_enforced_limits():
    workflow = yaml.load((ROOT / '.github/workflows/three-project-quality.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    steps = workflow['jobs']['platform-go']['steps']
    host = next(step for step in steps if step.get('run') == 'go test -race ./...')
    bounded = next(step for step in steps if 'go test -race -count=1 ./...' in step.get('run', ''))
    assert host['if'] == "matrix.module != 'workers/metric-runner'"
    assert bounded['if'] == "matrix.module == 'workers/metric-runner'"
    assert bounded['working-directory'] == '.'
    assert all(fragment in bounded['run'] for fragment in ('--memory 512m', '--pids-limit 128', '--user 65532:65532', 'target=/workspace,readonly', '/workspace/workers/metric-runner'))
    assert bounded.get('continue-on-error', 'false') == 'false'


@pytest.fixture
def verifier_functions():
    source = ast.parse((ROOT / 'scripts/verify_public_knowledge_postgres.py').read_text(encoding='utf-8'))
    functions = [node for node in source.body if isinstance(node, ast.FunctionDef) and node.name in {'run', 'safe_event_value'}]
    namespace = {'subprocess': subprocess, 're': re, 'Path': Path, 'receipt': {}, 'password': 'owned-db-secret', 'runtime_password': 'owned-runtime-secret'}
    exec(compile(ast.Module(body=functions, type_ignores=[]), '<verifier helpers>', 'exec'), namespace)
    return namespace


def test_fixture_setup_failure_is_diagnosable_without_private_values(monkeypatch, capsys, verifier_functions):
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, ['go', 'run'], output=b'migrate: cannot connect', stderr=b'postgresql://user:owned-db-secret@127.0.0.1/db owned-runtime-secret sensitive-signing-value TOKEN=another-secret')

    monkeypatch.setattr(subprocess, 'run', fail)
    with pytest.raises(subprocess.CalledProcessError):
        verifier_functions['run'](['go', 'run'], env={'INTERNAL_SIGNING_SECRET': 'sensitive-signing-value'})
    diagnostic = capsys.readouterr().out
    assert 'migrate: cannot connect' in diagnostic
    assert verifier_functions['receipt']['fixture_exit_code'] == 1
    for secret in ('owned-db-secret', 'owned-runtime-secret', 'sensitive-signing-value', 'another-secret', 'postgresql://'):
        assert secret not in diagnostic
        assert secret not in verifier_functions['receipt']['fixture_error_summary']


def test_postgres_readiness_waits_for_final_tcp_server():
    source = ast.parse((ROOT / 'scripts/verify_public_knowledge_postgres.py').read_text(encoding='utf-8'))
    probes = [node for node in ast.walk(source) if isinstance(node, ast.List) and any(isinstance(item, ast.Constant) and item.value == 'pg_isready' for item in node.elts)]
    assert len(probes) == 1
    values = [item.value for item in probes[0].elts if isinstance(item, ast.Constant)]
    assert values[values.index('-h') + 1] == '127.0.0.1'


def test_coverage_is_required_with_owned_postgres_before_compose_release():
    workflow = yaml.load((ROOT / '.github/workflows/three-project-quality.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    jobs = workflow['jobs']
    assert 'identity-sql' in jobs['compose-e2e']['needs']
    assert any('--suite identity-full --coverage' in step.get('run', '') for step in jobs['identity-sql']['steps'])
    coverage = (ROOT / 'scripts/check_go_coverage.py').read_text(encoding='utf-8')
    assert '["go", "test", "-p=1", "-cover", *packages]' in coverage
    assert '"./internal/identity": 25.0' in coverage
    assert '"./internal/execution": 40.0' in coverage
    for entry in ('unit.sh', 'unit.ps1'):
        assert '--suite identity-full --coverage' in (ROOT / 'scripts' / entry).read_text(encoding='utf-8')
