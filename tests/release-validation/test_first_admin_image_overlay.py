"""Source-build bootstrap must use its own images and stay in its own project."""
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('scenario,accepted', [
    ('clean-source-image', True),
    ('existing-public-replay', True),
    ('another-test-image', False),
    ('another-test-directory', False),
    ('formal-project-overlay', False),
])
def test_bootstrap_uses_only_the_matching_private_test_image(tmp_path, monkeypatch, scenario, accepted):
    spec = importlib.util.spec_from_file_location('first_admin_overlay_fixture', ROOT / 'scripts/bootstrap_first_admin.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, 'ROOT', tmp_path)
    project = 'agentplug-test-clean-012345abcdef'
    directory = tmp_path / '.tmp' / project
    image = 'agentplug:test-platform-' + project
    if scenario == 'existing-public-replay':
        project = 'agentplug-test-public-012345abcdef'
        directory = tmp_path / '.local-secrets' / project
        image = 'agentplug:test-platform-012345abcdef'
    elif scenario == 'another-test-image':
        image = 'agentplug:test-platform-agentplug-test-clean-ffffffffffff'
    elif scenario == 'another-test-directory':
        directory = tmp_path / '.tmp' / 'agentplug-test-clean-ffffffffffff'
    elif scenario == 'formal-project-overlay':
        project = 'agentplug'
        directory = tmp_path / '.local-secrets' / 'formal-overlay'
        image = 'agentplug:platform'
    directory.mkdir(parents=True)
    overlay = directory / 'images.json'
    overlay.write_text(json.dumps({'services': {'platform-migrate': {'image': image}}}), encoding='utf-8')
    configuration = tmp_path / 'administrator.json'
    configuration.write_text('{}', encoding='utf-8')
    environment = tmp_path / 'fixture.env'
    environment.write_text('APP_ENV=test\n', encoding='utf-8')
    for path in (overlay, configuration, environment):
        path.chmod(0o600)
    calls = []

    def docker(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=b'FIRST ADMINISTRATOR BOOTSTRAP PASS\n')

    monkeypatch.setattr(module.subprocess, 'run', docker)
    monkeypatch.setattr(sys, 'argv', ['bootstrap-first-admin', '--project', project, '--config', str(configuration),
                                   '--env-file', str(environment), '--compose-overlay', str(overlay)])
    if accepted:
        assert module.main() == 0
        assert len(calls) == 1
        command = calls[0]
        assert command[command.index('--project-name') + 1] == project
        assert str(overlay.resolve()) in command
        assert '--rm' in command and '--no-deps' in command
    else:
        with pytest.raises(SystemExit) as refusal:
            module.main()
        assert refusal.value.code == 2
        assert calls == []
