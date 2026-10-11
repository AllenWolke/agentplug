"""Diagnose one guarded DeepSeek request in the deployment's Linux runtime.

This is a provider connectivity check, never full RAG or billing acceptance.
Credentials remain in a read-only mount and never enter arguments or reports.
"""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
OWNER = 'live-model-linux-' + uuid.uuid4().hex
NAME = 'agentplug-test-' + OWNER
TEMP = ROOT / '.tmp' / OWNER
REPORTS = ROOT / 'docs/新增需求/github作品改造'
BASE = 'T3-04-Linux模型精确配置诊断'
record = {'owner': OWNER, 'scope': 'one fixed OK question using guarded platform adapter on Linux; not RAG acceptance',
          'credentials_logged': False, 'temporary_images_built': [], 'cleanup_errors': []}
TEMP.mkdir(parents=True)
try:
    metadata = json.loads((ROOT / '.local-secrets/model-providers/runtime-mounts/providers.json').read_text(encoding='utf-8'))['llm']
    if metadata['key_file'] != 'deepseek.key':
        raise RuntimeError('fixed prepared mounted credential required')
    download = Path(os.environ.get('USERPROFILE', str(Path.home()))) / 'go/pkg/mod/cache/download'
    if not download.is_dir():
        raise RuntimeError('existing offline module download cache required')
    settings = {'LEXAGENT_LIVE_DEEPSEEK_KEY_FILE': '/workspace/.local-secrets/model-providers/runtime-mounts/deepseek.key',
                'LEXAGENT_LIVE_DEEPSEEK_MODEL': metadata['model'], 'LEXAGENT_LIVE_DEEPSEEK_BASE_URL': metadata['base_url'],
                'GOMAXPROCS': '2', 'GOPROXY': 'file:///module-cache', 'GOSUMDB': 'off', 'GOTOOLCHAIN': 'local',
                'GOCACHE': '/test-cache/build', 'GOMODCACHE': '/test-cache/mod', 'GOFLAGS': '-buildvcs=false'}
    if any('\n' in value or '\r' in value for value in settings.values()):
        raise RuntimeError('single-line model metadata required')
    env_file = TEMP / 'go.env'
    env_file.write_text(''.join(key + '=' + value + '\n' for key, value in settings.items()), encoding='utf-8')
    cache = TEMP / 'go-cache'
    cache.mkdir()
    with (REPORTS / (BASE + '.log')).open('wb') as output:
        completed = subprocess.run(['docker', 'run', '--rm', '--name', NAME, '--label', 'agentplug.test.owner=' + OWNER,
            '--env-file', str(env_file), '--mount', 'type=bind,source=' + str(ROOT) + ',target=/workspace,readonly',
            '--mount', 'type=bind,source=' + str(download) + ',target=/module-cache,readonly',
            '--mount', 'type=bind,source=' + str(cache) + ',target=/test-cache',
            '--workdir', '/workspace/platform', 'golang:1.25-bookworm', 'go', 'test', '-p=1', '-count=1',
            '-timeout=120s', '-v', './internal/modelgateway', '-run', '^TestLiveDeepSeekGateway$'],
            stdout=output, stderr=subprocess.STDOUT, timeout=300)
    text = (REPORTS / (BASE + '.log')).read_text(encoding='utf-8', errors='replace')
    record.update(model=metadata['model'], base_url=metadata['base_url'], exit_code=completed.returncode,
                  passed=completed.returncode == 0 and '--- PASS: TestLiveDeepSeekGateway' in text and '--- SKIP:' not in text)
except Exception as error:
    record['failure'] = type(error).__name__
finally:
    found = subprocess.run(['docker', 'inspect', NAME], capture_output=True)
    if found.returncode == 0:
        actual = json.loads(found.stdout)[0]
        if actual.get('Config', {}).get('Labels', {}).get('agentplug.test.owner') == OWNER:
            if subprocess.run(['docker', 'rm', '--force', NAME], capture_output=True).returncode:
                record['cleanup_errors'].append('owned container removal failed')
        else:
            record['cleanup_errors'].append('container ownership mismatch')
    record['temporary_container_removed'] = subprocess.run(['docker', 'inspect', NAME], capture_output=True).returncode != 0
    resolved = TEMP.resolve()
    if resolved.is_relative_to((ROOT / '.tmp').resolve()) and resolved.name == OWNER and not TEMP.is_symlink():
        def remove_readonly(function, path, error):
            target = Path(path)
            if not target.resolve().is_relative_to(resolved) or target.is_symlink():
                raise RuntimeError('owned temporary path required')
            target.chmod(stat.S_IREAD | stat.S_IWRITE | (stat.S_IEXEC if target.is_dir() else 0))
            function(path)
        try:
            shutil.rmtree(TEMP, onexc=remove_readonly)
        except OSError:
            record['cleanup_errors'].append('owned directory removal failed')
    else:
        record['cleanup_errors'].append('temporary ownership mismatch')
    record['temporary_cache_removed'] = not TEMP.exists()
    record['result'] = 'PASS' if record.get('passed') and record['temporary_container_removed'] and record['temporary_cache_removed'] and not record['cleanup_errors'] else 'FAIL'
    (REPORTS / (BASE + '.json')).write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(record, ensure_ascii=False))
raise SystemExit(0 if record['result'] == 'PASS' else 1)
