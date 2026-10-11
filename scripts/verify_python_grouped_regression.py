"""Run SDK, business and template suites in separate interpreters.

Template SDK copies intentionally reuse module names. Evidence is immutable;
only this invocation's temporary pytest files are removed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--batch-id', required=True)
parser.add_argument('--group', action='append', choices=['sdk', 'sdk-embedded', 'documents', 'generic', 'langgraph'])
args = parser.parse_args()
if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,80}', args.batch_id):
    raise SystemExit('invalid batch identifier')
prefix = ROOT / 'docs/新增需求/github作品改造' / ('T3-11-Python分组集中回归-' + args.batch_id)
if list(prefix.parent.glob(prefix.name + '*')):
    raise SystemExit('refusing to overwrite evidence')
groups = [
    ('sdk', 'sdk/python', ['tests', 'agent_platform_sdk/test_runtime.py']),
    ('sdk-embedded', 'sdk/python', ['agent_platform_sdk']),
    ('documents', 'examples/python-documents', ['tests']),
    ('generic', 'templates/python-generic/platform_entry', ['.']),
    ('langgraph', 'templates/python-langgraph/platform_entry', ['.']),
]
if args.group:
    groups = [group for group in groups if group[0] in args.group]
def sources():
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for _, folder, _ in groups for p in sorted((ROOT / folder).rglob('*.py'))}
receipt = {'groups': [], 'scope': 'local SDK/business/template regressions; no live database or model acceptance',
           'source_sha256': sources(), 'database_changed': False, 'clone_changed': False}
env = os.environ.copy()
env['PYTHONDONTWRITEBYTECODE'] = '1'
env['PYTHONIOENCODING'] = 'utf-8'
env['PYTHONPATH'] = os.pathsep.join(str(ROOT / p) for p in
    ['sdk/python', '.cache/sdk-postgres', 'examples/python-documents'])
temporary_root = (ROOT / '.tmp').resolve()
temporary_root.mkdir(parents=True, exist_ok=True)
temporary = Path(tempfile.mkdtemp(prefix='python-regression-', dir=temporary_root)).resolve()
try:
    for name, folder, paths in groups:
        xml = temporary / (name + '.xml')
        # SDK tests share same-directory helpers using pytest's default import
        # mode. Each group has its own interpreter; templates keep importlib
        # to avoid collisions between their vendored SDK copies.
        import_mode = 'prepend' if name == 'sdk' else 'importlib'
        result = subprocess.run([sys.executable, '-B', '-m', 'pytest', '-p', 'no:cacheprovider',
            '--basetemp', str(temporary / name), '--junitxml', str(xml), '--import-mode=' + import_mode, '-q', *paths],
            cwd=ROOT / folder, env=env, capture_output=True, timeout=300)
        entry = {'group': name, 'exit_code': result.returncode}
        if xml.exists():
            suites = list(ET.parse(xml).getroot().iter('testsuite'))
            entry['counts'] = {key: sum(int(s.get(key, '0')) for s in suites)
                               for key in ['tests', 'failures', 'errors', 'skipped']}
            entry['skipped_cases'] = [
                {'name': case.get('name'), 'reason': case.find('skipped').get('message')}
                for case in ET.parse(xml).getroot().iter('testcase') if case.find('skipped') is not None]
        prefix.with_name(prefix.name + '-' + name + '.log').write_bytes(result.stdout + result.stderr)
        receipt['groups'].append(entry)
        print(json.dumps(entry), flush=True)
    receipt['sources_unchanged'] = sources() == receipt['source_sha256']
    receipt['passed'] = all(g['exit_code'] == 0 for g in receipt['groups']) and receipt['sources_unchanged']
except Exception as exc:
    receipt['error_type'] = type(exc).__name__
    receipt['passed'] = False
finally:
    try:
        if temporary.parent != temporary_root or temporary.is_symlink():
            raise RuntimeError('refusing cleanup outside the owned workspace fixture')
        shutil.rmtree(temporary)
    except Exception as exc:
        receipt['cleanup_error_type'] = type(exc).__name__
        receipt['passed'] = False
    receipt['temporary_cleanup'] = not temporary.exists()
    prefix.with_suffix('.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'passed': receipt.get('passed'), 'temporary_cleanup': receipt['temporary_cleanup']}))
raise SystemExit(0 if receipt.get('passed') and receipt['temporary_cleanup'] else 1)
