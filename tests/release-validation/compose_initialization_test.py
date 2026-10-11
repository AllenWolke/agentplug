"""Both shell launchers delegate literally and preserve private configuration."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import pytest

ROOT=Path(__file__).resolve().parents[2]

@pytest.mark.parametrize('existing',[False,'complete','missing_gateway','empty_gateway'])
def test_launcher_preserves_configuration_and_literal_arguments(tmp_path,existing):
    scripts=tmp_path/'scripts';scripts.mkdir()
    suffix='ps1' if os.name=='nt' else 'sh'
    launcher=scripts/('platform.'+suffix)
    shutil.copyfile(ROOT/'scripts'/launcher.name,launcher)
    (scripts/'compose.py').write_text("import json,sys\nfrom pathlib import Path\nPath('args.json').write_text(json.dumps(sys.argv[1:]))\n",encoding='utf-8')
    environment=tmp_path/'.env'
    original=b'INTERNAL_SIGNING_SECRET=operator-owned-existing-value\nMETRIC_RUNNER_TOKEN=operator-owned-runner-value\n'
    if existing=='complete':original+=b'BROWSER_GATEWAY_TOKEN=operator-owned-gateway-value\n'
    elif existing=='empty_gateway':original+=b'BROWSER_GATEWAY_TOKEN=\n'
    if existing:environment.write_bytes(original)
    env={**os.environ,'PYTHON':sys.executable,'PYTHONDONTWRITEBYTECODE':'1'}
    literal='private $(never-run).env'
    if os.name=='nt':
        executable=shutil.which('pwsh') or shutil.which('powershell')
        command=[executable,'-NoProfile','-File',str(launcher),'config','--env-file',literal]
    else:command=[shutil.which('bash'),str(launcher),'config','--env-file',literal]
    result=subprocess.run(command,cwd=tmp_path,env=env,capture_output=True,timeout=30)
    assert result.returncode==0
    assert json.loads((tmp_path/'args.json').read_text())==['config','--env-file',literal]
    assert environment.exists()==bool(existing)
    if existing:assert environment.read_bytes()==original
    assert b'operator-owned' not in result.stdout+result.stderr
