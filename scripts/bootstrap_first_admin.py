"""Initialize an empty identity store using an operator-owned private JSON file."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True,type=Path)
    parser.add_argument('--env-file',type=Path,default=ROOT/'.env')
    parser.add_argument('--project',default='agentplug')
    parser.add_argument('--compose-overlay',action='append',type=Path,default=[],help='owner-private Compose image overlay, used by isolated source-build acceptance projects')
    args=parser.parse_args()
    if not re.fullmatch(r'agentplug(?:-test-[a-z0-9-]+)?',args.project):
        parser.error('project must be agentplug or an isolated agentplug-test-* name')
    if args.config.is_symlink() or not args.config.is_file() or not args.env_file.is_file():
        parser.error('regular private configuration and environment files are required')
    overlays=[]
    for candidate in args.compose_overlay:
        try:
            resolved=candidate.expanduser().resolve(strict=True)
            resolved.relative_to((ROOT/'.local-secrets').resolve())
        except (OSError,ValueError):
            parser.error('Compose overlays must be existing regular files under .local-secrets')
        if candidate.is_symlink() or not resolved.is_file() or (os.name!='nt' and resolved.stat().st_mode&0o077):
            parser.error('Compose overlays must be owner-private regular files')
        try:
            overlay=json.loads(resolved.read_text(encoding='utf-8'))
        except (OSError,ValueError):
            parser.error('Compose overlay is invalid JSON')
        services=overlay.get('services') if isinstance(overlay,dict) else None
        image_kinds={'platform-app':'platform','platform-migrate':'platform','frontend':'frontend','metric-runner':'metric-runner'}
        suffix=args.project.removeprefix('agentplug-test-public-')
        if not args.project.startswith('agentplug-test-public-') or not suffix or not isinstance(services,dict) or not services or any(name not in image_kinds or not isinstance(spec,dict) or spec.get('image')!='agentplug:test-'+image_kinds.get(name,'')+'-'+suffix for name,spec in services.items()):
            parser.error('Compose overlay must bind only platform images to the exact isolated public replay project tag')
        overlays.append(resolved)
    with args.config.open('rb') as file:
        info=os.fstat(file.fileno())
        if os.name!='nt' and info.st_mode&0o077:
            parser.error('configuration must be owner-private (chmod 600)')
        raw=file.read(65537)
    if not raw or len(raw)>65536:
        parser.error('configuration size must be 1..65536 bytes')
    # Constant shell program; operator data travels only through stdin.
    shell='umask 077\nfile=/tmp/agentplug-first-admin.json\ntrap \'rm -f "$file"\' EXIT\ncat >"$file"\n/app/bootstrap-admin --config "$file"\n'
    command=['docker','compose','--project-name',args.project,'--env-file',str(args.env_file.resolve()),'-f',str(ROOT/'compose.yaml'),'-f',str(ROOT/'deploy/compose/compose.init.yaml')]
    for overlay in overlays:
        command.extend(['-f',str(overlay)])
    command.extend(['--profile','modular','--profile','init','run','--rm','--no-deps','-T','--entrypoint','sh','platform-migrate','-c',shell])
    result=subprocess.run(command,cwd=ROOT,input=raw,capture_output=True,timeout=60)
    if result.returncode or b'FIRST ADMINISTRATOR BOOTSTRAP PASS' not in result.stdout:
        print('First administrator initialization refused; configuration and credentials withheld.')
        return 1
    print('FIRST ADMINISTRATOR BOOTSTRAP PASS')
    return 0


if __name__=='__main__':raise SystemExit(main())
