"""Controller-owned Docker exit attestation; no database or runtime state writes.

Run on the trusted deployment host. The snapshot must be frozen by the operator
from the platform's pending execution and approved catalog image. The signing
key belongs to the deployment controller; never mount it in a business Agent.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlparse
import uuid

def timestamp(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))

def inspect(container_id):
    result = subprocess.run(['docker', 'inspect', container_id], capture_output=True, timeout=15)
    if result.returncode:
        raise RuntimeError('runtime inspection unavailable')
    return json.loads(result.stdout)[0]

def record(snapshot, container_id, key_file, receipt_dir, execute=False):
    if not re.fullmatch('[a-f0-9]{64}', container_id):
        raise ValueError('an immutable full container ID is required')
    if not re.fullmatch('agentplug(?:-with-ragplaform|-interview-rehearsal|-test-[a-z0-9-]+)?', snapshot['compose_project']):
        raise ValueError('only a formal project or an owned test project is permitted')
    endpoint = urlparse(snapshot['endpoint'])
    if endpoint.scheme not in ('http', 'https') or endpoint.hostname != snapshot['compose_service']:
        raise ValueError('runtime endpoint does not match the scoped Compose service')
    before = inspect(container_id)
    labels = before['Config'].get('Labels') or {}
    aliases = {name for network in before['NetworkSettings']['Networks'].values()
               for name in (network.get('Aliases') or [])}
    if (before['Id'] != container_id or before['Image'] != snapshot['image_digest']
            or labels.get('com.docker.compose.project') != snapshot['compose_project']
            or labels.get('com.docker.compose.service') != snapshot['compose_service']
            or snapshot['compose_service'] not in aliases
            or timestamp(before['State']['StartedAt']) > timestamp(snapshot['created_at'])):
        raise ValueError('container identity, approved image or process generation differs')
    key = key_file.read_bytes()
    if len(key) != 32:
        raise ValueError('controller key must contain exactly 32 bytes')
    if not execute:
        return {'validated': True, 'process_stopped': False, 'receipt_written': False}
    for command in [['docker', 'update', '--restart=no', container_id],
                    ['docker', 'stop', '--time', '15', container_id]]:
        result = subprocess.run(command, capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError('controlled process stop failed; no receipt issued')
    after = inspect(container_id)
    state = after['State']
    if (state['Running'] or state.get('Pid', 0) != 0 or state['Status'] != 'exited'
            or after['Id'] != container_id or after['Image'] != before['Image']
            or state['StartedAt'] != before['State']['StartedAt']
            or after['HostConfig']['RestartPolicy']['Name'] != 'no'
            or timestamp(state['FinishedAt']) < timestamp(snapshot['intent_at'])):
        raise RuntimeError('process exit or fencing not established; no receipt issued')
    payload = {field: snapshot[field] for field in
               ['run_id', 'execution_revision', 'lease_token_hash', 'request_hash', 'endpoint']}
    payload.update(schema='runtime-process-stop/v1', runtime_id=container_id,
                   image_digest=after['Image'], started_at=state['StartedAt'],
                   stopped_at=state['FinishedAt'], observed_at=datetime.now(timezone.utc).isoformat(),
                   running=False, restart_disabled=True)
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    envelope = json.dumps({'payload_base64': base64.b64encode(body).decode('ascii'),
                          'signature': hmac.new(key, body, hashlib.sha256).hexdigest()}).encode('utf-8')
    receipt_dir.mkdir(parents=True, exist_ok=True)
    target = receipt_dir / (hashlib.sha256(snapshot['run_id'].encode()).hexdigest() + '.json')
    if target.exists():
        raise RuntimeError('a receipt already exists; preserve and inspect it instead of overwriting')
    temporary = receipt_dir / ('receipt-' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('xb') as output:
            output.write(envelope)
        os.replace(temporary, target)
    finally:
        if temporary.exists(): temporary.unlink()
    return {'process_stopped': True, 'receipt_written': True, 'runtime_id': container_id,
            'image_digest': after['Image'], 'proof_digest': hashlib.sha256(body).hexdigest()}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--container-id', required=True)
    parser.add_argument('--key-file', type=Path, required=True)
    parser.add_argument('--receipt-dir', type=Path, required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    try:
        snapshot = json.loads(args.snapshot.read_text(encoding='utf-8'))
        print(json.dumps(record(snapshot, args.container_id, args.key_file, args.receipt_dir, args.execute)))
    except Exception as error:
        # Do not echo key data, Docker environment or the private execution snapshot.
        print(json.dumps({'complete': False, 'failure': type(error).__name__}))
        return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
