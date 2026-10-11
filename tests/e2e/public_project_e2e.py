"""Start the public Compose images with an empty, isolated PostgreSQL volume.

Uses generated credentials and normal browser APIs. Never reads the supplied
operator environment file or changes a running development/interview project.
Real three-Agent/model integration has separate opt-in acceptance evidence.
"""
from __future__ import annotations

import argparse
import base64
import http.cookiejar
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def isolated_compose_environment(settings):
    """Keep operator/CI shell exports out of the generated test deployment.

    Compose shell variables take precedence over --env-file. Include optional
    interpolation variables too, so a host DSN, bind address or secret mount
    cannot attach this empty-database test to the operator's deployment.
    Docker connection, PATH and build proxy settings remain available.
    """
    names = {name.upper() for name in settings}
    for path in (ROOT / 'compose.yaml', ROOT / 'deploy/compose/compose.init.yaml'):
        names.update(re.findall(r'(?<!\$)\$\{([A-Za-z_][A-Za-z0-9_]*)', path.read_text(encoding='utf-8')))
    environment = {key: value for key, value in os.environ.items()
                   if key.upper() not in names and not key.upper().startswith('COMPOSE_')}
    environment.update(settings)
    environment['COMPOSE_DISABLE_ENV_FILE'] = '1'
    return environment


def redact_diagnostic(message, settings, account_password=''):
    values = [value for key, value in settings.items()
              if any(word in key for word in ('PASSWORD', 'TOKEN', 'SECRET', 'KEY', 'DSN'))]
    for value in [*values, account_password]:
        if value:
            message = message.replace(value, '<redacted>')
    return message


def verify_published_endpoints(configuration, settings):
    """Check actual Compose mappings before sending credentials over HTTP."""
    services = configuration['services']
    for service, target, variable in (
        ('frontend', 80, 'FRONTEND_HOST_PORT'),
        ('platform-app', 8080, 'PLATFORM_HOST_PORT'),
        ('platform-app', 8081, 'PLATFORM_INTERNAL_HOST_PORT'),
        ('postgres', 5432, 'POSTGRES_HOST_PORT'),
    ):
        ports = [port for port in services[service].get('ports', []) if port['target'] == target]
        if (len(ports) != 1 or ports[0].get('host_ip') != '127.0.0.1'
                or str(ports[0].get('published')) != settings[variable]):
            raise RuntimeError('isolated Compose published port mismatch: ' + service + '/' + variable)


def wait_http_ready(opener, address, timeout=30):
    """Wait for host-side routing after container health checks have passed."""
    deadline = time.monotonic() + timeout
    last_error = 'no response'
    while time.monotonic() < deadline:
        try:
            with opener.open(address, timeout=min(2, max(0.1, deadline-time.monotonic()))) as response:
                if response.status == 200:
                    return
                last_error = 'HTTP ' + str(response.status)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            last_error = str(error)
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.5, remaining))
    raise RuntimeError('isolated host HTTP readiness failed: ' + address + ': ' + last_error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, help='launcher compatibility; not read')
    parser.add_argument('--build-images',action='store_true',help='build current source under isolated temporary agentplug tags')
    parser.add_argument('--temporary-root',type=Path,default=ROOT/'.tmp',help='isolated test files and generated fixture credentials')
    parser.add_argument('--verify-kafka-restart',action='store_true',help='verify delayed Kafka startup only in the newly created isolated test project')
    parser.add_argument('--report', type=Path, default=ROOT/'docs/新增需求/github作品改造/T3-11-干净PostgreSQL与五账号初始化实际验收.json')
    args = parser.parse_args()
    owner = 'agentplug-test-clean-'+uuid.uuid4().hex[:12]
    temporary_root = args.temporary_root.resolve()
    temporary = temporary_root/owner
    temporary.mkdir(parents=True, mode=0o700)
    env_file = temporary/'private.env'
    report = {'complete':False,'project':owner,'scope':'empty PostgreSQL migrations, local administrator, normal five-user creation/login/refresh/logout and Compose isolation; not three-Agent RAG acceptance','temporary_images_built':[],'cleanup_errors':[]}
    base = ['docker','compose','--project-name',owner,'--env-file',str(env_file),'-f',str(ROOT/'compose.yaml'),'--profile','modular']
    started = False
    image_tags=[]
    settings = {}
    environment = None
    report['stage'] = 'configuration'
    def run(arguments, data=None, timeout=240, require=True):
        result = subprocess.run(base+arguments,cwd=ROOT,input=data,capture_output=True,timeout=timeout,env=environment)
        if require and result.returncode:
            report['failed_operation']=arguments[0]
            message=result.stderr.decode('utf-8',errors='replace')[-3000:]
            report['compose_error_summary']=redact_diagnostic(message, settings)
            raise RuntimeError('isolated Compose operation failed')
        return result
    try:
        secret_dir = temporary/'empty-secrets'
        secret_dir.mkdir()
        private = Ed25519PrivateKey.generate()
        settings = {key:secrets.token_hex(32) for key in ('DB_PASSWORD','PLATFORM_RUNTIME_DB_PASSWORD','INTERNAL_TOKEN','BROWSER_GATEWAY_TOKEN','INTERNAL_SIGNING_SECRET','METRIC_RUNNER_TOKEN','ACCESS_TOKEN_SIGNING_KEY')}
        settings.update(APP_ENV='development',DB_DRIVER='pgx',PLATFORM_DEMO_IDENTITY_BOOTSTRAP='false',FRONTEND_AUTH_MODE='local',COOKIE_SECURE='false',PLATFORM_RUN_EXECUTOR='platform',PLATFORM_EVENT_BUS_MODE='kafka',PLATFORM_NOTIFICATION_ADAPTER='audit',PLATFORM_POLICY_RESOLVER='sql',PLATFORM_MODEL_SECRET_DIR=secret_dir.as_posix(),PLATFORM_WORKLOAD_SECRET_DIR=secret_dir.as_posix())
        settings['PLATFORM_CONTEXT_PRIVATE_KEY']=base64.b64encode(private.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())).decode()
        settings['PLATFORM_CONTEXT_PUBLIC_KEY']=base64.b64encode(private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
        ports=set()
        for key in ('POSTGRES_HOST_PORT','FRONTEND_HOST_PORT','PLATFORM_HOST_PORT','PLATFORM_INTERNAL_HOST_PORT'):
            port=free_port()
            while port in ports:port=free_port()
            ports.add(port);settings[key]=str(port)
        settings.update(FRONTEND_HOST_BIND='127.0.0.1', PLATFORM_HOST_BIND='127.0.0.1')
        environment = isolated_compose_environment(settings)
        env_file.write_text(''.join(k+'='+v+'\n' for k,v in settings.items()),encoding='utf-8')
        env_file.chmod(0o600)
        existing=subprocess.run(['docker','ps','-aq','--filter','label=com.docker.compose.project='+owner],capture_output=True,check=True)
        if existing.stdout.strip():raise RuntimeError('isolated project already exists')
        if args.build_images:
            report['stage'] = 'source-build'
            image_tags=['agentplug:test-'+name+'-'+owner for name in ('platform','frontend','metric-runner')]
            overlay=temporary/'build-overlay.json'
            image_services={name:{'image':image_tags[index]} for name,index in [('platform-app',0),('platform-migrate',0),('frontend',1),('metric-runner',2)]}
            image_services['platform-migrate']['profiles']=['init']
            overlay.write_text(json.dumps({'services':image_services}),encoding='utf-8')
            overlay.chmod(0o600)
            base[base.index('--profile'):base.index('--profile')]=['-f',str(overlay)]
            run(['build','platform-app','frontend','metric-runner'],timeout=900)
            report['temporary_images_built']=image_tags
            report['current_source_build_passed']=True
        report['stage'] = 'compose-configuration'
        rendered = json.loads(run(['config','--format','json']).stdout)
        verify_published_endpoints(rendered, settings)
        report['isolated_published_ports_verified'] = True
        report['published_ports'] = {key: settings[key] for key in (
            'POSTGRES_HOST_PORT', 'FRONTEND_HOST_PORT', 'PLATFORM_HOST_PORT', 'PLATFORM_INTERNAL_HOST_PORT')}
        started=True
        report['stage'] = 'initialization'
        sys.path.insert(0,str(ROOT/'scripts'))
        from initialize_compose import initialize_stack, PUBLIC_JOBS
        initialization_base=base.copy()
        position=initialization_base.index(str(ROOT/'compose.yaml'))+1
        initialization_base[position:position]=['-f',str(ROOT/'deploy/compose/compose.init.yaml')]
        if initialize_stack(initialization_base,ROOT,PUBLIC_JOBS,build=False,environment=environment):
            raise RuntimeError('explicit isolated initialization failed')
        report['explicit_initialization_passed']=True
        report['stage'] = 'service-startup'
        run(['up','-d','--no-build','--wait','--wait-timeout','180','postgres','metric-runner','platform-app','frontend'])
        report['empty_database_started']=True
        report['stage'] = 'first-administrator'
        account_password=secrets.token_urlsafe(24)
        configuration={'version':1,'db_dsn':'postgresql://platform_runtime:'+settings['PLATFORM_RUNTIME_DB_PASSWORD']+'@postgres:5432/agentplug?sslmode=disable','tenant_id':'tenant-demo','tenant_name':'SDK示例租户','department_id':'dept-platform','department_name':'平台管理','application_id':'app-platform-admin','application_name':'平台管理','principal_id':'system.admin','operator_id':'acceptance.operator','approval_reference':'isolated-public-initialization','local_password':account_password}
        config_file=temporary/'first-administrator.json'
        config_file.write_text(json.dumps(configuration),encoding='utf-8');config_file.chmod(0o600)
        command=[sys.executable,'-B',str(ROOT/'scripts/bootstrap_first_admin.py'),'--project',owner,'--env-file',str(env_file),'--config',str(config_file)]
        if args.build_images:
            command.extend(['--compose-overlay', str(overlay)])
        first=subprocess.run(command,cwd=ROOT,capture_output=True,timeout=60,env=environment)
        if first.returncode:raise RuntimeError('documented administrator initialization refused')
        if b'FIRST ADMINISTRATOR BOOTSTRAP PASS' not in first.stdout:raise RuntimeError('administrator bootstrap missing receipt')
        if subprocess.run(command,cwd=ROOT,capture_output=True,timeout=60,env=environment).returncode==0:raise RuntimeError('bootstrap overwrote populated identity store')
        report['first_administrator_reinitialization_denied']=True
        report['documented_first_administrator_command_verified']=True
        address='http://127.0.0.1:'+settings['FRONTEND_HOST_PORT']
        def client():return urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        def call(opener,method,path,body=None):
            request=urllib.request.Request(address+path,method=method,data=json.dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json','Origin':address})
            with opener.open(request,timeout=20) as response:return json.load(response)
        report['stage'] = 'host-http-readiness'
        probe = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        wait_http_ready(probe, address+'/healthz')
        wait_http_ready(probe, 'http://127.0.0.1:'+settings['PLATFORM_HOST_PORT']+'/health/ready')
        report['host_http_readiness_verified'] = True
        report['stage'] = 'five-user-authentication'
        admin=client();call(admin,'POST','/auth/login',{'username':'system.admin','password':account_password})
        usernames=['system.admin','permission.admin','demo.go.user','demo.python.user','demo.java.user']
        for name in usernames[1:]:
            body={'username':name,'display_name':name,'scope':{'scope_type':'application','tenant_id':'tenant-demo','department_id':'dept-platform','application_id':'app-platform-admin'},'idempotency_key':'clean-create-'+name,'reason':'隔离环境验证公开创建用户接口'}
            plan=call(admin,'POST','/api/modules/identity/principals:preview',body)
            body.update(password=account_password,plan_digest=plan['plan_digest'],plan_expires_at=plan['plan_expires_at'])
            call(admin,'POST','/api/modules/identity/principals:create',body)
            user=client();call(user,'POST','/auth/login',{'username':name,'password':account_password})
            call(user,'POST','/auth/refresh',{})
            call(user,'GET','/auth/me')
            call(user,'POST','/auth/logout',{})
            try:call(user,'GET','/auth/me')
            except urllib.error.HTTPError as error:
                if error.code!=401:raise
            else:raise RuntimeError('logged-out session accepted')
        report['five_human_logins']=usernames
        report['refresh_logout_revocation']=True
        report['stage'] = 'database-isolation'
        container=run(['ps','-q','postgres']).stdout.decode().strip()
        query="SELECT json_build_object('human_count',(SELECT count(*) FROM platform_identity_principal WHERE principal_type='user'),'machine_count',(SELECT count(*) FROM platform_identity_principal WHERE principal_type='service_principal'),'business_grants',(SELECT count(*) FROM platform_identity_grant),'old_runs',(SELECT count(*) FROM platform_execution_run),'extension',(SELECT extversion FROM pg_extension WHERE extname='vector'));"
        result=subprocess.run(['docker','exec',container,'psql','-X','-t','-A','-U','postgres','-d','agentplug','-c',query],capture_output=True,check=True)
        facts=json.loads(result.stdout)
        if facts['human_count']!=5 or facts['machine_count']!=0 or facts['business_grants']!=0 or facts['old_runs']!=0 or not facts['extension']:raise RuntimeError('unexpected clean database contents')
        report['database_facts']=facts
        payload=run(['ps','--all','--format','json']).stdout.decode().strip()
        rows=json.loads(payload) if payload.startswith('[') else [json.loads(line) for line in payload.splitlines()]
        if any(row.get('Service') in PUBLIC_JOBS for row in rows):raise RuntimeError('initialization container was retained')
        report['no_initialization_containers_retained']=True
        if args.verify_kafka_restart:
            report['stage'] = 'kafka-restart'
            # This project has a newly created empty volume and generated
            # credentials. Never perform fault injection on formal stacks.
            application=run(['ps','-q','platform-app']).stdout.decode().strip()
            def app_state():
                return json.loads(subprocess.run(['docker','inspect',application],capture_output=True,check=True).stdout)[0]
            before=app_state()['RestartCount']
            run(['stop','-t','10','kafka'])
            run(['restart','platform-app'])
            deadline=time.monotonic()+30
            while time.monotonic()<deadline:
                state=app_state()
                if state['RestartCount']>before and state['State'].get('Health',{}).get('Status')!='healthy':break
                time.sleep(1)
            else:raise RuntimeError('isolated platform did not reject unavailable Kafka')
            report['kafka_absent_startup_rejected']=True
            run(['start','kafka'])
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            deadline=time.monotonic()+90
            while time.monotonic()<deadline:
                try:
                    with opener.open('http://127.0.0.1:'+settings['PLATFORM_HOST_PORT']+'/health/ready',timeout=2) as response:
                        if response.status==200:break
                except (urllib.error.URLError,TimeoutError,ConnectionError):pass
                time.sleep(1)
            else:raise RuntimeError('isolated platform did not recover automatically')
            report['kafka_recovery_without_manual_platform_restart']=True
        report['complete']=True
        report['stage'] = 'completed'
    except Exception as error:
        report['failure']=type(error).__name__
        # The high-level failure message contains no request/configuration
        # payload; redact fixture values before publishing it nonetheless.
        report['failure_summary'] = redact_diagnostic(str(error), settings, locals().get('account_password', ''))[-3000:]
        if started:
            # Capture the owned project before finally removes it. Never fall
            # back to an operator/default Compose project or expose its env.
            try:
                status = run(['ps','--all','--format','json'],timeout=20,require=False)
                payload = status.stdout.decode('utf-8',errors='replace').strip()
                rows = json.loads(payload) if payload.startswith('[') else [json.loads(line) for line in payload.splitlines()]
                report['service_states'] = [{key: row.get(key) for key in ('Service','State','Health','ExitCode','Publishers')} for row in rows]
                report['service_diagnostics'] = {}
                for service in ('frontend','platform-app','postgres','kafka','metric-runner'):
                    logs = run(['logs','--no-color','--tail','25',service],timeout=10,require=False)
                    diagnostic = (logs.stdout+logs.stderr).decode('utf-8',errors='replace')
                    # Keep every service's tail; Kafka's output must not evict
                    # the frontend/platform details needed for HTTP failures.
                    report['service_diagnostics'][service] = redact_diagnostic(diagnostic,settings,locals().get('account_password',''))[-1600:]
            except Exception as diagnostic_error:
                report['diagnostic_failure'] = type(diagnostic_error).__name__
    finally:
        if started:
            result=run(['down','--volumes','--remove-orphans'],require=False)
            if result.returncode:report['cleanup_errors'].append('isolated Compose cleanup failed')
        remaining=subprocess.run(['docker','ps','-aq','--filter','label=com.docker.compose.project='+owner],capture_output=True)
        volumes=subprocess.run(['docker','volume','ls','-q','--filter','label=com.docker.compose.project='+owner],capture_output=True)
        networks=subprocess.run(['docker','network','ls','-q','--filter','label=com.docker.compose.project='+owner],capture_output=True)
        report['temporary_containers_removed']=remaining.returncode==0 and not remaining.stdout.strip()
        report['temporary_volumes_removed']=volumes.returncode==0 and not volumes.stdout.strip()
        report['temporary_networks_removed']=networks.returncode==0 and not networks.stdout.strip()
        for tag in image_tags:
            removal=subprocess.run(['docker','image','rm',tag],capture_output=True)
            if removal.returncode and subprocess.run(['docker','image','inspect',tag],capture_output=True).returncode==0:
                report['cleanup_errors'].append('temporary image tag removal failed')
        report['temporary_image_tags_removed']=all(subprocess.run(['docker','image','inspect',tag],capture_output=True).returncode!=0 for tag in image_tags)
        assert temporary.resolve().parent==temporary_root and temporary.name==owner
        if not report['cleanup_errors']:
            shutil.rmtree(temporary)
        report['temporary_files_removed']=not temporary.exists()
        report['complete']=report['complete'] and all(report[k] for k in ('temporary_containers_removed','temporary_volumes_removed','temporary_networks_removed','temporary_image_tags_removed','temporary_files_removed')) and not report['cleanup_errors']
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False))
    return 0 if report['complete'] else 1


if __name__=='__main__':raise SystemExit(main())
