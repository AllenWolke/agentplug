"""Restart receipts, unknown crash and cross-replica generation fencing."""
import asyncio
import base64
import json
import os
from pathlib import Path
from uuid import uuid4
import pytest
from agent_platform_sdk.errors import DomainExecutionError
from agent_platform_sdk.models import ExecuteRequest
from agent_platform_sdk.task_registry import ExecutionTaskRegistry
from agent_platform_sdk.generation_exit import PostgresGenerationExitStore


def request():
    envelope=json.loads((Path(__file__).resolve().parents[3]/'contracts/fixtures/execution-v2-request.json').read_text(encoding='utf8'))
    envelope['scope']['run_id']=str(uuid4())
    payload=base64.urlsafe_b64encode(json.dumps({'execution_revision':2,'lease_token_hash':'a'*64}).encode()).decode().rstrip('=')
    envelope['context_token']='fixture.'+payload+'.fixture'
    return ExecuteRequest.model_validate(envelope)

class MemoryReceipts:
    def __init__(self): self.rows={};self.entered=asyncio.Event();self.release=None
    async def admit(self,key,owner):
        self.entered.set()
        if self.release is not None: await self.release.wait()
        if key in self.rows and self.rows[key][0] != 'exited':
            raise DomainExecutionError('EXECUTION_ALREADY_ACTIVE')
        self.rows[key]=('active',owner)
    async def exit(self,key,owner):
        assert self.rows[key]==('active',owner)
        self.rows[key]=('exited',owner)
    async def stop_exited(self,key):
        row=self.rows.get(key)
        if not row or row[0]=='active': return False
        self.rows[key]=('stopped',row[1]);return True

@pytest.mark.asyncio
async def test_new_registry_restores_exact_observed_exit_and_fences_replay():
    store=MemoryReceipts();req=request()
    first=ExecutionTaskRegistry(exit_store=store)
    assert await first.execute(req,lambda:asyncio.sleep(0,result='finished'))=='finished'
    second=ExecutionTaskRegistry(exit_store=store)
    assert not second.has_exit_proof(req)
    assert await second.cancel(req)
    assert second.has_exit_proof(req)
    third=ExecutionTaskRegistry(exit_store=store)
    with pytest.raises(DomainExecutionError,match='EXECUTION_ALREADY_ACTIVE'):
        await third.execute(req,lambda:asyncio.sleep(0))
    assert await third.cancel(req)

@pytest.mark.asyncio
async def test_unknown_and_crashed_active_generation_never_become_exit_proof():
    store=MemoryReceipts();req=request();registry=ExecutionTaskRegistry(exit_store=store)
    assert not await registry.cancel(req)
    other=request();await store.admit(registry.key(other),str(uuid4()))
    assert not await registry.cancel(other)
    assert not registry.has_exit_proof(other)

@pytest.mark.asyncio
async def test_exit_proof_is_bound_to_scope_revision_and_lease():
    store=MemoryReceipts();req=request();registry=ExecutionTaskRegistry(exit_store=store)
    await registry.execute(req,lambda:asyncio.sleep(0))
    other=req.model_copy(deep=True);other.scope.principal_id='another-principal'
    assert not await ExecutionTaskRegistry(exit_store=store).cancel(other)
    claims=base64.urlsafe_b64encode(json.dumps({'execution_revision':3,'lease_token_hash':'b'*64}).encode()).decode().rstrip('=')
    other=req.model_copy(deep=True);other.context_token='fixture.'+claims+'.fixture'
    assert not await ExecutionTaskRegistry(exit_store=store).cancel(other)

@pytest.mark.asyncio
async def test_replica_admission_excludes_duplicate_action_and_old_receipt():
    store=MemoryReceipts();req=request();ready=asyncio.Event();release=asyncio.Event()
    async def action(): ready.set();await release.wait();return 1
    first=ExecutionTaskRegistry(exit_store=store);second=ExecutionTaskRegistry(exit_store=store)
    task=asyncio.create_task(first.execute(req,action));await ready.wait()
    try:
        with pytest.raises(DomainExecutionError,match='EXECUTION_ALREADY_ACTIVE'):
            await second.execute(req,action)
        assert not await second.cancel(req)
    finally: release.set();assert await task==1
    assert await second.cancel(req)

@pytest.mark.asyncio
async def test_cancel_during_admission_runs_no_business_action():
    store=MemoryReceipts();store.release=asyncio.Event();req=request();effects=[]
    registry=ExecutionTaskRegistry(exit_store=store)
    async def action():effects.append('unsafe')
    task=asyncio.create_task(registry.execute(req,action));await store.entered.wait()
    assert not await registry.cancel(req)
    store.release.set()
    with pytest.raises(DomainExecutionError,match='EXECUTION_CANCELLED'):await task
    assert effects==[]
    assert await registry.cancel(req)

@pytest.mark.asyncio
async def test_suppressed_cancel_needs_real_exit_and_durable_receipt():
    store=MemoryReceipts();req=request();started=asyncio.Event();release=asyncio.Event()
    async def action():
        started.set()
        try: await release.wait()
        except asyncio.CancelledError:await release.wait()
    registry=ExecutionTaskRegistry(exit_store=store)
    task=asyncio.create_task(registry.execute(req,action));await started.wait()
    try:
        with pytest.raises(DomainExecutionError,match='CANCELLATION_NOT_CONFIRMED'):
            await registry.cancel(req,timeout=.02)
        assert not registry.has_exit_proof(req)
        assert store.rows[registry.key(req)][0]=='active'
    finally: release.set();await task
    assert await registry.cancel(req)

@pytest.mark.asyncio
async def test_persistence_failure_cannot_create_fake_exit_receipt():
    class Broken(MemoryReceipts):
        async def exit(self,key,owner):raise RuntimeError('private-upstream-detail')
    store=Broken();req=request();registry=ExecutionTaskRegistry(exit_store=store)
    assert await registry.execute(req,lambda:asyncio.sleep(0,result=1))==1
    assert not registry.has_exit_proof(req)
    assert not await ExecutionTaskRegistry(exit_store=store).cancel(req)

@pytest.mark.asyncio
async def test_fastapi_restore_still_requires_current_authorization():
    import httpx
    from agent_platform_sdk.fastapi_factory import create_fastapi_agent_app
    store=MemoryReceipts();req=request();prior=ExecutionTaskRegistry(exit_store=store)
    await prior.execute(req,lambda:asyncio.sleep(0))
    authenticated=False;calls=[]
    def authorize(request,token):
        if not authenticated:raise PermissionError('revoked')
    async def cancel(run_id,request):calls.append(run_id);return {'run_id':run_id,'status':'cancelled'}
    app=create_fastapi_agent_app(title='test',agent_id='test',version='1',capabilities=[],authorize=authorize,
       cancel=cancel,task_registry=ExecutionTaskRegistry(exit_store=store))
    req.operation='cancel'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
        route=f'/internal/agent-execution/v2/runs/{req.scope.run_id}/cancel'
        response=await client.post(route,json=req.model_dump(mode='json'),headers={'Authorization':'Bearer fixture'})
        assert response.status_code==401 and calls==[]
        authenticated=True
        response=await client.post(route,json=req.model_dump(mode='json'),headers={'Authorization':'Bearer fixture'})
        assert response.status_code==200 and calls==[req.scope.run_id]

@pytest.mark.asyncio
async def test_actual_postgres_restart_active_unknown_and_same_generation_fence():
    dsn=os.getenv('DURABLE_EXIT_TEST_DSN','')
    if not dsn:pytest.skip('explicit isolated PostgreSQL runtime DSN required')
    store=PostgresGenerationExitStore(dsn);req=request();first=ExecutionTaskRegistry(exit_store=store)
    assert await first.execute(req,lambda:asyncio.sleep(0,result=42))==42
    second=ExecutionTaskRegistry(exit_store=PostgresGenerationExitStore(dsn))
    assert await second.cancel(req) and second.has_exit_proof(req)
    with pytest.raises(DomainExecutionError,match='EXECUTION_ALREADY_ACTIVE'):
        await ExecutionTaskRegistry(exit_store=store).execute(req,lambda:asyncio.sleep(0))
    crashed=request();await store.admit(first.key(crashed),str(uuid4()))
    assert not await second.cancel(crashed)
    assert not second.has_exit_proof(crashed)
    alien=req.model_copy(deep=True);alien.scope.principal_id='unauthorized-test-subject'
    assert not await second.cancel(alien)


@pytest.mark.asyncio
async def test_postgres_exit_receipt_delete_privilege_fails_closed():
    # 仅显式独立测试数据库可临时赋予多余权限；业务数据库不允许。
    from urllib.parse import urlsplit
    import hashlib
    import psycopg
    from psycopg import sql
    runtime_dsn = os.getenv("DURABLE_EXIT_TEST_DSN", "")
    admin_dsn = os.getenv("DURABLE_EXIT_TEST_ADMIN_DSN", "")
    if not runtime_dsn or not admin_dsn:
        pytest.skip("explicit isolated PostgreSQL administrative fixture required")
    runtime = urlsplit(runtime_dsn)
    administrative = urlsplit(admin_dsn)
    assert runtime.hostname == administrative.hostname == "127.0.0.1"
    assert runtime.path == administrative.path == "/knowledge_durable_test"
    assert runtime.port == administrative.port
    role = runtime.username
    assert role and role.startswith("sdk_exit_rt_")
    request_value = request()
    key = ExecutionTaskRegistry.key(request_value)
    async with await psycopg.AsyncConnection.connect(admin_dsn, autocommit=True) as connection:
        await connection.execute(sql.SQL("GRANT DELETE ON public.sdk_execution_generation TO {}").format(sql.Identifier(role)))
        try:
            store = PostgresGenerationExitStore(runtime_dsn)
            with pytest.raises(DomainExecutionError, match="CANCELLATION_NOT_CONFIRMED"):
                await store.admit(key, str(uuid4()))
            cursor = await connection.execute("SELECT COUNT(*) FROM public.sdk_execution_generation WHERE generation_sha256=%s", (hashlib.sha256(key.encode()).hexdigest(),))
            assert (await cursor.fetchone())[0] == 0
        finally:
            await connection.execute(sql.SQL("REVOKE DELETE ON public.sdk_execution_generation FROM {}").format(sql.Identifier(role)))
