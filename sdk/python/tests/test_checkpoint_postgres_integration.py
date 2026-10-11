"""Actual PostgreSQL workflow database only; never an existing application DB."""
import os
import asyncio
import sys
import subprocess
import secrets
import json
from datetime import datetime,timezone
from types import SimpleNamespace
from typing import TypedDict
from urllib.parse import urlsplit,urlunsplit,quote
from uuid import uuid4
import pytest

@pytest.mark.asyncio
async def test_checkpoint_postgres_roles_upgrade_and_resume(monkeypatch):
    dsn=os.getenv('CHECKPOINT_ISOLATED_TEST_DSN','')
    if not dsn: pytest.skip('explicit isolated PostgreSQL fixture required')
    parsed=urlsplit(dsn)
    assert parsed.hostname=='127.0.0.1' and parsed.path=='/knowledge_test'
    from psycopg import AsyncConnection,sql,errors
    from psycopg.types.json import Jsonb
    from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
    from agent_platform_sdk.checkpoint import PostgresCheckpointProvider,scoped_config
    from agent_platform_sdk.checkpoint_bootstrap import main as bootstrap,_checkpoint_schema_exists
    from agent_platform_sdk.checkpoint_readiness import wait_for_schema
    owner=await AsyncConnection.connect(dsn,autocommit=True)
    role='sdk_rt_'+uuid4().hex[:12];ddl_role='sdk_ddl_'+uuid4().hex[:12]
    password=secrets.token_hex(32)
    def role_dsn(user):
        return urlunsplit((parsed.scheme,quote(user,safe='')+':'+quote(password,safe='')+'@'+parsed.netloc.split('@')[-1],parsed.path,parsed.query,''))
    provider=None
    created=[]
    async def execute(query,args=None):
        async with owner.cursor() as cursor:
            await cursor.execute(query,args)
    async def grants():
        for table in ('checkpoints','checkpoint_blobs','checkpoint_writes'):
            await execute(sql.SQL('GRANT SELECT,INSERT,UPDATE,DELETE ON {} TO {}').format(sql.Identifier(table),sql.Identifier(role)))
        await execute(sql.SQL('GRANT SELECT ON checkpoint_migrations TO {}').format(sql.Identifier(role)))
    try:
        for user in (role,ddl_role):
            await execute(sql.SQL('CREATE ROLE {} LOGIN PASSWORD {}').format(sql.Identifier(user),sql.Literal(password)));created.append(user)
        await execute('REVOKE CREATE ON SCHEMA public FROM PUBLIC')
        await execute('REVOKE TEMP ON DATABASE knowledge_test FROM PUBLIC')
        await execute(sql.SQL('GRANT CREATE ON SCHEMA public TO {}').format(sql.Identifier(ddl_role)))
        monkeypatch.setenv('APP_ENV','production');monkeypatch.setenv('CHECKPOINT_DSN',dsn)
        monkeypatch.delenv('CHECKPOINT_SETUP',raising=False)
        completed = await asyncio.to_thread(subprocess.run,[sys.executable,'-m','agent_platform_sdk.checkpoint_bootstrap'],capture_output=True,timeout=20)
        assert completed.returncode == 0, 'actual checkpoint bootstrap command failed'
        assert b'checkpoint schema initialized' in completed.stdout
        assert await _checkpoint_schema_exists()
        await grants()
        await bootstrap() # Exact migration replay, without schema version changes.
        async with owner.cursor() as cursor:
            await cursor.execute('SELECT COUNT(*) FROM checkpoint_migrations')
            assert (await cursor.fetchone())[0]==len(AsyncPostgresSaver.MIGRATIONS)
        for table in ('checkpoint_writes','checkpoint_blobs','checkpoints','checkpoint_migrations'):
            await execute(sql.SQL('DROP TABLE {}').format(sql.Identifier(table)))
        await execute(AsyncPostgresSaver.MIGRATIONS[0])
        await execute(sql.SQL('GRANT SELECT ON checkpoint_migrations TO {}').format(sql.Identifier(role)))
        assert not await _checkpoint_schema_exists()
        uninitialized=PostgresCheckpointProvider(role_dsn(role))
        with pytest.raises(RuntimeError,match='bootstrap command'):await uninitialized.get()
        assert uninitialized._manager is None
        for version in range(5):
            await execute(AsyncPostgresSaver.MIGRATIONS[version])
            await execute('INSERT INTO checkpoint_migrations(v) VALUES(%s)',(version,))
        previous={'v':1,'id':'fixture-before-upgrade','ts':datetime.now(timezone.utc).isoformat(),'channel_values':{},'channel_versions':{},'versions_seen':{},'pending_sends':[]}
        await execute("INSERT INTO checkpoints(thread_id,checkpoint_ns,checkpoint_id,checkpoint,metadata) VALUES('fixture-upgrade-thread','','fixture-before-upgrade',%s,'{}')",(Jsonb(previous),))
        await bootstrap();await grants()
        monkeypatch.setenv('CHECKPOINT_DSN',role_dsn(role));await wait_for_schema(attempts=1,delay=0)
        provider=PostgresCheckpointProvider(role_dsn(role));saver=await provider.get()
        preserved=await saver.aget_tuple({'configurable':{'thread_id':'fixture-upgrade-thread','checkpoint_ns':''}})
        assert preserved and preserved.checkpoint['id']=='fixture-before-upgrade'
        context=SimpleNamespace(tenant_id='t',department_id='d',application_id='a',installation_id='i',agent_instance_id='instance',agent_id='agent',agent_version_id='v1',principal_type='user',actor_id='one',thread_id='same-session',session_id='same-session')
        config=scoped_config(context)
        checkpoint={'v':1,'id':str(uuid4()),'ts':datetime.now(timezone.utc).isoformat(),'channel_values':{'sample':'synthetic'},'channel_versions':{'sample':'1'},'versions_seen':{},'pending_sends':[]}
        saved=await saver.aput(config,checkpoint,{'source':'input','step':0,'parents':{}},{'sample':'1'})
        await saver.aput_writes(saved,[('sample','synthetic-write')],'fixture-task')
        found=await saver.aget_tuple(saved)
        assert found and found.checkpoint['channel_values']['sample']=='synthetic'
        assert len([entry async for entry in saver.alist(config)])==1
        context.actor_id='other'
        assert await saver.aget_tuple(scoped_config(context)) is None
        context.actor_id='one';context.agent_version_id='v2'
        assert await saver.aget_tuple(scoped_config(context)) is None
        async with saver.conn.cursor() as cursor:
            with pytest.raises(errors.InsufficientPrivilege):await cursor.execute('CREATE TABLE forbidden_sdk_ddl(id INT)')
            with pytest.raises(errors.InsufficientPrivilege):await cursor.execute('CREATE TEMP TABLE forbidden_sdk_temp(id INT)')
            with pytest.raises(errors.InsufficientPrivilege):await cursor.execute('INSERT INTO checkpoint_migrations(v) VALUES(100)')
        # Actual interrupted Graph resumes after the SDK connection is closed;
        # the completed prior node must not execute again.
        from langgraph.graph import StateGraph,START,END
        from langgraph.types import interrupt,Command
        class State(TypedDict):value:int
        calls={'before':0}
        def before(state):calls['before']+=1;return {'value':state['value']+1}
        def approval(state):return {'value':state['value']+int(interrupt('approve'))}
        def graph(checkpointer):
            builder=StateGraph(State);builder.add_node('before',before);builder.add_node('approval',approval)
            builder.add_edge(START,'before');builder.add_edge('before','approval');builder.add_edge('approval',END)
            return builder.compile(checkpointer=checkpointer)
        context.thread_id='graph-resume';graph_config=scoped_config(context)
        await graph(saver).ainvoke({'value':1},graph_config);assert calls['before']==1
        await provider.close();provider=PostgresCheckpointProvider(role_dsn(role));saver=await provider.get()
        assert (await graph(saver).ainvoke(Command(resume=True),graph_config))['value']==3
        assert calls['before']==1
        await provider.close();provider=None
        # Exercise the template's synchronous SDK provider and actual Graph
        # recovery with the same isolated, restricted workflow role.
        import importlib.util
        from pathlib import Path
        template_entry = Path(__file__).resolve().parents[3] / 'templates/python-langgraph/platform_entry'
        def verify_template():
            names = ('server', 'checkpoint_template_lifecycle')
            originals = {name: sys.modules.get(name) for name in names}
            try:
                for module_name, filename in zip(names, ('server.py', 'test_lifecycle.py')):
                    spec = importlib.util.spec_from_file_location(module_name, template_entry / filename)
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = module
                    spec.loader.exec_module(module)
                    if filename == 'test_lifecycle.py':
                        module.verify_postgres_restart(role_dsn(role))
            finally:
                for name, original in originals.items():
                    if original is None:
                        sys.modules.pop(name, None)
                    else:
                        sys.modules[name] = original
        await asyncio.to_thread(verify_template)
        unsafe=PostgresCheckpointProvider(role_dsn(ddl_role))
        # Give SELECT so structure is readable, then effective DDL is rejected.
        await execute(sql.SQL('GRANT SELECT ON ALL TABLES IN SCHEMA public TO {}').format(sql.Identifier(ddl_role)))
        with pytest.raises(RuntimeError,match='DML-only'):await unsafe.get()
        assert unsafe._manager is None
        from agent_platform_sdk import SyncPostgresCheckpointProvider
        sync_unsafe = SyncPostgresCheckpointProvider(role_dsn(ddl_role))
        with pytest.raises(RuntimeError, match='DML-only'):
            await asyncio.to_thread(sync_unsafe.get)
        assert sync_unsafe._manager is None
        monkeypatch.setenv('CHECKPOINT_DSN',dsn)
        await execute('INSERT INTO checkpoint_migrations(v) VALUES(%s)',(len(AsyncPostgresSaver.MIGRATIONS),))
        with pytest.raises(RuntimeError,match='newer'):await bootstrap()
        await execute('DELETE FROM checkpoint_migrations WHERE v=%s',(len(AsyncPostgresSaver.MIGRATIONS),))
        await execute('DELETE FROM checkpoint_migrations WHERE v=5')
        with pytest.raises(RuntimeError,match='history is incomplete'):await bootstrap()
        await execute('INSERT INTO checkpoint_migrations(v) VALUES(5)')
        await execute('ALTER TABLE checkpoints DROP COLUMN metadata')
        with pytest.raises(RuntimeError,match='columns'):await bootstrap()
        damaged=PostgresCheckpointProvider(role_dsn(role))
        with pytest.raises(RuntimeError,match='columns'):await damaged.get()
        assert damaged._manager is None
        sync_damaged = SyncPostgresCheckpointProvider(role_dsn(role))
        with pytest.raises(RuntimeError, match='columns'):
            await asyncio.to_thread(sync_damaged.get)
        assert sync_damaged._manager is None
        await execute('DROP TABLE checkpoint_blobs')
        with pytest.raises(RuntimeError,match='incomplete despite'):await bootstrap()
    finally:
        if provider:await provider.close()
        # This test deliberately damages its verifier-owned schema. Remove all
        # four test tables so a repeat starts clean, including after failure.
        # The loopback knowledge_test assertion above excludes application DBs.
        for table in ('checkpoint_writes','checkpoint_blobs','checkpoints','checkpoint_migrations'):
            await execute(sql.SQL('DROP TABLE IF EXISTS {}').format(sql.Identifier(table)))
        for user in created:
            await execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(user)))
            await execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(user)))
        await owner.close()
