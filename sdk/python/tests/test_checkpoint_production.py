import pytest

from agent_platform_sdk.checkpoint import PostgresCheckpointProvider, validate_checkpoint_dsn


@pytest.mark.parametrize('environment', ['production', 'prod', ' PRODUCTION ', ''])
@pytest.mark.parametrize('dsn', [None, 'postgres://postgres:some-valid-length-password@localhost/db',
                              'postgres://runtime:short@localhost/db',
                              'postgres://runtime:replace-with-long-password@localhost/db',
                              'postgres://runtime:重重重重重重重重@localhost/db',
                              'postgres://runtime:aaaaaaaaaaaaaaaa@localhost/db',
                              'postgres://runtime:some-valid-length-password@localhost',
                              'postgres://runtime:some-valid-length-password@[invalid/db'])
@pytest.mark.asyncio
async def test_runtime_rejects_invalid_connection_before_connecting(monkeypatch, environment, dsn):
    monkeypatch.setenv('APP_ENV', environment)
    monkeypatch.delenv('CHECKPOINT_DSN', raising=False)
    provider = PostgresCheckpointProvider(dsn)
    async def forbidden(**kwargs):
        pytest.fail('unsafe credentials reached connection setup')
    monkeypatch.setattr(provider, '_connect', forbidden)
    with pytest.raises(RuntimeError, match='CHECKPOINT_DSN') as error:
        await provider.get()
    if dsn:
        assert dsn not in str(error.value)


@pytest.mark.asyncio
async def test_runtime_cannot_enable_schema_setup_but_bootstrap_remains_separate(monkeypatch):
    monkeypatch.setenv('APP_ENV', 'production')
    monkeypatch.setenv('CHECKPOINT_SETUP', 'true')
    provider = PostgresCheckpointProvider('postgres://runtime:some-valid-length-password@localhost/db')
    calls = []
    async def connect(**kwargs):
        calls.append(kwargs)
        return 'connected'
    monkeypatch.setattr(provider, '_connect', connect)
    with pytest.raises(RuntimeError, match='forbids CHECKPOINT_SETUP'):
        await provider.get()
    assert calls == []
    assert await provider.initialize_schema() == 'connected'
    assert calls == [{'setup': True, 'runtime': False}]


@pytest.mark.asyncio
async def test_valid_runtime_connection_decodes_credentials_and_never_sets_up_schema(monkeypatch):
    monkeypatch.setenv('APP_ENV', 'prod')
    monkeypatch.delenv('CHECKPOINT_SETUP', raising=False)
    provider = PostgresCheckpointProvider('postgres://runtime:p%40ss%3A%2F%25-long-credential@localhost/db')
    calls = []
    async def connect(**kwargs):
        calls.append(kwargs)
        return 'connected'
    monkeypatch.setattr(provider, '_connect', connect)
    assert await provider.get() == 'connected'
    assert calls == [{'setup': False, 'runtime': True}]


def test_schema_owner_role_allows_postgres_only_with_explicit_strong_connection(monkeypatch):
    monkeypatch.setenv('APP_ENV', 'production')
    dsn = 'postgres://postgres:some-valid-length-password@localhost/db'
    validate_checkpoint_dsn(dsn, runtime=False)
    with pytest.raises(RuntimeError):
        validate_checkpoint_dsn(dsn)
    with pytest.raises(RuntimeError):
        validate_checkpoint_dsn('postgres://postgres:root@localhost/db', runtime=False)


@pytest.mark.asyncio
async def test_native_privilege_projection_fails_closed():
    from agent_platform_sdk.checkpoint_privileges import validate_checkpoint_grants
    class Probe:
        def __init__(self,value):self.value=value
        def cursor(self,**kwargs):return self
        async def __aenter__(self):return self
        async def __aexit__(self,*args):pass
        async def execute(self,query):assert query.startswith('SELECT')
        async def fetchone(self):return self.value
    await validate_checkpoint_grants(Probe((True,)))
    for value in [(False,),None,(1,)]:
        with pytest.raises(RuntimeError,match='DML-only'):
            await validate_checkpoint_grants(Probe(value))
