import pytest
from agent_platform_sdk.checkpoint import PostgresCheckpointProvider

@pytest.mark.asyncio
async def test_postgres_native_uri_credentials_without_global_parser_patch(monkeypatch):
    monkeypatch.setenv('APP_ENV','test')
    from psycopg import AsyncConnection
    from psycopg.conninfo import conninfo_to_dict
    captured={}
    async def connect(conninfo,**kwargs):
        captured.update(conninfo_to_dict(conninfo));captured.update(kwargs)
        raise OSError('synthetic connection probe')
    monkeypatch.setattr(AsyncConnection,'connect',connect)
    dsn='postgres://schema%40owner:p%40ss%3A%2F%25@127.0.0.1:5433/db%2Dname'
    provider=PostgresCheckpointProvider(dsn)
    with pytest.raises(RuntimeError,match='connection or initialization failed'):
        await provider.get()
    assert captured['user']=='schema@owner'
    assert captured['password']=='p@ss:/%'
    assert captured['dbname']=='db-name'
    assert captured['port']=='5433'
    assert captured['autocommit'] is True
    assert provider._manager is None and provider._saver is None
