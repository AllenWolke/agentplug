import pytest

from agent_platform_sdk.checkpoint_schema import REQUIRED_COLUMNS, REQUIRED_PRIMARY_KEYS, checkpoint_schema_state, migration_state


@pytest.mark.parametrize('versions,expected,state', [([], 21, 'upgrade'), ([0], 21, 'upgrade'),
                                                   (list(range(22)), 21, 'ready'), ([1, 0], 1, 'ready')])
def test_contiguous_migrations_are_ready_only_at_current_version(versions, expected, state):
    assert migration_state(versions, expected) == state


@pytest.mark.parametrize('versions', [[0, 2], [0, 0], [-1], ['0'], [0.0], list(range(23))])
def test_gapped_invalid_and_future_history_is_rejected(versions):
    with pytest.raises(RuntimeError):
        migration_state(versions, 21)


class ProbeConnection:
    def __init__(self, tables=None, versions=None, damage=None):
        self.tables = tables if tables is not None else [(table, 'BASE TABLE') for table in REQUIRED_COLUMNS]
        self.versions = list(range(10)) if versions is None else versions
        self.damage = damage
        self.query = ''

    def cursor(self, **kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def execute(self, query, args=None):
        assert query.startswith('SELECT'), 'schema readiness must never issue DDL'
        self.query = query

    async def fetchall(self):
        if 'FROM pg_catalog.pg_class c' in self.query:
            return self.tables
        if 'SELECT v ' in self.query:
            return [(v,) for v in self.versions]
        if 'information_schema.columns' in self.query:
            rows = []
            for table, columns in REQUIRED_COLUMNS.items():
                for name, kind in columns.items():
                    if self.damage == 'missing-column' and name == 'metadata':
                        continue
                    if self.damage in {'wrong-type','old-namespace'} and name == 'checkpoint_ns':
                        kind = 'character varying'
                    rows.append((table, name, kind))
            return rows
        if 'FROM pg_catalog.pg_index' in self.query:
            return [(table, name) for table, names in REQUIRED_PRIMARY_KEYS.items() for name in names
                    if not (self.damage == 'wrong-primary-key' and name == 'checkpoint_ns')]
        raise AssertionError('unexpected metadata query')


@pytest.mark.asyncio
async def test_marker_only_is_upgrade_and_current_schema_is_ready():
    assert await checkpoint_schema_state(ProbeConnection(tables=[], versions=[]), 'public') == 'absent'
    assert await checkpoint_schema_state(ProbeConnection(tables=[('checkpoint_migrations', 'BASE TABLE')], versions=[]), 'public') == 'upgrade'
    assert await checkpoint_schema_state(ProbeConnection(), 'public') == 'ready'


@pytest.mark.parametrize('damage', ['missing-column', 'wrong-type', 'old-namespace', 'wrong-primary-key'])
@pytest.mark.asyncio
async def test_recorded_latest_version_cannot_hide_structural_damage(damage):
    with pytest.raises(RuntimeError):
        await checkpoint_schema_state(ProbeConnection(damage=damage), 'public')


@pytest.mark.asyncio
async def test_missing_history_or_table_is_rejected():
    with pytest.raises(RuntimeError):
        await checkpoint_schema_state(ProbeConnection(tables=[('checkpoints', 'BASE TABLE')]), 'public')
    with pytest.raises(RuntimeError):
        await checkpoint_schema_state(ProbeConnection(tables=[('checkpoint_migrations', 'BASE TABLE')]), 'public')
