"""Checkpoint SPI guard tests: production must never fall back to MemorySaver.

生产环境检查点 SPI 守卫：未配置持久化实现时必须拒绝启动。
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SERVER_PATH = Path(__file__).resolve().parent / "server.py"


def _load_server_module():
    spec = importlib.util.spec_from_file_location("langgraph_server", SERVER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_production_without_checkpointer_refuses_to_start():
    server = _load_server_module()
    with pytest.raises(RuntimeError, match="PLATFORM_CHECKPOINTER"):
        server.resolve_checkpointer({"PLATFORM_ENV": "production"})


def test_production_rejects_explicit_memory_saver():
    server = _load_server_module()
    with pytest.raises(RuntimeError, match="forbidden"):
        server.resolve_checkpointer({"PLATFORM_ENV": "production", "PLATFORM_CHECKPOINTER": "memory"})


def test_development_defaults_to_memory_saver():
    server = _load_server_module()
    checkpointer = server.resolve_checkpointer({})
    assert checkpointer is not None


def test_unknown_checkpointer_kind_is_rejected():
    server = _load_server_module()
    with pytest.raises(RuntimeError, match="unknown PLATFORM_CHECKPOINTER"):
        server.resolve_checkpointer({"PLATFORM_CHECKPOINTER": "redis"})


@pytest.mark.parametrize('kind', ['sqlite', 'mysql', 'factory'])
def test_other_persistence_selections_are_rejected(kind):
    server = _load_server_module()
    with pytest.raises(RuntimeError, match=r'expected memory\|postgres'):
        server.resolve_checkpointer({'PLATFORM_CHECKPOINTER': kind})


def test_postgres_requires_dsn():
    server = _load_server_module()
    with pytest.raises(RuntimeError, match='CHECKPOINT_DSN'):
        server.resolve_checkpointer({'PLATFORM_CHECKPOINTER': 'postgres'})


def test_app_env_production_cannot_bypass_durability():
    server = _load_server_module()
    with pytest.raises(RuntimeError, match='forbidden'):
        server.resolve_checkpointer({'APP_ENV': 'production', 'PLATFORM_ENV': 'development'})


def test_postgres_runtime_rejects_schema_setup():
    server = _load_server_module()
    with pytest.raises(RuntimeError, match='must not apply'):
        server.resolve_checkpointer({'PLATFORM_CHECKPOINTER': 'postgres',
            'CHECKPOINT_DSN': 'postgresql://runtime:strong-password@localhost/workflow',
            'CHECKPOINT_SETUP': 'true'})
