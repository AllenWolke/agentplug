"""Private Go caches must be removable without changing unrelated directories."""
import ast
import os
from pathlib import Path
import shutil
import stat

import pytest

ROOT = Path(__file__).resolve().parents[2]


def cleanup_callback(owned):
    source = ast.parse((ROOT / 'scripts/verify_public_knowledge_postgres.py').read_text(encoding='utf-8'))
    functions = [node for node in ast.walk(source) if isinstance(node, ast.FunctionDef) and node.name == 'remove_readonly']
    assert len(functions) == 1
    namespace = {'Path': Path, 'stat': stat, 'resolved': owned.resolve()}
    exec(compile(ast.Module(body=functions, type_ignores=[]), '<owned cleanup>', 'exec'), namespace)
    return namespace['remove_readonly']


def test_owned_go_module_cache_with_readonly_parents_is_removed(tmp_path):
    owned = tmp_path / 'owned-fixture'
    directory = owned / 'go-cache' / 'mod' / 'example@v1' / 'nested'
    directory.mkdir(parents=True)
    file = directory / 'module.go'
    file.write_text('package example\n', encoding='utf-8')
    file.chmod(0o444)
    for path in (directory, directory.parent):
        path.chmod(0o555)
    shutil.rmtree(owned, onexc=cleanup_callback(owned))
    assert not owned.exists()


def test_cleanup_refuses_to_change_or_delete_an_unrelated_directory(tmp_path):
    owned = tmp_path / 'owned-fixture'
    owned.mkdir()
    other = tmp_path / 'unrelated'
    other.mkdir()
    file = other / 'keep.txt'
    file.write_text('keep unrelated data', encoding='utf-8')
    before = (other.stat().st_mode, file.stat().st_mode)
    with pytest.raises(RuntimeError, match='outside owned temporary directory'):
        cleanup_callback(owned)(os.unlink, str(file), PermissionError('fixture denied'))
    assert file.read_text(encoding='utf-8') == 'keep unrelated data'
    assert (other.stat().st_mode, file.stat().st_mode) == before
