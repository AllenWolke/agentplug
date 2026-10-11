import importlib.util
import os
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("native", ROOT / "scripts/local.py")
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)


def private_file(root, text):
    path = root / "private.env"
    path.write_text(text)
    path.chmod(0o600)
    return path


def test_env_values_are_literal_and_never_shell_expanded(tmp_path):
    path = private_file(tmp_path, 'INTERNAL_TOKEN="$(do-not-execute)"\nDB_DSN=user:literal@tcp(127.0.0.1)/db\n')
    values = NATIVE.load_settings(path)
    assert values["INTERNAL_TOKEN"] == "$(do-not-execute)"
    assert values["DB_DSN"].endswith("/db")


@pytest.mark.parametrize("text", ["TOKEN=replace-with-secret\n", "TOKEN=a\nTOKEN=b\n", "invalid-key=value\n"])
def test_invalid_private_configs_fail_closed(tmp_path, text):
    with pytest.raises(ValueError):
        NATIVE.load_settings(private_file(tmp_path, text))


def test_initialization_does_not_inherit_runtime_secrets(monkeypatch):
    monkeypatch.setenv("INTERNAL_TOKEN", "private-runtime-token")
    env = NATIVE.environment("migrate", {"APP_ENV": "development", "DB_DRIVER": "pgx", "DB_DSN": "fixture"})
    assert "INTERNAL_TOKEN" not in env
    with pytest.raises(ValueError):
        NATIVE.environment("migrate", {"INTERNAL_TOKEN": "fixture"})
    with pytest.raises(ValueError):
        NATIVE.environment("checkpoint-init", {"DB_DSN": "fixture"})


def test_checkpoint_bootstrap_is_owned_by_shared_sdk():
    command, working = NATIVE.command("checkpoint-init", "/private/venv/python")
    assert command == ["/private/venv/python", "-m", "agent_platform_sdk.checkpoint_bootstrap"]
    assert working == ROOT
    env = NATIVE.environment("checkpoint-init", {"CHECKPOINT_DSN": "fixture"})
    assert str(ROOT / "sdk/python") in env["PYTHONPATH"].split(os.pathsep)


def test_missing_native_binary_is_not_replaced_by_docker(tmp_path, monkeypatch):
    monkeypatch.setattr(NATIVE, "BUILD", tmp_path)
    with pytest.raises(ValueError, match="native binary missing"):
        NATIVE.command("platform", "python")


def test_first_administrator_is_a_separate_maintenance_action():
    assert NATIVE.GO_TARGETS['bootstrap-admin'] == ('platform', './cmd/bootstrap-admin')
    assert 'bootstrap-admin' not in NATIVE.SERVICES
    source = (ROOT / 'scripts/local.py').read_text(encoding='utf-8')
    assert 'first_admin.add_argument("--config"' in source
    assert 'bootstrap_environment' in source
    dockerfile = (ROOT / 'platform/Dockerfile').read_text(encoding='utf-8')
    assert '-o /out/bootstrap-admin ./cmd/bootstrap-admin' in dockerfile
    assert 'COPY --from=build /out/bootstrap-admin /app/bootstrap-admin' in dockerfile


def test_unknown_native_service_does_not_launch_a_process():
    with pytest.raises(ValueError, match="unsupported native service"):
        NATIVE.command("unknown-agent", "python")
