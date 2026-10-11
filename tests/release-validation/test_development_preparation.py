"""Behavioral checks for private development configuration generation."""

import base64
import importlib.util
import json
import io
from pathlib import Path
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("development_preparation", ROOT / "scripts/prepare_local_development.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
PORTS = {"FRONTEND_HOST_PORT": 33000, "POSTGRES_HOST_PORT": 35432,
         "PLATFORM_HOST_PORT": 38082, "PLATFORM_INTERNAL_HOST_PORT": 38083}


def settings(path):
    return dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines()
                if line and not line.startswith("#"))


def test_generated_credentials_are_independent_and_bootstrap_matches_database(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    (tmp_path / ".env.example").write_text((ROOT / ".env.example").read_text(encoding="utf-8"), encoding="utf-8")
    environment, administrator = MODULE.prepare(tmp_path, "platform.admin", "example-test-password-only", PORTS)
    values = settings(environment)
    request = json.loads(administrator.read_text(encoding="utf-8"))
    assert len({values[key] for key in MODULE.SECRET_KEYS}) == len(MODULE.SECRET_KEYS)
    assert all(len(values[key]) >= 32 for key in MODULE.SECRET_KEYS)
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(values["PLATFORM_CONTEXT_PRIVATE_KEY"]))
    assert private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == base64.b64decode(values["PLATFORM_CONTEXT_PUBLIC_KEY"])
    assert values["PLATFORM_RUNTIME_DB_PASSWORD"] in request["db_dsn"]
    assert request["local_password"] == "example-test-password-only"
    assert values["PLATFORM_DEMO_IDENTITY_BOOTSTRAP"] == "false"
    assert values["FRONTEND_AUTH_MODE"] == "local"
    assert values["FRONTEND_HOST_PORT"] == "33000"


def test_existing_files_remain_unchanged(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    (tmp_path / ".env").write_text("existing private configuration", encoding="utf-8")
    with pytest.raises(FileExistsError):
        MODULE.prepare(tmp_path, "platform.admin", "example-test-password-only", PORTS)
    assert (tmp_path / ".env").read_text() == "existing private configuration"
    assert not (tmp_path / ".local-secrets/first-admin.json").exists()


@pytest.mark.parametrize("username,password,ports", [
    ("platform.admin", "short", PORTS),
    ("../invalid", "example-test-password-only", PORTS),
    ("platform.admin", "example-test-password-only", {**PORTS, "FRONTEND_HOST_PORT": 35432}),
    ("platform.admin", "example-test-password-only", {**PORTS, "FRONTEND_HOST_PORT": 70000}),
])
def test_invalid_input_creates_no_configuration(tmp_path, monkeypatch, username, password, ports):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    with pytest.raises(ValueError):
        MODULE.prepare(tmp_path, username, password, ports)
    assert not (tmp_path / ".env").exists()


def test_destination_must_stay_inside_repository(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path / "repository")
    with pytest.raises(ValueError):
        MODULE.prepare(tmp_path / "outside", "platform.admin", "example-test-password-only", PORTS)
    assert not (tmp_path / "outside").exists()


def test_password_stdin_creates_configuration_without_echoing_password(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    (tmp_path / ".env.example").write_text((ROOT / ".env.example").read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["prepare", "--password-stdin"])
    monkeypatch.setattr(sys, "stdin", io.StringIO("example-test-password-only\n"))
    assert MODULE.main() == 0
    assert json.loads((tmp_path / ".local-secrets/first-admin.json").read_text(encoding="utf-8"))["local_password"] == "example-test-password-only"
    output = capsys.readouterr()
    assert "example-test-password-only" not in output.out + output.err


@pytest.mark.parametrize("raw", ["", "too-short\n", "valid-example-password\nsecond-line\n", "x" * 300])
def test_invalid_password_stdin_leaves_no_configuration(tmp_path, monkeypatch, raw):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", ["prepare", "--password-stdin"])
    monkeypatch.setattr(sys, "stdin", io.StringIO(raw))
    assert MODULE.main() == 1
    assert not (tmp_path / ".env").exists()
