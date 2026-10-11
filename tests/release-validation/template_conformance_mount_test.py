"""Live template builds must mount the source tree under test."""

from pathlib import Path

import pytest

from scripts import run_template_conformance as conformance


def test_default_mount_is_current_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LEXAGENT_DOCKER_MOUNT_ROOT", raising=False)
    assert Path(conformance.docker_mount()).resolve() == conformance.ROOT.resolve()


def test_override_cannot_redirect_build_to_another_checkout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("LEXAGENT_DOCKER_MOUNT_ROOT", str(tmp_path))
    with pytest.raises(RuntimeError, match="current source tree"):
        conformance.docker_mount()


def test_explicit_maven_launcher_must_exist(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("LEXAGENT_MAVEN_COMMAND", str(tmp_path / "missing-maven"))
    with pytest.raises(RuntimeError, match="existing Maven launcher"):
        conformance.maven_package("java-generic")
