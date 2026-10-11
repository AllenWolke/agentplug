"""Initialization is sequential, fail-closed, version-matched and ephemeral."""
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("initialize_compose", ROOT / "scripts/initialize_compose.py")
INIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INIT)


def fake_docker(monkeypatch, *, running=None, failure=None, mismatch=False):
    commands = []
    services = {name: {"image": "selected:platform"} for name in INIT.PUBLIC_JOBS}
    services["platform-app"] = {"image": "selected:wrong" if mismatch else "selected:platform"}
    services["platform-migrate"]["build"] = {"context": "."}
    def run(command, **kwargs):
        commands.append(command)
        if "ps" in command:
            payload = json.dumps(running or [])
        elif "config" in command:
            payload = json.dumps({"services": services})
        else:
            payload = "private token must never enter terminal output"
        code = 9 if failure and failure in command else 0
        return subprocess.CompletedProcess(command, code, payload, "private password")
    monkeypatch.setattr(INIT.subprocess, "run", run)
    return commands


def test_normal_compose_has_no_init_services_or_dependencies():
    regular = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))["services"]
    init = yaml.safe_load((ROOT / "deploy/compose/compose.init.yaml").read_text(encoding="utf-8"))["services"]
    expected = set(INIT.INTERVIEW_JOBS if "regulatory-validation-agent" in regular else INIT.PUBLIC_JOBS)
    assert set(init) == expected
    assert not expected.intersection(regular)
    for spec in regular.values():
        assert not expected.intersection(spec.get("depends_on", {}))
    assert all(spec["profiles"] == ["init"] for spec in init.values())


def test_first_deployment_builds_then_runs_jobs_in_order_and_removes_containers(monkeypatch):
    commands = fake_docker(monkeypatch)
    assert INIT.initialize_stack(["docker", "compose"], ROOT, INIT.PUBLIC_JOBS) == 0
    runs = [command for command in commands if "run" in command]
    assert [command[-1] for command in runs] == list(INIT.PUBLIC_JOBS)
    assert all(command[-5:-1] == ["run", "--rm", "--no-deps", "-T"] for command in runs)
    operations = [next(item for item in command if item in {"ps", "config", "build", "up", "run"}) for command in commands]
    assert operations == ["ps", "config", "build", "up", "run", "run"]
    up = next(command for command in commands if "up" in command)
    assert up[-2:] == ["postgres", "kafka"]


@pytest.mark.parametrize("service", ["platform-app", "regulatory-qa-agent"])
def test_maintenance_guard_prevents_ddl_with_active_application(monkeypatch, service):
    commands = fake_docker(monkeypatch, running=[{"Service": service, "State": "running"}])
    assert INIT.initialize_stack(["docker", "compose"], ROOT, INIT.PUBLIC_JOBS) == 1
    assert len(commands) == 1


def test_migration_failure_stops_before_topic_job_and_withholds_credentials(monkeypatch, capsys):
    commands = fake_docker(monkeypatch, failure="platform-migrate")
    assert INIT.initialize_stack(["docker", "compose"], ROOT, INIT.PUBLIC_JOBS, build=False) == 9
    assert not any(command[-1] == "kafka-topic-bootstrap" for command in commands)
    out = capsys.readouterr()
    assert "private" not in out.out + out.err


def test_version_mismatch_cannot_initialize_or_start_services(monkeypatch):
    commands = fake_docker(monkeypatch, mismatch=True)
    assert INIT.initialize_stack(["docker", "compose"], ROOT, INIT.PUBLIC_JOBS) == 1
    assert len(commands) == 2

