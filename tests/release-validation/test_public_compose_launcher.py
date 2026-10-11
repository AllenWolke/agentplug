import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("public_compose", ROOT / "scripts/compose.py")
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


@pytest.mark.parametrize("arguments", [["reset"], ["reset", "--force", "--project", "agentplug-with-ragplaform"]])
def test_destructive_command_cannot_touch_interview_project_or_bypass_confirmation(arguments, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["compose.py", *arguments])
    monkeypatch.setattr(LAUNCHER.subprocess, "run", lambda *a, **kw: pytest.fail("Docker must not be invoked"))
    with pytest.raises(SystemExit) as result:
        LAUNCHER.main()
    assert result.value.code == 2


def test_private_env_path_is_passed_literally_and_not_evaluated(tmp_path, monkeypatch):
    settings = tmp_path / "private $(never-run).env"
    settings.write_text("INTERNAL_TOKEN=not-printed\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["compose.py", "config", "--env-file", str(settings)])
    seen = []

    def docker(command, **kwargs):
        seen.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(LAUNCHER.subprocess, "run", docker)
    assert LAUNCHER.main() == 0
    command, options = seen[0]
    assert command[command.index("--env-file") + 1] == str(settings.resolve())
    assert command[-2:] == ["config", "--quiet"]
    assert options.get("shell", False) is False
    assert "not-printed" not in str(command)


def test_repeated_env_files_and_selected_overlays_keep_declared_order(tmp_path, monkeypatch):
    base_env = tmp_path / "base.env"
    runtime_env = tmp_path / "runtime $(literal).env"
    base_env.write_text("BASE_ONLY=hidden\n", encoding="utf-8")
    runtime_env.write_text("RUNTIME_ONLY=hidden\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [
        "compose.py", "config",
        "--env-file", str(base_env), "--env-file", str(runtime_env),
        "--examples", "--runtime", "--profile", "full",
    ])
    seen = []

    def docker(command, **kwargs):
        seen.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(LAUNCHER.subprocess, "run", docker)
    assert LAUNCHER.main() == 0
    command = seen[0]
    env_paths = [command[index + 1] for index, item in enumerate(command[:-1]) if item == "--env-file"]
    compose_paths = [command[index + 1] for index, item in enumerate(command[:-1]) if item == "-f"]
    assert env_paths == [str(base_env.resolve()), str(runtime_env.resolve())]
    assert compose_paths == [
        str(ROOT / "compose.yaml"),
        str(ROOT / "deploy/compose/compose.examples.yaml"),
        str(ROOT / "deploy/compose/compose.runtime.yaml"),
    ]
    assert command[-2:] == ["config", "--quiet"]
    assert "hidden" not in str(command)


def test_runtime_overlay_requires_examples_and_does_not_invoke_docker(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["compose.py", "config", "--runtime"])
    monkeypatch.setattr(LAUNCHER.subprocess, "run", lambda *a, **kw: pytest.fail("Docker must not be invoked"))
    with pytest.raises(SystemExit) as result:
        LAUNCHER.main()
    assert result.value.code == 2


@pytest.mark.parametrize("state,health,expected", [("running", "healthy", 0), ("running", "unhealthy", 1), ("exited", "healthy", 1)])
def test_readiness_fails_on_unhealthy_or_stopped_platform(tmp_path, monkeypatch, state, health, expected):
    settings = tmp_path / "private.env"
    settings.write_text("", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["compose.py", "smoke", "--env-file", str(settings)])
    rows = [{"Service": name, "State": "running", "Health": "healthy"}
            for name in ["platform-app", "frontend", "postgres", "metric-runner", "kafka"]]
    rows[0].update(State=state, Health=health)
    monkeypatch.setattr(LAUNCHER.subprocess, "run", lambda command, **kw: subprocess.CompletedProcess(command, 0, json.dumps(rows)))
    assert LAUNCHER.main() == expected


def test_readiness_decodes_docker_labels_in_chinese_windows_workspace(tmp_path, monkeypatch):
    settings = tmp_path / "private.env"
    settings.write_text("", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["compose.py", "smoke", "--env-file", str(settings)])
    rows = [{"Service": name, "State": "running", "Health": "healthy", "Labels": "工作目录=D:/项目/agentplug"}
            for name in ["platform-app", "frontend", "postgres", "metric-runner", "kafka"]]
    raw = json.dumps(rows, ensure_ascii=False).encode("utf-8")
    def read_compose(command, **options):
        text = raw.decode(options.get("encoding", "gbk"), errors=options.get("errors", "strict"))
        return subprocess.CompletedProcess(command, 0, text)
    monkeypatch.setattr(LAUNCHER.subprocess, "run", read_compose)
    assert LAUNCHER.main() == 0


def test_readiness_includes_selected_overlay_processes_without_assuming_healthchecks(tmp_path, monkeypatch):
    settings = tmp_path / "private.env"
    settings.write_text("", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [
        "compose.py", "smoke", "--env-file", str(settings), "--examples", "--runtime",
    ])
    base = [{"Service": name, "State": "running", "Health": "healthy"}
            for name in ["platform-app", "frontend", "postgres", "metric-runner", "kafka"]]
    overlays = [{"Service": name, "State": "running"}
                for name in ["example-python", "example-go", "example-java", "code-runtime"]]
    command_seen = []

    def docker(command, **kwargs):
        command_seen.append(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(base + overlays))

    monkeypatch.setattr(LAUNCHER.subprocess, "run", docker)
    assert LAUNCHER.main() == 0
    compose_paths = [command_seen[0][index + 1] for index, item in enumerate(command_seen[0][:-1]) if item == "-f"]
    assert compose_paths == [
        str(ROOT / "compose.yaml"),
        str(ROOT / "deploy/compose/compose.examples.yaml"),
        str(ROOT / "deploy/compose/compose.runtime.yaml"),
    ]


def test_readiness_rejects_missing_kafka_even_when_other_services_are_healthy(tmp_path, monkeypatch):
    settings = tmp_path / "private.env"
    settings.write_text("", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["compose.py", "smoke", "--env-file", str(settings)])
    rows = [{"Service": name, "State": "running", "Health": "healthy"}
            for name in ["platform-app", "frontend", "postgres", "metric-runner"]]
    monkeypatch.setattr(LAUNCHER.subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, json.dumps(rows)))
    assert LAUNCHER.main() == 1


@pytest.mark.parametrize("stack,profile", [("eval", "manual"), ("eval-services", "fixture"), ("eval-services", "judge"), ("compensation", None)])
def test_optional_stacks_have_isolated_projects_and_repository_relative_paths(tmp_path, monkeypatch, stack, profile):
    settings = tmp_path / "private.env"
    settings.write_text("", encoding="utf-8")
    arguments = ["compose.py", "config", "--stack", stack, "--env-file", str(settings)]
    if profile:
        arguments += ["--profile", profile]
    monkeypatch.setattr(sys, "argv", arguments)
    seen = []
    monkeypatch.setattr(LAUNCHER.subprocess, "run", lambda command, **kw: seen.append(command) or subprocess.CompletedProcess(command, 0))
    assert LAUNCHER.main() == 0
    command = seen[0]
    assert command[command.index("--project-name") + 1] == "agentplug-" + stack
    assert command[command.index("--project-directory") + 1] == str(ROOT)
    assert [command[i + 1] for i, value in enumerate(command[:-1]) if value == "-f"] == [str(ROOT / ("deploy/compose/compose." + stack + ".yaml"))]


@pytest.mark.parametrize("arguments", [
    ["config", "--stack", "eval", "--project", "agentplug"],
    ["config", "--stack", "eval", "--examples"],
    ["init", "--stack", "compensation"],
    ["config", "--stack", "eval-services"],
    ["config", "--stack", "eval", "--profile", "full"],
    ["run", "--stack", "eval", "--service", "platform-app"],
    ["run", "--stack", "platform", "--service", "postgres"],
])
def test_optional_stack_rejects_cross_project_services_and_ambiguous_selection(monkeypatch, arguments):
    monkeypatch.setattr(sys, "argv", ["compose.py", *arguments])
    monkeypatch.setattr(LAUNCHER.subprocess, "run", lambda *a, **kw: pytest.fail("Docker must not be invoked"))
    with pytest.raises(SystemExit) as result:
        LAUNCHER.main()
    assert result.value.code == 2


def test_optional_tool_arguments_are_passed_without_shell_evaluation(tmp_path, monkeypatch):
    settings = tmp_path / "private.env"
    settings.write_text("", encoding="utf-8")
    tool_arguments = ["validate", "--file", "/inputs/literal $(never-run).json"]
    monkeypatch.setattr(sys, "argv", ["compose.py", "run", "--stack", "eval", "--env-file", str(settings),
                                     "--service", "agent-eval", "--command", *tool_arguments])
    seen = []
    monkeypatch.setattr(LAUNCHER.subprocess, "run", lambda command, **kw: seen.append((command, kw)) or subprocess.CompletedProcess(command, 0))
    assert LAUNCHER.main() == 0
    command, options = seen[0]
    assert command[-7:] == ["run", "--rm", "--no-deps", "agent-eval", *tool_arguments]
    assert options.get("shell", False) is False
