"""Replay the documented first-developer journey in an isolated public source copy.

Builds a new platform and custom support-assistant; no external model calls.
Never reads the repository's private .env or existing deployment credentials.
Owner containers, volumes, image tags and workspace are removed after success.
On failure they remain for exact-state diagnosis; --resume or --cleanup use the
same owner workspace. Completed or ambiguous requests keep their original keys.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from check_publication import audit, candidates


def free_ports():
    ports = set()
    while len(ports) < 4:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            ports.add(sock.getsockname()[1])
    return sorted(ports)


def owner_state(folder):
    folder = folder.absolute()
    if any(p.is_symlink() or p.is_junction() for p in (folder, *folder.parents)):
        raise ValueError("workspace must not contain links or junctions")
    folder = folder.resolve(strict=True)
    folder.relative_to((ROOT / ".tmp").resolve())
    state = json.loads((folder / "state.json").read_text(encoding="utf-8"))
    if not re.fullmatch(
        r"agentplug-test-public-[a-f0-9]{12}", state.get("project", "")
    ):
        raise ValueError("exact isolated tutorial owner required")
    if Path(state["source"]).resolve() != folder / "source":
        raise ValueError("source copy must belong to this workspace")
    suffix = state["project"].removeprefix("agentplug-test-public-")
    expected = {
        name: "agentplug:test-" + name + "-" + suffix
        for name in ("platform", "frontend", "metric-runner")
    }
    if state.get("tags") != expected:
        raise ValueError("unexpected image ownership")
    return folder, state


def prepare():
    owner = "agentplug-test-public-" + uuid.uuid4().hex[:12]
    folder = ROOT / ".tmp" / ("developer-walkthrough-" + owner)
    folder.mkdir(parents=True, mode=0o700)
    entries, failures = audit(ROOT, candidates(ROOT))
    if failures:
        raise ValueError("public source audit failed; no deployment started")
    source = folder / "source"
    source.mkdir()
    for entry in entries:
        destination = source / entry["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / entry["path"], destination)
    suffix = owner.removeprefix("agentplug-test-public-")
    tags = {
        name: "agentplug:test-" + name + "-" + suffix
        for name in ("platform", "frontend", "metric-runner")
    }
    compose = source / "compose.yaml"
    content = compose.read_text(encoding="utf-8")
    for name, tag in tags.items():
        content = content.replace(
            "image: agentplug:" + name + "\n", "image: " + tag + "\n"
        )
    compose.write_text(content, encoding="utf-8")
    initialization = source / "deploy/compose/compose.init.yaml"
    overlay = json.loads(initialization.read_text(encoding="utf-8"))
    overlay["services"]["platform-migrate"]["image"] = tags["platform"]
    initialization.write_text(json.dumps(overlay), encoding="utf-8")
    state = {
        "project": owner,
        "source": str(source),
        "tags": tags,
        "ports": free_ports(),
        "source_file_count": len(entries),
        "steps": [],
    }
    (folder / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    return folder, state


def run_step(
    folder, state, command, *, input_data=None, cwd=None, env=None, timeout=1000
):
    environment = os.environ.copy()
    environment.update(
        PYTHONIOENCODING="utf-8",
        PYTHONDONTWRITEBYTECODE="1",
        GOCACHE=str(folder / "go-cache"),
    )
    if env:
        environment.update(env)
    print("RUN " + " ".join(command[:4]), flush=True)
    result = subprocess.run(
        command,
        cwd=cwd or state["source"],
        input=input_data,
        capture_output=True,
        env=environment,
        timeout=timeout,
    )
    state["steps"].append({"command": command, "exit_code": result.returncode})
    (folder / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    if result.returncode:
        (folder / "failure.log").write_bytes(result.stdout + result.stderr)
        raise RuntimeError("step failed; private diagnostics remain in " + str(folder))
    print("PASS", flush=True)
    return result.stdout


def journey(folder, state):
    source, owner = Path(state["source"]), state["project"]
    ports = state["ports"]
    if not (source / ".env").exists():
        password = secrets.token_urlsafe(24)
        run_step(
            folder,
            state,
            [
                sys.executable,
                "scripts/prepare_local_development.py",
                "--password-stdin",
                "--frontend-port",
                str(ports[0]),
                "--postgres-port",
                str(ports[1]),
                "--platform-port",
                str(ports[2]),
                "--internal-port",
                str(ports[3]),
            ],
            input_data=(password + "\n").encode(),
        )
    if not state.get("platform_started"):
        run_step(
            folder,
            state,
            [
                sys.executable,
                "scripts/compose.py",
                "config",
                "--env-file",
                ".env",
                "--project",
                owner,
            ],
        )
        run_step(
            folder,
            state,
            [
                sys.executable,
                "scripts/init_platform.py",
                "--env-file",
                ".env",
                "--project",
                owner,
            ],
        )
        already_bootstrapped = state.get("administrator_initialized") or any(
            step.get("exit_code") == 0
            and "scripts/bootstrap_first_admin.py" in step.get("command", [])
            for step in state["steps"]
        )
        if not already_bootstrapped:
            run_step(
                folder,
                state,
                [
                    sys.executable,
                    "scripts/bootstrap_first_admin.py",
                    "--env-file",
                    ".env",
                    "--config",
                    ".local-secrets/first-admin.json",
                    "--project",
                    owner,
                ],
            )
        state["administrator_initialized"] = True
        (folder / "state.json").write_text(
            json.dumps(state, indent=2), encoding="utf-8"
        )
        run_step(
            folder,
            state,
            [
                sys.executable,
                "scripts/compose.py",
                "up",
                "--env-file",
                ".env",
                "--project",
                owner,
            ],
        )
        state["platform_started"] = True
    run_step(
        folder,
        state,
        [
            sys.executable,
            "scripts/compose.py",
            "smoke",
            "--env-file",
            ".env",
            "--project",
            owner,
        ],
    )
    cli = source / "cli/agentctl"
    agent = cli / "out/support-assistant"
    if not agent.exists():
        run_step(
            folder,
            state,
            [
                "go",
                "run",
                "./cmd/agentctl",
                "create",
                "--template",
                "python-generic",
                "--language",
                "python",
                "--name",
                "support-assistant",
                "--output",
                "out/support-assistant",
            ],
            cwd=cli,
        )
    for filename, destination in (
        ("business.py", "domain/business.py"),
        ("server.py", "domain/server.py"),
        ("test_business.py", "eval/test_business.py"),
        ("input.schema.json", "eval/input.schema.json"),
        ("output.schema.json", "eval/output.schema.json"),
        ("requirements-dev.txt", "requirements-dev.txt"),
        ("Dockerfile.business", "Dockerfile.business"),
        ("dockerignore.business", ".dockerignore"),
    ):
        shutil.copyfile(
            source / "docs/developer/snippets" / filename, agent / destination
        )
    run_step(
        folder,
        state,
        ["go", "run", "./cmd/agentctl", "validate", "--path", "out/support-assistant"],
        cwd=cli,
    )
    virtualenv = folder / "agent-venv"
    interpreter = virtualenv / (
        "Scripts/python.exe" if os.name == "nt" else "bin/python"
    )
    if not interpreter.exists():
        run_step(folder, state, [sys.executable, "-m", "venv", str(virtualenv)])
    run_step(
        folder,
        state,
        [str(interpreter), "-m", "pip", "install", "-r", "requirements.txt"],
        cwd=agent,
    )
    run_step(
        folder,
        state,
        [str(interpreter), "-m", "pip", "install", "-r", "requirements-dev.txt"],
        cwd=agent,
    )
    results = run_step(
        folder,
        state,
        [
            str(interpreter),
            "-m",
            "pytest",
            "platform_entry",
            "eval",
            "-q",
            "-p",
            "no:cacheprovider",
        ],
        cwd=agent,
        env={"PYTHONPATH": str(agent / "platform_entry")},
    )
    if b"skipped" in results:
        raise RuntimeError("generated project contains skipped contract checks")
    state["generated_tests"] = next(
        line
        for line in reversed(results.decode("utf-8", errors="replace").splitlines())
        if "passed" in line
    )
    run_step(
        folder,
        state,
        [
            sys.executable,
            str(ROOT / "tests/e2e/developer_agent_delivery.py"),
            "--workspace",
            str(folder),
        ],
        timeout=1000,
    )


def cleanup(folder, state):
    folder, state = owner_state(folder)
    source, owner = Path(state["source"]), state["project"]
    command = [
        "docker",
        "compose",
        "--project-directory",
        str(source),
        "--project-name",
        owner,
        "--env-file",
        str(source / ".env"),
        "-f",
        str(source / "compose.yaml"),
        "--profile",
        "modular",
    ]
    overlay = source / ".local-secrets/tutorial.compose.json"
    if overlay.is_file():
        command += ["-f", str(overlay)]
    if (source / "compose.yaml").is_file() and (source / ".env").is_file():
        result = subprocess.run(
            command + ["down", "--volumes", "--remove-orphans"],
            cwd=source, capture_output=True, timeout=90,
        )
        if result.returncode:
            raise RuntimeError("owned Compose cleanup failed; retained workspace")
    for resource in ("container", "volume"):
        result = subprocess.run(
            [
                "docker",
                resource,
                "ls",
                "-q",
                "--filter",
                "label=com.docker.compose.project=" + owner,
            ],
            capture_output=True,
        )
        if result.returncode or result.stdout.strip():
            raise RuntimeError("owned Docker resources remain; retained workspace")
    tags = [
        *state["tags"].values(),
        "agentplug:tutorial-support-" + owner.removeprefix("agentplug-test-public-"),
    ]
    for tag in tags:
        existing = subprocess.run(
            ["docker", "image", "inspect", tag], capture_output=True
        )
        if existing.returncode == 0:
            removed = subprocess.run(
                ["docker", "image", "rm", tag], capture_output=True
            )
            if removed.returncode:
                raise RuntimeError("owned image tag removal failed; retained workspace")
    for child in folder.rglob("*"):
        if child.is_symlink() or child.is_junction():
            raise RuntimeError("workspace contains a link; refused recursive cleanup")
    def remove_readonly(function, path, error):
        if not isinstance(error, PermissionError):
            raise error
        candidate = Path(path).resolve()
        candidate.relative_to(folder)
        if candidate.is_symlink() or candidate.is_junction():
            raise RuntimeError("cleanup target became a link")
        candidate.chmod(0o700)
        function(path)

    shutil.rmtree(folder, onexc=remove_readonly)
    return {
        "temporary_containers_removed": True,
        "temporary_volumes_removed": True,
        "temporary_image_tags_removed": tags,
        "temporary_workspace_removed": not folder.exists(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument(
        "--resume",
        type=Path,
        help="resume the exact owner workspace printed on failure",
    )
    actions.add_argument(
        "--cleanup", type=Path, help="remove only the exact tutorial owner"
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="retain the completed tutorial for interactive inspection",
    )
    parser.add_argument(
        "--report", type=Path, default=ROOT / ".tmp/developer-walkthrough-report.json"
    )
    args = parser.parse_args()
    report_path = args.report.absolute()
    report_path.relative_to(ROOT)
    folder, state = (
        owner_state(args.resume or args.cleanup)
        if args.resume or args.cleanup
        else prepare()
    )
    try:
        if args.cleanup:
            outcome = cleanup(folder, state)
            if report_path.is_file():
                previous = json.loads(report_path.read_text(encoding="utf-8"))
                if previous.get("project") == state["project"]:
                    previous["cleanup"] = outcome
                    previous.pop("retained_workspace", None)
                    report_path.write_text(json.dumps(previous, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps(outcome))
            return 0
        journey(folder, state)
        report = json.loads(
            (folder / "delivery-receipts.json").read_text(encoding="utf-8")
        )
        report.update(
            complete=True,
            external_provider_calls=0,
            generated_tests=state["generated_tests"],
            source_file_count=state["source_file_count"],
            documented_commands=state["steps"],
        )
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report["cleanup"] = {"status": "pending"}
        report_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        if not args.keep:
            report["cleanup"] = cleanup(folder, state)
        else:
            report["retained_workspace"] = str(folder)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(
            json.dumps(
                {
                    "result": "PASS",
                    "report": str(report_path),
                    "project": state["project"],
                }
            )
        )
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        print(
            "Resume or clean the exact owner workspace: " + str(folder), file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
