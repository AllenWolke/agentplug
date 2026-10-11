#!/usr/bin/env python3
"""Time the supported-template Agent create flow.

Stages: create, format/compile, test, Docker build, start, Conformance.
A total above 30 minutes is FAIL. Missing Docker is BLOCKED, never a fake PASS.
对受支持模板的 Agent 创建流程计时。总耗时超过 30 分钟为 FAIL；缺少 Docker 记
BLOCKED，绝不能写成假 PASS。
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / ".tmp" / "agent-create-timing.json"
LIMIT_SECONDS = 30 * 60
AGENTCTL = ROOT / "cli" / "agentctl"
OUTPUT_REL = "out/timing-agent"


def run(command: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    completed = subprocess.run(command, cwd=str(cwd), env=env or os.environ.copy(), check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()[-800:]
        raise RuntimeError(f"command failed ({completed.returncode}): {' '.join(command)} :: {detail}")


def timed(name: str, stages: list[dict[str, object]], fn) -> None:
    started = time.perf_counter()
    fn()
    elapsed = time.perf_counter() - started
    stages.append({"stage": name, "seconds": round(elapsed, 3), "result": "PASS"})


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> int:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    stages: list[dict[str, object]] = []
    overall = "PASS"
    started = time.perf_counter()
    generated = AGENTCTL / OUTPUT_REL
    shutil.rmtree(generated, ignore_errors=True)
    container = ""
    image = f"lexagent-create-timing:{uuid.uuid4().hex}"
    try:
        timed("create", stages, lambda: run(
            ["go", "run", "./cmd/agentctl", "create", "--language", "python", "--template", "python-generic", "--name", "timing-agent", "--output", OUTPUT_REL],
            AGENTCTL,
        ))
        timed("format-compile", stages, lambda: run([sys.executable, "-m", "py_compile", "platform_entry/server.py"], generated))
        timed("test", stages, lambda: run(
            [sys.executable, "-m", "pytest", "-q", "platform_entry"],
            generated,
            {**os.environ, "PYTHONPATH": str(generated / "platform_entry")},
        ))
        if shutil.which("docker") is None:
            stages.append({"stage": "docker-build", "seconds": 0, "result": "BLOCKED", "reason": "docker not on PATH"})
            overall = "BLOCKED"
        else:
            timed("docker-build", stages, lambda: run(["docker", "build", "-t", image, "."], generated))

            def _start() -> None:
                nonlocal container
                port = free_port()
                key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                completed = subprocess.run(
                    [
                        "docker", "run", "-d", "--rm",
                        "-p", f"127.0.0.1:{port}:8080",
                        "-e", "PORT=8080",
                        "-e", "AGENT_PLATFORM_AGENT_ID=timing-agent",
                        "-e", f"AGENT_PLATFORM_PUBLIC_KEY_BASE64={key}",
                        image,
                    ],
                    check=False, capture_output=True, text=True,
                )
                if completed.returncode != 0:
                    raise RuntimeError(completed.stderr[-800:])
                container = completed.stdout.strip()
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                deadline = time.time() + 60
                last = ""
                while time.time() < deadline:
                    try:
                        with opener.open(f"http://127.0.0.1:{port}/health/ready", timeout=2) as response:
                            if response.status == 200:
                                return
                    except Exception as exc:  # noqa: BLE001
                        last = str(exc)
                    time.sleep(0.5)
                raise RuntimeError(f"generated image did not become ready: {last}")

            timed("start", stages, _start)
        timed("conformance", stages, lambda: run([sys.executable, str(ROOT / "scripts" / "run_template_conformance.py")], ROOT))
        total = time.perf_counter() - started
        if total > LIMIT_SECONDS:
            overall = "FAIL"
        document = {"result": overall, "total_seconds": round(total, 3), "limit_seconds": LIMIT_SECONDS, "stages": stages}
        REPORT_PATH.write_text(json.dumps(document, indent=2), encoding="utf-8")
        print(json.dumps({"result": overall, "total_seconds": document["total_seconds"], "report": str(REPORT_PATH)}))
        return 0 if overall == "PASS" else 1
    except Exception as exc:  # noqa: BLE001
        total = time.perf_counter() - started
        document = {"result": "FAIL", "total_seconds": round(total, 3), "limit_seconds": LIMIT_SECONDS, "stages": stages, "error": str(exc)[:800]}
        REPORT_PATH.write_text(json.dumps(document, indent=2), encoding="utf-8")
        print(json.dumps({"result": "FAIL", "error": str(exc)[:400], "report": str(REPORT_PATH)}, ensure_ascii=False))
        return 1
    finally:
        if container:
            subprocess.run(["docker", "rm", "-f", container], check=False, capture_output=True)
        if shutil.which("docker"):
            subprocess.run(["docker", "image", "rm", image], check=False, capture_output=True)
        shutil.rmtree(generated, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
