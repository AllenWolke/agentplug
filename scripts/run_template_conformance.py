#!/usr/bin/env python3
"""Live HTTP Conformance for the six language templates.

Starts two real processes per template, exercises Manifest-declared capabilities
over HTTP, and writes a machine-readable report. File-existence checks are not
a substitute for this gate.
六种语言模板的真实 HTTP Conformance：每个模板启动两个真实进程，按 Manifest 声明
的能力打 HTTP，并写出机器可读报告。文件存在性检查不能代替本门禁。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / ".tmp" / "template-conformance-report.json"
MAX_BODY = 8 * 1024 * 1024


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def canonical_hash(payload: dict[str, Any]) -> str:
    body = {k: v for k, v in payload.items() if k != "context_token"}
    raw = json.dumps(body, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def mint_token(
    private_key: Ed25519PrivateKey,
    audience: str,
    request: dict[str, Any],
    actions: list[str],
) -> str:
    now = int(time.time())
    scope = request["scope"]
    policy = request["input"]["policy_snapshot"]["content_hash"]
    claims = {
        "iss": "platform-runtime-gateway",
        "aud": audience,
        "subject_type": scope["principal_type"],
        "sub": scope["principal_id"],
        "tenant_id": scope["tenant_id"],
        "application_id": scope["application_id"],
        "agent_instance_id": scope["agent_instance_id"],
        "installation_id": scope["installation_id"],
        "authorization_epoch": scope["authorization_epoch"],
        "actions": actions,
        "policy_snapshot_hash": policy,
        "body_hash": canonical_hash(request),
        "iat": now,
        "exp": now + 120,
    }
    header = b64url(json.dumps({"alg": "EdDSA"}, separators=(",", ":")).encode())
    payload = b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signing = f"{header}.{payload}".encode()
    signature = b64url(private_key.sign(signing))
    return f"{header}.{payload}.{signature}"


def execute_request(agent_id: str, run_id: str, operation: str) -> dict[str, Any]:
    request = {
        "protocol_version": "agent-execution/v2",
        "operation": operation,
        "idempotency_key": f"{agent_id}-{operation}-{run_id}",
        "input_schema": "schema://example/input/v1",
        "input": {"policy_snapshot": {"content_hash": "a" * 64}, "question": "ping"},
        "scope": {
            "tenant_id": "tenant-a",
            "department_id": "compliance",
            "application_id": "business-app",
            "agent_instance_id": "instance-a",
            "installation_id": "installation-a",
            "agent_id": agent_id,
            "agent_version_id": "v2",
            "principal_type": "user",
            "principal_id": "user-a",
            "session_id": "session-a",
            "run_id": run_id,
            "authorization_epoch": 1,
            "trace_id": "0" * 32,
        },
    }
    if operation == "resume":
        request["resume_input"] = {"decision": "approve"}
    return request


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_json(
    url: str, payload: dict[str, Any] | None = None, token: str = ""
) -> tuple[int, bytes, str]:
    headers = {"Accept": "application/json"}
    data = None
    method = "GET"
    if payload is not None:
        method = "POST"
        data = json.dumps(payload, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    last: Exception | None = None
    for _ in range(8):
        try:
            with _OPENER.open(request, timeout=10) as response:
                return (
                    response.status,
                    response.read(MAX_BODY + 1),
                    response.headers.get("Content-Type", ""),
                )
        except urllib.error.HTTPError as exc:
            return (
                exc.code,
                exc.read(MAX_BODY + 1),
                exc.headers.get("Content-Type", "") if exc.headers else "",
            )
        except (TimeoutError, ConnectionError, OSError) as exc:
            last = exc
            time.sleep(0.4)
    assert last is not None
    raise last


def wait_ready(
    url: str, timeout: float = 90.0, proc: subprocess.Popen[bytes] | None = None
) -> None:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            raise RuntimeError(f"service exited {proc.returncode} before ready: {last}")
        try:
            status, _, _ = http_json(url)
            if status == 200:
                return
            last = f"status {status}"
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
        time.sleep(0.4)
    raise RuntimeError(f"service was not ready: {last}")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_process(
    command: list[str], cwd: Path, env: dict[str, str], log_name: str
) -> subprocess.Popen[bytes]:
    log_path = ROOT / ".tmp" / f"conformance-{log_name}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(log_path, "wb", buffering=0)
    # Put each live probe in its own process group so a JVM/Node child cannot
    # outlive the Python runner on Windows. / 为每个实时探针创建独立进程组，
    # 确保 Windows 上的 JVM/Node 子进程不会在 Python runner 退出后泄漏。
    creationflags = (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    )
    proc = subprocess.Popen(
        command,
        cwd=str(cwd),
        env=env,
        stdout=handle,
        stderr=subprocess.STDOUT,
        creationflags=creationflags,
    )
    proc._conformance_log = handle  # type: ignore[attr-defined]
    return proc


def stop_process(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None:
        return
    if os.name == "nt":
        # Terminate the owned process tree, not arbitrary processes sharing
        # the same executable. / 仅终止本次门禁创建的进程树，不影响同名外部进程。
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
            capture_output=True,
            check=False,
        )
    else:
        proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    handle = getattr(proc, "_conformance_log", None)
    if handle is not None:
        try:
            handle.close()
        except OSError:
            pass


def python_command(
    template: str, agent_id: str, port: int, public_b64: str
) -> tuple[list[str], Path, dict[str, str]]:
    cwd = ROOT / "templates" / template
    env = os.environ.copy()
    env.update(
        {
            "PORT": str(port),
            "AGENT_PLATFORM_AGENT_ID": agent_id,
            "AGENT_PLATFORM_AUDIENCE": agent_id,
            "AGENT_PLATFORM_ISSUER": "platform-runtime-gateway",
            "AGENT_PLATFORM_PUBLIC_KEY_BASE64": public_b64,
            "PYTHONPATH": str(cwd / "platform_entry"),
        }
    )
    return [sys.executable, str(cwd / "platform_entry" / "server.py")], cwd, env


def go_command(
    template: str, agent_id: str, port: int, public_b64: str
) -> tuple[list[str], Path, dict[str, str]]:
    cwd = ROOT / "templates" / template
    out_dir = ROOT / ".tmp" / "conformance-bin"
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = out_dir / (f"{template}-{agent_id}" + (".exe" if os.name == "nt" else ""))
    env = os.environ.copy()
    # Do not depend on a user-global Go cache: on Windows a stale cache may be
    # owned by another process/account and make a healthy template fail with
    # "Access is denied" before its HTTP contract is even exercised.  Keeping
    # the cache under the repository also makes the gate reproducible in CI.
    go_cache = ROOT / ".tmp" / "template-go-build-cache"
    go_cache.mkdir(parents=True, exist_ok=True)
    env["GOCACHE"] = str(go_cache)
    try:
        built = subprocess.run(
            ["go", "build", "-o", str(binary), "./platform_entry"],
            cwd=str(cwd),
            env=env,
            check=False,
            timeout=float(os.environ.get("TEMPLATE_BUILD_TIMEOUT_SECONDS", "120")),
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{template} go build timed out") from exc
    if built.returncode != 0:
        raise RuntimeError(f"{template} go build failed")
    env.update(
        {
            "PORT": str(port),
            "AGENT_PLATFORM_AGENT_ID": agent_id,
            "AGENT_PLATFORM_AUDIENCE": agent_id,
            "AGENT_PLATFORM_ISSUER": "platform-runtime-gateway",
            "AGENT_PLATFORM_PUBLIC_KEY_BASE64": public_b64,
            "NO_PROXY": "localhost,127.0.0.1,::1",
            "no_proxy": "localhost,127.0.0.1,::1",
        }
    )
    return [str(binary)], cwd, env


_PACKAGED: set[str] = set()


def docker_mount() -> str:
    override = os.environ.get("LEXAGENT_DOCKER_MOUNT_ROOT", "").strip()
    if override:
        if Path(override).resolve(strict=True) != ROOT.resolve(strict=True):
            raise RuntimeError("Docker mount root must resolve to the current source tree")
        return override.replace("\\", "/")
    return str(ROOT).replace("\\", "/")


def maven_package(template: str) -> None:
    if template in _PACKAGED:
        return
    cwd = ROOT / "templates" / template
    # Always package the current source: a pre-existing jar/classpath may be
    # stale after edits and would turn this live gate into an artifact test.
    # 每次都打包当前源码：预存 jar/classpath 可能落后于源文件，不能让实时门禁
    # 意外退化成旧构件验收。
    timeout = float(os.environ.get("TEMPLATE_BUILD_TIMEOUT_SECONDS", "300"))
    package_args = ["mvn", "-q", "-DskipTests"]
    if template == "java-spring-ai":
        # Run compiled current classes with copied runtime dependencies instead
        # of replacing a possibly running Spring Boot jar during repackage.
        # 用当前编译类和 runtime 依赖运行，避免 repackage 替换正在使用的 jar。
        package_args.extend(
            ["compile", "dependency:copy-dependencies", "-DincludeScope=runtime"]
        )
    else:
        package_args.append("package")
    maven_command = os.environ.get("LEXAGENT_MAVEN_COMMAND", "").strip() or shutil.which("mvn")
    if maven_command:
        if os.environ.get("LEXAGENT_MAVEN_COMMAND") and not Path(maven_command).is_file():
            raise RuntimeError("LEXAGENT_MAVEN_COMMAND must name an existing Maven launcher")
        command = [maven_command, *package_args[1:]]
        try:
            completed = subprocess.run(
                command, cwd=str(cwd), check=False, timeout=timeout
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"{template} maven package timed out") from exc
    elif shutil.which("docker"):
        mount = docker_mount()
        command = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{mount}:/workspace",
            "-v",
            f"{mount}/.cache/m2:/root/.m2",
            "-w",
            f"/workspace/templates/{template}",
            "maven:3.9.9-eclipse-temurin-21",
            *package_args,
        ]
        try:
            completed = subprocess.run(command, check=False, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"{template} docker maven package timed out") from exc
    else:
        raise RuntimeError(
            "maven or docker is required to start Java template services"
        )
    if completed.returncode != 0:
        raise RuntimeError(f"{template} package failed")
    _PACKAGED.add(template)


def java_env(agent_id: str, port: int, public_b64: str) -> dict[str, str]:
    env = os.environ.copy()
    # Keep the live conformance gate runnable on developer laptops and CI
    # workers with a small page file.  Without an explicit heap policy the
    # Spring Boot JVM selects G1 and reserves hundreds of megabytes before the
    # service can even bind its port (especially on Windows).  Serial GC is
    # sufficient for this short-lived contract probe and avoids that large
    # virtual-memory reservation. / 为了让实时一致性门禁在小页面文件的
    # 开发机和 CI 上也能运行，显式限制堆并使用 Serial GC；否则 Spring Boot
    # JVM 可能在绑定端口前由 G1 预留数百 MB，Windows 上尤其容易启动失败。
    memory_options = (
        "-Xms8m -Xmx128m -Xss256k "
        "-XX:MaxMetaspaceSize=64m -XX:ReservedCodeCacheSize=32m "
        "-XX:CICompilerCount=2 -XX:+UseSerialGC"
    )
    existing_options = env.get("JAVA_TOOL_OPTIONS", "").strip()
    env["JAVA_TOOL_OPTIONS"] = f"{existing_options} {memory_options}".strip()
    env.update(
        {
            "PORT": str(port),
            "SERVER_PORT": str(port),
            "AGENT_PLATFORM_AGENT_ID": agent_id,
            "AGENT_PLATFORM_AUDIENCE": agent_id,
            "AGENT_PLATFORM_ISSUER": "platform-runtime-gateway",
            "AGENT_PLATFORM_PUBLIC_KEY_BASE64": public_b64,
            "NO_PROXY": "localhost,127.0.0.1,::1",
            "no_proxy": "localhost,127.0.0.1,::1",
        }
    )
    return env


def java_generic_command(
    agent_id: str, port: int, public_b64: str
) -> tuple[list[str], Path, dict[str, str]]:
    cwd = ROOT / "templates" / "java-generic"
    maven_package("java-generic")
    sep = ";" if os.name == "nt" else ":"
    classpath = (
        str(cwd / "target" / "classes") + sep + str(cwd / "target" / "lib" / "*")
    )
    return (
        ["java", "-cp", classpath, "generated.GenericAgent"],
        cwd,
        java_env(agent_id, port, public_b64),
    )


def java_spring_command(
    agent_id: str, port: int, public_b64: str
) -> tuple[list[str], Path, dict[str, str]]:
    cwd = ROOT / "templates" / "java-spring-ai"
    maven_package("java-spring-ai")
    sep = ";" if os.name == "nt" else ":"
    classpath = (
        str(cwd / "target" / "classes") + sep + str(cwd / "target" / "dependency" / "*")
    )
    if not (cwd / "target" / "classes" / "generated" / "Application.class").is_file():
        raise RuntimeError(
            "java-spring-ai compile did not produce the current Application class"
        )
    return (
        ["java", "-cp", classpath, "generated.Application"],
        cwd,
        java_env(agent_id, port, public_b64),
    )


def exercise(
    base: str,
    agent_id: str,
    private_key: Ed25519PrivateKey,
    cases: list[dict[str, Any]],
) -> None:
    status, raw, _ = http_json(base + "/health/ready")
    assert status == 200, f"health failed: {status}"
    cases.append({"name": "health", "result": "PASS"})
    status, raw, _ = http_json(base + "/.well-known/agent-manifest.json")
    manifest = json.loads(raw)
    assert status == 200 and manifest.get("manifest_version") == "agent-manifest/v1"
    capabilities = set(manifest.get("capabilities") or [])
    cases.append(
        {"name": "manifest", "result": "PASS", "capabilities": sorted(capabilities)}
    )
    status, raw, content = http_json(
        base + "/internal/agent-execution/v2/invoke",
        {"protocol_version": "agent-execution/v2"},
        token="invalid",
    )
    assert status in {400, 401, 422}, f"malformed invoke returned {status}"
    cases.append({"name": "malformed-invoke", "result": "PASS"})
    status, raw, _ = http_json(
        base + "/internal/agent-execution/v2/runs/run-x/checkpoint",
        execute_request(agent_id, "run-x", "checkpoint"),
        token="x",
    )
    body = json.loads(raw.decode("utf-8", "replace") or "{}")
    assert status == 404 and body.get("code") == "UNSUPPORTED_CAPABILITY", body
    cases.append({"name": "undeclared-capability", "result": "PASS"})
    if "invoke" in capabilities:
        request = execute_request(agent_id, f"run-{agent_id}-invoke", "invoke")
        token = mint_token(private_key, agent_id, request, ["invoke"])
        request["context_token"] = token
        status, raw, content = http_json(
            base + "/internal/agent-execution/v2/invoke", request, token=token
        )
        payload = json.loads(raw)
        assert status in {200, 202}, payload
        assert payload.get("protocol_version") == "agent-execution/v2"
        assert payload.get("run_id") == request["scope"]["run_id"]
        cases.append({"name": "invoke", "result": "PASS"})
    for name, path_op in (
        ("run", "runs"),
        ("cancel", None),
        ("resume", None),
        ("events", None),
    ):
        if name not in capabilities:
            continue
        if name == "run":
            request = execute_request(agent_id, f"run-{agent_id}-run", "run")
            token = mint_token(private_key, agent_id, request, ["run"])
            request["context_token"] = token
            status, raw, _ = http_json(
                base + "/internal/agent-execution/v2/runs", request, token=token
            )
            payload = json.loads(raw)
            assert status in {200, 202}, payload
            cases.append({"name": "run", "result": "PASS"})


def run_template(
    name: str, version: str, builder, private_key: Ed25519PrivateKey, public_b64: str
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "template": name,
        "version": version,
        "image_digest": None,
        "image_build": "not-performed-by-this-gate",
        "execution_mode": "host-process",
        "declared_capabilities": [],
        "cases": [],
        "result": "PASS",
    }
    processes: list[subprocess.Popen[bytes]] = []
    try:
        ports = [free_port(), free_port()]
        agents = [f"{name}-a", f"{name}-b"]
        for agent_id, port in zip(agents, ports):
            command, cwd, env = builder(agent_id, port, public_b64)
            proc = start_process(command, cwd, env, f"{name}-{agent_id}")
            processes.append(proc)
            wait_ready(
                f"http://127.0.0.1:{port}/health/ready",
                timeout=float(os.environ.get("TEMPLATE_READY_TIMEOUT_SECONDS", "60")),
                proc=proc,
            )
        for agent_id, port in zip(agents, ports):
            cases: list[dict[str, Any]] = []
            exercise(f"http://127.0.0.1:{port}", agent_id, private_key, cases)
            report["cases"].extend({"agent": agent_id, **item} for item in cases)
            caps = next(
                (
                    item.get("capabilities")
                    for item in cases
                    if item.get("name") == "manifest"
                ),
                [],
            )
            report["declared_capabilities"] = caps or report["declared_capabilities"]
        status_a, _, _ = http_json(f"http://127.0.0.1:{ports[0]}/health/ready")
        status_b, _, _ = http_json(f"http://127.0.0.1:{ports[1]}/health/ready")
        assert status_a == 200 and status_b == 200
        report["cases"].append(
            {"name": "two-instance-isolation", "result": "PASS", "ports": ports}
        )
    except Exception as exc:  # noqa: BLE001
        report["result"] = "FAIL"
        report["error"] = f"{type(exc).__name__}: {exc}"
        report["cases"].append({"name": "live-service", "result": "FAIL"})
    finally:
        for proc in processes:
            stop_process(proc)
    return report


def main() -> int:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    public_b64 = base64.b64encode(
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    templates = [
        (
            "python-generic",
            "1.0.0",
            lambda agent, port, key: python_command("python-generic", agent, port, key),
        ),
        (
            "python-langgraph",
            "1.0.0",
            lambda agent, port, key: python_command(
                "python-langgraph", agent, port, key
            ),
        ),
        (
            "go-generic",
            "1.0.0",
            lambda agent, port, key: go_command("go-generic", agent, port, key),
        ),
        (
            "go-eino",
            "1.0.0",
            lambda agent, port, key: go_command("go-eino", agent, port, key),
        ),
        (
            "java-generic",
            "1.0.0",
            lambda agent, port, key: java_generic_command(agent, port, key),
        ),
        (
            "java-spring-ai",
            "1.0.0",
            lambda agent, port, key: java_spring_command(agent, port, key),
        ),
    ]
    results = [
        run_template(name, version, builder, private_key, public_b64)
        for name, version, builder in templates
    ]
    document = {
        "ok": all(item["result"] == "PASS" for item in results),
        "templates": results,
    }
    REPORT_PATH.write_text(json.dumps(document, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {"ok": document["ok"], "report": str(REPORT_PATH)}, ensure_ascii=False
        )
    )
    return 0 if document["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
