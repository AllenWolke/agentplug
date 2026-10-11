"""Smoke-check the formal Go example image; clean only owned test containers."""
import argparse
import base64
import json
import secrets
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


def docker(*arguments, timeout=30):
    result = subprocess.run(["docker", *arguments], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=timeout)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--example", choices=["go", "java", "python"], default="go")
    example = parser.parse_args().example
    image_name = "agentplug:example-" + example
    agent_id = {"go":"example-go-operations", "java":"example-java-tickets", "python":"example-python-documents"}[example]
    evidence_name = {"go":"T3-05-Go正式镜像启动记录.json", "java":"T3-07-Java正式镜像启动记录.json", "python":"T3-06-Python正式镜像启动记录.json"}[example]
    owner = example + "-example-" + secrets.token_hex(12)
    names = [owner + "-missing", owner + "-runtime"]
    created = []
    report = {"result": "FAIL", "owner": owner, "image": image_name,
              "real_provider_calls": 0, "database_changed": False,
              "temporary_images_built": [], "cleanup_remaining": []}
    try:
        inspected = docker("image", "inspect", image_name, "--format", "{{json .}}")
        if inspected.returncode:
            raise RuntimeError("formal example image is missing")
        image = json.loads(inspected.stdout)
        if image["Config"]["User"] != "65532:65532":
            raise RuntimeError("image must run as a non-root user")
        report.update(image_id=image["Id"], image_bytes=image["Size"], non_root=True)
        missing = docker("run", "--name", names[0], "--label", "agentplug.test.owner=" + owner,
                         "--network", "none", "--read-only", "--cap-drop", "ALL",
                         "--security-opt", "no-new-privileges:true", image_name)
        # Never print raw logs or environment values.
        check = docker("container", "inspect", names[0], "--format", '{{index .Config.Labels "agentplug.test.owner"}}')
        if check.returncode == 0 and check.stdout.strip() == owner:
            created.append(names[0])
        expected_failure = {"go":"platform capability verification is not configured", "java":"Java ticket Agent configuration or startup failed", "python":"platform verification key and capability URL required"}[example]
        if missing.returncode == 0 or expected_failure not in missing.stderr + missing.stdout:
            raise RuntimeError("unconfigured image did not fail closed")
        report["missing_verification_refused"] = True
        env = {"AGENT_PLATFORM_PUBLIC_KEY_BASE64": base64.b64encode(bytes(32)).decode(),
               "APP_ENV": "production",
               "AGENT_PLATFORM_ISSUER": "platform", "AGENT_PLATFORM_AGENT_ID": agent_id,
               "AGENT_PLATFORM_AUDIENCE": "agent-runtime", "PLATFORM_CAPABILITY_URL": "http://127.0.0.1:9",
               "INTERNAL_TOKEN": secrets.token_hex(32), "INTERNAL_SIGNING_SECRET": secrets.token_hex(32),
               "AGENT_CLIENT_ID": "smoke-machine", "AGENT_CLIENT_SECRET": secrets.token_hex(32)}
        arguments = ["run", "-d", "--name", names[1], "--label", "agentplug.test.owner=" + owner,
                     "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                     "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "-p", "127.0.0.1::8080"]
        for name, value in env.items():
            arguments.extend(["-e", name + "=" + value])
        started = docker(*arguments, image_name)
        if started.returncode:
            raise RuntimeError("configured image failed to start")
        created.append(names[1])
        port = docker("port", names[1], "8080/tcp")
        if port.returncode or not port.stdout.strip().startswith("127.0.0.1:"):
            raise RuntimeError("smoke port must be loopback only")
        base = "http://" + port.stdout.strip()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(30):
            try:
                with opener.open(base + "/health/ready", timeout=1) as response:
                    if response.status == 200:
                        break
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        else:
            raise RuntimeError("configured image readiness failed")
        with opener.open(base + "/.well-known/agent-manifest.json", timeout=2) as response:
            manifest = json.load(response)
        if manifest["agent_id"] != agent_id or "agent-execution/v2" not in manifest["execution_protocols"]:
            raise RuntimeError("runtime manifest does not match the example")
        if example == "python":
            published = Path(__file__).resolve().parents[1] / "examples/python-documents/manifest.json"
            if manifest != json.loads(published.read_text(encoding="utf-8")):
                raise RuntimeError("Python runtime manifest differs from Catalog input")
            report["runtime_manifest_matches_catalog_input"] = True
        request = urllib.request.Request(base + "/internal/agent-execution/v2/invoke",
                                        data=json.dumps({"protocol_version": "agent-execution/v2", "operation": "invoke",
                                                         "context_token": "invalid-context-token-with-32-bytes", "idempotency_key": "smoke-command",
                                                         "input_schema": "schema://" + agent_id + "/input/v1",
                                                         "input": {}, "scope": {"tenant_id": "smoke", "department_id": "smoke",
                                                         "application_id": "smoke", "installation_id": "smoke", "agent_instance_id": "smoke",
                                                         "agent_id": agent_id, "agent_version_id": "smoke", "principal_type": "user",
                                                         "principal_id": "smoke", "run_id": "smoke", "session_id": "smoke",
                                                         "trace_id": "0" * 32, "authorization_epoch": 1}}).encode(),
                                        headers={"Content-Type": "application/json"}, method="POST")
        try:
            opener.open(request, timeout=2)
            raise RuntimeError("unsigned invocation accepted")
        except urllib.error.HTTPError as error:
            if error.code != 401:
                raise RuntimeError("unsigned invocation did not fail authentication")
        report.update(result="PASS", configured_readiness=True, runtime_manifest=True,
                      unsigned_invocation_refused=True, scope="container startup and unauthenticated boundary only")
    except RuntimeError as error:
        report["failure"] = str(error)
        raise
    finally:
        # Inspect every freshly generated name, including a run that timed out
        # after Docker created its container but before reporting success.
        for name in reversed(names):
            check = docker("container", "inspect", name, "--format", '{{index .Config.Labels "agentplug.test.owner"}}')
            if check.returncode == 0 and check.stdout.strip() == owner:
                if docker("rm", "-f", name).returncode:
                    report["cleanup_remaining"].append(name)
            elif check.returncode == 0:
                report["cleanup_remaining"].append(name)
        output = Path(__file__).resolve().parents[1] / "docs/新增需求/github作品改造" / evidence_name
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if report["cleanup_remaining"]:
        raise RuntimeError("owned smoke container cleanup incomplete")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit("Example image verification failed; inspect the saved redacted stage report") from None
