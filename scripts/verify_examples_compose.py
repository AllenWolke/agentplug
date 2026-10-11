"""Parse three-example Compose with synthetic credentials; never start services."""
import base64
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
report = {"result":"FAIL", "scope":"actual Compose parser and static runtime wiring only", "containers_started":0, "database_changed":False, "credentials_logged":False}
temporary = None
try:
    env = os.environ.copy()
    for path in (ROOT/"compose.yaml", ROOT/"deploy/compose/compose.examples.yaml"):
        for name in re.findall(r"\$\{([A-Z_]+):\?", path.read_text(encoding="utf-8")):
            env[name] = secrets.token_hex(32)
    env["PLATFORM_CONTEXT_PUBLIC_KEY"] = base64.b64encode(bytes(32)).decode()
    for language in ("GO","PYTHON","JAVA"):
        env["EXAMPLE_"+language+"_CLIENT_ID"] = "compose-fixture-"+language.lower()
    (ROOT/".tmp").mkdir(exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix="example-compose-", suffix=".env", dir=ROOT/".tmp", delete=False) as handle:
        temporary = Path(handle.name)
    result = subprocess.run(["docker","compose","--env-file",str(temporary),"-f",str(ROOT/"compose.yaml"),"-f",str(ROOT/"deploy/compose/compose.examples.yaml"),"--profile","full","config","--format","json"], env=env, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError("Compose parser rejected example overlay")
    config = json.loads(result.stdout)
    platform = config["services"]["platform-app"]["environment"]
    ids = set()
    for language in ("go","python","java"):
        service = config["services"]["example-"+language]
        environment = service["environment"]
        if service["image"] != "agentplug:example-"+language or service.get("ports") or not service.get("read_only"):
            raise RuntimeError("example image, port or read-only boundary mismatch")
        if environment["AGENT_PLATFORM_AUDIENCE"] != platform["PLATFORM_CONTEXT_AUDIENCE"] or environment["AGENT_PLATFORM_ISSUER"] != platform["PLATFORM_CONTEXT_ISSUER"]:
            raise RuntimeError("execution issuer or audience mismatch")
        if environment["PLATFORM_CAPABILITY_URL"] != "http://platform-app:8081":
            raise RuntimeError("example bypassed platform capability endpoint")
        ids.add(environment["AGENT_CLIENT_ID"])
    if len(ids) != 3 or config["name"] != "agentplug":
        raise RuntimeError("project or independent machine identity mismatch")
    report.update(result="PASS", example_images=["agentplug:example-"+x for x in ("go","python","java")], independent_workloads=True, execution_issuer_audience_match=True, no_example_host_ports=True)
except Exception as error:
    report["failure"] = type(error).__name__
finally:
    if temporary is not None and temporary.is_file():
        if temporary.resolve().parent != (ROOT/".tmp").resolve():
            raise RuntimeError("owned temporary path mismatch")
        temporary.unlink()
    report["temporary_env_removed"] = temporary is None or not temporary.exists()
    (ROOT/"docs/新增需求/github作品改造/T3-06-三语言Compose配置记录.json").write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
print(json.dumps(report, ensure_ascii=False))
raise SystemExit(0 if report["result"] == "PASS" and report["temporary_env_removed"] else 1)
