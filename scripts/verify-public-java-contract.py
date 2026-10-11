"""Verify Java's shared execution fixtures using the reviewed cached toolchain."""
import json
from pathlib import Path
import shutil
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
owner = "public-java-contract-" + uuid.uuid4().hex
temporary = ROOT / ".tmp" / owner
workspace = temporary / "workspace"
name = "agentplug-" + owner
evidence = ROOT / "docs/新增需求/github作品改造"
receipt = {"owner": owner, "tests_passed": False, "temporary_images_built": [], "cleanup_errors": []}
try:
    for relative in ["sdk/java", "agents/examples/java-spring-ai", "examples/java-tickets", "contracts"]:
        shutil.copytree(ROOT / relative, workspace / relative,
                        ignore=shutil.ignore_patterns("target", "__pycache__", ".pytest_cache"))
    command = ["docker", "run", "--rm", "--name", name, "--label", "agentplug.test.owner=" + owner,
               "--network", "none", "--mount", f"type=bind,source={workspace},target=/workspace",
               "--mount", f"type=bind,source={ROOT / '.cache/m2'},target=/m2,readonly",
               "--workdir", "/workspace", "maven:3.9.9-eclipse-temurin-21",
               "mvn", "--batch-mode", "--no-transfer-progress", "--offline", "-s", "/m2/settings-docker.xml",
               "-Dmaven.repo.local=/m2/repository", "-f", "sdk/java/pom.xml", "-pl", "agent-platform-sdk", "-am",
               "-Dtest=ExecutionContractFixtureTest", "-Dsurefire.failIfNoSpecifiedTests=false", "test"]
    with (evidence / "T3-03-JavaSDK公共夹具容器验证.log").open("wb") as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT)
    receipt["tests_passed"] = result.returncode == 0
    import xml.etree.ElementTree as ET
    totals = {key: 0 for key in ["tests", "failures", "errors", "skipped"]}
    for report in workspace.rglob("surefire-reports/TEST-*.xml"):
        suite = ET.parse(report).getroot()
        for key in totals:
            totals[key] += int(suite.attrib.get(key, 0))
    receipt["test_totals"] = totals
    receipt["tests_passed"] = receipt["tests_passed"] and totals["tests"] > 0 and not any(totals[k] for k in ["failures", "errors", "skipped"])
finally:
    inspection = subprocess.run(["docker", "inspect", name], capture_output=True)
    if inspection.returncode == 0:
        container = json.loads(inspection.stdout)[0]
        if container.get("Config", {}).get("Labels", {}).get("agentplug.test.owner") == owner:
            removal = subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            if removal.returncode:
                receipt["cleanup_errors"].append("owned container cleanup failed")
        else:
            receipt["cleanup_errors"].append("container owner mismatch")
    path = temporary.resolve()
    if path.is_relative_to((ROOT / ".tmp").resolve()) and path.name == owner and not temporary.is_symlink():
        shutil.rmtree(temporary, ignore_errors=False)
    else:
        receipt["cleanup_errors"].append("temporary path ownership check failed")
    receipt["temporary_workspace_removed"] = not temporary.exists()
    (evidence / "T3-03-JavaSDK公共夹具容器验证.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps(receipt, ensure_ascii=False))
raise SystemExit(0 if receipt["tests_passed"] and not receipt["cleanup_errors"] else 1)
