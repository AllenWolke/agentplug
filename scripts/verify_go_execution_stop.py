"""Verify SDK execution exit barriers on Linux with the race detector.

Only a labelled, disposable container is used. Repository mount is read-only;
module/build caches live in tmpfs, not host or shared Docker cache directories.
No project database, external model or credential is used.
"""
import json
import hashlib
from pathlib import Path
import subprocess
import uuid
import argparse
import os
import re

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "docs/新增需求/github作品改造"
OWNER = "sdk-stop-" + uuid.uuid4().hex
NAME = "agentplug-test-" + OWNER
IMAGE = "golang:1.25-bookworm"
parser = argparse.ArgumentParser()
parser.add_argument("--batch-id", default="sdk-stop-" + uuid.uuid4().hex)
args = parser.parse_args()
if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}[a-z0-9]|[a-z0-9]", args.batch_id):
    raise SystemExit("invalid batch identifier")
report_name = "T3-20-GoSDK集中回归-Linux-" + args.batch_id
if any((REPORT / (report_name + suffix)).exists() for suffix in (".log", ".json")):
    raise SystemExit("refusing to overwrite existing evidence")
download_cache = Path(os.environ["USERPROFILE"]) / "go/pkg/mod/cache/download"
if not download_cache.is_dir():
    raise SystemExit("existing offline Go download cache is required")
receipt = {"owner": OWNER, "scope": "actual Linux Go SDK signed HTTP and handler exit barriers; no platform database, external supplier or durable restart recovery acceptance", "passed_tests": [], "skipped_tests": [], "cleanup_errors": [], "temporary_images_built": []}
def sources():
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((ROOT / "sdk/go").rglob("*.go"))}
receipt["source_sha256"] = sources()
log = b""
try:
    REPORT.mkdir(parents=True, exist_ok=True)
    inspection = subprocess.run(["docker", "image", "inspect", IMAGE], check=True, capture_output=True)
    receipt["image_id"] = json.loads(inspection.stdout)[0]["Id"]
    command = ["docker", "run", "--rm", "--name", NAME, "--label", "agentplug.test.owner=" + OWNER,
               "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--tmpfs", "/tmp:rw,exec,nosuid,size=1g", "--tmpfs", "/test-cache:rw,exec,nosuid,size=2g",
               "--env", "GOCACHE=/test-cache/build", "--env", "GOMODCACHE=/test-cache/mod", "--env", "GOTOOLCHAIN=local",
               "--env", "GOPROXY=file:///module-cache", "--env", "GOSUMDB=off",
               "--mount", "type=bind,source="+str(download_cache)+",target=/module-cache,readonly",
               "--mount", "type=bind,source="+str(ROOT)+",target=/workspace,readonly",
               "--workdir", "/workspace/sdk/go", IMAGE, "go", "test", "-race", "-count=1", "-json", "./..."]
    result = subprocess.run(command, capture_output=True, timeout=420)
    log = result.stdout + result.stderr
    receipt["exit_code"] = result.returncode
    for line in result.stdout.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            continue
        if event.get("Test") and event.get("Action") in ("pass", "skip"):
            field = "passed_tests" if event["Action"] == "pass" else "skipped_tests"
            receipt[field].append(event["Test"])
    required = {"TestExecutionCancellationRequiresHandlerExit", "TestExecutionCancellationRequiresHandlerExit/invoke", "TestExecutionCancellationRequiresHandlerExit/run", "TestStopAuthorityDoesNotReturnBusinessOutput", "TestResumeDoesNotDuplicateStartedLifecycleEvent", "TestServerContainsBusinessPanicsPerRun"}
    receipt["sources_unchanged_during_test"] = sources() == receipt["source_sha256"]
    receipt["passed"] = result.returncode == 0 and required <= set(receipt["passed_tests"]) and not receipt["skipped_tests"] and receipt["sources_unchanged_during_test"]
except subprocess.TimeoutExpired as error:
    log = (error.stdout or b"") + (error.stderr or b"")
    receipt["error"] = "owned Linux SDK verification timed out"
    receipt["passed"] = False
except Exception as error:
    receipt["error"] = type(error).__name__
    receipt["passed"] = False
finally:
    try:
        inspection = subprocess.run(["docker", "container", "inspect", NAME], capture_output=True)
        if inspection.returncode == 0:
            info = json.loads(inspection.stdout)[0]
            if info.get("Config", {}).get("Labels", {}).get("agentplug.test.owner") != OWNER:
                raise RuntimeError("container owner mismatch")
            subprocess.run(["docker", "rm", "--force", NAME], check=True, capture_output=True)
        verification = subprocess.run(["docker", "ps", "--all", "--filter", "name=^"+NAME+"$", "--format", "{{.Names}}"], check=True, capture_output=True)
        receipt["temporary_container_removed"] = not verification.stdout.strip()
        if not receipt["temporary_container_removed"]:
            raise RuntimeError("owned container remains")
        receipt["private_tmpfs_cache_removed"] = receipt["temporary_container_removed"]
    except Exception as error:
        receipt["cleanup_errors"].append(type(error).__name__)
    (REPORT / (report_name + ".log")).write_bytes(log)
    (REPORT / (report_name + ".json")).write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"passed":receipt.get("passed"), "passed_tests":len(receipt["passed_tests"]), "skipped_tests":len(receipt["skipped_tests"]), "cleanup_errors":receipt["cleanup_errors"], "report":report_name}, ensure_ascii=False))
raise SystemExit(0 if receipt.get("passed") and not receipt["cleanup_errors"] else 1)
