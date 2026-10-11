"""Actual disposable Linux Code sandbox tests using existing pinned local images.

No builds/pulls, provider calls, application DB writes, or shared cleanup.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
OWNER = "code-runtime-test-" + uuid.uuid4().hex
WORK = ROOT / ".tmp" / OWNER
EVIDENCE = ROOT / "docs/新增需求/github作品改造"
BASENAME = "T3-19-CodeRuntime正式执行镜像集中验证-20261005"
CODE_IMAGE_TAGS = {
    "python": "agentplug:code-python",
    "javascript": "agentplug:code-javascript",
    "shell": "agentplug:code-shell",
}

parser = argparse.ArgumentParser(description="Verify the existing local Code sandbox images")
parser.add_argument("--batch-id", help="safe independent report batch ID (ASCII alphanumeric, '_' or '-', max 64)")
args = parser.parse_args()
if args.batch_id is not None and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.batch_id) is None:
    parser.error("--batch-id must be 1-64 canonical ASCII letters/digits/underscore/hyphen and start with a letter or digit")
REPORT_BASENAME = BASENAME if args.batch_id is None else BASENAME + "-" + args.batch_id
LOG_PATH = EVIDENCE / (REPORT_BASENAME + ".log")
JSON_PATH = EVIDENCE / (REPORT_BASENAME + ".json")
if any(path.exists() or path.is_symlink() for path in (LOG_PATH, JSON_PATH)):
    raise SystemExit("refusing to overwrite an existing Code runtime report")
try:
    LOG_HANDLE = LOG_PATH.open("xb")
except FileExistsError:
    raise SystemExit("refusing to overwrite an existing Code runtime log") from None

receipt = {"owner": OWNER, "result": "FAIL", "scope": "actual local Docker Linux sandbox only; no public Code gateway, signed execution permit, complete SDK/Harness or formal three-Agent acceptance",
           "temporary_images_built": [], "images_pulled": [], "external_provider_calls": 0,
           "development_database_changed": False, "interview_copy_changed": False, "cleanup_errors": [],
           "batch_id": args.batch_id, "report_basename": REPORT_BASENAME}
def docker(*args):
    result = subprocess.run(["docker", *args], capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError("owned Docker operation failed")
    return result.stdout.decode("utf-8")
try:
    WORK.mkdir(parents=True)
    images = {}
    receipt["pinned_images"] = {}
    for language, tag in CODE_IMAGE_TAGS.items():
        info = json.loads(docker("image", "inspect", tag))[0]
        if info.get("Os") != "linux": raise RuntimeError("Linux fixture required")
        images[language] = info["Id"]
        receipt["pinned_images"][language] = {"tag": tag, "id": info["Id"], "repo_digests":info.get("RepoDigests", [])}
    env = dict(os.environ)
    env["AGENTPLUG_CODE_RUNTIME_TEST_IMAGES"] = json.dumps(images)
    env["AGENTPLUG_CODE_RUNTIME_TEST_OWNER"] = OWNER
    env["GOTMPDIR"] = str(WORK)
    run = subprocess.run(["go","test","-json","./internal/sandbox","-count=1"], cwd=ROOT/"workers/code-runtime", env=env,
                         stdout=LOG_HANDLE, stderr=subprocess.STDOUT, timeout=240)
    receipt["test_exit_code"] = run.returncode
    events=[]
    LOG_HANDLE.flush()
    for line in LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
        try: events.append(json.loads(line))
        except ValueError: pass
    receipt["passed_tests"] = [e["Test"] for e in events if e.get("Action")=="pass" and e.get("Test")]
    receipt["skipped_tests"] = [e["Test"] for e in events if e.get("Action")=="skip" and e.get("Test")]
    required={"TestCodeRuntimeValidatesLimitsBeforeLaunching", "TestCodeRuntimeActualThreeLanguagesAndStreamCapture",
              "TestCodeRuntimeActualKernelPathGuardRejectsTraversalLinksAndDescriptors",
              "TestCodeRuntimeActualFilesystemNetworkCredentialsAndJobIsolation", "TestCodeRuntimeActualDiskPIDsAndMemoryLimits",
              "TestCodeRuntimeActualCPUTimeoutCancellationAndOutputLimits",
              "TestCodeRuntimeIntentionalExitIsNotResourceEvidence",
              "TestStoppedContainerStateRequiresCompleteMatchingEngineEvidence"}
    required |= {"TestCodeRuntimeActualThreeLanguagesAndStreamCapture/"+language for language in images}
    receipt["required_tests"] = sorted(required)
    receipt["tests_passed"] = run.returncode==0 and required.issubset(receipt["passed_tests"]) and not receipt["skipped_tests"]
    if receipt["tests_passed"]: receipt["result"]="PASS"
except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
    receipt["failure"]="isolated Code runtime verification failed; see controlled fixture log"
finally:
    try:
        ids=docker("ps","--all","--filter","label=agentplug.code.controller="+OWNER,"--format","{{.ID}}").split()
        for identifier in ids:
            row=json.loads(docker("inspect",identifier))[0]
            labels=row.get("Config",{}).get("Labels",{})
            if labels.get("agentplug.code.controller")!=OWNER or not labels.get("agentplug.test.owner","").startswith("code-runtime-"):
                raise RuntimeError("unexpected container owner")
            docker("rm","--force",identifier)
        receipt["owned_container_cleanup_confirmed"] = not docker("ps","--all","--filter","label=agentplug.code.controller="+OWNER,"--format","{{.ID}}").strip()
    except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired):
        receipt["cleanup_errors"].append("owned code containers could not be verified/removed")
    target=WORK.resolve()
    if target.is_relative_to((ROOT/".tmp").resolve()) and target.name==OWNER and not WORK.is_symlink():
        if WORK.exists(): shutil.rmtree(WORK)
        receipt["temporary_workspace_removed"]=not WORK.exists()
    else:
        receipt["cleanup_errors"].append("temporary workspace path rejected")
    if receipt["cleanup_errors"]: receipt["result"]="FAIL"
    LOG_HANDLE.flush()
    LOG_HANDLE.close()
    try:
        with JSON_PATH.open("x", encoding="utf-8", newline="\n") as output:
            output.write(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n")
    except FileExistsError:
        receipt["failure"]="refused to overwrite an existing report JSON"
        receipt["result"]="FAIL"
print(json.dumps(receipt,ensure_ascii=True))
raise SystemExit(0 if receipt["result"]=="PASS" else 1)
