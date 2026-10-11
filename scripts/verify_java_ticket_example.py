"""Verify the repository SDK and ticket example with an isolated cached JDK.

No external network, business database, supplier credential or global cleanup.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
OWNER = "java-ticket-" + uuid.uuid4().hex
TEMP = ROOT / ".tmp" / OWNER
WORKSPACE = TEMP / "workspace"
NAME = "agentplug-" + OWNER
EVIDENCE = ROOT / "docs/新增需求/github作品改造"
JAVA_EXAMPLE_POM = ROOT / "examples/java-tickets/pom.xml"
MAVEN_POM_NAMESPACE = "http://maven.apache.org/POM/4.0.0"
SAFE_ARTIFACT_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
SAFE_BATCH_ID = re.compile(r"(?:[a-z0-9]|[a-z0-9][a-z0-9_-]{0,62}[a-z0-9])\Z")
MODE_FLAGS = {"--full-reactor", "--function-calling", "--business-state", "--runtime-observation", "--tool-confirmation", "--harness"}


def parse_arguments(arguments):
    mode_flags = []
    batch_id = None
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--batch-id":
            if batch_id is not None or index + 1 >= len(arguments):
                raise SystemExit("--batch-id requires one unique safe identifier")
            candidate = arguments[index + 1]
            if not SAFE_BATCH_ID.fullmatch(candidate) or len(candidate) > 64:
                raise SystemExit("--batch-id must be 1-64 lowercase ASCII letters, digits, '_' or '-', starting and ending with a letter or digit")
            batch_id = candidate
            index += 2
            continue
        if argument not in MODE_FLAGS:
            raise SystemExit("unsupported Java verification option")
        mode_flags.append(argument)
        index += 1
    full_reactor_count = mode_flags.count("--full-reactor")
    focused_modes = [flag for flag in mode_flags if flag != "--full-reactor"]
    if full_reactor_count > 1 or len(focused_modes) > 1:
        raise SystemExit("select --full-reactor at most once and at most one focused Java verification mode")
    return set(mode_flags), batch_id


OPTIONS, BATCH_ID = parse_arguments(sys.argv[1:])
FULL_REACTOR = "--full-reactor" in OPTIONS
FUNCTION_CALLING = "--function-calling" in OPTIONS
BUSINESS_STATE = "--business-state" in OPTIONS
RUNTIME_OBSERVATION = "--runtime-observation" in OPTIONS
TOOL_CONFIRMATION = "--tool-confirmation" in OPTIONS
HARNESS = "--harness" in OPTIONS
REPORT_NAME = ("T3-20-Java公共Harness与SDK模板回归" if HARNESS else "T3-18-Java批准令牌交接与SDK回归" if TOOL_CONFIRMATION else "T3-18-JavaObservation与完整SDK回归" if RUNTIME_OBSERVATION else "T3-14-Java公共检查点与SDK回归" if BUSINESS_STATE else
               "T3-13-JavaFunctionCalling与SDK回归" if FUNCTION_CALLING else
               "T3-11-Java全部SDK与模板最终回归" if FULL_REACTOR else "T3-07-Java业务与SDK回归")
REPORT_NAME += "-20261005修正版"
if BATCH_ID is not None:
    REPORT_NAME += "-" + BATCH_ID
if any((EVIDENCE / (REPORT_NAME + extension)).exists()
       or (EVIDENCE / (REPORT_NAME + extension)).is_symlink() for extension in (".log", ".json")):
    raise SystemExit("refusing to overwrite an existing verification batch")
receipt = {"owner": OWNER, "result": "FAIL", "scope": "SDK, ticket business and actual SDK HTTP integration; not actual platform/SQL/providers",
           "external_provider_calls": 0, "development_database_changed": False,
           "interview_copy_changed": False, "temporary_images_built": [], "cleanup_errors": []}
receipt["full_sdk_reactor"] = FULL_REACTOR
receipt["batch_id"] = BATCH_ID


def tree_sha256(root):
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("isolated Java source workspace contains a symbolic link")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def read_java_example_version():
    root = ET.parse(JAVA_EXAMPLE_POM).getroot()
    if root.tag != f"{{{MAVEN_POM_NAMESPACE}}}project":
        raise ValueError("unexpected Java example POM root")
    artifacts = root.findall(f"{{{MAVEN_POM_NAMESPACE}}}artifactId")
    versions = root.findall(f"{{{MAVEN_POM_NAMESPACE}}}version")
    if len(artifacts) != 1 or (artifacts[0].text or "").strip() != "example-java-tickets":
        raise ValueError("unexpected Java example artifact")
    if len(versions) != 1:
        raise ValueError("Java example version is missing")
    value = (versions[0].text or "").strip()
    if len(value) > 32 or not SAFE_ARTIFACT_VERSION.fullmatch(value):
        raise ValueError("Java example version is not a safe numeric release version")
    return value


try:
    example_version = read_java_example_version()
    receipt["example_version"] = example_version
    for relative in ["sdk/java", "agents/examples/java-spring-ai", "examples/java-tickets",
                     "templates/java-generic", "templates/java-spring-ai", "contracts"]:
        shutil.copytree(ROOT / relative, WORKSPACE / relative,
                        ignore=shutil.ignore_patterns("target", "__pycache__", ".pytest_cache"))
    receipt["source_workspace_sha256"] = tree_sha256(WORKSPACE)
    commands = [
        (["-f", "sdk/java/pom.xml", "package"] if FULL_REACTOR else ["-f", "sdk/java/pom.xml", "-pl", ":example-java-tickets", "-am", "package"]),
        ["-f", "templates/java-generic/pom.xml", "test"],
        ["-f", "templates/java-spring-ai/pom.xml", "test"],
    ]
    receipt["command_exit_codes"] = []
    with (EVIDENCE / (REPORT_NAME + ".log")).open("wb") as output:
        for arguments in commands:
            command = ["docker", "run", "--rm", "--name", NAME, "--label", "agentplug.test.owner=" + OWNER,
                       "--network", "none", "--mount", f"type=bind,source={WORKSPACE},target=/workspace",
                       "--mount", f"type=bind,source={ROOT / '.cache/m2'},target=/m2,readonly",
                       "--workdir", "/workspace", "maven:3.9.9-eclipse-temurin-21",
                       "mvn", "--batch-mode", "--no-transfer-progress", "--offline", "-s", "/m2/settings-docker.xml",
                       "-Dmaven.repo.local=/m2/repository", *arguments]
            result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=240)
            receipt["command_exit_codes"].append(result.returncode)
            if result.returncode:
                break
    totals = {key: 0 for key in ["tests", "failures", "errors", "skipped"]}
    receipt["suites"] = []
    for report in WORKSPACE.rglob("surefire-reports/TEST-*.xml"):
        suite = ET.parse(report).getroot()
        entry = {"name": suite.attrib["name"], **{key: int(suite.attrib.get(key, 0)) for key in totals}}
        receipt["suites"].append(entry)
        for key in totals:
            totals[key] += entry[key]
    receipt["test_totals"] = totals
    expected = {"com.lexagent.examples.tickets.TicketAssistantTest", "com.lexagent.examples.tickets.TicketTransportTest"}
    names = {suite["name"] for suite in receipt["suites"]}
    receipt["tests_passed"] = (len(receipt["command_exit_codes"]) == 3
                               and not any(receipt["command_exit_codes"])
                               and expected.issubset(names) and totals["tests"] > 0
                               and not any(totals[key] for key in ["failures", "errors", "skipped"]))
    receipt["example_jar_built"] = (WORKSPACE / "examples/java-tickets/target" / f"example-java-tickets-{example_version}.jar").is_file()
    receipt["runtime_sdk_dependency_present"] = (WORKSPACE / "examples/java-tickets/target/lib/agent-platform-sdk-2.0.0.jar").is_file()
    if receipt["tests_passed"] and receipt["example_jar_built"] and receipt["runtime_sdk_dependency_present"]:
        receipt["result"] = "PASS"
except (OSError, ValueError, ET.ParseError, subprocess.TimeoutExpired):
    receipt["failure"] = "isolated Java verification failed; see redacted fixture log"
finally:
    inspection = subprocess.run(["docker", "inspect", NAME], capture_output=True)
    if inspection.returncode == 0:
        container = json.loads(inspection.stdout)[0]
        if container.get("Config", {}).get("Labels", {}).get("agentplug.test.owner") == OWNER:
            if subprocess.run(["docker", "rm", "-f", NAME], capture_output=True).returncode:
                receipt["cleanup_errors"].append("owned container cleanup failed")
        else:
            receipt["cleanup_errors"].append("container owner mismatch")
    path = TEMP.resolve()
    if path.is_relative_to((ROOT / ".tmp").resolve()) and path.name == OWNER and not TEMP.is_symlink():
        if TEMP.exists():
            shutil.rmtree(TEMP)
    else:
        receipt["cleanup_errors"].append("temporary path ownership check failed")
    receipt["temporary_workspace_removed"] = not TEMP.exists()
    (EVIDENCE / (REPORT_NAME + ".json")).write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps(receipt, ensure_ascii=False))
raise SystemExit(0 if receipt["result"] == "PASS" and not receipt["cleanup_errors"] else 1)
