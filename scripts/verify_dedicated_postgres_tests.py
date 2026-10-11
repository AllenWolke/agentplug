"""Execute every compensation PostgreSQL test that the normal suite skips.

Creates an owner-labelled, disposable PostgreSQL container and a separate
database per package. No project database, credentials or network are used.
Go JSON output is kept privately; the public receipt requires every selected
test and subtest to finish PASS, with no skips or failures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("capability", "compensation", "execution", "knowledge", "notification")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True,
                        help="sanitized full-suite receipt containing go_json_summary.skipped_tests")
    parser.add_argument("--batch-id", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", args.batch_id):
        parser.error("safe batch id required")
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    cases = [case for case in inventory["go_json_summary"]["skipped_tests"]
             if case["package"].rsplit("/", 1)[-1] in PACKAGES
             and case["test"] != "TestRealSignedTCPTimeoutWaitsForPythonGraphStop"]
    if len(cases) != 66 or any(not re.fullmatch(r"Test[A-Za-z0-9_]+(?:/[^\r\n]+)?", c["test"]) for c in cases):
        parser.error("the expected 66 compensation test/subtest inventory is required")
    output = ROOT / "docs/新增需求/生产级评审/界面验证" / ("专用PostgreSQL用例-" + args.batch_id + ".json")
    if output.exists():
        parser.error("batch receipt already exists; choose another id")
    owner = "dedicated-pg-" + uuid.uuid4().hex
    name = "agentplug-test-" + owner
    private = ROOT / ".local-secrets/test-evidence" / owner
    private.mkdir(parents=True, exist_ok=False)
    password = secrets.token_hex(32)
    env_file = private / "postgres.env"
    env_file.write_text("POSTGRES_PASSWORD=" + password + "\nPOSTGRES_DB=postgres\n"
                        "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=trust\n", encoding="utf-8")
    receipt = {"schema": "agentplug-dedicated-postgres-tests/v1", "owner": owner,
               "complete": False, "expected_tests": len(cases), "packages": [], "cleanup_errors": [],
               "project_database_used": False, "credentials_logged": False,
               "scope": "actual PostgreSQL compensation, cancellation, index undo and recipient inbox transactions; controlled authority/stop/provider fixtures are not deployed Agent shutdown proof"}

    def command(arguments: list[str], *, data: bytes | None = None, timeout: int = 60) -> bytes:
        completed = subprocess.run(arguments, input=data, capture_output=True, timeout=timeout)
        if completed.returncode:
            raise RuntimeError("fixture command failed; private diagnostics suppressed")
        return completed.stdout

    try:
        image = json.loads(command(["docker", "image", "inspect", "pgvector/pgvector:pg16"]))[0]
        receipt["postgres_image_id"] = image["Id"]
        command(["docker", "run", "--detach", "--name", name, "--label", "agentplug.test.owner=" + owner,
                 "--env-file", str(env_file), "--publish", "127.0.0.1::5432", "--read-only", "--user", "postgres",
                 "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                 "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size=1g,uid=999,gid=999,mode=0700",
                 "--tmpfs", "/var/run/postgresql:rw,nosuid,uid=999,gid=999,mode=0700",
                 "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m", image["Id"]])
        for _ in range(90):
            if subprocess.run(["docker", "exec", name, "pg_isready", "-U", "postgres"], capture_output=True).returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("isolated PostgreSQL readiness timed out")
        metadata = json.loads(command(["docker", "inspect", name]))[0]
        if metadata["Config"]["Labels"].get("agentplug.test.owner") != owner:
            raise RuntimeError("fixture container ownership mismatch")
        port = metadata["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostPort"]
        for package in PACKAGES:
            selected = [case for case in cases if case["package"].rsplit("/", 1)[-1] == package]
            parents = sorted({case["test"].split("/", 1)[0] for case in selected})
            database = "agentplug_compensation_test_" + owner[-16:] + "_" + package
            command(["docker", "exec", "-i", name, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"],
                    data=("CREATE DATABASE " + database + ";\n").encode())
            env = os.environ.copy()
            for key in list(env):
                if re.search(r"(?i)(DSN|DATABASE_URL|API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|OPENAI|DEEPSEEK|ANTHROPIC)", key):
                    env.pop(key, None)
            env.update(COMPENSATION_TEST_POSTGRES_DSN=f"postgres://postgres:{password}@127.0.0.1:{port}/{database}?sslmode=disable",
                       GOFLAGS="-buildvcs=false", GOMAXPROCS="2")
            log = private / (package + ".jsonl")
            start = time.monotonic()
            print(json.dumps({"package": package, "expected": len(selected), "status": "running"}), flush=True)
            with log.open("xb") as stream:
                completed = subprocess.run(["go", "test", "-json", "-p=1", "-parallel=1", "-count=1", "-timeout=10m",
                                            "-run", "^(" + "|".join(parents) + ")$", "./internal/" + package],
                                           cwd=ROOT / "platform", env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=660)
            states: dict[str, str] = {}
            for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get("Test") and event.get("Action") in {"pass", "fail", "skip"}:
                    states[event["Test"]] = event["Action"]
            result = {"package": package, "exit_code": completed.returncode, "seconds": round(time.monotonic() - start, 2),
                      "required_states": {case["test"]: states.get(case["test"], "missing") for case in selected},
                      "pass_events": sum(v == "pass" for v in states.values()),
                      "failed_tests": [k for k, v in states.items() if v == "fail"],
                      "skipped_tests": [k for k, v in states.items() if v == "skip"],
                      "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
            result["passed"] = completed.returncode == 0 and not result["failed_tests"] and not result["skipped_tests"] and all(v == "pass" for v in result["required_states"].values())
            receipt["packages"].append(result)
            print(json.dumps({k: v for k, v in result.items() if k != "required_states"}), flush=True)
        receipt["tests_passed"] = len(receipt["packages"]) == len(PACKAGES) and all(r["passed"] for r in receipt["packages"])
    except Exception as error:
        receipt["failure"] = type(error).__name__ + ": " + str(error).replace(password, "<redacted>")
    finally:
        found = subprocess.run(["docker", "inspect", name], capture_output=True)
        if found.returncode == 0:
            actual = json.loads(found.stdout)[0]
            if actual.get("Config", {}).get("Labels", {}).get("agentplug.test.owner") != owner:
                receipt["cleanup_errors"].append("container ownership mismatch")
            elif subprocess.run(["docker", "rm", "--force", name], capture_output=True).returncode:
                receipt["cleanup_errors"].append("owned container removal failed")
        receipt["temporary_container_removed"] = subprocess.run(["docker", "inspect", name], capture_output=True).returncode != 0
        env_file.unlink(missing_ok=True)
        receipt["temporary_credentials_removed"] = not env_file.exists()
        receipt["complete"] = bool(receipt.get("tests_passed")) and receipt["temporary_container_removed"] and receipt["temporary_credentials_removed"] and not receipt["cleanup_errors"]
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"complete": receipt["complete"], "receipt": str(output.relative_to(ROOT)), "failure": receipt.get("failure")}, ensure_ascii=True), flush=True)
    return 0 if receipt["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
