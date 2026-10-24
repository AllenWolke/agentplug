"""Verify opt-in cache migration, signed SDK numbers and paused-worker fences.

The database and Go cache are disposable. No application database, provider
credential, model request or Docker control socket is passed to the test runner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "golang:1.26.10-bookworm"
TESTS = {
    "modelgovernance": ["TestPostgresContextCachePriceUpgradePreservesOldRowsAndExplicitZero"],
    "capability": ["TestPostgresModelPerformanceKeepsHistoricalClockMismatchMissing",
                   "TestSQLToolStoppedProcessCannotSubmitAfterTakeover"],
    "execution": ["TestPlatformSignatureAcceptedByNativeGoSDKWithNumericEvidence"],
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-id", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", args.batch_id):
        parser.error("safe batch id required")
    output = ROOT / ".tmp" / ("conditional-contracts-" + args.batch_id + ".json")
    if output.exists():
        parser.error("batch receipt already exists")
    owner = "conditional-sql-" + uuid.uuid4().hex
    name = "agentplug-test-" + owner
    go_name = name + "-go"
    private = ROOT / ".local-secrets/test-evidence" / owner
    private.mkdir(parents=True, exist_ok=False)
    env_file = private / "fixture.env"
    password = secrets.token_hex(32)
    record = {"schema": "agentplug-conditional-contracts/v1", "owner": owner,
              "project_database_used": False, "real_model_requests": 0,
              "packages": [], "cleanup_errors": [], "complete": False}

    def command(arguments: list[str], *, data: bytes | None = None, timeout: int = 60) -> bytes:
        result = subprocess.run(arguments, input=data, capture_output=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError("fixture command failed; private diagnostics suppressed")
        return result.stdout

    def logged(label: str, arguments: list[str], timeout: int = 660) -> tuple[int, Path]:
        path = private / (label + ".jsonl")
        with path.open("xb") as stream:
            result = subprocess.run(arguments, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        return result.returncode, path

    try:
        download = Path(os.environ.get("GOMODCACHE", str(Path.home() / "go/pkg/mod"))) / "cache/download"
        if not download.is_dir():
            raise RuntimeError("existing offline Go download cache required")
        for image in ("pgvector/pgvector:pg16", IMAGE):
            command(["docker", "image", "inspect", image])
        env_file.write_text("POSTGRES_PASSWORD=" + password + "\nPOSTGRES_DB=conditional_test\n"
                            "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=trust\n", encoding="utf-8")
        command(["docker", "run", "--detach", "--name", name, "--network", "none",
                 "--label", "agentplug.test.owner=" + owner, "--env-file", str(env_file),
                 "--read-only", "--user", "postgres", "--cap-drop", "ALL",
                 "--security-opt", "no-new-privileges",
                 "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size=512m,uid=999,gid=999,mode=0700",
                 "--tmpfs", "/var/run/postgresql:rw,nosuid,uid=999,gid=999,mode=0700",
                 "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m", "pgvector/pgvector:pg16"])
        for _ in range(90):
            if subprocess.run(["docker", "exec", name, "pg_isready", "-U", "postgres"], capture_output=True).returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("owned PostgreSQL readiness timeout")
        command(["docker", "exec", "-i", name, "psql", "-X", "-v", "ON_ERROR_STOP=1",
                 "-U", "postgres", "-d", "conditional_test"], data=b"CREATE SCHEMA ctxcache_20261012_conditional;\n")
        dsn = f"postgres://postgres:{password}@127.0.0.1:5432/conditional_test?sslmode=disable"
        settings = {"PUBLIC_TEST_POSTGRES_MIGRATION_DSN": dsn,
                    "PUBLIC_TEST_CONTEXT_CACHE_POSTGRES_DSN": dsn + "&search_path=ctxcache_20261012_conditional",
                    "DB_DSN": dsn, "DB_DRIVER": "pgx", "APP_ENV": "test",
                    "GOTOOLCHAIN": "local", "GOPROXY": "file:///module-cache", "GOSUMDB": "off",
                    "GOMAXPROCS": "2", "GOFLAGS": "-buildvcs=false", "GOMODCACHE": "/test-cache/mod",
                    "GOCACHE": "/test-cache/build", "SDK_GO_NUMERIC_FIXTURE": "/test-cache/numeric-receiver"}
        env_file.write_text("".join(k + "=" + v + "\n" for k, v in settings.items()), encoding="utf-8")
        command(["docker", "run", "--detach", "--name", go_name,
                 "--label", "agentplug.test.owner=" + owner, "--network", "container:" + name,
                 "--env-file", str(env_file),
                 "--mount", "type=bind,source=" + str(ROOT) + ",target=/workspace,readonly",
                 "--mount", "type=bind,source=" + str(download.resolve()) + ",target=/module-cache,readonly",
                 "--tmpfs", "/test-cache:rw,exec,nosuid,size=2g", "--workdir", "/workspace/platform",
                 IMAGE, "sleep", "infinity"])
        prefix = ["docker", "exec", go_name]
        for label, action in (
            ("migration", ["go", "run", "./cmd/migrate"]),
            ("numeric-build", ["go", "-C", "../sdk/go", "build", "-race", "-o", "/test-cache/numeric-receiver",
                               "../../platform/internal/execution/testdata/go_numeric_sdk_fixture.go"]),
        ):
            code, log = logged(label, [*prefix, *action])
            record[label] = {"exit_code": code, "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
            if code:
                raise RuntimeError(label + " failed")
        for package, expected in TESTS.items():
            print(json.dumps({"package": package, "status": "running"}), flush=True)
            code, log = logged(package, [*prefix, "go", "test", "-race", "-json", "-p=1", "-parallel=1",
                                        "-count=1", "-timeout=5m", "-run", "^(" + "|".join(expected) + ")$",
                                        "./internal/" + package])
            states = {}
            for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get("Test") and event.get("Action") in {"pass", "fail", "skip"}:
                    states[event["Test"]] = event["Action"]
            result = {"package": package, "exit_code": code, "states": states,
                      "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
            result["passed"] = code == 0 and all(states.get(t) == "pass" for t in expected) and all(s == "pass" for s in states.values())
            record["packages"].append(result)
            print(json.dumps(result), flush=True)
        record["tests_passed"] = len(record["packages"]) == len(TESTS) and all(p["passed"] for p in record["packages"])
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error).replace(password, "<redacted>")
    finally:
        for container in (go_name, name):
            found = subprocess.run(["docker", "inspect", container], capture_output=True)
            if found.returncode == 0:
                actual = json.loads(found.stdout)[0]
                if actual["Config"]["Labels"].get("agentplug.test.owner") != owner:
                    record["cleanup_errors"].append("container ownership mismatch")
                elif subprocess.run(["docker", "rm", "--force", container], capture_output=True).returncode:
                    record["cleanup_errors"].append("owned container removal failed")
        env_file.unlink(missing_ok=True)
        record["temporary_containers_removed"] = all(subprocess.run(["docker", "inspect", c], capture_output=True).returncode != 0 for c in (go_name, name))
        record["temporary_credentials_removed"] = not env_file.exists()
        record["complete"] = bool(record.get("tests_passed")) and record["temporary_containers_removed"] and record["temporary_credentials_removed"] and not record["cleanup_errors"]
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"complete": record["complete"], "receipt": str(output.relative_to(ROOT)), "failure": record.get("failure")}, ensure_ascii=True), flush=True)
    return 0 if record["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
