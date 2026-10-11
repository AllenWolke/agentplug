"""Run opt-in real Python transport or external model tests without skips.

Models are real paid vendor calls (four tiny requests across three tests).
Supply an existing private providers.json with llm/embedding model, base_url
and key_file fields. Credential files stay private and are never printed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("interop", "models"), required=True)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--model-metadata", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", args.batch_id):
        parser.error("safe batch id required")
    if (args.suite == "models") != (args.model_metadata is not None):
        parser.error("models require explicit private provider metadata; interop does not use it")
    output = ROOT / "docs/新增需求/生产级评审/界面验证" / ("专用环境-" + args.suite + "-" + args.batch_id + ".json")
    if output.exists():
        parser.error("batch receipt already exists")
    owner = "dedicated-" + args.suite + "-" + uuid.uuid4().hex
    private = ROOT / ".local-secrets/test-evidence" / owner
    private.mkdir(parents=True, exist_ok=False)
    record = {"schema": "agentplug-optional-tests/v1", "owner": owner, "suite": args.suite,
              "complete": False, "packages": [], "credentials_logged": False,
              "project_database_used": False, "real_external_model_calls": args.suite == "models"}
    try:
        env = os.environ.copy()
        for key in list(env):
            if re.search(r"(?i)(DSN|DATABASE_URL|API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|OPENAI|DEEPSEEK|ANTHROPIC)", key):
                env.pop(key, None)
        env.update(GOFLAGS="-buildvcs=false", GOMAXPROCS="2", PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        if args.suite == "interop":
            required = ("grpc", "google.protobuf", "fastapi", "uvicorn", "cryptography")
            if any(importlib.util.find_spec(module) is None for module in required):
                raise RuntimeError("Python transport dependencies are missing")
            env.update(LEXAGENT_RUN_PYTHON_GRPC_INTEROP="1", LEXAGENT_PYTHON=sys.executable, SDK_TCP_INTEROP_TEST="1")
            packages = {"agentgateway": ("TestGRPCTransportInteropWithPythonBridge",),
                        "execution": ("TestRealSignedTCPTimeoutWaitsForPythonGraphStop",)}
            record["scope"] = "actual Go-to-Python gRPC bridge and signed real TCP cancellation; disposable Python fixtures, not deployed business Agents"
        else:
            metadata_path = args.model_metadata.resolve(strict=True)
            settings = json.loads(metadata_path.read_text(encoding="utf-8"))
            for kind, prefix in (("llm", "LEXAGENT_LIVE_DEEPSEEK"), ("embedding", "LEXAGENT_LIVE_EMBEDDING")):
                provider = settings[kind]
                if not all(isinstance(provider.get(k), str) and provider[k].strip() and "\n" not in provider[k] for k in ("model", "base_url", "key_file")):
                    raise RuntimeError("provider model, endpoint and credential file are required")
                filename = Path(provider["key_file"])
                if filename.name != provider["key_file"] or filename.is_absolute():
                    raise RuntimeError("provider credential must be a sibling filename")
                key_path = metadata_path.parent / filename
                if key_path.is_symlink() or not key_path.is_file():
                    raise RuntimeError("regular private provider credential file required")
                if not provider["base_url"].startswith("https://"):
                    raise RuntimeError("real provider HTTPS endpoint required")
                env[prefix + "_KEY_FILE"] = str(key_path)
                env[prefix + "_MODEL"] = provider["model"]
                env[prefix + "_BASE_URL"] = provider["base_url"]
            env["LEXAGENT_LIVE_DEEPSEEK_REASONING_MODE"] = "disabled"
            packages = {"modelgateway": ("TestLiveDeepSeekGateway", "TestLiveDeepSeekNativeFunctionCalling", "TestLiveEmbeddingGateway")}
            record["scope"] = "guarded external chat completion, two-turn native function calling and one embedding batch; no platform IAM or SQL billing acceptance"
        for package, expected in packages.items():
            log = private / (package + ".jsonl")
            print(json.dumps({"package": package, "expected": len(expected), "status": "running"}), flush=True)
            start = time.monotonic()
            with log.open("xb") as stream:
                process = subprocess.run(["go", "test", "-json", "-p=1", "-parallel=1", "-count=1", "-timeout=5m", "-run",
                                          "^(" + "|".join(expected) + ")$", "./internal/" + package],
                                         cwd=ROOT / "platform", env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=330)
            states = {}
            for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get("Test") and event.get("Action") in {"pass", "fail", "skip"}:
                    states[event["Test"]] = event["Action"]
            result = {"package": package, "exit_code": process.returncode, "seconds": round(time.monotonic() - start, 2),
                      "required_states": {test: states.get(test, "missing") for test in expected},
                      "failed_tests": [test for test, state in states.items() if state == "fail"],
                      "skipped_tests": [test for test, state in states.items() if state == "skip"],
                      "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
            result["passed"] = process.returncode == 0 and not result["failed_tests"] and not result["skipped_tests"] and all(s == "pass" for s in result["required_states"].values())
            record["packages"].append(result)
            print(json.dumps(result), flush=True)
        record["complete"] = len(record["packages"]) == len(packages) and all(p["passed"] for p in record["packages"])
    except Exception as error:
        # Never include third-party response bodies or private metadata here.
        record["failure"] = type(error).__name__
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"complete": record["complete"], "receipt": str(output.relative_to(ROOT)), "failure": record.get("failure")}, ensure_ascii=True), flush=True)
    return 0 if record["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
