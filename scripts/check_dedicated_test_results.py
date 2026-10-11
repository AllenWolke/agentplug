"""Check all 73 original skipped events against one dedicated test batch.

Read-only validation of the source receipts and private Go logs; no containers,
model calls, staging, or publication. Missing, skipped or failed cases fail the
check. Original evidence is retained and the aggregate output is exclusive.
An explicitly selected independent scale rerun uses the same acceptance checks;
its receipt and log digests are recorded without overwriting the failed batch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / "docs/新增需求/生产级评审"
EVIDENCE = REVIEW / "界面验证"
SQL_EVIDENCE = ROOT / "docs/新增需求/github作品改造"
SQL_PACKAGES = {"capability", "compensation", "execution", "knowledge", "notification"}
INTEROP = {"TestGRPCTransportInteropWithPythonBridge", "TestRealSignedTCPTimeoutWaitsForPythonGraphStop"}
MODELS = {"TestLiveDeepSeekGateway", "TestLiveDeepSeekNativeFunctionCalling", "TestLiveEmbeddingGateway"}
SEED = "TestSeedPlatformProcessRestartRun"
SCALE = "TestSQLPermissionScaleAcceptance"


def review_reference(path: Path) -> str:
    return Path(os.path.relpath(path.resolve(), REVIEW)).as_posix()


def read_json(path: Path) -> dict:
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(ROOT) or path.is_symlink() or not path.is_file() or path.stat().st_size > 8 << 20:
        raise ValueError("invalid evidence file")
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("invalid evidence object")
    return value


def json_log_states(path: Path, checksum: str) -> dict[tuple[str, str], str]:
    if not path.resolve(strict=True).is_relative_to(ROOT / ".local-secrets/test-evidence") or path.is_symlink() or path.stat().st_size > 64 << 20:
        raise ValueError("invalid private log")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != checksum:
        raise ValueError("private log checksum mismatch")
    states = {}
    for line in raw.decode("utf-8").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("Action") in {"pass", "fail", "skip"}:
            key = event.get("Package", ""), event.get("Test", "")
            if event["Action"] != "pass":
                raise ValueError("private log contains a failed or skipped event")
            states[key] = event["Action"]
    return states


def check_batch(inventory: dict, batch: str, scale_receipt: Path | None = None) -> tuple[list[dict], list[dict]]:
    original = inventory["go_json_summary"]["skipped_tests"]
    pairs = {(case["package"], case["test"]) for case in original}
    if len(original) != 73 or len(pairs) != 73:
        raise ValueError("expected 73 unique original skipped events")
    files = {
        "postgres": EVIDENCE / f"专用PostgreSQL用例-{batch}.json",
        "interop": EVIDENCE / f"专用环境-interop-{batch}.json",
        "models": EVIDENCE / f"专用环境-models-{batch}.json",
        "scale": SQL_EVIDENCE / f"T3-04A-PostgreSQL权限规模实际验证-{batch}.json",
        "restart": SQL_EVIDENCE / f"T3-21-原始评测种子与真实平台进程重启验证-{batch}.json",
    }
    if scale_receipt is not None:
        if scale_receipt.is_symlink():
            raise ValueError("scale: symbolic-link receipt is not accepted")
        scale_receipt = scale_receipt.resolve(strict=True)
        if scale_receipt.parent != SQL_EVIDENCE.resolve() or not re.fullmatch(
            r"T3-04A-PostgreSQL权限规模实际验证-[a-z0-9][a-z0-9-]{0,79}\.json", scale_receipt.name
        ):
            raise ValueError("scale: invalid independent receipt")
        files["scale"] = scale_receipt
    records, sources, states = {}, [], {}
    for group, path in files.items():
        record = read_json(path)
        if record.get("complete") is not True:
            raise ValueError(f"{group}: incomplete receipt")
        sources.append({"category": group, "receipt": review_reference(path),
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        records[group] = record
        if group in {"postgres", "interop", "models"}:
            owner = record["owner"]
            if not re.fullmatch(r"dedicated-(?:pg|interop|models)-[0-9a-f]{32}", owner):
                raise ValueError(f"{group}: invalid private log owner")
            expected_packages = SQL_PACKAGES if group == "postgres" else {"agentgateway", "execution"} if group == "interop" else {"modelgateway"}
            packages = record["packages"]
            if len(packages) != len(expected_packages) or {p["package"] for p in packages} != expected_packages:
                raise ValueError(f"{group}: missing or duplicate package")
            for package in packages:
                if package.get("passed") is not True or package.get("exit_code") != 0 or package.get("failed_tests") != [] or package.get("skipped_tests") != []:
                    raise ValueError(f"{group}: package did not pass without skips")
                package_name = "github.com/lexagent/platform/internal/" + package["package"]
                log = ROOT / ".local-secrets/test-evidence" / owner / (package["package"] + ".jsonl")
                actual = json_log_states(log, package["log_sha256"])
                if actual.get((package_name, "")) != "pass":
                    raise ValueError(f"{group}: package PASS event missing")
                for test, status in package["required_states"].items():
                    if status != "pass" or actual.get((package_name, test)) != "pass":
                        raise ValueError(f"{group}: required event missing or inconsistent")
                    states[(package_name, test)] = "pass"
        if group in {"postgres", "scale", "restart"}:
            if record.get("tests_passed") is not True or record.get("cleanup_errors") != [] or record.get("temporary_container_removed") is not True or record.get("temporary_credentials_removed") is not True:
                raise ValueError(f"{group}: test or fixture cleanup not complete")
        if group in {"scale", "restart"}:
            if record.get("test_exit_code") != 0 or record.get("skipped_tests") != [] or record.get("real_postgresql") is not True:
                raise ValueError(f"{group}: SQL test did not pass without skips")
            if any(record.get(key) is not True for key in ("temporary_python_container_removed", "temporary_go_container_removed", "temporary_kafka_container_removed")):
                raise ValueError(f"{group}: temporary helper cleanup incomplete")
            log = path.with_suffix(".log")
            if not log.resolve(strict=True).is_relative_to(SQL_EVIDENCE) or log.is_symlink() or log.stat().st_size > 64 << 20:
                raise ValueError(f"{group}: invalid retained test log")
            text = log.read_text(encoding="utf-8")
            sources[-1]["test_log_sha256"] = hashlib.sha256(log.read_bytes()).hexdigest()
            actual = set(re.findall(r"^\s*--- PASS: ([^\s]+)", text, flags=re.MULTILINE))
            if re.search(r"^\s*--- (?:FAIL|SKIP):", text, flags=re.MULTILINE):
                raise ValueError(f"{group}: test log contains failure or skip")
            if any(test not in actual for test in record["required_parent_tests"]):
                raise ValueError(f"{group}: required SQL PASS event missing")
            if group == "scale" and SCALE not in actual:
                raise ValueError("scale: original scale test missing")
            if group == "restart" and (record.get("original_evaluation_seed_executed") is not True or record.get("actual_evaluation_process_restart") is not True or record.get("actual_linux_platform_executable") is not True or record.get("platform_executable_built_with_race_detector") is not True or "original_restart_seed_test=PASS" not in text or "actual_platform_restart_recovered_original_seed=PASS" not in text):
                raise ValueError("restart: actual original seed and platform restart not proven")
    cases, counts = [], {}
    for number, case in enumerate(original, 1):
        package, test = case["package"], case["test"]
        if test in INTEROP:
            group = "interop"
        elif test in MODELS:
            group = "models"
        elif test == SCALE:
            if package != "github.com/lexagent/platform/internal/identity":
                raise ValueError("scale: original package mismatch")
            group = "scale"
        elif test == SEED:
            if package != "github.com/lexagent/platform/internal/evaluationproduct":
                raise ValueError("restart: original package mismatch")
            group = "restart"
        elif package.rsplit("/", 1)[-1] in SQL_PACKAGES:
            group = "postgres"
        else:
            raise ValueError("original inventory contains an unmapped dedicated test")
        if group not in {"scale", "restart"} and states.get((package, test)) != "pass":
            raise ValueError("original test has no verified dedicated PASS event")
        counts[group] = counts.get(group, 0) + 1
        cases.append({"number": number, "package": package, "test": test, "original_skip_reason": case["reason"],
                      "status": "pass", "category": group, "receipt": review_reference(files[group])})
    if counts != {"postgres": 66, "interop": 2, "models": 3, "scale": 1, "restart": 1}:
        raise ValueError("original inventory category counts changed")
    return cases, sources


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--scale-receipt", type=Path,
                        help="explicit independently rerun scale receipt; original failed evidence remains unchanged")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", args.batch_id):
        parser.error("safe batch id required")
    output = EVIDENCE / f"73项专用环境逐项验收-{args.batch_id}.json"
    if output.exists():
        parser.error("aggregate receipt already exists; choose another batch")
    try:
        inventory = read_json(args.inventory)
        cases, sources = check_batch(inventory, args.batch_id, args.scale_receipt)
        report = {"schema": "agentplug-dedicated-73-tests/v2", "complete": True,
                  "total": 73, "passed": 73, "failed": 0, "skipped": 0, "pending": 0,
                  "batch_id": args.batch_id, "original_receipt": review_reference(args.inventory),
                  "original_receipt_sha256": hashlib.sha256(args.inventory.read_bytes()).hexdigest(),
                  "private_go_logs_rechecked": True, "sources": sources, "cases": cases}
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    except (OSError, ValueError, KeyError, TypeError) as error:
        # Never echo private log contents or credential-bearing exception text.
        print(json.dumps({"complete": False, "error_type": type(error).__name__}))
        return 1
    print(json.dumps({"complete": True, "passed": 73, "failed": 0, "skipped": 0, "pending": 0,
                      "receipt": output.relative_to(ROOT).as_posix()}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
