"""Exercise POSIX configuration initialization using an isolated, offline container."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
OWNER = "posix-initialization-" + uuid.uuid4().hex
TEMP = ROOT / ".tmp" / OWNER
REPORT = ROOT / "docs/新增需求/用户权限设计/验收证据/conversation-erasure-posix-20261001.json"
result = {"owner": OWNER, "passed": False, "cases": [], "temporary_images_built": [], "cleanup_errors": []}

def invoke(mode):
    proc = subprocess.run([
        "docker", "run", "--rm", "--network", "none", "--label", "codex.test.owner=" + OWNER,
        "--volume", str(TEMP) + ":/fixtures", "golang:1.26.10-bookworm", "bash", "-c",
        'function docker() { return 0; }; export -f docker; bash "$1" status',
        "fixture", "/fixtures/" + mode + "/scripts/platform.sh",
    ], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    if proc.returncode:
        raise RuntimeError("POSIX initialization failed; captured output withheld")
    return proc.stdout + proc.stderr

try:
    if TEMP.exists() or ROOT.is_symlink() or (ROOT / ".tmp").is_symlink():
        raise RuntimeError("unsafe fixture parent")
    TEMP.mkdir(parents=True)
    for mode in ("fresh", "complete", "missing", "empty"):
        fixture = TEMP / mode
        (fixture / "scripts").mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/platform.sh", fixture / "scripts/platform.sh")
        shutil.copyfile(ROOT / ".env.example", fixture / ".env.example")
        original = b"INTERNAL_SIGNING_SECRET=operator-signing\nMETRIC_RUNNER_TOKEN=operator-runner\n"
        if mode == "complete":
            original += b"BROWSER_GATEWAY_TOKEN=operator-gateway\n"
        elif mode == "empty":
            original += b"BROWSER_GATEWAY_TOKEN=\n"
        env = fixture / ".env"
        if mode != "fresh":
            env.write_bytes(original)
        output = invoke(mode)
        settings = dict(line.split("=", 1) for line in env.read_text(encoding="utf-8").splitlines() if "=" in line and not line.startswith("#"))
        if mode == "complete":
            assert env.read_bytes() == original
        else:
            gateway = settings["BROWSER_GATEWAY_TOKEN"]
            assert re.fullmatch("[0-9a-f]{32,64}", gateway) and gateway not in output
            if mode != "fresh":
                assert settings["INTERNAL_SIGNING_SECRET"] == "operator-signing"
                assert settings["METRIC_RUNNER_TOKEN"] == "operator-runner"
                assert len(settings) == 3
            else:
                names = ("DB_PASSWORD", "INTERNAL_TOKEN", "BROWSER_GATEWAY_TOKEN", "INTERNAL_SIGNING_SECRET", "METRIC_RUNNER_TOKEN", "CREDIT_SYSTEM_CLIENT_SECRET", "MEMORY_ENCRYPTION_KEY")
                values = [settings[name] for name in names]
                assert len(set(values)) == len(values)
                assert all(re.fullmatch("[0-9a-f]{32,64}", value) and value not in output for value in values)
        before = env.read_bytes()
        invoke(mode)
        assert env.read_bytes() == before
        result["cases"].append({"mode": mode, "passed": True, "retry_preserves_credentials": True})
    result["passed"] = True
finally:
    if TEMP.exists():
        if TEMP.parent.resolve() != (ROOT / ".tmp").resolve() or any(p.is_symlink() or p.is_junction() for p in [TEMP, *TEMP.rglob("*")]):
            result["cleanup_errors"].append("unsafe linked fixture; retained")
        else:
            result["deleted_fixture_bytes"] = sum(p.stat().st_size for p in TEMP.rglob("*") if p.is_file())
            shutil.rmtree(TEMP)
    result["fixture_removed"] = not TEMP.exists()
    REPORT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
if result["cleanup_errors"]:
    raise RuntimeError("fixture cleanup failed")
print(json.dumps({"passed": result["passed"], "cases": len(result["cases"]), "fixture_removed": result["fixture_removed"]}))
