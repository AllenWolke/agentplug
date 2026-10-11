"""Exercise the real scanner against isolated, synthetic Git histories."""

from pathlib import Path
import json
import os
import secrets
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "zricethezav/gitleaks:v8.24.3@sha256:e1b35e12a8c6fa8901f060459cfb6b2fc4c484d3afbe3b029733a3bbfab07055"
FIXTURE_PATH = "workers/metric-runner/cmd/metric-service/main_test.go"
FIXTURE_VALUE = "0123456789abcdef0123456789abcdef"


def command(args: list[str], cwd: Path, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def remove_readonly(function, path, error) -> None:
    os.chmod(path, 0o700)
    function(path)


def main() -> None:
    results = []
    with tempfile.TemporaryDirectory(prefix="agentplug-scan-controls-", ignore_cleanup_errors=False) as temporary:
        owned = Path(temporary)
        try:
            for name, expected in (("reviewed-fixture", 0), ("different-value", 1),
                                   ("different-path", 1), ("additional-value", 1),
                                   ("deleted-from-head", 1)):
                repo = owned / name
                repo.mkdir()
                shutil.copyfile(ROOT / ".gitleaks.toml", repo / ".gitleaks.toml")
                path = repo / ("elsewhere/main_test.go" if name == "different-path" else FIXTURE_PATH)
                path.parent.mkdir(parents=True, exist_ok=True)
                value = secrets.token_hex(32) if name in ("different-value", "deleted-from-head") else FIXTURE_VALUE
                text = 'package fixture\nconst token = "' + value + '"\n'
                if name == "additional-value":
                    text += 'const api_key = "' + secrets.token_hex(32) + '"\n'
                path.write_text(text, encoding="utf-8")
                for args in (["git", "init", "-q"], ["git", "add", "--all"],
                             ["git", "-c", "user.name=Scanner Fixture", "-c", "user.email=fixture@example.invalid",
                              "commit", "-q", "-m", "Synthetic scanner control"]):
                    if command(args, repo).returncode:
                        raise RuntimeError("Cannot initialize isolated scanner fixture")
                if name == "deleted-from-head":
                    path.unlink()
                    for args in (["git", "add", "--all"], ["git", "-c", "user.name=Scanner Fixture", "-c",
                                 "user.email=fixture@example.invalid", "commit", "-q", "-m", "Remove synthetic value"]):
                        if command(args, repo).returncode:
                            raise RuntimeError("Cannot commit history control")
                scan = command(["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
                                "-e", "GIT_CONFIG_COUNT=1", "-e", "GIT_CONFIG_KEY_0=safe.directory",
                                "-e", "GIT_CONFIG_VALUE_0=/repo", "--mount",
                                "type=bind,source=" + str(repo) + ",target=/repo,readonly", IMAGE,
                                "git", "/repo", "--config=/repo/.gitleaks.toml", "--log-opts=--all",
                                "--redact", "--no-banner"], repo, timeout=120)
                # 不输出扫描器原始结果，避免意外泄露任何值；基础设施错误同样不算通过。
                if scan.returncode != expected:
                    raise RuntimeError(f"Scanner control {name}: expected {expected}, got {scan.returncode}")
                results.append({"control": name, "expected_exit": expected, "actual_exit": scan.returncode})
                print("PASS " + name, flush=True)
        finally:
            shutil.rmtree(owned, onexc=remove_readonly)
    print(json.dumps({"image": IMAGE, "controls": results}, indent=2))


if __name__ == "__main__":
    main()
