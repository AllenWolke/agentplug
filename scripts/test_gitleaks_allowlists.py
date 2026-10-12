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


def reviewed_fixtures() -> list[tuple[str, str, str]]:
    """Keep real matching syntax: identifier false positives differ from keys."""
    fixtures = [(FIXTURE_PATH, FIXTURE_VALUE, 'const token = "' + FIXTURE_VALUE + '"')]
    specs = [
        ("examples/java-tickets/src/main/java/com/lexagent/examples/tickets/TicketAssistant.java", "ticket-plan-v1"),
        ("examples/python-documents/tests/test_transport.py", "fixture-signing-secret-with-32-bytes"),
        ("platform/cmd/migrate/runtime_checkpoint_recovery_test.go", "fixture-signing-secret-with-32-bytes"),
        ("platform/cmd/migrate/runtime_go_verify_test.go", "fixture-signing-secret-with-32-bytes"),
        ("platform/cmd/migrate/runtime_python_verify_test.go", "fixture-signing-secret-with-32-bytes"),
    ]
    for path, value in specs:
        lines = (ROOT / path).read_text(encoding="utf-8").splitlines()
        fixtures.append((path, value, next(line for line in lines if value in line)))
    path = "contracts/fixtures/execution-v2-capability.json"
    value = json.loads((ROOT / path).read_text(encoding="utf-8"))["token"]
    fixtures.append((path, value, '"token": "' + value + '"'))
    return fixtures


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
                paths = []
                expected_files = set()
                for relative, value, line in reviewed_fixtures():
                    relative = "elsewhere/" + relative if name == "different-path" else relative
                    path = repo / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if name in ("different-value", "deleted-from-head"):
                        different = (value.rsplit(".", 1)[0] + "." + secrets.token_urlsafe(48)
                                     if value.startswith("eyJ") else secrets.token_hex(32))
                        line = line.replace(value, different)
                    if name == "additional-value":
                        line += '\nconst api_key = "' + secrets.token_hex(32) + '"'
                    path.write_text(line + "\n", encoding="utf-8")
                    paths.append(path)
                    expected_files.add(relative)
                for args in (["git", "init", "-q"], ["git", "add", "--all"],
                             ["git", "-c", "user.name=Scanner Fixture", "-c", "user.email=fixture@example.invalid",
                              "commit", "-q", "-m", "Synthetic scanner control"]):
                    if command(args, repo).returncode:
                        raise RuntimeError("Cannot initialize isolated scanner fixture")
                if name == "deleted-from-head":
                    for path in paths:
                        path.unlink()
                    for args in (["git", "add", "--all"], ["git", "-c", "user.name=Scanner Fixture", "-c",
                                 "user.email=fixture@example.invalid", "commit", "-q", "-m", "Remove synthetic value"]):
                        if command(args, repo).returncode:
                            raise RuntimeError("Cannot commit history control")
                reports = owned / (name + "-reports")
                reports.mkdir()
                # Keep host ownership when Docker Desktop writes the report.
                (reports / "findings.json").write_text("[]", encoding="utf-8")
                scan = command(["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
                                "-e", "GIT_CONFIG_COUNT=1", "-e", "GIT_CONFIG_KEY_0=safe.directory",
                                "-e", "GIT_CONFIG_VALUE_0=/repo", "--mount",
                                "type=bind,source=" + str(repo) + ",target=/repo,readonly", "--mount",
                                "type=bind,source=" + str(reports) + ",target=/reports", IMAGE,
                                "git", "/repo", "--config=/repo/.gitleaks.toml", "--log-opts=--all",
                                "--redact", "--no-banner", "--report-format=json",
                                "--report-path=/reports/findings.json"], repo, timeout=120)
                # 不输出扫描器原始结果，避免意外泄露任何值；基础设施错误同样不算通过。
                if scan.returncode != expected:
                    raise RuntimeError(f"Scanner control {name}: expected {expected}, got {scan.returncode}")
                # Docker Desktop may map a container-created 0600 file to an
                # unreadable host ACL. Read inside the same isolated filesystem.
                report = command(["docker", "run", "--rm", "--network", "none", "--read-only",
                                  "--entrypoint", "/bin/cat", "--mount",
                                  "type=bind,source=" + str(reports) + ",target=/reports,readonly",
                                  IMAGE, "/reports/findings.json"], repo)
                if report.returncode:
                    raise RuntimeError("Cannot read redacted scanner report")
                findings = json.loads(report.stdout) or []
                actual_files = {finding["File"] for finding in findings}
                if actual_files != (expected_files if expected else set()):
                    raise RuntimeError(f"Scanner control {name}: detection coverage mismatch")
                results.append({"control": name, "expected_exit": expected, "actual_exit": scan.returncode})
                print("PASS " + name, flush=True)
        finally:
            shutil.rmtree(owned, onexc=remove_readonly)
    print(json.dumps({"image": IMAGE, "controls": results}, indent=2))


if __name__ == "__main__":
    main()
