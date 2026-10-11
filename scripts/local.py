"""Build and run AgentPlug as host processes, without application containers."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / ".local-build" / "bin"
GO_TARGETS = {
    "platform": ("platform", "./cmd/platform"),
    "migrate": ("platform", "./cmd/migrate"),
    "bootstrap-admin": ("platform", "./cmd/bootstrap-admin"),
    "frontend": ("frontend", "./server"),
    "runner": ("workers/metric-runner", "./cmd/metric-service"),
}
SERVICES = (*(name for name in GO_TARGETS if name != "bootstrap-admin"), "checkpoint-init")
BASE_ENVIRONMENT = {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP",
                    "HOME", "USERPROFILE", "USERNAME", "USER", "LOGNAME", "APPDATA", "LOCALAPPDATA",
                    "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR"}
MIGRATION_KEYS = {"APP_ENV", "DB_DRIVER", "DB_DSN", "PLATFORM_DEV_RUNTIME_PASSWORD"}
CHECKPOINT_KEYS = {"APP_ENV", "CHECKPOINT_DSN"}


def load_settings(path: Path) -> dict[str, str]:
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise ValueError("private environment file must be owner-only")
    settings: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not separator or not re.fullmatch(r"[A-Z_][A-Z0-9_]*", key) or key in settings:
            raise ValueError(f"invalid or duplicate environment key on line {number}")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if "\x00" in value or "replace-" in value.lower() or "change-me" in value.lower():
            raise ValueError(f"unresolved configuration on line {number}")
        # Values are literal: no shell evaluation, interpolation or command substitution.
        settings[key] = value
    return settings


def environment(service: str, settings: dict[str, str]) -> dict[str, str]:
    result = {key: value for key, value in os.environ.items() if key.upper() in BASE_ENVIRONMENT}
    allowed = MIGRATION_KEYS if service == "migrate" else CHECKPOINT_KEYS if service == "checkpoint-init" else None
    if allowed is not None and set(settings) - allowed:
        raise ValueError("initialization config contains unrelated runtime credentials")
    result.update(settings)
    if service in {"checkpoint-init"}:
        result["PYTHONPATH"] = os.pathsep.join([str(ROOT), str(ROOT / "sdk/python")])
    return result


def command(service: str, python: str, settings: dict[str, str] | None = None) -> tuple[list[str], Path]:
    if service in GO_TARGETS:
        binary = BUILD / (service + (".exe" if os.name == "nt" else ""))
        if not binary.is_file():
            raise ValueError("native binary missing; run local.py build first")
        working = ROOT / "frontend/dist" if service == "frontend" else ROOT
        if not working.is_dir():
            raise ValueError("frontend assets missing; run local.py build first")
        return [str(binary)], working
    if service == "checkpoint-init":
        return [python, "-m", "agent_platform_sdk.checkpoint_bootstrap"], ROOT
    raise ValueError("unsupported native service")


def build() -> None:
    BUILD.mkdir(parents=True, exist_ok=True)
    build_environment = os.environ.copy()
    build_environment["CGO_ENABLED"] = "0"
    build_environment["GOCACHE"] = str(ROOT / ".cache/go-build")
    for name, (directory, package) in GO_TARGETS.items():
        output = BUILD / (name + (".exe" if os.name == "nt" else ""))
        subprocess.run(["go", "build", "-trimpath", "-o", str(output), package],
                       cwd=ROOT / directory, env=build_environment, check=True)
    npm = "npm.cmd" if os.name == "nt" else "npm"
    subprocess.run([npm, "ci"], cwd=ROOT / "frontend", check=True)
    subprocess.run([npm, "run", "build"], cwd=ROOT / "frontend", check=True)
    print("NATIVE BUILD PASS")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("build")
    first_admin = actions.add_parser("bootstrap-admin", help="initialize only an empty production identity store")
    first_admin.add_argument("--config", type=Path, required=True, help="owner-private JSON configuration")
    run = actions.add_parser("run")
    run.add_argument("service", choices=SERVICES)
    run.add_argument("--env-file", type=Path, required=True)
    run.add_argument("--python", default=sys.executable, help="Agent virtualenv Python executable")
    args = parser.parse_args()
    try:
        if args.action == "build":
            build()
            return 0
        if args.action == "bootstrap-admin":
            arguments, working = command("bootstrap-admin", sys.executable)
            bootstrap_environment = {key: value for key, value in os.environ.items() if key.upper() in BASE_ENVIRONMENT}
            return subprocess.run([*arguments, "--config", str(args.config.resolve())],
                                  cwd=working, env=bootstrap_environment, check=False).returncode
        settings = load_settings(args.env_file)
        process_environment = environment(args.service, settings)
        arguments, working = command(args.service, args.python, settings)
        # Foreground execution lets the user's terminal/service manager own lifecycle.
        with subprocess.Popen(arguments, cwd=working, env=process_environment) as process:
            try:
                return process.wait()
            except KeyboardInterrupt:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                return 130
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # No environment values or source credentials are printed.
        print(f"native operation failed ({type(error).__name__}); inspect tools, private config and service logs", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
