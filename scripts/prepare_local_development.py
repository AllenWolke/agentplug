"""Prepare fresh, private Docker development configuration without starting services."""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import sys

ROOT = Path(__file__).resolve().parents[1]
SECRET_KEYS = (
    "DB_PASSWORD", "PLATFORM_RUNTIME_DB_PASSWORD", "INTERNAL_TOKEN",
    "BROWSER_GATEWAY_TOKEN", "METRIC_RUNNER_TOKEN", "INTERNAL_SIGNING_SECRET",
    "ACCESS_TOKEN_SIGNING_KEY",
)


def prepare(directory: Path, username: str, password: str, ports: dict[str, int]) -> tuple[Path, Path]:
    """Create both files exclusively; preserve any existing deployment configuration."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", username):
        raise ValueError("administrator ID must contain only letters, digits, dots, underscores or hyphens")
    if not 10 <= len(password.encode("utf-8")) <= 128 or "\x00" in password:
        raise ValueError("administrator password must contain 10..128 UTF-8 bytes and no NUL")
    if set(ports) != {"FRONTEND_HOST_PORT", "POSTGRES_HOST_PORT", "PLATFORM_HOST_PORT", "PLATFORM_INTERNAL_HOST_PORT"}:
        raise ValueError("all four development ports are required")
    if any(not 1 <= port <= 65535 for port in ports.values()) or len(set(ports.values())) != len(ports):
        raise ValueError("development ports must be distinct integers in 1..65535")
    directory = directory.absolute()
    # Refuse existing symlink components before resolving the destination.
    if any(path.is_symlink() for path in (directory, *directory.parents)):
        raise ValueError("configuration destination must not contain symlinks")
    directory = directory.resolve()
    directory.relative_to(ROOT.resolve())
    private = directory / ".local-secrets"
    if private.is_symlink():
        raise ValueError("private configuration directory must not be a symlink")
    environment = directory / ".env"
    administrator = private / "first-admin.json"
    if any(path.exists() or path.is_symlink() for path in (environment, administrator)):
        raise FileExistsError("configuration already exists; use the existing files instead of generating new credentials")
    replacements = {key: secrets.token_urlsafe(32) for key in SECRET_KEYS}
    key = Ed25519PrivateKey.generate()
    replacements["PLATFORM_CONTEXT_PRIVATE_KEY"] = base64.b64encode(key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())).decode("ascii")
    replacements["PLATFORM_CONTEXT_PUBLIC_KEY"] = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
    replacements.update({name: str(port) for name, port in ports.items()})
    replacements.update({"APP_ENV": "development", "FRONTEND_AUTH_MODE": "local",
                         "PLATFORM_DEMO_IDENTITY_BOOTSTRAP": "false"})
    lines = []
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        name, separator, _ = line.partition("=")
        lines.append(f"{name}={replacements[name]}" if separator and name in replacements else line)
    request = {
        "version": 1,
        "db_dsn": "postgresql://platform_runtime:" + replacements["PLATFORM_RUNTIME_DB_PASSWORD"] + "@postgres:5432/agentplug?sslmode=disable",
        "tenant_id": "tenant-demo", "tenant_name": "Development Company",
        "department_id": "dept-platform", "department_name": "Platform Administration",
        "application_id": "app-platform-admin", "application_name": "Platform Administration",
        "principal_id": username, "operator_id": "deployment.operator",
        "local_password": password, "approval_reference": "local-development-initialization",
    }
    directory.mkdir(parents=True, exist_ok=True)
    private.mkdir(mode=0o700, exist_ok=True)
    # Create bind sources as the host user. Docker-created directories on
    # Windows may inherit permissions that prevent later owned cleanup.
    for name in ("agent-workloads", "model-providers"):
        bind_source = private / name
        if bind_source.is_symlink() or bind_source.is_junction():
            raise ValueError("private bind source must not be a link")
        bind_source.mkdir(mode=0o700, exist_ok=True)
    written: list[Path] = []
    try:
        for target, body in ((environment, "\n".join(lines) + "\n"),
                             (administrator, json.dumps(request, ensure_ascii=False, indent=2) + "\n")):
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            written.append(target)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(body)
    except Exception:
        for target in reversed(written):
            target.unlink()
        raise
    return environment, administrator


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT, help="new configuration directory inside this repository; existing files are never replaced")
    parser.add_argument("--administrator", default="platform.admin", help="first platform administrator ID (default: platform.admin)")
    parser.add_argument("--password-stdin", action="store_true", help="read one password from private standard input for automation; never pass passwords as command arguments")
    for name, default in (("frontend", 3000), ("postgres", 5432), ("platform", 38082), ("internal", 38083)):
        parser.add_argument(f"--{name}-port", type=int, default=default)
    args = parser.parse_args()
    try:
        # Check before prompting so existing deployments never need to enter credentials.
        if any(path.exists() or path.is_symlink() for path in (
            args.directory / ".env", args.directory / ".local-secrets/first-admin.json")):
            raise FileExistsError("configuration already exists; no files were changed")
        if args.password_stdin:
            raw = sys.stdin.read(257)
            password = raw.removesuffix("\n").removesuffix("\r")
            if "\n" in password or "\r" in password:
                raise ValueError("standard input must contain exactly one password line")
        else:
            password = getpass.getpass("First administrator password (10..128 UTF-8 bytes): ")
            if password != getpass.getpass("Confirm administrator password: "):
                raise ValueError("password confirmation does not match")
        paths = prepare(args.directory, args.administrator, password, {
            "FRONTEND_HOST_PORT": args.frontend_port, "POSTGRES_HOST_PORT": args.postgres_port,
            "PLATFORM_HOST_PORT": args.platform_port, "PLATFORM_INTERNAL_HOST_PORT": args.internal_port,
        })
    except ImportError:
        print('Install prerequisite: python -m pip install "cryptography>=43,<46"', file=sys.stderr)
        return 1
    except (OSError, ValueError, EOFError, KeyboardInterrupt) as error:
        # Do not serialize user data, private paths or environment contents in errors.
        message = str(error) if isinstance(error, (ValueError, FileExistsError)) else type(error).__name__
        print(f"Development preparation refused: {message}", file=sys.stderr)
        return 1
    print("DEVELOPMENT CONFIGURATION READY (no services started)")
    for path in paths:
        print(path.relative_to(ROOT))
    print(f"Administrator: {args.administrator}")
    print(f"Console after startup: http://127.0.0.1:{args.frontend_port}")
    print("Keep configuration private; restrict Windows ACLs or retain POSIX owner-only permissions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
