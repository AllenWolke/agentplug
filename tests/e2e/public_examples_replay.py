"""Isolated replay phases for the public five-human/three-machine workflow.

This controller is deliberately separate from the default five-account smoke
test. It creates a unique Compose project and owner-private state, then calls
the same documented bootstrap functions and authenticated APIs used by an
operator. It has no production endpoint mode.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import getpass
import ipaddress
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import bootstrap_public_examples as bootstrap
import public_example_authorization as example_authorization
import public_model_governance as public_model_governance
import public_knowledge_replay as public_knowledge
import public_business_replay as public_business
import publish_public_policy_release as public_policy
from public_project_e2e import free_port

STATE_ROOT = ROOT / ".local-secrets" / "public-project-replay"
COMPOSE_BASE = ROOT / "compose.yaml"
COMPOSE_EXAMPLES = ROOT / "deploy/compose/compose.examples.yaml"
COMPOSE_RUNTIME = ROOT / "deploy/compose/compose.runtime.yaml"
HUMANS = ("system.admin", "permission.admin", *bootstrap.DEMO_USERS)
AUTHOR_ROLE = "agent_developer"
ROLE_DURATION = timedelta(hours=8)
BUSINESS_ROLE_DURATION = timedelta(hours=24)
AUDIT_ROLE_DURATION = timedelta(hours=8)
_OWNER_HUMAN_API_SESSIONS: dict[tuple, dict] = {}
_SESSION_REFRESH_SKEW_SECONDS = 5
def project_name(value: str) -> str:
    if not re.fullmatch(r"agentplug-test-public-[a-f0-9]{12}", value):
        raise ValueError("project must be a freshly prepared agentplug-test-public-* owner")
    return value


def state_dir(project: str) -> Path:
    project_name(project)
    return STATE_ROOT / project


def write_json_private(path: Path, value: dict) -> None:
    content = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    if not path.exists():
        bootstrap.write_new_private_file(path, content)
        return
    bootstrap.verify_private_file(path)
    temporary = path.with_name(path.name + ".next-" + uuid.uuid4().hex)
    try:
        bootstrap.write_new_private_file(temporary, content)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def replace_private_file(path: Path, content: str) -> None:
    bootstrap.verify_private_file(path)
    temporary = path.with_name(path.name + ".next-" + uuid.uuid4().hex)
    try:
        bootstrap.write_new_private_file(temporary, content)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_owner_env(directory: Path) -> dict[str, str]:
    path = directory / "private.env"
    bootstrap.verify_private_file(path)
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or key in values:
            raise RuntimeError("owner Compose environment has an invalid or duplicate setting")
        values[key] = value
    return values


def owner_private_output(directory: Path, target: Path, *, allow_existing: bool = False) -> Path:
    candidate = target if target.is_absolute() else directory / target
    if ".." in candidate.parts:
        raise ValueError("output path may not traverse parent directories")
    try:
        root = directory.resolve(strict=True)
        parent = candidate.parent.resolve(strict=True)
        parent.relative_to(root)
    except (OSError, ValueError):
        raise ValueError("output must be placed in this exact owner-private project directory") from None
    # Check the lexical path components before resolving them. Walking the
    # resolved parent would hide a symlink/junction that still lands inside
    # the owner directory.
    try:
        lexical_parent = candidate.parent.absolute()
        lexical_relative = lexical_parent.relative_to(directory.absolute())
    except ValueError:
        raise ValueError("output must be placed in this exact owner-private project directory") from None
    current = directory.absolute()
    for component in lexical_relative.parts:
        current = current / component
        if bootstrap.is_reparse_point(current):
            raise ValueError("output path may not traverse a symlink, junction or reparse point")
    if bootstrap.is_reparse_point(candidate):
        raise ValueError("output path may not be a symlink, junction or reparse point")
    bootstrap.ensure_private_directory(parent)
    if candidate.exists():
        if not allow_existing:
            raise ValueError("owner-private output already exists; no file was overwritten")
        if not candidate.is_file():
            raise ValueError("existing owner-private output is not a regular file")
        bootstrap.verify_private_file(candidate)
        return candidate
    return parent / candidate.name


def write_or_reuse_exact_private_json(directory: Path, target: Path, value: dict) -> Path:
    """Write a private JSON artifact once, or reuse it only when identical."""
    path = owner_private_output(directory, target, allow_existing=True)
    expected = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if path.exists():
        try:
            actual = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise RuntimeError("existing owner-private input is unreadable; no file was overwritten") from None
        if actual != value:
            raise RuntimeError("owner-private input already contains a different plan; no file was overwritten")
        return path
    bootstrap.write_new_private_file(path, expected)
    return path


def prepare_model_secrets(project: str, chat_endpoint: str | None = None, embedding_endpoint: str | None = None,
                          chat_key: str | None = None, embedding_key: str | None = None,
                          input_value=input, secret_input=getpass.getpass) -> None:
    """Collect externally authorized provider material without writing secrets to logs."""
    directory, owner, _passwords = read_manifest(project)
    if owner.get("model_secrets_ready") or owner.get("identity_complete"):
        raise RuntimeError("model credential preparation is one-time and must precede the first Compose startup")
    chat_endpoint = chat_endpoint if chat_endpoint is not None else input_value("HTTPS endpoint for the approved chat provider: ").strip()
    embedding_endpoint = embedding_endpoint if embedding_endpoint is not None else input_value("HTTPS endpoint for the approved embedding provider: ").strip()
    chat_key = chat_key if chat_key is not None else secret_input("Approved chat-provider key (hidden): ")
    embedding_key = embedding_key if embedding_key is not None else secret_input("Approved embedding-provider key (hidden): ")
    endpoints = {"service://example-chat": chat_endpoint, "service://example-embedding": embedding_endpoint}
    for value in endpoints.values():
        try:
            parsed = bootstrap.urllib.parse.urlsplit(value)
            port = parsed.port
        except ValueError:
            raise ValueError("provider endpoint must be a valid HTTPS URL") from None
        if (not isinstance(value, str) or value != value.strip() or "\\" in value
                or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or port not in (None, 443)):
            raise ValueError("provider endpoint must use clean HTTPS without credentials, query, fragment or a nonstandard port")
    for value in (chat_key, embedding_key):
        if (not isinstance(value, str) or not value or len(value) > 8192
                or any(ord(char) < 33 or ord(char) > 126 for char in value)):
            raise ValueError("provider credential must be one bounded nonempty ASCII token")
    target = directory / "model-secrets"
    bootstrap.ensure_private_directory(target)
    metadata_path = directory / "model-metadata.json"
    if any((target / filename).exists() for filename in ("deepseek.key", "embedding.key")) or metadata_path.exists():
        raise RuntimeError("owner model credential mount is not empty; refusing to overwrite any secret or metadata")
    bootstrap.write_new_private_file(target / "deepseek.key", chat_key + "\n")
    bootstrap.write_new_private_file(target / "embedding.key", embedding_key + "\n")
    env_path = directory / "private.env"
    bootstrap.verify_private_file(env_path)
    values = read_owner_env(directory)
    mappings = json.dumps(endpoints, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    values["PLATFORM_POLICY_RESOLVER"] = "sql"
    values["PLATFORM_MODEL_ENDPOINTS_JSON"] = mappings
    replace_private_file(env_path, "".join(f"{key}={value}\n" for key, value in values.items()))
    metadata = {"schema": "public-model-metadata/v1", "endpoints": endpoints,
                "key_files": {"chat": "deepseek.key", "embedding": "embedding.key"}}
    bootstrap.write_new_private_file(metadata_path, json.dumps(metadata, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    owner["model_secrets_ready"] = True
    owner["model_secret_references"] = ["secret://deepseek.key", "secret://embedding.key"]
    owner["model_endpoint_references"] = sorted(endpoints)
    write_json_private(directory / "owner.json", owner)
    print(json.dumps({"result": "owner_private_model_secret_mount_prepared", "project": project,
                      "secret_references": owner["model_secret_references"], "endpoint_references": owner["model_endpoint_references"],
                      "secret_values_printed": False, "provider_connectivity_tested": False}, ensure_ascii=False))


def prepare_model_plan(project: str, directory: Path, output: Path, chat_model: str, embedding_model: str,
                       prices: dict, dimensions: int, chat_context_limit: int, embedding_context_limit: int,
                       effective_from: str, semantic_version: str = "0.1.0") -> Path:
    _directory, owner, _passwords = read_manifest(project)
    if not owner.get("model_secrets_ready") or owner.get("identity_complete"):
        raise RuntimeError("model plan preparation requires the private provider metadata before the first Compose startup")
    metadata_path = directory / "model-metadata.json"
    bootstrap.verify_private_file(metadata_path)
    if bootstrap.is_reparse_point(metadata_path):
        raise RuntimeError("owner model metadata must be a regular private file")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if (not isinstance(metadata, dict) or set(metadata) != {"schema", "endpoints", "key_files"}
            or metadata.get("schema") != "public-model-metadata/v1"
            or metadata.get("key_files") != {"chat": "deepseek.key", "embedding": "embedding.key"}
            or set(metadata.get("endpoints", {})) != {"service://example-chat", "service://example-embedding"}):
        raise RuntimeError("owner model metadata is incomplete or contains unexpected fields")
    for filename in ("deepseek.key", "embedding.key"):
        secret_path = directory / "model-secrets" / filename
        if bootstrap.is_reparse_point(secret_path):
            raise RuntimeError("owner model credential mount contains a reparse point")
        bootstrap.verify_private_file(secret_path)
    plan = public_model_governance.build_plan(
        project, bootstrap.BUSINESS_SCOPE,
        {"llm": {"model": chat_model, "base_url": metadata["endpoints"]["service://example-chat"], "key_file": "deepseek.key"},
         "embedding": {"model": embedding_model, "base_url": metadata["endpoints"]["service://example-embedding"], "key_file": "embedding.key"}},
        prices, dimensions, {"chat": chat_context_limit, "embedding": embedding_context_limit},
        effective_from, semantic_version,
    )
    output_path = owner_private_output(directory, output)
    bootstrap.write_new_private_file(output_path, json.dumps(plan, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"result": "key_free_model_governance_plan_saved", "project": project,
                      "path": str(output_path.relative_to(directory).as_posix()), "model_count": 2,
                      "secret_values_printed": False, "provider_urls_printed": False,
                      "platform_api_called": False}, ensure_ascii=False))
    return output_path


def compose_prefix(project: str, directory: Path, include_examples: bool = True, include_runtime: bool = False) -> list[str]:
    prefix = ["docker", "compose", "--project-name", project, "--env-file", str(directory / "private.env"), "-f", str(COMPOSE_BASE)]
    if include_examples:
        prefix.extend(["-f", str(COMPOSE_EXAMPLES)])
    if include_runtime:
        prefix.extend(["--env-file", str(directory / "runtime-control" / "compose.env"), "-f", str(COMPOSE_RUNTIME)])
    if include_examples:
        prefix.extend(["-f", str(directory / "compose-image-overlay.json")])
    if include_runtime:
        prefix.extend(["-f", str(directory / "runtime-owner-overlay.json")])
    return prefix + ["--profile", "modular"]


def isolated_compose_environment(directory: Path, include_runtime: bool = False) -> dict[str, str]:
    """Prevent shell exports from overriding this owner's generated Compose inputs."""
    result = os.environ.copy()
    files = [directory / "private.env"]
    if include_runtime:
        files.append(directory / "runtime-control" / "compose.env")
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#") or "=" not in line:
                continue
            name = line.partition("=")[0]
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise ValueError("owner Compose environment contains an invalid key")
            result.pop(name, None)
    return result


def select_owner_network_subnet(existing_subnets: list[str]) -> str:
    occupied = [ipaddress.ip_network(value, strict=True) for value in existing_subnets]
    for third in range(16, 240):
        candidate = ipaddress.ip_network(f"172.29.{third}.0/28", strict=True)
        if not any(candidate.overlaps(value) for value in occupied if value.version == 4):
            return str(candidate)
    raise RuntimeError("no isolated owner subnet available; no network was created")


def owner_network_overlay(project: str) -> dict:
    ids = subprocess.run(["docker", "network", "ls", "-q"], capture_output=True, check=True, timeout=30).stdout.decode().split()
    networks = []
    if ids:
        inspected = subprocess.run(["docker", "network", "inspect", *ids], capture_output=True, check=True, timeout=30)
        networks = json.loads(inspected.stdout)
    occupied = [row["Subnet"] for network in networks for row in network.get("IPAM", {}).get("Config", []) if row.get("Subnet")]
    subnet = select_owner_network_subnet(occupied)
    return {"networks": {"default": {"name": project + "_default", "ipam": {"config": [{"subnet": subnet}]}}}}


def prepare() -> dict:
    project = "agentplug-test-public-" + uuid.uuid4().hex[:12]
    directory = state_dir(project)
    bootstrap.ensure_private_directory(directory)
    secret_dir = directory / "empty-secrets"
    model_secret_dir = directory / "model-secrets"
    bootstrap.ensure_private_directory(secret_dir)
    bootstrap.ensure_private_directory(model_secret_dir)
    machine_env = directory / "machines.env"
    machine_credentials = bootstrap.load_or_create_machine_env(machine_env)

    private_key = Ed25519PrivateKey.generate()
    settings = {key: secrets.token_urlsafe(48) for key in (
        "DB_PASSWORD", "PLATFORM_RUNTIME_DB_PASSWORD", "INTERNAL_TOKEN", "BROWSER_GATEWAY_TOKEN",
        "INTERNAL_SIGNING_SECRET", "METRIC_RUNNER_TOKEN", "ACCESS_TOKEN_SIGNING_KEY",
    )}
    settings.update(
        APP_ENV="development", DB_DRIVER="pgx", PLATFORM_DEMO_IDENTITY_BOOTSTRAP="false",
        FRONTEND_AUTH_MODE="local", COOKIE_SECURE="false", FRONTEND_HOST_BIND="127.0.0.1", PLATFORM_RUN_EXECUTOR="platform",
        PLATFORM_EVENT_BUS_MODE="disabled", PLATFORM_POLICY_RESOLVER="disabled",
        PLATFORM_RUN_TREE_BUDGET_ENABLED="true",
        PLATFORM_MODEL_SECRET_DIR=model_secret_dir.as_posix(), PLATFORM_WORKLOAD_SECRET_DIR=secret_dir.as_posix(),
    )
    # Use only this owner's PostgreSQL projection, regardless of host exports.
    settings["KNOWLEDGE_DATABASE_DSN"] = owner_knowledge_dsn(settings["PLATFORM_RUNTIME_DB_PASSWORD"])
    settings["PLATFORM_CONTEXT_PRIVATE_KEY"] = base64.b64encode(private_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption(),
    )).decode("ascii")
    settings["PLATFORM_CONTEXT_PUBLIC_KEY"] = base64.b64encode(private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )).decode("ascii")
    used = set()
    for key in ("POSTGRES_HOST_PORT", "FRONTEND_HOST_PORT", "PLATFORM_HOST_PORT", "PLATFORM_INTERNAL_HOST_PORT"):
        port = free_port()
        while port in used:
            port = free_port()
        used.add(port)
        settings[key] = str(port)
    settings.update(machine_credentials)
    bootstrap.write_new_private_file(directory / "private.env", "".join(f"{key}={value}\n" for key, value in settings.items()))

    passwords = {username: secrets.token_urlsafe(32) for username in HUMANS}
    admin_configuration = {
        "version": 1,
        "db_dsn": "postgresql://platform_runtime:" + settings["PLATFORM_RUNTIME_DB_PASSWORD"] + "@postgres:5432/agentplug?sslmode=disable",
        "tenant_id": bootstrap.ADMIN_SCOPE["tenant_id"], "tenant_name": "Public replay tenant",
        "department_id": bootstrap.ADMIN_SCOPE["department_id"], "department_name": "Platform administration",
        "application_id": bootstrap.ADMIN_SCOPE["application_id"], "application_name": "Platform administration",
        "principal_id": "system.admin", "operator_id": "isolated-public-replay",
        "approval_reference": "isolated-public-initialization", "local_password": passwords["system.admin"],
    }
    write_json_private(directory / "first-administrator.json", admin_configuration)
    write_json_private(directory / "human-credentials.json", {"owner": project, "passwords": passwords})

    image_names = {
        "platform-app": "platform", "platform-migrate": "platform", "frontend": "frontend",
        "metric-runner": "metric-runner", "example-go": "example-go",
        "example-python": "example-python", "example-java": "example-java",
    }
    images = {service: f"agentplug:test-{kind}-{project.removeprefix('agentplug-test-public-')}" for service, kind in image_names.items()}
    full_overlay = {"services": {service: {"image": image} for service, image in images.items()}}
    admin_overlay = {"services": {service: {"image": images[service]} for service in ("platform-app", "platform-migrate", "frontend", "metric-runner")}}
    # Fixed SDK source /32s require a user-configured Docker subnet. Persist the
    # same collision-checked network in bootstrap and later Runtime phases.
    network_overlay = owner_network_overlay(project)
    full_overlay.update(network_overlay)
    admin_overlay.update(network_overlay)
    write_json_private(directory / "compose-image-overlay.json", full_overlay)
    write_json_private(directory / "bootstrap-image-overlay.json", admin_overlay)
    manifest = {"owner": project, "ports": {key: int(settings[key]) for key in (
        "FRONTEND_HOST_PORT", "PLATFORM_HOST_PORT", "PLATFORM_INTERNAL_HOST_PORT", "POSTGRES_HOST_PORT",
    )}, "images": list(images.values()), "identity_complete": False, "machines_complete": False,
        "runtime_prepared": False, "runtime_process_started": False, "catalog_lifecycle": {}, "skill_lifecycle": {},
        "machine_principals_complete": False, "machine_binding_journal": {},
        "temporary_author_roles": {}, "permission_admin_appointment": None, "permission_admin_delegations": [],
        "model_secrets_ready": False, "model_governance": None, "model_governance_journal": {}}
    write_json_private(directory / "owner.json", manifest)
    return {"project": project, "private_directory": str(directory), "ports": manifest["ports"], "secret_values_printed": False}


def owner_knowledge_dsn(runtime_password: str) -> str:
    if not isinstance(runtime_password, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", runtime_password):
        raise ValueError("owner runtime password must be a generated URL-safe secret")
    return "postgresql://platform_runtime:" + runtime_password + "@postgres:5432/agentplug?sslmode=disable"


def read_manifest(project: str) -> tuple[Path, dict, dict]:
    directory = state_dir(project)
    bootstrap.ensure_private_directory(directory)
    owner_path = directory / "owner.json"
    credentials_path = directory / "human-credentials.json"
    bootstrap.verify_private_file(owner_path)
    bootstrap.verify_private_file(credentials_path)
    owner = json.loads(owner_path.read_text(encoding="utf-8"))
    credentials = json.loads(credentials_path.read_text(encoding="utf-8"))
    if owner.get("owner") != project or credentials.get("owner") != project:
        raise ValueError("private replay owner does not match the requested Compose project")
    if set(credentials.get("passwords", {})) != set(HUMANS):
        raise ValueError("private replay credential map does not contain exactly the five reviewed humans")
    return directory, owner, credentials["passwords"]


def run_compose(project: str, directory: Path, arguments: list[str], timeout: int = 240, required: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(compose_prefix(project, directory) + arguments, cwd=ROOT, capture_output=True,
                            timeout=timeout, env=isolated_compose_environment(directory))
    if required and result.returncode:
        raise RuntimeError("isolated Compose operation failed; inspect project-scoped container health without exposing credentials")
    return result


def existing_project_resources(project: str) -> bool:
    containers = subprocess.run(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project], capture_output=True, check=True)
    volumes = subprocess.run(["docker", "volume", "ls", "-q", "--filter", "label=com.docker.compose.project=" + project], capture_output=True, check=True)
    return bool(containers.stdout.strip() or volumes.stdout.strip())


def start_isolated_base(project: str, directory: Path) -> None:
    if existing_project_resources(project):
        raise RuntimeError("new replay project already has Compose resources; refusing to attach to an existing project")
    run_compose(project, directory, ["config", "--quiet"])
    run_compose(project, directory, ["build", "platform-app", "frontend", "metric-runner", "example-go", "example-python", "example-java"], timeout=900)
    run_compose(project, directory, ["up", "-d", "--no-build", "--wait", "--wait-timeout", "180", "postgres", "metric-runner", "platform-app", "frontend"])


def initialize_first_admin(project: str, directory: Path) -> None:
    command = [sys.executable, "-B", str(ROOT / "scripts" / "bootstrap_first_admin.py"),
               "--project", project, "--env-file", str(directory / "private.env"),
               "--config", str(directory / "first-administrator.json"),
               "--compose-overlay", str(directory / "bootstrap-image-overlay.json")]
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=60)
    if completed.returncode or b"FIRST ADMINISTRATOR BOOTSTRAP PASS" not in completed.stdout:
        raise RuntimeError("first administrator initialization did not verify on the isolated database")


def identity_phase(project: str, apply_confirmation: str) -> None:
    directory, owner, passwords = read_manifest(project)
    if apply_confirmation != project or owner.get("identity_complete") or not owner.get("model_secrets_ready"):
        raise ValueError("identity phase requires one-time owner confirmation and an owner-private model endpoint/secret mount prepared before startup")
    start_isolated_base(project, directory)
    initialize_first_admin(project, directory)
    api = bootstrap.BrowserAPI("http://127.0.0.1:" + str(owner["ports"]["FRONTEND_HOST_PORT"]))
    api.login("system.admin", passwords["system.admin"])
    api.select_workspace(bootstrap.ADMIN_SCOPE)
    bootstrap.verify_login_identity(api.call("GET", "/auth/me"), "system.admin", bootstrap.ADMIN_SCOPE)

    confirmations = iter(["dept-demo", "app-demo", *["create " + name for name, _ in bootstrap.ACCOUNTS],
                          *[name + "@app-demo" for name in ("system.admin", "permission.admin", *bootstrap.DEMO_USERS)]])
    saved_getpass, saved_confirm = bootstrap.getpass.getpass, bootstrap.confirm
    def password_for(prompt: str) -> str:
        match = re.search(r"for ([a-z][a-z0-9.]*)", prompt)
        if not match or match.group(1) not in passwords:
            raise RuntimeError("public identity helper requested an unexpected credential")
        return passwords[match.group(1)]
    def approve(_phrase: str) -> bool:
        try:
            expected = next(confirmations)
        except StopIteration:
            return False
        return _phrase == expected
    try:
        bootstrap.getpass.getpass = password_for
        bootstrap.confirm = approve
        bootstrap.ensure_organization(api)
        bootstrap.create_accounts(api)
        for username in HUMANS:
            bootstrap.add_membership(api, username, preserve_initial_admin=username == "system.admin")
        if next(confirmations, None) is not None:
            raise RuntimeError("one or more expected clean-project Identity plans were not submitted")
    finally:
        bootstrap.getpass.getpass = saved_getpass
        bootstrap.confirm = saved_confirm

    for username in HUMANS:
        independent = bootstrap.BrowserAPI(api.origin)
        independent.login(username, passwords[username])
        selected = bootstrap.BUSINESS_SCOPE if username in {"system.admin", "permission.admin", *bootstrap.DEMO_USERS} else bootstrap.ADMIN_SCOPE
        independent.select_workspace(selected)
        bootstrap.verify_login_identity(independent.call("GET", "/auth/me"), username, selected)
        access = bootstrap.profile(independent, username)
        bootstrap.verify_public_human_access(access, username, allow_business_membership=True)
        if not bootstrap.active_membership(access, username, bootstrap.BUSINESS_SCOPE):
            raise RuntimeError("human business-workspace membership did not verify")
        independent.call("POST", "/auth/logout", {})
    owner["identity_complete"] = True
    write_json_private(directory / "owner.json", owner)
    print(json.dumps({"result": "five_independent_human_logins_verified", "project": project,
                      "business_members": ["system.admin", "permission.admin", *bootstrap.DEMO_USERS],
                      "business_roles": [], "system_admin_management_binding_preserved": True,
                      "resource_grants": [], "credentials_printed": False}, ensure_ascii=False))


def verify_identity_organization(api: bootstrap.BrowserAPI) -> None:
    department_query = bootstrap.urllib.parse.urlencode({"tenant_id": "tenant-demo", "department_id": "dept-demo", "status": "active"})
    departments = bootstrap.items(api.call("GET", bootstrap.api_path("/departments?" + department_query)), "department list")
    department = [item for item in departments if item.get("id") == "dept-demo"]
    if len(department) != 1 or any(department[0].get(key) != value for key, value in {
        "tenant_id": "tenant-demo", "code": "examples", "name": "SDK示例", "status": "active", "revision": 1,
    }.items()):
        raise RuntimeError("identity recovery requires the exact existing dept-demo; it will not create or repair organization records")
    app_query = bootstrap.urllib.parse.urlencode({**bootstrap.BUSINESS_SCOPE, "status": "active"})
    applications = bootstrap.items(api.call("GET", bootstrap.api_path("/applications?" + app_query)), "application list")
    application = [item for item in applications if item.get("id") == "app-demo"]
    if len(application) != 1 or any(application[0].get(key) != value for key, value in {
        "tenant_id": "tenant-demo", "department_id": "dept-demo", "code": "sdk-examples",
        "name": "SDK业务示例", "status": "active", "revision": 1,
    }.items()):
        raise RuntimeError("identity recovery requires the exact existing app-demo; it will not create or repair organization records")


def verify_identity_reconcile_inputs(project: str, directory: Path, owner: dict, passwords: dict[str, str]) -> dict[str, str]:
    if owner.get("identity_complete") or not owner.get("model_secrets_ready"):
        raise ValueError("identity-reconcile requires an incomplete identity owner with its private model mounts prepared")
    for name in ("private.env", "first-administrator.json", "compose-image-overlay.json"):
        path = directory / name
        bootstrap.verify_private_file(path)
        if bootstrap.is_reparse_point(path):
            raise RuntimeError("identity recovery input is not a regular owner-private file")
    env = read_owner_env(directory)
    if (env.get("APP_ENV") != "development" or env.get("DB_DRIVER") != "pgx"
            or env.get("PLATFORM_DEMO_IDENTITY_BOOTSTRAP") != "false"
            or env.get("FRONTEND_AUTH_MODE") != "local" or env.get("FRONTEND_HOST_BIND") != "127.0.0.1"):
        raise RuntimeError("identity recovery owner environment differs from the isolated PostgreSQL/local-login setup")
    ports = owner.get("ports")
    if not isinstance(ports, dict) or set(ports) != {"FRONTEND_HOST_PORT", "PLATFORM_HOST_PORT", "PLATFORM_INTERNAL_HOST_PORT", "POSTGRES_HOST_PORT"}:
        raise RuntimeError("identity recovery owner port inventory is invalid")
    for name, port in ports.items():
        if not isinstance(port, int) or not 1 <= port <= 65535 or env.get(name) != str(port):
            raise RuntimeError("identity recovery owner environment and private port inventory differ")
    config = json.loads((directory / "first-administrator.json").read_text(encoding="utf-8"))
    if any(config.get(key) != value for key, value in {
        "version": 1, "tenant_id": bootstrap.ADMIN_SCOPE["tenant_id"],
        "department_id": bootstrap.ADMIN_SCOPE["department_id"],
        "application_id": bootstrap.ADMIN_SCOPE["application_id"],
        "principal_id": "system.admin", "approval_reference": bootstrap.FIRST_ADMIN_APPROVAL_REFERENCE,
        "local_password": passwords["system.admin"],
    }.items()):
        raise RuntimeError("private first-administrator configuration does not match this owner and credential file")
    verify_owner_frontend(project, directory, owner)
    return env


def identity_membership_facts(profile: dict) -> dict:
    principal = profile.get("principal") if isinstance(profile, dict) else None
    if not isinstance(principal, dict):
        raise RuntimeError("Identity principal profile is invalid before membership reconciliation")
    return {
        "principal": {key: principal.get(key) for key in ("id", "type", "tenant_id", "is_active", "revision", "roles", "groups")},
        "role_bindings": deepcopy(profile.get("role_bindings")),
        "resource_grants": deepcopy(profile.get("resource_grants")),
        "task_assignments": deepcopy(profile.get("task_assignments")),
        "delegations": deepcopy(profile.get("delegations")),
        "memberships": deepcopy(profile.get("memberships")),
    }


def verify_identity_membership_delta(before: dict, after: dict, username: str) -> dict:
    bootstrap.verify_public_human_access(after, username, allow_business_membership=True)
    prior = before.get("principal") if isinstance(before, dict) else None
    current = after.get("principal") if isinstance(after, dict) else None
    if not isinstance(prior, dict) or not isinstance(current, dict):
        raise RuntimeError("Identity membership receipt has no principal revision baseline")
    expected_revision = prior.get("revision")
    if type(expected_revision) is not int or current.get("revision") != expected_revision + 1:
        raise RuntimeError("membership-only CAS did not advance the principal revision exactly once")
    for key in ("id", "type", "tenant_id", "is_active", "roles", "groups"):
        if current.get(key) != prior.get(key):
            raise RuntimeError("membership-only CAS changed another principal attribute")
    for key in ("role_bindings", "resource_grants", "task_assignments", "delegations"):
        if after.get(key) != before.get(key):
            raise RuntimeError(f"membership-only CAS unexpectedly changed {key.replace('_', ' ')}")
    old_memberships = before.get("memberships")
    new_memberships = after.get("memberships")
    if not isinstance(old_memberships, list) or not isinstance(new_memberships, list) or len(new_memberships) != len(old_memberships) + 1:
        raise RuntimeError("membership-only CAS did not add exactly one workspace membership")
    old_by_id = {item.get("id"): item for item in old_memberships if isinstance(item, dict)}
    new_by_id = {item.get("id"): item for item in new_memberships if isinstance(item, dict)}
    if (None in old_by_id or None in new_by_id or len(old_by_id) != len(old_memberships)
            or len(new_by_id) != len(new_memberships)
            or any(new_by_id.get(key) != value for key, value in old_by_id.items())):
        raise RuntimeError("membership-only CAS modified or replaced an existing membership")
    membership_id = "public-demo-workspace-v1-" + username.replace(".", "-")
    added = new_by_id.get(membership_id)
    if not isinstance(added, dict) or any(added.get(key) != value for key, value in {
        "subject_id": username, "scope": bootstrap.management_scope(bootstrap.BUSINESS_SCOPE),
        "status": "active", "revision": 1, "source_id": "membership:public-demo-workspace-v1:" + username,
    }.items()):
        raise RuntimeError("membership-only CAS did not create the exact active app-demo membership")
    if added.get("delegation_id") not in (None, "") or added.get("starts_at") is not None or added.get("expires_at") is not None:
        raise RuntimeError("app-demo membership unexpectedly includes delegated or time-limited authority")
    return added


def identity_membership_command(username: str, revision: int) -> dict:
    return {
        "subject_type": "user", "subject_id": username, "expected_revision": revision,
        "idempotency_key": "public-demo-workspace-v1:" + username,
        "reason": "Add the public example application workspace without business roles or resource grants",
        "memberships": [{"id": "public-demo-workspace-v1-" + username.replace(".", "-"),
                         "scope": bootstrap.management_scope(bootstrap.BUSINESS_SCOPE),
                         "expected_revision": 0, "status": "active"}],
    }


def verify_identity_membership_preview_change(plan: dict, command: dict, username: str, revision: int) -> None:
    """Compare the request while accounting only for Go's serialized zero time.Time field."""
    if (plan.get("actor_id") != "system.admin" or plan.get("subject_id") != username
            or plan.get("baseline_revision") != revision):
        raise RuntimeError("Identity membership preview actor, subject or CAS baseline differs from the request")
    normalized = plan.get("change")
    if not isinstance(normalized, dict):
        raise RuntimeError("Identity membership preview has no normalized change")
    normalized = deepcopy(normalized)
    if "plan_expires_at" in normalized:
        if normalized["plan_expires_at"] != "0001-01-01T00:00:00Z":
            raise RuntimeError("Identity membership preview contains an unexpected change expiration")
        normalized.pop("plan_expires_at")
    if "plan_digest" in normalized:
        if normalized["plan_digest"] != "":
            raise RuntimeError("Identity membership preview contains an unexpected nested digest")
        normalized.pop("plan_digest")
    if normalized != command:
        raise RuntimeError("Identity membership preview differs from the exact system.admin CAS request")


def reconcile_identity_membership(api: bootstrap.BrowserAPI, project: str, directory: Path, owner: dict, username: str) -> None:
    journal = owner.get("identity_reconcile_journal")
    if journal is None:
        journal = {"schema": "public-identity-reconcile/v1", "memberships": {}}
        owner["identity_reconcile_journal"] = journal
    if (not isinstance(journal, dict) or journal.get("schema") != "public-identity-reconcile/v1"
            or not isinstance(journal.get("memberships"), dict)
            or not set(journal.get("memberships", {})).issubset(set(HUMANS))):
        raise RuntimeError("owner identity-reconcile journal has an unknown schema")
    entries = journal["memberships"]
    record = entries.get(username)
    current = bootstrap.profile(api, username)
    bootstrap.verify_public_human_access(current, username, allow_business_membership=None)
    if record is not None:
        if not isinstance(record, dict) or record.get("username") != username or not isinstance(record.get("before_facts"), dict):
            raise RuntimeError("owner membership journal entry is invalid")
        if (record.get("expected_revision") != record["before_facts"].get("principal", {}).get("revision")
                or not isinstance(record.get("plan_digest"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", record.get("plan_digest", ""))
                or not re.fullmatch(r"[a-f0-9]{64}", record.get("request_sha256", ""))):
            raise RuntimeError("owner membership journal does not bind its baseline revision and reviewed request")
        saved_request = record.get("request")
        expected_request = identity_membership_command(username, record["expected_revision"])
        verify_identity_membership_preview_change({
            "actor_id": "system.admin", "subject_id": username,
            "baseline_revision": record["expected_revision"], "change": record.get("preview_change"),
        }, expected_request, username, record["expected_revision"])
        if (not isinstance(saved_request, dict)
                or {key: value for key, value in saved_request.items() if key not in {"plan_digest", "plan_expires_at"}} != expected_request
                or saved_request.get("plan_digest") != record["plan_digest"]
                or hashlib.sha256(json.dumps(saved_request, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest() != record["request_sha256"]):
            raise RuntimeError("owner membership journal request is not the exact reviewed app-demo change")
        if not bootstrap.active_membership(current, username, bootstrap.BUSINESS_SCOPE):
            raise RuntimeError("an identity write intent already exists without its exact live membership; refusing to resubmit")
        verify_identity_membership_delta(record["before_facts"], current, username)
        if record.get("state") not in {"intent", "submitted", "verified"}:
            raise RuntimeError("owner membership journal state is unknown")
        saved_receipt = record.get("server_receipt")
        if saved_receipt is not None and (not isinstance(saved_receipt, dict)
                or saved_receipt.get("subject_id") != username or saved_receipt.get("actor_id") != "system.admin"
                or saved_receipt.get("revision") != record["expected_revision"] + 1
                or saved_receipt.get("plan_digest") != record["plan_digest"]):
            raise RuntimeError("saved Identity receipt does not match this membership intent")
        record["state"] = "verified"
        record["readback_revision"] = current["principal"]["revision"]
        record["readback_membership"] = next(item for item in current["memberships"] if item.get("id") == "public-demo-workspace-v1-" + username.replace(".", "-"))
        write_json_private(directory / "owner.json", owner)
        return
    if bootstrap.active_membership(current, username, bootstrap.BUSINESS_SCOPE):
        # A prior pre-journal run may have completed this one exact public membership.
        bootstrap.verify_public_human_access(current, username, allow_business_membership=True)
        return

    principal = current["principal"]
    revision = principal.get("revision")
    if type(revision) is not int or revision < 1:
        raise RuntimeError(f"{username} has no usable current principal revision")
    command = identity_membership_command(username, revision)
    plan = api.call("POST", bootstrap.api_path("/authorization-changes:preview"), command)
    bootstrap.validate_membership_plan(plan, username)
    verify_identity_membership_preview_change(plan, command, username, revision)
    if not isinstance(plan.get("plan_digest"), str) or not re.fullmatch(r"[a-f0-9]{64}", plan["plan_digest"]):
        raise RuntimeError("Identity membership preview digest is invalid")
    try:
        plan_expiry = datetime.fromisoformat(plan["plan_expires_at"].replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise RuntimeError("Identity membership preview expiration is invalid") from None
    if plan_expiry.tzinfo is None or plan_expiry <= datetime.now(timezone.utc):
        raise RuntimeError("Identity membership preview is expired or has no timezone")
    phrase = username + "@app-demo"
    if not bootstrap.confirm(phrase):
        raise RuntimeError(f"workspace membership cancelled for {username}")
    submit = dict(plan["change"])
    submit["plan_digest"] = plan["plan_digest"]
    submit["plan_expires_at"] = plan["plan_expires_at"]
    before_facts = identity_membership_facts(current)
    entries[username] = {
        "username": username, "state": "intent", "expected_revision": revision,
        "preview_change": deepcopy(plan["change"]),
        "plan_digest": plan["plan_digest"], "request": submit, "request_sha256": hashlib.sha256(
            json.dumps(submit, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(), "before_facts": before_facts,
    }
    write_json_private(directory / "owner.json", owner)

    receipt = api.call("POST", bootstrap.api_path("/authorization-changes"), submit)
    record = entries[username]
    record["state"] = "submitted"
    if isinstance(receipt, dict):
        record["server_receipt"] = {key: receipt.get(key) for key in ("change_id", "actor_id", "subject_id", "revision", "plan_digest")}
    write_json_private(directory / "owner.json", owner)
    if (not isinstance(receipt, dict) or receipt.get("subject_id") != username
            or receipt.get("actor_id") != "system.admin" or receipt.get("revision") != revision + 1
            or receipt.get("plan_digest") != plan["plan_digest"]):
        raise RuntimeError("Identity returned an unexpected membership receipt; owner intent retained and no retry will be made")
    after = bootstrap.profile(api, username)
    added = verify_identity_membership_delta(before_facts, after, username)
    record["state"] = "verified"
    record["readback_revision"] = after["principal"]["revision"]
    record["readback_membership"] = added
    write_json_private(directory / "owner.json", owner)


def identity_reconcile_phase(project: str, apply_confirmation: str) -> None:
    """Finish memberships after a partial first identity run without restarting or recreating anything."""
    directory, owner, passwords = read_manifest(project)
    if apply_confirmation != project:
        raise ValueError("identity-reconcile requires exact confirmation of this private owner")
    _env = verify_identity_reconcile_inputs(project, directory, owner, passwords)
    origin = "http://127.0.0.1:" + str(owner["ports"]["FRONTEND_HOST_PORT"])
    api = bootstrap.BrowserAPI(origin)
    api.login("system.admin", passwords["system.admin"])
    api.select_workspace(bootstrap.ADMIN_SCOPE)
    bootstrap.verify_login_identity(api.call("GET", "/auth/me"), "system.admin", bootstrap.ADMIN_SCOPE)
    verify_identity_organization(api)

    # Confirm all five existing credentials independently before any Identity write.
    # This stage never calls the first-admin initializer, account creation, or password reset.
    for username in HUMANS:
        independent = bootstrap.BrowserAPI(origin)
        independent.login(username, passwords[username])
        independent.select_workspace(bootstrap.ADMIN_SCOPE)
        bootstrap.verify_login_identity(independent.call("GET", "/auth/me"), username, bootstrap.ADMIN_SCOPE)
        access = bootstrap.profile(independent, username)
        bootstrap.verify_public_human_access(access, username, allow_business_membership=None)
        independent.call("POST", "/auth/logout", {})

    for username in HUMANS:
        reconcile_identity_membership(api, project, directory, owner, username)

    # Read each final session and profile as its own human principal.
    for username in HUMANS:
        independent = bootstrap.BrowserAPI(origin)
        independent.login(username, passwords[username])
        independent.select_workspace(bootstrap.BUSINESS_SCOPE)
        bootstrap.verify_login_identity(independent.call("GET", "/auth/me"), username, bootstrap.BUSINESS_SCOPE)
        access = bootstrap.profile(independent, username)
        bootstrap.verify_public_human_access(access, username, allow_business_membership=True)
        if not bootstrap.active_membership(access, username, bootstrap.BUSINESS_SCOPE):
            raise RuntimeError(f"{username} app-demo membership did not verify after reconciliation")
        independent.call("POST", "/auth/logout", {})

    owner["identity_complete"] = True
    write_json_private(directory / "owner.json", owner)
    print(json.dumps({"result": "five_existing_human_accounts_reconciled_and_independently_verified",
                      "project": project, "created_accounts": [], "passwords_reset": False,
                      "changed_identity_facts": ["app-demo membership only"], "first_admin_management_binding_preserved": True,
                      "business_roles": [], "resource_grants": [], "credentials_printed": False}, ensure_ascii=False))


def verify_example_container_health(project: str, directory: Path) -> None:
    agents = (
        ("example-go", "example-go-machine"),
        ("example-python", "example-python-machine"),
        ("example-java", "example-java-machine"),
    )
    for service, _machine in agents:
        result = run_compose(project, directory, ["exec", "-T", "platform-app", "wget", "-qO-",
                                                 f"http://{service}:8080/health/ready"], timeout=25, required=False)
        if result.returncode:
            raise RuntimeError(f"isolated {service} /health/ready probe did not pass")


def services_phase(project: str, apply_confirmation: str) -> None:
    directory, owner, _passwords = read_manifest(project)
    if apply_confirmation != project or not owner.get("identity_complete") or owner.get("services_ready"):
        raise ValueError("services phase requires the completed identity stage and exact project confirmation")
    run_compose(project, directory, ["up", "-d", "--no-build", "--wait", "--wait-timeout", "180",
                                     "example-go", "example-python", "example-java"])
    verify_example_container_health(project, directory)
    owner["services_ready"] = True
    write_json_private(directory / "owner.json", owner)
    print(json.dumps({"result": "three_isolated_example_health_endpoints_verified", "project": project,
                      "health_path": "/health/ready", "provider_calls": 0}, ensure_ascii=False))


def catalog_deployment_items(response: dict, limit: int = 100) -> list[dict]:
    """Normalize the Catalog JSON encoding of an empty deployment list only."""
    if not isinstance(response, dict) or "items" not in response:
        raise RuntimeError("Catalog deployment list response is invalid")
    rows = response["items"]
    if rows is None:
        return []
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise RuntimeError("Catalog deployment list response is invalid")
    if len(rows) >= limit:
        raise RuntimeError("Catalog deployment list is truncated at its requested limit")
    return rows


def verify_catalog_installation_readiness(api: bootstrap.BrowserAPI) -> list[dict]:
    verified = []
    services = {"example-go-machine": "example-go", "example-python-machine": "example-python", "example-java-machine": "example-java"}
    for machine_id, agent_id, installation_id, _prefix in bootstrap.MACHINES:
        installation = api.call("GET", "/api/modules/catalog/installations/" + bootstrap.urllib.parse.quote(installation_id, safe=""))
        if not isinstance(installation, dict) or any(installation.get(key) != value for key, value in {
            "id": installation_id, "tenant_id": bootstrap.BUSINESS_SCOPE["tenant_id"],
            "department_id": bootstrap.BUSINESS_SCOPE["department_id"],
            "application_id": bootstrap.BUSINESS_SCOPE["application_id"], "agent_id": agent_id,
            "status": "active",
        }.items()):
            raise RuntimeError(f"{machine_id} Catalog installation is not the exact active public example installation")
        version_id = installation.get("version_id")
        if not isinstance(version_id, str) or not version_id:
            raise RuntimeError(f"{machine_id} active installation is missing its selected Catalog version")
        deployments = api.call("GET", "/api/modules/catalog/installations/" + bootstrap.urllib.parse.quote(installation_id, safe="") + "/deployments?limit=100")
        rows = catalog_deployment_items(deployments)
        if not rows:
            raise RuntimeError(f"{machine_id} has no current platform-owned Catalog deployment observation")
        revisions = [row.get("desired_revision") for row in rows]
        if (any(type(value) is not int or value < 1 for value in revisions)
                or revisions != sorted(revisions, reverse=True)
                or len(revisions) > 1 and revisions[0] == revisions[1]):
            raise RuntimeError(f"{machine_id} deployment list is truncated, unordered or ambiguous at its latest desired revision")
        current = rows[0]
        endpoint = "http://" + services[machine_id] + ":8080"
        if any(current.get(key) != value for key, value in {
            "tenant_id": bootstrap.BUSINESS_SCOPE["tenant_id"],
            "department_id": bootstrap.BUSINESS_SCOPE["department_id"],
            "application_id": bootstrap.BUSINESS_SCOPE["application_id"],
            "agent_installation_id": installation_id, "agent_version_id": version_id,
            "endpoint_ref": endpoint, "status": "ready",
        }.items()) or not isinstance(current.get("id"), str) or not current["id"] or type(current.get("desired_revision")) is not int or current["desired_revision"] < 1 or type(current.get("observed_revision")) is not int or current.get("observed_revision") != current["desired_revision"]:
            raise RuntimeError(f"{machine_id} latest Catalog deployment is not ready at its exact desired revision and Compose endpoint")
        verified.append({"machine_id": machine_id, "installation_id": installation_id,
                         "agent_version_id": version_id, "deployment_id": current.get("id"),
                         "observed_revision": current["observed_revision"], "status": current["status"]})
    return verified


def catalog_installations_by_id(rows: list[dict]) -> dict[str, dict]:
    """Index the three verified Catalog installation receipts by their installation IDs."""
    expected = {installation_id: machine_id for machine_id, _agent_id, installation_id, _prefix in bootstrap.MACHINES}
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise RuntimeError("live readiness must contain exactly the three public Catalog installations")
    indexed: dict[str, dict] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("live Catalog readiness contains a malformed installation receipt")
        installation_id = row.get("installation_id")
        if (installation_id not in expected or installation_id in indexed
                or row.get("machine_id") != expected[installation_id]):
            raise RuntimeError("live Catalog readiness installation ID is missing, duplicated or mismatched")
        indexed[installation_id] = row
    if set(indexed) != set(expected):
        raise RuntimeError("live Catalog readiness omitted one exact public installation")
    return indexed


def machine_principals_phase(project: str, apply_confirmation: str, base_url: str, raw_cidrs: list[str]) -> None:
    directory, owner, _passwords = read_manifest(project)
    if (apply_confirmation != project or not owner.get("identity_complete") or not owner.get("services_ready")
            or owner.get("machine_principals_complete") or owner.get("machines_complete")):
        raise ValueError("machine-principals phase requires completed isolated identity/services and exact owner confirmation")
    cidrs = bootstrap.parse_agent_cidrs(raw_cidrs)
    parsed = bootstrap.urllib.parse.urlsplit(base_url)
    expected_url = "http://127.0.0.1:" + str(owner["ports"]["FRONTEND_HOST_PORT"])
    if base_url != expected_url or parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("machine-principals stage must use this exact owner's prepared loopback frontend origin")
    verify_owner_frontend(project, directory, owner)
    verify_example_container_health(project, directory)
    api = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    bootstrap.verify_login_identity(api.call("GET", "/auth/me"), "system.admin", bootstrap.BUSINESS_SCOPE)
    installations = verify_catalog_installation_readiness(api)
    access = bootstrap.profile(api, "system.admin")
    bootstrap.verify_initial_admin_access(access, allow_business_membership=True)
    saved_confirm = bootstrap.confirm
    allowed_confirmation_phrases = {machine[0] for machine in bootstrap.MACHINES}
    approved_phrases: set[str] = set()
    receipts: list[dict] = []
    def approve_principal_change(phrase: str) -> bool:
        if phrase not in allowed_confirmation_phrases or phrase in approved_phrases:
            return False
        approved_phrases.add(phrase)
        return True
    try:
        bootstrap.confirm = approve_principal_change
        receipts = bootstrap.create_workload_principals(api, directory / "machines.env", cidrs)
    finally:
        bootstrap.confirm = saved_confirm
    if (not isinstance(receipts, list) or len(receipts) != 3
            or {item.get("principal_id") for item in receipts if isinstance(item, dict)} != {row[0] for row in bootstrap.MACHINES}
            or any(not isinstance(item, dict) or item.get("type") != "service_principal"
                   or item.get("is_active") is not True or item.get("roles") != []
                   or item.get("resource_grants") != [] or item.get("binding_created") is not False
                   for item in receipts)):
        raise RuntimeError("machine principal readbacks are incomplete or contain non-empty access")
    owner["machine_principals_complete"] = True
    owner["machine_principal_receipts"] = receipts
    write_json_private(directory / "owner.json", owner)
    print(json.dumps({"result": "three_unprivileged_machine_principals_verified", "project": project,
                      "catalog_readiness": installations, "bindings_created": False,
                      "resource_grants": [], "machine_secrets_printed": False}, ensure_ascii=False))


def machines_phase(project: str, apply_confirmation: str, base_url: str) -> None:
    directory, owner, _passwords = read_manifest(project)
    if (apply_confirmation != project or owner.get("machine_principals_complete") is not True
            or owner.get("machines_complete")):
        raise ValueError("machine binding phase requires verified principals and exact owner confirmation")
    expected_agents = {row[1] for row in bootstrap.MACHINES}
    policy_lifecycle = owner.get("policy_lifecycle")
    if (not isinstance(policy_lifecycle, dict) or set(policy_lifecycle) != expected_agents
            or any(policy_lifecycle[agent].get("published") is not True for agent in expected_agents)):
        raise RuntimeError("workload installation bindings require all three reviewed six-asset PolicyAsset snapshots to be published")
    parsed = bootstrap.urllib.parse.urlsplit(base_url)
    expected_url = "http://127.0.0.1:" + str(owner["ports"]["FRONTEND_HOST_PORT"])
    if base_url != expected_url or parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("machine binding stage must use this exact owner's prepared loopback frontend origin")
    verify_owner_frontend(project, directory, owner)
    verify_example_container_health(project, directory)
    api = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    bootstrap.verify_login_identity(api.call("GET", "/auth/me"), "system.admin", bootstrap.BUSINESS_SCOPE)
    installations = verify_catalog_installation_readiness(api)
    releases = load_pinned_release_plans(project, directory, owner)
    policies = {agent_id: live_policy_inventory(api, project, directory, owner, release)
                for agent_id, release in releases.items()}
    if set(policies) != expected_agents:
        raise RuntimeError("binding preflight did not verify each current published runtime policy")
    bootstrap.verify_initial_admin_access(bootstrap.profile(api, "system.admin"), allow_business_membership=True)
    journal = owner.setdefault("machine_binding_journal", {})
    if not isinstance(journal, dict):
        raise RuntimeError("machine binding journal has an unknown owner-private shape")

    def persist():
        write_json_private(directory / "owner.json", owner)

    def before_binding(machine_id: str, binding: dict, command: dict) -> None:
        prior = journal.get(machine_id)
        if prior is not None:
            raise RuntimeError(f"{machine_id} has an earlier unresolved binding intent; inspect live GET state before any new POST")
        journal[machine_id] = {"status": "intent", "binding": binding,
                               "request_sha256": hashlib.sha256(example_authorization.canonical(command)).hexdigest(),
                               "idempotency_key": command["idempotency_key"]}
        persist()

    def after_binding(machine_id: str, _binding: dict, _command: dict, response) -> None:
        record = journal.get(machine_id)
        if not isinstance(record, dict) or record.get("status") != "intent":
            raise RuntimeError("machine binding response has no exact durable intent")
        record["status"] = "api_response_received"
        record["response_sha256"] = hashlib.sha256(example_authorization.canonical(response)).hexdigest()
        persist()

    def after_binding_verified(machine_id: str, binding: dict, actual: dict) -> None:
        record = journal.get(machine_id)
        if record is None:
            record = {"request_sha256": None, "idempotency_key": None}
            journal[machine_id] = record
        if not isinstance(record, dict) or record.get("binding", binding) != binding:
            raise RuntimeError("machine binding readback differs from its durable exact intent")
        record.update({"status": "verified", "binding": binding, "readback": actual})
        persist()

    saved_confirm = bootstrap.confirm
    allowed_confirmation_phrases = {machine[2] for machine in bootstrap.MACHINES}
    approved_phrases: set[str] = set()

    def approve_binding(phrase: str) -> bool:
        if phrase not in allowed_confirmation_phrases or phrase in approved_phrases:
            return False
        approved_phrases.add(phrase)
        return True

    try:
        bootstrap.confirm = approve_binding
        bootstrap.create_workload_bindings(api, before_binding, after_binding, after_binding_verified)
    finally:
        bootstrap.confirm = saved_confirm
    if set(journal) != {machine[0] for machine in bootstrap.MACHINES} or any(
        not isinstance(journal.get(machine[0]), dict) or journal[machine[0]].get("status") != "verified"
        for machine in bootstrap.MACHINES
    ):
        raise RuntimeError("the three exact workload bindings did not all verify")
    owner["machines_complete"] = True
    owner["machine_binding_journal"] = journal
    write_json_private(directory / "owner.json", owner)
    print(json.dumps({"result": "three_policy_backed_workload_bindings_verified", "project": project,
                      "catalog_readiness": installations, "policy_snapshots_verified": len(policies),
                      "resource_grants": [], "machine_secrets_printed": False}, ensure_ascii=False))


INDEX_WORKLOAD_ROTATION_SCHEMA = "public-index-workload-rotation/v1"
INDEX_WORKLOAD_ROTATION_PATH = "/api/modules/identity/machine-credentials"
INDEX_WORKLOAD_LOOPBACK_CIDR = "127.0.0.1/32"
INDEX_IP_CORRECTION_SCHEMA = "public-index-sdk-ip-correction/v1"
INDEX_IP_OVERLAY_NAME = "index-sdk-source-overlay.json"


def index_workload_machine(language: str) -> tuple[str, str, str, str]:
    if language not in public_knowledge.EXAMPLES:
        raise ValueError("index credential operation must select one of the three fixed public languages")
    knowledge_id = public_knowledge.EXAMPLES[language][0]
    agent_id = "example-" + knowledge_id
    matches = [row for row in bootstrap.MACHINES if row[1] == agent_id]
    if len(matches) != 1:
        raise RuntimeError("Knowledge language does not map to one exact owner workload installation")
    return matches[0]


def index_workload_secret_filename(scope: dict[str, str], installation_id: str) -> str:
    if (not isinstance(scope, dict) or set(scope) != {"tenant_id", "department_id", "application_id"}
            or any(not isinstance(value, str) or not value for value in scope.values())
            or not isinstance(installation_id, str) or not installation_id):
        raise ValueError("workload secret filename requires the exact application scope and installation")
    raw = json.dumps([scope["tenant_id"], scope["department_id"], scope["application_id"], installation_id],
                     separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest() + ".json"


def parse_machine_env_private(path: Path) -> dict[str, str]:
    bootstrap.validate_machine_env_path(path)
    bootstrap.verify_private_file(path)
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key in values or not value:
            raise RuntimeError("owner machines.env is malformed; no credential was changed")
        values[key] = value
    expected = {prefix + suffix for _, _, _, prefix in bootstrap.MACHINES
                for suffix in ("_CLIENT_ID", "_CLIENT_SECRET")}
    if set(values) != expected:
        raise RuntimeError("owner machines.env does not contain exactly the six reviewed machine credential fields")
    for machine_id, _agent_id, _installation, prefix in bootstrap.MACHINES:
        if (values.get(prefix + "_CLIENT_ID") != machine_id
                or not valid_machine_secret(values.get(prefix + "_CLIENT_SECRET"))):
            raise RuntimeError("owner machines.env does not match the fixed machine IDs and secret format")
    return values


def valid_machine_secret(value: Any) -> bool:
    return (isinstance(value, str) and 32 <= len(value) <= 4096 and value == value.strip()
            and all(33 <= ord(char) <= 126 for char in value))


def validate_index_machine_credential(row: Any, client_id: str, *, allow_loopback: bool = False) -> dict:
    if not isinstance(row, dict):
        raise RuntimeError("machine credential inventory contains a malformed row")
    networks = row.get("network_cidrs")
    if (row.get("client_id") != client_id
            or row.get("tenant_id") != bootstrap.BUSINESS_SCOPE["tenant_id"]
            or row.get("status") != "active" or type(row.get("revision")) is not int
            or row["revision"] < 1 or not isinstance(networks, list)
            or len(networks) != (2 if allow_loopback else 1)):
        raise RuntimeError("machine credential differs from the exact active owner machine")
    parsed = []
    for raw in networks:
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except (TypeError, ValueError):
            raise RuntimeError("machine credential must use canonical exact SDK /32 CIDRs") from None
        if (not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 32 or str(network) != raw):
            raise RuntimeError("machine credential must preserve exact IPv4 /32 CIDRs")
        parsed.append(network)
    loopback = [network for network in parsed if network.network_address.is_loopback]
    sdk = [network for network in parsed if not network.network_address.is_loopback]
    if (not allow_loopback and (loopback or len(sdk) != 1)
            or allow_loopback and (len(loopback) != 1 or str(loopback[0]) != INDEX_WORKLOAD_LOOPBACK_CIDR or len(sdk) != 1)):
        raise RuntimeError("machine credential CIDRs are not the one exact SDK address plus optional loopback /32")
    return row


def validate_index_machine_credentials(response: Any, *, allow_loopback: bool = False) -> dict[str, dict]:
    rows = response if isinstance(response, list) else response.get("items") if isinstance(response, dict) else None
    if not isinstance(rows, list) or len(rows) != len(bootstrap.MACHINES):
        raise RuntimeError("machine credential inventory must contain exactly the three isolated workload machines")
    expected_ids = {row[0] for row in bootstrap.MACHINES}
    indexed: dict[str, dict] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("machine credential inventory contains a malformed row")
        client_id = row.get("client_id")
        if client_id not in expected_ids or client_id in indexed:
            raise RuntimeError("machine credential inventory differs from the exact active owner machines")
        indexed[client_id] = validate_index_machine_credential(row, client_id, allow_loopback=allow_loopback)
    if set(indexed) != expected_ids:
        raise RuntimeError("machine credential inventory omitted a fixed workload principal")
    return indexed


def validate_index_machine_credentials_for_rotation(response: Any, journal: dict, directory: Path,
                                                    unresolved_machine_id: str | None = None) -> dict[str, dict]:
    """Validate the exact owner inventory while earlier machines may already be rotated.

    A machine with a durable secret receipt must match its rotation exactly. An unresolved
    post may be either wholly unapplied or applied, but without its response receipt it is
    never treated as recoverable and the caller must stop without another POST.
    """
    rows = response if isinstance(response, list) else response.get("items") if isinstance(response, dict) else None
    if not isinstance(rows, list) or len(rows) != len(bootstrap.MACHINES):
        raise RuntimeError("machine credential inventory must contain exactly the three isolated workload machines")
    expected = {row[0]: row for row in bootstrap.MACHINES}
    indexed: dict[str, dict] = {}
    entries = journal.get("machines", {})
    if not isinstance(entries, dict):
        raise RuntimeError("owner machine credential rotation journal is malformed")
    for raw in rows:
        if not isinstance(raw, dict):
            raise RuntimeError("machine credential inventory contains a malformed row")
        machine_id = raw.get("client_id")
        if machine_id not in expected or machine_id in indexed:
            raise RuntimeError("machine credential inventory differs from the exact active owner machines")
        entry = entries.get(machine_id)
        if entry is None:
            indexed[machine_id] = validate_index_machine_credential(raw, machine_id)
            continue
        if not isinstance(entry, dict) or entry.get("machine_id") != machine_id:
            raise RuntimeError("owner credential journal machine identity differs from live inventory")
        language = next((name for name in public_knowledge.EXAMPLES
                         if index_workload_machine(name)[0] == machine_id), None)
        if language is None:
            raise RuntimeError("owner credential journal references a machine outside the fixed language map")
        receipt_path = index_rotation_receipt_path(directory, language)
        has_receipt = receipt_path.exists()
        if has_receipt:
            receipt = read_index_rotation_receipt(project=journal["owner"], directory=directory,
                                                 language=language,
                                                 expected={"request_sha256": entry.get("request_sha256"),
                                                           "machine_id": machine_id,
                                                           "installation_id": entry.get("installation_id")})
            response_row = validate_index_machine_rotation_response(
                receipt["response"], machine_id, entry["expected_revision"], entry["network_cidrs"])
            if (raw.get("revision") != response_row["revision"]
                    or raw.get("network_cidrs") != response_row["network_cidrs"]
                    or raw.get("status") != "active"
                    or raw.get("tenant_id") != bootstrap.BUSINESS_SCOPE["tenant_id"]):
                raise RuntimeError("live machine credential differs from its durable secret-bearing rotation receipt")
            indexed[machine_id] = raw
            continue
        if machine_id != unresolved_machine_id or entry.get("status") not in {"post_started", "unknown"}:
            raise RuntimeError("a previously rotated machine is missing its required owner-private response receipt")
        # An unknown POST can leave the prior credential intact or rotate it. Accept only
        # those exact CAS outcomes so we can report the ambiguity without ever retrying.
        baseline_network = [entry.get("sdk_ip_before", "") + "/32"]
        current = raw.get("network_cidrs")
        unchanged = (raw.get("revision") == entry.get("expected_revision")
                     and current == baseline_network)
        applied = (raw.get("revision") == entry.get("expected_revision", 0) + 1
                   and current == entry.get("network_cidrs"))
        # Validate the full row shape as an exact one-address or exact SDK+loopback pair.
        try:
            if unchanged:
                validate_index_machine_credential(raw, machine_id)
            elif applied:
                validate_index_machine_credential(raw, machine_id, allow_loopback=True)
            else:
                raise RuntimeError("unresolved machine rotation has an unexpected revision or CIDR")
        except RuntimeError:
            raise RuntimeError("unresolved machine rotation has an unexpected revision or CIDR") from None
        indexed[machine_id] = raw
    if set(indexed) != set(expected):
        raise RuntimeError("machine credential inventory omitted a fixed workload principal")
    return indexed


def build_index_machine_rotation(machine_id: str, installation_id: str, current: dict, sdk_ip: str) -> dict:
    selected = next((row for row in bootstrap.MACHINES if row[0] == machine_id), None)
    if selected is None or selected[2] != installation_id:
        raise ValueError("machine credential rotation is outside the exact reviewed installation mapping")
    row = validate_index_machine_credential(current, machine_id)
    current_network = row["network_cidrs"][0]
    try:
        parsed_ip = ipaddress.ip_address(sdk_ip)
    except ValueError:
        raise RuntimeError("owner SDK container has no valid source IP") from None
    if not isinstance(parsed_ip, ipaddress.IPv4Address) or current_network != str(parsed_ip) + "/32":
        raise RuntimeError("machine credential CIDR does not match the exact live SDK container IP")
    wanted = [current_network, INDEX_WORKLOAD_LOOPBACK_CIDR]
    if INDEX_WORKLOAD_LOOPBACK_CIDR in row["network_cidrs"]:
        raise RuntimeError("machine credential already includes loopback; reconcile its owner rotation receipt")
    return {"expected_revision": row["revision"], "network_cidrs": wanted}


def validate_index_machine_rotation_response(response: Any, machine_id: str, expected_revision: int,
                                             wanted_cidrs: list[str]) -> dict:
    if (not isinstance(response, dict) or response.get("client_id") != machine_id
            or not valid_machine_secret(response.get("client_secret"))
            or response.get("status") != "active" or response.get("revision") != expected_revision + 1
            or response.get("network_cidrs") != wanted_cidrs):
        raise RuntimeError("machine credential rotation response differs from the exact CAS request")
    validate_index_machine_credential({"client_id": response["client_id"], "tenant_id": bootstrap.BUSINESS_SCOPE["tenant_id"],
                                       "network_cidrs": response["network_cidrs"], "status": response["status"],
                                       "revision": response["revision"]}, machine_id, allow_loopback=True)
    return response


def index_rotation_journal(owner: dict, project: str) -> dict:
    value = owner.get("index_workload_credentials")
    if value is None:
        return {"schema": INDEX_WORKLOAD_ROTATION_SCHEMA, "owner": project,
                "scope": dict(bootstrap.BUSINESS_SCOPE), "machines": {}, "deployment": None,
                "mount_activation": None}
    if (not isinstance(value, dict) or value.get("schema") != INDEX_WORKLOAD_ROTATION_SCHEMA
            or value.get("owner") != project or value.get("scope") != bootstrap.BUSINESS_SCOPE
            or not isinstance(value.get("machines"), dict)
            or not set(value["machines"]).issubset({row[0] for row in bootstrap.MACHINES})):
        raise RuntimeError("owner index-workload credential journal is malformed or belongs to another project")
    return value


def persist_index_rotation_state(project: str, directory: Path, expected_plan_digest: str,
                                 journal: dict) -> dict:
    _directory, current, _passwords = read_manifest(project)
    pin = current.get("authorization_plan")
    if not isinstance(pin, dict) or pin.get("plan_sha256") != expected_plan_digest:
        raise RuntimeError("owner authorization plan changed during machine credential rotation")
    existing = index_rotation_journal(current, project)
    if existing.get("schema") != journal.get("schema"):
        raise RuntimeError("owner workload credential state changed during rotation")
    current["index_workload_credentials"] = deepcopy(journal)
    write_json_private(directory / "owner.json", current)
    return current


def machine_access_boundary(profile: dict, machine_id: str) -> tuple[int, dict]:
    if not isinstance(profile, dict) or not isinstance(profile.get("principal"), dict):
        raise RuntimeError("machine access profile is invalid before/after credential rotation")
    principal = profile["principal"]
    revision = principal.get("revision")
    if (principal.get("id") != machine_id or principal.get("type") != "service_principal"
            or principal.get("tenant_id") != bootstrap.BUSINESS_SCOPE["tenant_id"]
            or principal.get("is_active") is not True or type(revision) is not int or revision < 1
            or principal.get("roles") not in (None, []) or profile.get("role_bindings") != []
            or not isinstance(profile.get("memberships"), list)
            or not isinstance(profile.get("resource_grants"), list)
            or not isinstance(profile.get("delegations"), list)
            or not isinstance(profile.get("task_assignments"), list)):
        raise RuntimeError("machine profile has unexpected role, membership, Grant, delegation or revision facts")
    boundary = {"principal": {key: principal.get(key) for key in ("id", "type", "tenant_id", "is_active", "roles")},
                "memberships": profile["memberships"], "role_bindings": profile["role_bindings"],
                "resource_grants": profile["resource_grants"], "delegations": profile["delegations"],
                "task_assignments": profile["task_assignments"]}
    return revision, boundary


def index_rotation_receipt_path(directory: Path, language: str) -> Path:
    return directory / ("index-workload-rotation-" + language + ".json")


def read_index_rotation_receipt(project: str, directory: Path, language: str, expected: dict) -> dict:
    path = index_rotation_receipt_path(directory, language)
    bootstrap.verify_private_file(path)
    if bootstrap.is_reparse_point(path):
        raise RuntimeError("owner machine credential receipt may not be a link or reparse point")
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise RuntimeError("owner machine credential rotation receipt is unreadable") from None
    if (not isinstance(receipt, dict) or receipt.get("schema") != "public-index-machine-credential-receipt/v1"
            or receipt.get("owner") != project or receipt.get("language") != language
            or receipt.get("request_sha256") != expected.get("request_sha256")
            or receipt.get("machine_id") != expected.get("machine_id")
            or receipt.get("installation_id") != expected.get("installation_id")
            or not isinstance(receipt.get("response"), dict)):
        raise RuntimeError("owner machine credential receipt does not match the exact outstanding rotation intent")
    return receipt


def verify_live_index_rotation(api: bootstrap.BrowserAPI, entry: dict, response: dict,
                               journal: dict, directory: Path) -> dict:
    machine_id = entry["machine_id"]
    inventory = validate_index_machine_credentials_for_rotation(
        api.call("GET", INDEX_WORKLOAD_ROTATION_PATH), journal, directory, unresolved_machine_id=machine_id)
    current = inventory.get(machine_id)
    validate_index_machine_rotation_response(response, machine_id, entry["expected_revision"], entry["network_cidrs"])
    if (not isinstance(current, dict) or current.get("revision") != response["revision"]
            or current.get("network_cidrs") != response["network_cidrs"] or current.get("status") != "active"):
        raise RuntimeError("live machine credential readback differs from the persisted exact rotation receipt")
    profile = bootstrap.profile(api, machine_id, "service_principal")
    revision, boundary = machine_access_boundary(profile, machine_id)
    boundary_digest = hashlib.sha256(example_authorization.canonical(boundary)).hexdigest()
    if (revision != entry.get("grant_profile_revision", 0) + 1
            or boundary_digest != entry.get("access_boundary_sha256")):
        raise RuntimeError("live machine profile does not prove exactly one credential revision and unchanged role/Grant facts")
    return {"credential_revision": response["revision"], "profile_revision": revision,
            "access_boundary_sha256": boundary_digest}


def owner_machine_secret_files(directory: Path, language: str, machine_id: str,
                               installation_id: str, secret: str,
                               old_secret_sha256: str) -> tuple[Path, Path]:
    if not valid_machine_secret(secret):
        raise RuntimeError("owner machine credential secret is invalid")
    machine = next((row for row in bootstrap.MACHINES if row[0] == machine_id), None)
    knowledge_id = public_knowledge.EXAMPLES.get(language, (None,))[0]
    if machine is None or machine[2] != installation_id or machine[1] != "example-" + str(knowledge_id):
        raise RuntimeError("owner machine environment update is outside the exact installation mapping")
    env_path = directory / "machines.env"
    private_path = directory / "private.env"
    bootstrap.validate_machine_env_path(env_path)
    bootstrap.validate_machine_env_path(private_path)
    bootstrap.verify_private_file(env_path)
    bootstrap.verify_private_file(private_path)
    current_machine = parse_machine_env_private(env_path)
    current_private = read_owner_env(directory)
    machine_keys = {row[3] + suffix for row in bootstrap.MACHINES for suffix in ("_CLIENT_ID", "_CLIENT_SECRET")}
    if not machine_keys.issubset(current_private):
        raise RuntimeError("owner private.env is missing one or more exact machine credential fields")
    selected_key = machine[3] + "_CLIENT_SECRET"
    new_digest = hashlib.sha256(secret.encode("ascii")).hexdigest()
    if not re.fullmatch(r"[0-9a-f]{64}", old_secret_sha256):
        raise RuntimeError("owner credential update lacks its exact write-ahead prior-secret digest")
    for row in bootstrap.MACHINES:
        id_key, secret_key = row[3] + "_CLIENT_ID", row[3] + "_CLIENT_SECRET"
        if current_private[id_key] != current_machine[id_key]:
            raise RuntimeError("owner machines.env and private.env credentials differ before rotation")
        if secret_key == selected_key:
            permitted = {old_secret_sha256, new_digest}
            if any(not valid_machine_secret(value) or hashlib.sha256(value.encode("ascii")).hexdigest() not in permitted
                   for value in (current_machine[secret_key], current_private[secret_key])):
                raise RuntimeError("selected owner credential files contain a value outside the exact prior/rotated pair")
        elif current_private[secret_key] != current_machine[secret_key]:
            raise RuntimeError("owner machines.env and private.env credentials differ before rotation")
    if current_machine[machine[3] + "_CLIENT_ID"] != machine_id:
        raise RuntimeError("owner machines.env client ID differs from the exact selected machine")
    return env_path, private_path


def replace_rotated_machine_secret(directory: Path, language: str, machine_id: str,
                                   installation_id: str, old_secret_sha256: str, new_secret: str,
                                   file_intent=None, file_verified=None) -> None:
    env_path, private_path = owner_machine_secret_files(directory, language, machine_id, installation_id,
                                                        new_secret, old_secret_sha256)
    _, _agent_id, _installation, prefix = next(row for row in bootstrap.MACHINES if row[0] == machine_id)
    key = prefix + "_CLIENT_SECRET"
    current_machine = parse_machine_env_private(env_path)
    current_private = read_owner_env(directory)
    current_values = (current_machine[key], current_private[key])
    new_digest = hashlib.sha256(new_secret.encode("ascii")).hexdigest()
    for value in current_values:
        digest = hashlib.sha256(value.encode("ascii")).hexdigest()
        if digest not in {old_secret_sha256, new_digest}:
            raise RuntimeError("owner credential files contain an unrelated secret; refusing to overwrite")
    def render(values: dict[str, str]) -> str:
        lines = (env_path if values is current_machine else private_path).read_text(encoding="utf-8").splitlines()
        rendered = []
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                rendered.append(raw)
                continue
            name, separator, _value = line.partition("=")
            if not separator:
                raise RuntimeError("owner private environment file became malformed during rotation")
            rendered.append(name + "=" + (new_secret if name == key else values.get(name, _value)))
        return "\n".join(rendered) + "\n"
    if hashlib.sha256(current_machine[key].encode("ascii")).hexdigest() == old_secret_sha256:
        if file_intent is not None:
            file_intent("machines.env")
        replace_private_file(env_path, render(current_machine))
        if file_verified is not None:
            file_verified("machines.env")
    if hashlib.sha256(current_private[key].encode("ascii")).hexdigest() == old_secret_sha256:
        if file_intent is not None:
            file_intent("private.env")
        replace_private_file(private_path, render(current_private))
        if file_verified is not None:
            file_verified("private.env")
    after_machine = parse_machine_env_private(env_path)
    after_private = read_owner_env(directory)
    if (after_machine[key] != new_secret or after_private[key] != new_secret
            or any(after_machine[field] != after_private[field] for field in after_machine)):
        raise RuntimeError("owner machines.env/private.env did not converge to the exact rotated credential")


def inspect_owner_default_network(project: str) -> dict:
    network_name = project + "_default"
    result = subprocess.run(["docker", "network", "inspect", "--format",
                             "{{.Id}} {{json .IPAM.Config}} {{json .Labels}}", network_name],
                            cwd=ROOT, capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError("isolated owner Docker network could not be inspected")
    output = result.stdout.decode("utf-8", errors="strict").strip()
    fields = output.split(" ", 2)
    if len(fields) != 3:
        raise RuntimeError("isolated owner Docker network inspection is malformed")
    try:
        network_id, configs, labels = fields[0], json.loads(fields[1]), json.loads(fields[2])
    except ValueError:
        raise RuntimeError("isolated owner Docker network IPAM or labels are malformed") from None
    if (not isinstance(configs, list) or len(configs) != 1 or not isinstance(configs[0], dict)
            or not isinstance(labels, dict) or labels.get("com.docker.compose.project") != project
            or labels.get("com.docker.compose.network") != "default"
            or not re.fullmatch(r"[0-9a-f]{64}", network_id)):
        raise RuntimeError("Docker network is not the exact owner-labeled single-subnet default network")
    subnet, gateway = configs[0].get("Subnet"), configs[0].get("Gateway")
    try:
        network = ipaddress.ip_network(subnet, strict=True)
        gateway_address = ipaddress.ip_address(gateway)
    except (TypeError, ValueError):
        raise RuntimeError("owner Docker network lacks canonical subnet and gateway IPAM") from None
    if (not isinstance(network, ipaddress.IPv4Network) or not isinstance(gateway_address, ipaddress.IPv4Address)
            or str(network) != subnet or str(gateway_address) != gateway or gateway_address not in network):
        raise RuntimeError("owner Docker network IPAM is not one exact private IPv4 subnet and gateway")
    return {"name": network_name, "network_id": network_id,
            "subnet": str(network), "gateway": str(gateway_address)}


def build_index_sdk_source_overlay(project: str, network: dict, target_ips: dict[str, str]) -> dict:
    if set(target_ips) != {row[0] for row in bootstrap.MACHINES}:
        raise ValueError("static SDK source overlay requires exactly the three owner workload IPs")
    subnet = network.get("subnet") if isinstance(network, dict) else None
    gateway = network.get("gateway") if isinstance(network, dict) else None
    try:
        parsed_network, parsed_gateway = ipaddress.ip_network(subnet, strict=True), ipaddress.ip_address(gateway)
    except (TypeError, ValueError):
        raise ValueError("static SDK source overlay requires exact inspected owner network IPAM") from None
    if (not isinstance(network, dict) or network.get("name") != project + "_default"
            or not re.fullmatch(r"[0-9a-f]{64}", str(network.get("network_id", "")))
            or not isinstance(parsed_network, ipaddress.IPv4Network) or not isinstance(parsed_gateway, ipaddress.IPv4Address)
            or not parsed_gateway.is_private or parsed_gateway not in parsed_network):
        raise ValueError("static SDK source overlay must remain inside the owner private IPv4 network")
    services = {}
    used = set()
    for machine_id, _agent, _installation, _prefix in bootstrap.MACHINES:
        raw = target_ips.get(machine_id)
        try:
            address = ipaddress.ip_address(raw)
        except (TypeError, ValueError):
            raise ValueError("static SDK source overlay contains an invalid address") from None
        if (not isinstance(address, ipaddress.IPv4Address) or not address.is_private or address not in parsed_network
                or address in {parsed_network.network_address, parsed_network.broadcast_address, parsed_gateway}
                or str(address) != raw or raw in used):
            raise ValueError("static SDK address must be a unique usable host in the isolated owner network")
        used.add(raw)
        service = {"example-go-machine": "example-go", "example-python-machine": "example-python",
                   "example-java-machine": "example-java"}[machine_id]
        services[service] = {"networks": {"default": {"ipv4_address": raw}}}
    return {"services": services,
            "networks": {"default": {"external": True, "name": project + "_default"}}}


def ensure_owner_index_ip_overlay(project: str, directory: Path, journal: dict,
                                 network: dict | None = None) -> tuple[Path, str, dict]:
    records = journal.get("machines") if isinstance(journal, dict) else None
    if not isinstance(records, dict) or set(records) != {row[0] for row in bootstrap.MACHINES}:
        raise RuntimeError("fixed SDK source overlay requires all three owner credential rotations")
    targets = {}
    for machine_id, _agent, _installation, _prefix in bootstrap.MACHINES:
        row = records[machine_id]
        if (not isinstance(row, dict) or row.get("status") != "environment_updated"
                or not isinstance(row.get("sdk_ip_before"), str)
                or row.get("network_cidrs", [None])[0] != row.get("sdk_ip_before") + "/32"):
            raise RuntimeError("fixed SDK source address is not pinned by its exact credential rotation receipt")
        targets[machine_id] = row["sdk_ip_before"]
    network = network or inspect_owner_default_network(project)
    expected = build_index_sdk_source_overlay(project, network, targets)
    target = directory / INDEX_IP_OVERLAY_NAME
    path = write_or_reuse_exact_private_json(directory, target, expected)
    digest = hashlib.sha256(example_authorization.canonical(expected)).hexdigest()
    run_owner_runtime_compose(project, directory, ["config", "--quiet"], timeout=60,
                              include_index_ip_overlay=True)
    return path, digest, network


def run_owner_runtime_compose(project: str, directory: Path, arguments: list[str], timeout: int = 240,
                              required: bool = True, include_index_ip_overlay: bool = False) -> subprocess.CompletedProcess:
    prefix = compose_prefix(project, directory, include_examples=True, include_runtime=True)
    if include_index_ip_overlay:
        overlay = directory / INDEX_IP_OVERLAY_NAME
        bootstrap.verify_private_file(overlay)
        prefix.extend(["-f", str(overlay)])
    result = subprocess.run(prefix + arguments,
                            cwd=ROOT, capture_output=True, timeout=timeout,
                            env=isolated_compose_environment(directory, include_runtime=True))
    if required and result.returncode:
        raise RuntimeError("owner runtime Compose operation failed; inspect only this project without exposing credentials")
    return result


def inspect_owner_compose_service(project: str, directory: Path, service: str) -> dict:
    if service not in {"platform-app", "example-go", "example-python", "example-java"}:
        raise ValueError("container inspection is limited to the exact isolated platform and SDK services")
    listed = run_owner_runtime_compose(project, directory, ["ps", "-q", service], timeout=30, required=False)
    output = listed.stdout.decode("utf-8", errors="replace") if isinstance(listed.stdout, bytes) else str(listed.stdout)
    identifiers = [item for item in output.splitlines() if item.strip()]
    if listed.returncode or len(identifiers) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", identifiers[0]):
        raise RuntimeError("the exact owner Compose service does not have one inspectable running container")
    container_id = identifiers[0]
    def inspect(template: str) -> Any:
        result = subprocess.run(["docker", "inspect", "--format", template, container_id], cwd=ROOT,
                                capture_output=True, timeout=20)
        if result.returncode:
            raise RuntimeError("owner container readback failed; no container mutation was attempted")
        try:
            return json.loads(result.stdout.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise RuntimeError("owner container metadata readback is malformed") from None
    labels = inspect("{{json .Config.Labels}}")
    networks = inspect("{{json .NetworkSettings.Networks}}")
    environment = inspect("{{json .Config.Env}}")
    if (not isinstance(labels, dict) or labels.get("com.docker.compose.project") != project
            or labels.get("com.docker.compose.service") != service or not isinstance(networks, dict)
            or not isinstance(environment, list)
            or any(not isinstance(value, str) or "=" not in value for value in environment)):
        raise RuntimeError("container is not the exact owner-labeled Compose service")
    default_network = project + "_default"
    network = networks.get(default_network)
    if not isinstance(network, dict) or not isinstance(network.get("IPAddress"), str):
        raise RuntimeError("owner SDK service is not connected to its exact project default network")
    try:
        address = ipaddress.ip_address(network["IPAddress"])
    except ValueError:
        raise RuntimeError("owner service has an invalid default-network IPv4 address") from None
    if not isinstance(address, ipaddress.IPv4Address):
        raise RuntimeError("owner service default network must use IPv4")
    env_pairs = [value.split("=", 1) for value in environment]
    env_names = [key for key, _value in env_pairs]
    if len(env_names) != len(set(env_names)):
        raise RuntimeError("owner container has duplicate environment keys; credential source is ambiguous")
    env_map = dict(env_pairs)
    return {"container_id": container_id, "ip": str(address), "environment": env_map}


def verify_sdk_process_machine_credentials(project: str, directory: Path, values: dict[str, str]) -> dict[str, str]:
    verified_ips: dict[str, str] = {}
    for machine_id, _agent, _installation, prefix in bootstrap.MACHINES:
        service = {"example-go-machine": "example-go", "example-python-machine": "example-python",
                   "example-java-machine": "example-java"}[machine_id]
        inspected = inspect_owner_compose_service(project, directory, service)
        environment = inspected["environment"]
        if (environment.get("AGENT_CLIENT_ID") != values[prefix + "_CLIENT_ID"]
                or environment.get("AGENT_CLIENT_SECRET") != values[prefix + "_CLIENT_SECRET"]):
            raise RuntimeError("SDK process has not switched to the owner-rotated credential")
        verified_ips[machine_id] = inspected["ip"]
    return verified_ips


def verify_sdk_process_pre_rotation_credentials(project: str, directory: Path, journal: dict) -> dict[str, str]:
    """Prove that the still-running SDKs use the old credentials before recreation.

    The new secrets already live in owner env files at this point, so comparing the
    old process against those values would reject the intended transition. Only
    hashes of the process credentials are retained; no credential is logged.
    """
    verified_ips: dict[str, str] = {}
    for machine_id, _agent, _installation, _prefix in bootstrap.MACHINES:
        entry = journal.get("machines", {}).get(machine_id)
        if (not isinstance(entry, dict) or entry.get("status") != "environment_updated"
                or not isinstance(entry.get("old_secret_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", entry["old_secret_sha256"])):
            raise RuntimeError("pre-recreation SDK proof lacks the exact prior credential digest")
        service = {"example-go-machine": "example-go", "example-python-machine": "example-python",
                   "example-java-machine": "example-java"}[machine_id]
        inspected = inspect_owner_compose_service(project, directory, service)
        environment = inspected["environment"]
        secret = environment.get("AGENT_CLIENT_SECRET")
        if (environment.get("AGENT_CLIENT_ID") != machine_id or not valid_machine_secret(secret)
                or hashlib.sha256(secret.encode("ascii")).hexdigest() != entry["old_secret_sha256"]):
            raise RuntimeError("running SDK does not prove the exact pre-rotation credential before recreate")
        source_ip = inspected["ip"]
        if (source_ip != entry.get("sdk_ip_before")
                or entry.get("network_cidrs", [None])[0] != source_ip + "/32"):
            raise RuntimeError("pre-recreation SDK source IP differs from the preserved exact machine /32")
        verified_ips[machine_id] = source_ip
    return verified_ips


def verify_sdk_source_ip(project: str, directory: Path, machine_id: str, network_cidr: str) -> str:
    service = {"example-go-machine": "example-go", "example-python-machine": "example-python",
               "example-java-machine": "example-java"}.get(machine_id)
    if service is None:
        raise ValueError("source IP verification requires one fixed public workload machine")
    inspected = inspect_owner_compose_service(project, directory, service)
    if network_cidr != inspected["ip"] + "/32":
        raise RuntimeError("Identity machine CIDR does not match the exact owner SDK container source IP")
    return inspected["ip"]


def index_workload_credential_rotation_phase(project: str, directory: Path, language: str,
                                             confirm_resource: str, confirm=None) -> dict:
    _directory, owner, _passwords = read_manifest(project)
    machine_id, agent_id, installation_id, prefix = index_workload_machine(language)
    target = machine_id + "@" + installation_id
    if confirm_resource != target:
        raise ValueError("machine credential rotation requires the exact Machine@Installation confirmation")
    if (not owner.get("identity_complete") or not owner.get("services_ready") or not owner.get("machines_complete")
            or owner.get("business_roles_complete") is not True or owner.get("authorization_complete") is not True
            or owner.get("runtime_prepared") is not True or owner.get("runtime_process_started") is not True):
        raise RuntimeError("index workload credential rotation requires the complete isolated identity, release, policy, runtime and 57-Grant stages")
    plan = load_knowledge_plan(project, directory, owner)
    item = next((row for row in plan["items"] if row["language"] == language), None)
    expected_owner = "demo." + language + ".user"
    if (not isinstance(item, dict) or item.get("machine") != machine_id or item.get("installation_id") != installation_id
            or item.get("owner") != expected_owner):
        raise RuntimeError("Knowledge plan machine, human owner or installation differs from the fixed language map")
    knowledge_journal = owner.get("knowledge_replay_journal")
    source_row = knowledge_journal.get("languages", {}).get(language, {}) if isinstance(knowledge_journal, dict) else {}
    if not isinstance(source_row.get("source_receipt"), dict):
        raise RuntimeError("machine credential rotation requires the exact published Knowledge source receipt")
    if owner.get("knowledge_index_lifecycle", {}).get(agent_id, {}).get("index_publication_verified") is True:
        raise RuntimeError("a verified index already exists for this installation; credential rotation must precede indexing")

    journal = index_rotation_journal(owner, project)
    prior = journal["machines"].get(machine_id)
    if prior is not None and (not isinstance(prior, dict) or prior.get("language") != language
                              or prior.get("installation_id") != installation_id):
        raise RuntimeError("owner machine credential rotation journal has an unexpected machine mapping")
    if journal.get("mount_activation") is not None:
        raise RuntimeError("index workload secret mount has already entered activation; no credential rotation may be replayed")
    secret_root = directory / "empty-secrets"
    bootstrap.ensure_private_directory(secret_root)
    if any(bootstrap.is_reparse_point(path) for path in secret_root.iterdir()):
        raise RuntimeError("worker credential mount contains a reparse point")
    if any(secret_root.iterdir()):
        raise RuntimeError("worker credential mount is not empty before credential recovery")

    machine_values = machine_environment_credentials(directory)
    old_secret = machine_values[prefix + "_CLIENT_SECRET"]
    old_secret_digest = hashlib.sha256(old_secret.encode("ascii")).hexdigest()
    verify_owner_frontend(project, directory, owner)
    verify_example_container_health(project, directory)
    api = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    bootstrap.verify_login_identity(api.call("GET", "/auth/me"), "system.admin", bootstrap.BUSINESS_SCOPE)
    bootstrap.verify_initial_admin_access(bootstrap.profile(api, "system.admin"), allow_business_membership=True)
    verify_catalog_installation_readiness(api)
    auth_pin = owner.get("authorization_plan")
    if not isinstance(auth_pin, dict) or not isinstance(auth_pin.get("path"), str):
        raise RuntimeError("machine credential rotation has no owner-pinned 57-Grant authorization plan")
    grant_plan, _grant_relative = load_authorization_plan(project, directory, Path(auth_pin["path"]))
    verify_live_minimum_grants(api, project, grant_plan, owner)
    inventory = validate_index_machine_credentials_for_rotation(
        api.call("GET", INDEX_WORKLOAD_ROTATION_PATH), journal, directory,
        unresolved_machine_id=machine_id if prior is not None else None)
    current_credential = inventory.get(machine_id)
    if not isinstance(current_credential, dict):
        raise RuntimeError("the selected machine credential is not present in the exact owner inventory")
    sdk_network = next((value for value in current_credential["network_cidrs"]
                        if not ipaddress.ip_network(value, strict=True).network_address.is_loopback), None)
    if not isinstance(sdk_network, str):
        raise RuntimeError("machine credential has no exact owner SDK source CIDR")
    sdk_ip = verify_sdk_source_ip(project, directory, machine_id, sdk_network)

    if prior is not None:
        receipt_path = index_rotation_receipt_path(directory, language)
        if not receipt_path.exists():
            observed = {"credential_revision": current_credential["revision"],
                        "network_cidrs": current_credential["network_cidrs"], "sdk_ip": sdk_ip}
            prior["status"] = "unknown"
            prior["last_readonly_reconcile"] = observed
            journal["machines"][machine_id] = prior
            persist_index_rotation_state(project, directory, owner["authorization_plan"]["plan_sha256"], journal)
            print(json.dumps({"result": "machine_rotation_unknown_readonly_reconcile", "project": project,
                              "language": language, "machine_id": machine_id, "installation_id": installation_id,
                              "observed_revision": current_credential["revision"],
                              "rotation_secret_recoverable": False, "post_retried": False,
                              "worker_secret_file_exposed": False}, ensure_ascii=False))
            raise RuntimeError("rotation intent has no secret-bearing response receipt; POST was not repeated")
        expected_receipt = {"request_sha256": prior.get("request_sha256"), "machine_id": machine_id,
                            "installation_id": installation_id}
        receipt = read_index_rotation_receipt(project, directory, language, expected_receipt)
        response = receipt["response"]
        checked = verify_live_index_rotation(api, prior, response, journal, directory)
        if sdk_ip + "/32" != prior.get("network_cidrs", [None])[0]:
            raise RuntimeError("owner SDK source IP changed after credential rotation; worker secret mount remains disabled")
        def file_intent(name: str) -> None:
            prior["status"] = "machines_env_write_started" if name == "machines.env" else "private_env_write_started"
            prior["file_write_intent"] = name
            journal["machines"][machine_id] = prior
            persist_index_rotation_state(project, directory, owner["authorization_plan"]["plan_sha256"], journal)
        def file_verified(name: str) -> None:
            prior["file_write_verified"] = name
            journal["machines"][machine_id] = prior
            persist_index_rotation_state(project, directory, owner["authorization_plan"]["plan_sha256"], journal)
        replace_rotated_machine_secret(directory, language, machine_id, installation_id,
                                       prior["old_secret_sha256"], response["client_secret"], file_intent, file_verified)
        prior.update({"status": "environment_updated", "secret_sha256": hashlib.sha256(response["client_secret"].encode("ascii")).hexdigest(),
                      "profile_revision_after": checked["profile_revision"], "sdk_ip_before": sdk_ip})
        journal["machines"][machine_id] = prior
        persist_index_rotation_state(project, directory, owner["authorization_plan"]["plan_sha256"], journal)
        print(json.dumps({"result": "owner_machine_credential_environment_reconciled", "project": project,
                          "language": language, "machine_id": machine_id, "installation_id": installation_id,
                          "revision": response["revision"], "secret_values_printed": False,
                          "worker_secret_file_exposed": False}, ensure_ascii=False))
        return prior

    if current_credential["network_cidrs"] != [sdk_ip + "/32"]:
        raise RuntimeError("fresh machine rotation requires the one exact current SDK /32 before adding loopback")
    if current_credential["revision"] < 1:
        raise RuntimeError("machine credential has no usable CAS revision")
    complete, receipts = verified_grant_subject_prefix(owner, grant_plan, auth_pin["plan_sha256"])
    if set(complete) != {row["subject_id"] for row in grant_plan["changes"]}:
        raise RuntimeError("machine credential rotation requires all six existing minimum Grant readbacks")
    grant_receipt = next((row for row in receipts if row["subject_id"] == machine_id), None)
    profile_before = bootstrap.profile(api, machine_id, "service_principal")
    profile_revision, boundary = machine_access_boundary(profile_before, machine_id)
    if not grant_receipt or grant_receipt.get("revision") != profile_revision:
        raise RuntimeError("machine principal revision differs from its real completed Grant receipt; no synthetic revision is accepted")
    request = build_index_machine_rotation(machine_id, installation_id, current_credential, sdk_ip)
    request_digest = hashlib.sha256(example_authorization.canonical(request)).hexdigest()
    phrase = f"{project} rotate {machine_id}@{installation_id} rev{request['expected_revision']} {request_digest}"
    print(json.dumps({"phase": "machine_credential_rotation_preview", "project": project,
                      "machine_id": machine_id, "installation_id": installation_id,
                      "expected_revision": request["expected_revision"], "network_cidrs": request["network_cidrs"],
                      "sdk_ip": sdk_ip, "request_sha256": request_digest, "confirmation": phrase,
                      "business_grants_changed": False, "secret_values_printed": False}, ensure_ascii=False))
    if not confirm_digest_phrase(phrase, confirm):
        raise RuntimeError("machine credential rotation was not confirmed")

    receipt = {"schema": "public-index-machine-credential-receipt/v1", "owner": project,
               "language": language, "machine_id": machine_id, "installation_id": installation_id,
               "request_sha256": request_digest, "response": None}
    entry = {"language": language, "machine_id": machine_id, "installation_id": installation_id,
             "status": "post_started", "expected_revision": request["expected_revision"],
             "network_cidrs": request["network_cidrs"], "request_sha256": request_digest,
             "old_secret_sha256": old_secret_digest, "grant_profile_revision": profile_revision,
             "access_boundary_sha256": hashlib.sha256(example_authorization.canonical(boundary)).hexdigest(),
             "sdk_ip_before": sdk_ip,
             "grant_count": len(next(change for change in grant_plan["changes"] if change["subject_id"] == machine_id)["resource_grants"])}
    journal["machines"][machine_id] = entry
    persist_index_rotation_state(project, directory, auth_pin["plan_sha256"], journal)
    try:
        response = api.call("POST", INDEX_WORKLOAD_ROTATION_PATH + "/" + bootstrap.urllib.parse.quote(machine_id, safe="") + "/rotate", request)
    except Exception as error:
        entry["status"] = "unknown"
        entry["error_type"] = type(error).__name__
        journal["machines"][machine_id] = entry
        persist_index_rotation_state(project, directory, auth_pin["plan_sha256"], journal)
        raise RuntimeError("machine credential POST outcome is unknown; no retry was attempted and no secret mount was exposed") from None

    receipt["response"] = response
    receipt_target = owner_private_output(directory, index_rotation_receipt_path(directory, language))
    bootstrap.write_new_private_file(receipt_target, json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    entry["status"] = "response_received"
    entry["receipt_path"] = receipt_target.relative_to(directory.resolve()).as_posix()
    entry["response_sha256"] = hashlib.sha256(example_authorization.canonical(response)).hexdigest()
    journal["machines"][machine_id] = entry
    persist_index_rotation_state(project, directory, auth_pin["plan_sha256"], journal)
    verified_response = validate_index_machine_rotation_response(response, machine_id,
                                                                 request["expected_revision"], request["network_cidrs"])
    checked = verify_live_index_rotation(api, entry, verified_response, journal, directory)
    if sdk_ip + "/32" != request["network_cidrs"][0]:
        raise RuntimeError("owner SDK source address was not retained in the exact credential CIDR")
    def file_intent(name: str) -> None:
        entry["status"] = "machines_env_write_started" if name == "machines.env" else "private_env_write_started"
        entry["file_write_intent"] = name
        journal["machines"][machine_id] = entry
        persist_index_rotation_state(project, directory, auth_pin["plan_sha256"], journal)
    def file_verified(name: str) -> None:
        entry["file_write_verified"] = name
        journal["machines"][machine_id] = entry
        persist_index_rotation_state(project, directory, auth_pin["plan_sha256"], journal)
    replace_rotated_machine_secret(directory, language, machine_id, installation_id,
                                   old_secret_digest, verified_response["client_secret"], file_intent, file_verified)
    entry.update({"status": "environment_updated", "secret_sha256": hashlib.sha256(verified_response["client_secret"].encode("ascii")).hexdigest(),
                  "profile_revision_after": checked["profile_revision"]})
    journal["machines"][machine_id] = entry
    persist_index_rotation_state(project, directory, auth_pin["plan_sha256"], journal)
    print(json.dumps({"result": "owner_machine_credential_rotated_and_environment_updated", "project": project,
                      "language": language, "machine_id": machine_id, "installation_id": installation_id,
                      "credential_revision": verified_response["revision"],
                      "profile_revision_before": profile_revision, "profile_revision_after": checked["profile_revision"],
                      "grant_profile_boundary_unchanged": True, "sdk_ip_before": sdk_ip,
                      "secret_values_printed": False, "worker_secret_file_exposed": False}, ensure_ascii=False))
    return entry


def machine_environment_credentials(directory: Path) -> dict[str, str]:
    machine = parse_machine_env_private(directory / "machines.env")
    private = read_owner_env(directory)
    if any(private.get(key) != value for key, value in machine.items()):
        raise RuntimeError("owner machines.env and private.env do not contain the same exact workload credentials")
    return machine


def index_workload_credential_deploy_phase(project: str, directory: Path) -> dict:
    _directory, owner, _passwords = read_manifest(project)
    journal = index_rotation_journal(owner, project)
    if set(journal["machines"]) != {row[0] for row in bootstrap.MACHINES} or any(
        not isinstance(journal["machines"].get(row[0]), dict)
        or journal["machines"][row[0]].get("status") != "environment_updated" for row in bootstrap.MACHINES
    ):
        raise RuntimeError("SDK deployment requires all three owner credential rotations and environment readbacks")
    values = machine_environment_credentials(directory)
    overlay_path, overlay_digest, network = ensure_owner_index_ip_overlay(project, directory, journal)
    target_ips = {machine_id: row["sdk_ip_before"] for machine_id, row in journal["machines"].items()}
    deployment = journal.get("deployment")
    if deployment is not None:
        if (not isinstance(deployment, dict) or deployment.get("status") not in {"started", "unknown", "verified", "corrected"}
                or deployment.get("services") != ["example-go", "example-python", "example-java"]
                or not isinstance(deployment.get("source_ips_before"), dict)
                or not isinstance(deployment.get("platform_container_id_before"), str)):
            raise RuntimeError("owner SDK credential deployment journal has an unknown state")
        if deployment.get("index_ip_overlay_sha256") not in (None, overlay_digest):
            raise RuntimeError("owner SDK deployment references a different pinned source-IP overlay")
        if deployment.get("status") in {"started", "unknown", "verified", "corrected"}:
            verify_example_container_health(project, directory)
            current = verify_sdk_process_machine_credentials(project, directory, values)
            platform = inspect_owner_compose_service(project, directory, "platform-app")
            if platform["container_id"] != deployment["platform_container_id_before"]:
                raise RuntimeError("platform-app container changed during SDK-only deployment; MCP network namespace proof failed")
            correction = journal.get("ip_correction")
            expected_ips = target_ips if deployment.get("status") == "corrected" or (
                isinstance(correction, dict) and correction.get("status") == "verified") else deployment["source_ips_before"]
            if current != expected_ips:
                raise RuntimeError("SDK source IP drift is unresolved; run the explicit owner IP-correction stage, not deploy again")
            for machine_id, ip in current.items():
                row = journal["machines"].get(machine_id)
                if not isinstance(row, dict) or row.get("network_cidrs", [None])[0] != ip + "/32":
                    raise RuntimeError("rotated machine CIDR no longer matches the exact SDK source IP")
            if isinstance(correction, dict) and correction.get("status") == "verified":
                correction_request = correction.get("request")
                failed_snapshot = correction.get("failed_deployment_snapshot")
                correction_digest = (hashlib.sha256(example_authorization.canonical(correction_request)).hexdigest()
                                     if isinstance(correction_request, dict) else None)
                if (correction.get("schema") != INDEX_IP_CORRECTION_SCHEMA
                        or not isinstance(failed_snapshot, dict) or failed_snapshot.get("status") != "unknown"
                        or not isinstance(correction_request, dict)
                        or correction_request.get("failed_deployment_sha256") != hashlib.sha256(
                            example_authorization.canonical(failed_snapshot)).hexdigest()
                        or correction.get("request_sha256") != correction_digest
                        or deployment.get("status") == "unknown"
                        and example_authorization.canonical(failed_snapshot) != example_authorization.canonical(deployment)
                        or deployment.get("status") == "corrected"
                        and deployment.get("corrected_by_sha256") != correction_digest
                        or correction.get("target_ips") != target_ips
                        or correction.get("platform_container_id") != platform["container_id"]
                        or correction.get("overlay_sha256") != overlay_digest):
                    raise RuntimeError("explicit SDK IP correction receipt differs from the current pinned network proof")
                deployment.update({"status": "corrected", "source_ips_after": current,
                                   "platform_container_id_after": platform["container_id"],
                                   "corrected_by_sha256": correction.get("request_sha256"),
                                   "index_ip_overlay_sha256": overlay_digest,
                                   "verified_services": ["example-go", "example-python", "example-java"]})
            elif deployment.get("status") in {"started", "unknown"}:
                deployment.update({"status": "verified", "source_ips_after": current,
                                   "platform_container_id_after": platform["container_id"],
                                   "index_ip_overlay_sha256": overlay_digest,
                                   "verified_services": ["example-go", "example-python", "example-java"]})
            journal["deployment"] = deployment
            persist_index_rotation_state(project, directory, owner["authorization_plan"]["plan_sha256"], journal)
            return deployment
    verify_owner_frontend(project, directory, owner)
    verify_example_container_health(project, directory)
    source_ips_before = dict(target_ips)
    if set(source_ips_before) != {row[0] for row in bootstrap.MACHINES}:
        raise RuntimeError("SDK deployment requires the exact three pre-rotation source IP proofs")
    platform_before = inspect_owner_compose_service(project, directory, "platform-app")
    sdk_before = verify_sdk_process_pre_rotation_credentials(project, directory, journal)
    if sdk_before != source_ips_before:
        raise RuntimeError("SDK network source changed before the environment-switch deployment")
    for machine_id, ip in sdk_before.items():
        if journal["machines"][machine_id].get("network_cidrs", [None])[0] != ip + "/32":
            raise RuntimeError("rotated machine CIDR does not match the running SDK source before recreation")
    journal["deployment"] = {"status": "started", "services": ["example-go", "example-python", "example-java"],
                             "source_ips_before": source_ips_before,
                             "platform_container_id_before": platform_before["container_id"],
                             "platform_container_id_after": None, "network": network,
                             "index_ip_overlay_sha256": overlay_digest}
    persist_index_rotation_state(project, directory, owner["authorization_plan"]["plan_sha256"], journal)
    try:
        services = ["example-go", "example-python", "example-java"]
        run_owner_runtime_compose(project, directory, ["stop", *services], timeout=90, include_index_ip_overlay=True)
        run_owner_runtime_compose(project, directory, ["rm", "-f", *services], timeout=90, include_index_ip_overlay=True)
        run_owner_runtime_compose(project, directory, ["up", "-d", "--no-deps", "--no-build", "--force-recreate", "--wait",
                                                       "--wait-timeout", "180", *services], timeout=240,
                                  include_index_ip_overlay=True)
        verify_example_container_health(project, directory)
        source_ips_after = verify_sdk_process_machine_credentials(project, directory, values)
        platform_after = inspect_owner_compose_service(project, directory, "platform-app")
        if platform_after["container_id"] != platform_before["container_id"]:
            raise RuntimeError("platform-app container changed during SDK-only deployment; MCP namespace must remain intact")
        if source_ips_after != source_ips_before:
            raise RuntimeError("SDK source IP changed after recreation; worker credentials remain unexposed")
        for machine_id, ip in source_ips_after.items():
            if journal["machines"][machine_id].get("network_cidrs", [None])[0] != ip + "/32":
                raise RuntimeError("rotated machine CIDR no longer matches the exact recreated SDK source IP")
    except Exception as error:
        journal["deployment"]["status"] = "unknown"
        journal["deployment"]["error_type"] = type(error).__name__
        persist_index_rotation_state(project, directory, owner["authorization_plan"]["plan_sha256"], journal)
        raise RuntimeError("SDK credential deployment is unresolved; no second Compose recreation was attempted") from None
    journal["deployment"].update({"status": "verified", "verified_services": ["example-go", "example-python", "example-java"],
                                  "source_ips_after": source_ips_after,
                                  "platform_container_id_after": platform_after["container_id"]})
    persist_index_rotation_state(project, directory, owner["authorization_plan"]["plan_sha256"], journal)
    print(json.dumps({"result": "all_three_sdk_processes_switched_to_owner_credentials", "project": project,
                      "services": ["example-go", "example-python", "example-java"],
                      "source_ips": source_ips_after, "platform_container_preserved": True,
                      "credential_values_printed": False, "worker_secret_files_exposed": False}, ensure_ascii=False))
    return journal["deployment"]


def index_workload_credential_correct_ips_phase(project: str, directory: Path, confirm=None) -> dict:
    """Run a new, explicitly confirmed SDK-only repair after proving an IP-only drift."""
    _directory, owner, _passwords = read_manifest(project)
    journal = index_rotation_journal(owner, project)
    deployment = journal.get("deployment")
    if (not isinstance(deployment, dict) or deployment.get("status") != "unknown"
            or deployment.get("services") != ["example-go", "example-python", "example-java"]
            or not isinstance(deployment.get("source_ips_before"), dict)
            or not isinstance(deployment.get("platform_container_id_before"), str)
            or journal.get("mount_activation") is not None):
        raise RuntimeError("explicit IP correction requires one unresolved SDK-only deployment and an unexposed worker mount")
    if set(journal["machines"]) != {row[0] for row in bootstrap.MACHINES} or any(
        not isinstance(row, dict) or row.get("status") != "environment_updated" for row in journal["machines"].values()
    ):
        raise RuntimeError("explicit IP correction requires all three receipt-backed rotated credentials")
    values = machine_environment_credentials(directory)
    _overlay_path, overlay_digest, network = ensure_owner_index_ip_overlay(project, directory, journal)
    target_ips = {machine_id: row["sdk_ip_before"] for machine_id, row in journal["machines"].items()}
    correction = journal.get("ip_correction")

    def validate_correction_record(value: dict) -> None:
        request = value.get("request") if isinstance(value, dict) else None
        failed_snapshot = value.get("failed_deployment_snapshot") if isinstance(value, dict) else None
        expected_request_keys = {"schema", "owner", "failed_deployment_sha256", "target_ips", "observed_ips",
                                 "observed_container_ids", "platform_container_id", "network", "overlay_sha256", "services"}
        if (not isinstance(request, dict) or set(request) != expected_request_keys
                or request.get("schema") != INDEX_IP_CORRECTION_SCHEMA or request.get("owner") != project
                or not isinstance(failed_snapshot, dict) or failed_snapshot.get("status") != "unknown"
                or request.get("failed_deployment_sha256") != hashlib.sha256(example_authorization.canonical(failed_snapshot)).hexdigest()
                or request.get("target_ips") != target_ips
                or request.get("observed_ips") != value.get("observed_ips_before")
                or request.get("observed_container_ids") != value.get("container_ids_before")
                or request.get("platform_container_id") != deployment.get("platform_container_id_before")
                or request.get("network") != network or request.get("overlay_sha256") != overlay_digest
                or request.get("services") != ["example-go", "example-python", "example-java"]
                or value.get("schema") != INDEX_IP_CORRECTION_SCHEMA
                or value.get("request_sha256") != hashlib.sha256(example_authorization.canonical(request)).hexdigest()
                or value.get("target_ips") != target_ips or value.get("overlay_sha256") != overlay_digest
                or value.get("platform_container_id") != deployment.get("platform_container_id_before")):
            raise RuntimeError("SDK IP correction record differs from its exact owner-bound write-ahead request")
        if value.get("status") == "verified":
            after_ids = value.get("container_ids_after")
            if (value.get("source_ips_after") != target_ips or not isinstance(after_ids, dict)
                    or set(after_ids) != set(target_ips) or after_ids == value.get("container_ids_before")
                    or value.get("platform_container_id_after") != deployment.get("platform_container_id_before")):
                raise RuntimeError("verified SDK IP correction receipt lacks exact recreated service/platform readback")

    def prove_current() -> tuple[dict[str, str], dict[str, str], dict]:
        verify_example_container_health(project, directory)
        current_ips = verify_sdk_process_machine_credentials(project, directory, values)
        current_ids = {}
        for machine_id, agent_id, _installation_id, _prefix in bootstrap.MACHINES:
            service = {"example-go-machine": "example-go", "example-python-machine": "example-python",
                       "example-java-machine": "example-java"}[machine_id]
            inspected = inspect_owner_compose_service(project, directory, service)
            if inspected["ip"] != current_ips.get(machine_id):
                raise RuntimeError("SDK IP changed while reading the owner correction proof")
            current_ids[machine_id] = inspected["container_id"]
        platform = inspect_owner_compose_service(project, directory, "platform-app")
        if platform["container_id"] != deployment["platform_container_id_before"]:
            raise RuntimeError("platform-app changed during the failed SDK deploy; stop before any correction")
        try:
            current_addresses = [ipaddress.ip_address(ip) for ip in current_ips.values()]
            current_network = ipaddress.ip_network(network["subnet"], strict=True)
        except (TypeError, ValueError):
            raise RuntimeError("live SDK source addresses or owner subnet are malformed") from None
        if (set(current_ips) != set(target_ips) or any(address not in current_network
                                                       for address in current_addresses)):
            raise RuntimeError("live SDK source addresses are not the exact three owner network addresses")
        return current_ips, current_ids, platform

    verify_owner_frontend(project, directory, owner)
    current_ips, current_ids, platform = prove_current()
    if correction is not None:
        if (not isinstance(correction, dict) or correction.get("schema") != INDEX_IP_CORRECTION_SCHEMA
                or correction.get("target_ips") != target_ips or correction.get("overlay_sha256") != overlay_digest
                or correction.get("platform_container_id") != platform["container_id"]
                or correction.get("status") not in {"started", "unknown", "verified"}):
            raise RuntimeError("owner SDK IP correction journal does not match the current exact project state")
        validate_correction_record(correction)
        if correction.get("status") == "verified":
            if current_ips != target_ips or current_ids != correction.get("container_ids_after"):
                raise RuntimeError("verified SDK IP correction receipt no longer matches current container readback")
            return correction
        # A prior correction may have reached the target despite a lost local
        # acknowledgement. Read back only; never repeat its stop/rm/up commands.
        if current_ips != target_ips:
            raise RuntimeError("SDK IP correction outcome remains unknown; no Compose operation was retried")
        if current_ids == correction.get("container_ids_before"):
            raise RuntimeError("SDK IP correction did not prove container recreation; no Compose operation was retried")
        correction.update({"status": "verified", "container_ids_after": current_ids,
                           "source_ips_after": current_ips,
                           "platform_container_id_after": platform["container_id"],
                           "reconciled_readonly": True})
        journal["ip_correction"] = correction
        persist_index_rotation_state(project, directory, owner["authorization_plan"]["plan_sha256"], journal)
        return correction

    if current_ips == target_ips:
        raise RuntimeError("SDK source IPs already match their original pins; reconcile the deployment journal read-only")
    if current_ips == deployment["source_ips_before"]:
        raise RuntimeError("there is no SDK IP drift to correct; reconcile the deployment journal read-only")
    if set(deployment["source_ips_before"]) != set(target_ips):
        raise RuntimeError("failed SDK deployment lacks the exact original three source-IP proofs")
    request = {"schema": INDEX_IP_CORRECTION_SCHEMA, "owner": project,
               "failed_deployment_sha256": hashlib.sha256(example_authorization.canonical(deployment)).hexdigest(),
               "target_ips": target_ips, "observed_ips": current_ips,
               "observed_container_ids": current_ids,
               "platform_container_id": platform["container_id"], "network": network,
               "overlay_sha256": overlay_digest,
               "services": ["example-go", "example-python", "example-java"]}
    request_digest = hashlib.sha256(example_authorization.canonical(request)).hexdigest()
    phrase = f"{project} correct-sdk-ips {request_digest}"
    print(json.dumps({"phase": "owner_sdk_ip_correction_preview", "project": project,
                      "observed_ips": current_ips, "target_ips": target_ips,
                      "platform_container_preserved": True, "overlay_sha256": overlay_digest,
                      "request_sha256": request_digest, "confirmation": phrase,
                      "credentials_rotated": False, "worker_secret_file_exposed": False}, ensure_ascii=False))
    if not confirm_digest_phrase(phrase, confirm):
        raise RuntimeError("owner SDK IP correction was not confirmed")

    correction = {"schema": INDEX_IP_CORRECTION_SCHEMA, "status": "started",
                  "request_sha256": request_digest, "request": request,
                  "failed_deployment_snapshot": deepcopy(deployment),
                  "observed_ips_before": current_ips, "container_ids_before": current_ids,
                  "target_ips": target_ips, "platform_container_id": platform["container_id"],
                  "network": network, "overlay_sha256": overlay_digest,
                  "services": request["services"]}
    journal["ip_correction"] = correction
    persist_index_rotation_state(project, directory, owner["authorization_plan"]["plan_sha256"], journal)
    services = ["example-go", "example-python", "example-java"]
    try:
        run_owner_runtime_compose(project, directory, ["stop", *services], timeout=90, include_index_ip_overlay=True)
        run_owner_runtime_compose(project, directory, ["rm", "-f", *services], timeout=90, include_index_ip_overlay=True)
        run_owner_runtime_compose(project, directory, ["up", "-d", "--no-deps", "--no-build", "--force-recreate", "--wait",
                                                       "--wait-timeout", "180", *services], timeout=240,
                                  include_index_ip_overlay=True)
        verify_example_container_health(project, directory)
        source_ips_after = verify_sdk_process_machine_credentials(project, directory, values)
        container_ids_after = {}
        for machine_id, _agent_id, _installation_id, _prefix in bootstrap.MACHINES:
            service = {"example-go-machine": "example-go", "example-python-machine": "example-python",
                       "example-java-machine": "example-java"}[machine_id]
            container_ids_after[machine_id] = inspect_owner_compose_service(project, directory, service)["container_id"]
        platform_after = inspect_owner_compose_service(project, directory, "platform-app")
        if (source_ips_after != target_ips or platform_after["container_id"] != platform["container_id"]
                or container_ids_after == current_ids):
            raise RuntimeError("explicit IP correction failed to restore pinned SDK addresses or preserve platform namespace")
    except Exception as error:
        correction["status"] = "unknown"
        correction["error_type"] = type(error).__name__
        journal["ip_correction"] = correction
        persist_index_rotation_state(project, directory, owner["authorization_plan"]["plan_sha256"], journal)
        raise RuntimeError("explicit SDK IP correction outcome is unknown; Compose was not retried") from None
    correction.update({"status": "verified", "source_ips_after": source_ips_after,
                       "container_ids_after": container_ids_after,
                       "platform_container_id_after": platform_after["container_id"]})
    journal["ip_correction"] = correction
    persist_index_rotation_state(project, directory, owner["authorization_plan"]["plan_sha256"], journal)
    print(json.dumps({"result": "explicit_sdk_ip_correction_verified", "project": project,
                      "source_ips": source_ips_after, "platform_container_preserved": True,
                      "credentials_rotated": False, "worker_secret_file_exposed": False}, ensure_ascii=False))
    return correction


def create_private_file_no_replace(path: Path, content: str) -> None:
    bootstrap.validate_machine_env_path(path)
    bootstrap.ensure_private_directory(path.parent)
    if bootstrap.is_reparse_point(path):
        raise RuntimeError("worker credential output may not be a symlink, junction or reparse point")
    stage = path.with_name(path.name + ".tmp")
    if path.exists():
        raise FileExistsError("worker credential output already exists; no file was overwritten")
    encoded = content.encode("utf-8")
    if stage.exists():
        bootstrap.verify_private_file(stage)
        if stage.read_bytes() != encoded:
            raise RuntimeError("private worker credential staging file differs; no output was activated")
    else:
        bootstrap.write_new_private_file(stage, content)
    try:
        os.link(stage, path)
    except FileExistsError:
        raise FileExistsError("worker credential output appeared concurrently; no file was overwritten") from None
    except OSError:
        raise RuntimeError("filesystem cannot atomically expose the completed owner-private worker credential") from None
    stage.unlink()
    bootstrap.verify_private_file(path)
    if path.read_bytes() != encoded:
        raise RuntimeError("worker credential file readback differs from the owner-private staged bytes")


def index_workload_credential_activate_phase(project: str, directory: Path) -> dict:
    _directory, owner, _passwords = read_manifest(project)
    journal = index_rotation_journal(owner, project)
    if (set(journal["machines"]) != {row[0] for row in bootstrap.MACHINES}
            or not isinstance(journal.get("deployment"), dict)
            or journal["deployment"].get("status") not in {"verified", "corrected"}):
        raise RuntimeError("worker secret activation requires all three verified rotations and SDK process switches")
    if journal["deployment"].get("status") == "corrected":
        correction = journal.get("ip_correction")
        if (not isinstance(correction, dict) or correction.get("schema") != INDEX_IP_CORRECTION_SCHEMA
                or correction.get("status") != "verified"
                or correction.get("request_sha256") != journal["deployment"].get("corrected_by_sha256")):
            raise RuntimeError("corrected SDK deployment lacks its separate verified IP-correction receipt")
    values = machine_environment_credentials(directory)
    verify_owner_frontend(project, directory, owner)
    verify_example_container_health(project, directory)
    current_ips = verify_sdk_process_machine_credentials(project, directory, values)
    deployment = journal["deployment"]
    platform = inspect_owner_compose_service(project, directory, "platform-app")
    if (current_ips != deployment.get("source_ips_after")
            or platform.get("container_id") != deployment.get("platform_container_id_after")):
        raise RuntimeError("SDK credentials, source IPs or platform-app namespace changed after deployment verification")
    target = directory / "empty-secrets"
    bootstrap.ensure_private_directory(target)
    allowed_names = set()
    secrets_by_name: dict[str, tuple[str, str]] = {}
    for language in public_knowledge.EXAMPLES:
        machine = index_workload_machine(language)
        row = journal["machines"].get(machine[0])
        if not isinstance(row, dict) or row.get("status") != "environment_updated":
            raise RuntimeError("worker secret activation is missing one exact owner credential receipt")
        receipt = read_index_rotation_receipt(project, directory, language,
                                              {"request_sha256": row.get("request_sha256"),
                                               "machine_id": machine[0], "installation_id": machine[2]})
        response = validate_index_machine_rotation_response(receipt["response"], machine[0],
                                                             row["expected_revision"], row["network_cidrs"])
        prefix = machine[3]
        if (values[prefix + "_CLIENT_ID"] != machine[0]
                or values[prefix + "_CLIENT_SECRET"] != response["client_secret"]
                or hashlib.sha256(response["client_secret"].encode("ascii")).hexdigest() != row.get("secret_sha256")):
            raise RuntimeError("worker secret receipt and both owner SDK credential files are not synchronized")
        filename = index_workload_secret_filename(bootstrap.BUSINESS_SCOPE, machine[2])
        allowed_names.add(filename)
        secret_value = json.dumps({"client_id": machine[0], "client_secret": response["client_secret"]},
                                  separators=(",", ":")) + "\n"
        secrets_by_name[filename] = (language, secret_value)
    existing = list(target.iterdir())
    for path in existing:
        if bootstrap.is_reparse_point(path) or not path.is_file() or path.name not in allowed_names | {name + ".tmp" for name in allowed_names}:
            raise RuntimeError("worker credential mount contains an unexpected file or reparse point")
    state = journal.get("mount_activation")
    if state is None:
        journal["mount_activation"] = {"status": "started", "filenames": sorted(allowed_names),
                                       "completed_files": [], "current_file_intent": None}
        persist_index_rotation_state(project, directory, owner["authorization_plan"]["plan_sha256"], journal)
    elif (not isinstance(state, dict) or state.get("filenames") != sorted(allowed_names)
          or state.get("status") not in {"started", "verified"}):
        raise RuntimeError("worker credential mount activation has an unknown owner journal state")
    for filename in sorted(allowed_names):
        path = target / filename
        language, content = secrets_by_name[filename]
        journal["mount_activation"]["current_file_intent"] = filename
        persist_index_rotation_state(project, directory, owner["authorization_plan"]["plan_sha256"], journal)
        if path.exists():
            bootstrap.verify_private_file(path)
            if path.read_text(encoding="utf-8") != content:
                raise RuntimeError("existing worker credential file differs from the exact owner rotation receipt")
            stage = path.with_name(path.name + ".tmp")
            if stage.exists():
                bootstrap.verify_private_file(stage)
                if stage.read_text(encoding="utf-8") != content:
                    raise RuntimeError("worker credential staging file differs from the exact owner receipt")
                stage.unlink()
        else:
            create_private_file_no_replace(path, content)
        journal["mount_activation"]["completed_files"] = sorted(set(
            journal["mount_activation"].get("completed_files", [])) | {filename})
        journal["mount_activation"]["current_file_intent"] = None
        persist_index_rotation_state(project, directory, owner["authorization_plan"]["plan_sha256"], journal)
    for filename in sorted(allowed_names):
        bootstrap.verify_private_file(target / filename)
    journal["mount_activation"].update({"status": "verified", "file_count": len(allowed_names),
                                        "filenames": sorted(allowed_names)})
    latest = persist_index_rotation_state(project, directory, owner["authorization_plan"]["plan_sha256"], journal)
    latest["index_workload_secrets_active"] = True
    write_json_private(directory / "owner.json", latest)
    print(json.dumps({"result": "three_installation_bound_index_credentials_activated_after_sdk_switch", "project": project,
                      "file_count": len(allowed_names), "filenames": sorted(allowed_names),
                      "credential_values_printed": False}, ensure_ascii=False))
    return journal["mount_activation"]


def validate_runtime_material_inputs(subnet: str, private_ip: str, image_ids: dict[str, str], docker_cli_image: str, socket_gid: str) -> None:
    try:
        network = ipaddress.ip_network(subnet, strict=True)
        address = ipaddress.ip_address(private_ip)
    except ValueError:
        raise ValueError("Code Runtime requires a canonical private subnet and controller address") from None
    if not isinstance(network, ipaddress.IPv4Network) or not network.is_private or not 16 <= network.prefixlen <= 28:
        raise ValueError("Code Runtime subnet must be a dedicated private IPv4 /16 through /28")
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_private or address not in network or address in (network.network_address, network.broadcast_address, network.network_address + 1):
        raise ValueError("Code Runtime controller address must be a usable private host distinct from gateway/network/broadcast")
    if set(image_ids) != {"python", "javascript", "shell"} or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in image_ids.values()):
        raise ValueError("Code Runtime requires three actual immutable language image IDs")
    if not re.fullmatch(r"docker\.io/library/docker@sha256:[0-9a-f]{64}", docker_cli_image):
        raise ValueError("Code Runtime requires a verified immutable official Docker CLI image digest")
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,9})", socket_gid) or int(socket_gid) > 0xFFFFFFFF:
        raise ValueError("Code Runtime requires the verified numeric Docker socket group ID")


def build_runtime_owner_overlay(directory: Path, project: str) -> dict:
    project_name(project)
    runtime_dir = (directory / "runtime-control").resolve()
    required = {
        "platform-app": ("bindings.json", "/run/secrets/code-runtime/bindings.json"),
        "platform-permit.key": ("platform-permit.key", "/run/secrets/code-runtime/platform-permit.key"),
        "tool-approval.key": ("tool-approval.key", "/run/secrets/code-runtime/tool-approval.key"),
        "controller-ca.crt": ("controller-ca.crt", "/run/secrets/code-runtime/controller-ca.crt"),
    }
    platform_mounts = []
    for name, (_same_name, target) in required.items():
        filename = name if name != "platform-app" else "bindings.json"
        platform_mounts.append({"type": "bind", "source": (runtime_dir / filename).as_posix(), "target": target,
                               "read_only": True, "bind": {"create_host_path": False}})
    controller_mounts = [{"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock",
                          "bind": {"create_host_path": False}}]
    controller_files = (
        ("code-runtime.json", "/etc/agentplug-code/code-runtime.json"),
        ("permit-public.key", "/etc/agentplug-code/permit-public.key"),
        ("controller-state.key", "/etc/agentplug-code/controller-state.key"),
        ("controller.crt", "/etc/agentplug-code/controller.crt"),
        ("controller.key", "/etc/agentplug-code/controller.key"),
    )
    for filename, target in controller_files:
        controller_mounts.append({"type": "bind", "source": (runtime_dir / filename).as_posix(), "target": target,
                                  "read_only": True, "bind": {"create_host_path": False}})
    suffix = project.removeprefix("agentplug-test-public-")
    return {"services": {
        "platform-app": {"volumes": platform_mounts},
        "code-runtime": {"image": f"agentplug:test-code-runtime-{suffix}", "volumes": controller_mounts},
    }}


def runtime_prepare_phase(project: str, apply_confirmation: str, subnet: str, private_ip: str,
                          image_ids: dict[str, str], docker_cli_image: str, socket_gid: str) -> None:
    directory, owner, _passwords = read_manifest(project)
    if apply_confirmation != project or not owner.get("identity_complete") or not owner.get("services_ready") or owner.get("runtime_prepared"):
        raise ValueError("Code Runtime preparation requires completed isolated identity/services and exact project confirmation")
    validate_runtime_material_inputs(subnet, private_ip, image_ids, docker_cli_image, socket_gid)
    output = directory / "runtime-control"
    command = ["go", "run", "./cmd/prepare-code-runtime", "--output", str(output), "--private-ip", private_ip,
               "--subnet", subnet, "--tenant", bootstrap.BUSINESS_SCOPE["tenant_id"],
               "--application", bootstrap.BUSINESS_SCOPE["application_id"],
               "--python-image-id", image_ids["python"], "--javascript-image-id", image_ids["javascript"],
               "--shell-image-id", image_ids["shell"], "--docker-cli-image", docker_cli_image, "--socket-gid", socket_gid]
    result = subprocess.run(command, cwd=ROOT / "platform", capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError("public Code Runtime material generator failed; no runtime service was started")
    required_files = {"bindings.json", "platform-permit.key", "tool-approval.key", "controller-ca.crt",
                      "permit-public.key", "controller-state.key", "controller.crt", "controller.key",
                      "code-runtime.json", "compose.env"}
    if not output.is_dir() or {item.name for item in output.iterdir()} != required_files:
        raise RuntimeError("Code Runtime generator output did not match the exact ten-file contract")
    for filename in required_files:
        bootstrap.verify_private_file(output / filename)
    env_lines = (output / "compose.env").read_text(encoding="utf-8").splitlines()
    env = dict(line.split("=", 1) for line in env_lines if line and not line.startswith("#"))
    if env.get("CODE_RUNTIME_PRIVATE_IP") != private_ip or env.get("CODE_RUNTIME_SUBNET") != subnet or env.get("CODE_RUNTIME_DOCKER_CLI_IMAGE") != docker_cli_image or env.get("CODE_RUNTIME_DOCKER_SOCKET_GID") != socket_gid:
        raise RuntimeError("generated Code Runtime Compose settings do not match the reviewed inputs")
    overlay = build_runtime_owner_overlay(directory, project)
    write_json_private(directory / "runtime-owner-overlay.json", overlay)
    owner["runtime_prepared"] = True
    owner["images"].append("agentplug:test-code-runtime-" + project.removeprefix("agentplug-test-public-"))
    write_json_private(directory / "owner.json", owner)
    print(json.dumps({"result": "isolated_code_runtime_material_prepared", "project": project,
                      "compose_overlay": "deploy/compose/compose.runtime.yaml", "private_network": env["CODE_RUNTIME_SUBNET"],
                      "language_image_ids": image_ids, "secrets_printed": False, "service_started": False,
                      "iam_or_policy_mutations": False}, ensure_ascii=False))


def runtime_start_phase(project: str, apply_confirmation: str) -> None:
    directory, owner, _passwords = read_manifest(project)
    if apply_confirmation != project or not owner.get("runtime_prepared") or owner.get("runtime_process_started"):
        raise ValueError("Code Runtime startup requires the prepared owner overlay and exact project confirmation")
    bootstrap.verify_private_file(directory / "runtime-control" / "compose.env")
    bootstrap.verify_private_file(directory / "runtime-owner-overlay.json")
    prefix = compose_prefix(project, directory, include_runtime=True)
    environment = isolated_compose_environment(directory, include_runtime=True)
    # Identity/services have already built or installed the platform artifact.
    # Runtime preparation changes its mounts and environment, not its source.
    # Rebuilding here would overwrite a previously pinned platform image tag.
    for args, timeout in ((["config", "--quiet"], 60), (["build", "code-runtime"], 900),
                          (["up", "-d", "--no-build", "--wait", "--wait-timeout", "180", "platform-app", "code-runtime"], 240)):
        result = subprocess.run(prefix + args, cwd=ROOT, capture_output=True, timeout=timeout, env=environment)
        if result.returncode:
            raise RuntimeError("isolated Code Runtime Compose operation failed; project state is retained for review")
    listed = subprocess.run(prefix + ["ps", "--status", "running", "--services"], cwd=ROOT, capture_output=True, timeout=30, env=environment)
    services = set(listed.stdout.decode("utf-8", errors="replace").splitlines())
    if listed.returncode or not {"platform-app", "code-runtime"}.issubset(services):
        raise RuntimeError("isolated Code Runtime and platform processes are not both running")
    owner["runtime_process_started"] = True
    write_json_private(directory / "owner.json", owner)
    print(json.dumps({"result": "isolated_code_runtime_processes_running", "project": project,
                      "compose_overlay": "deploy/compose/compose.runtime.yaml", "runtime_execution_verified": False,
                      "policy_or_resource_grants_created": False, "secrets_printed": False}, ensure_ascii=False))


def load_release_bundle(directory: Path, path: Path, expected_agent: str) -> dict:
    candidate = path if path.is_absolute() else directory / path
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(directory.resolve(strict=True))
    except (OSError, ValueError):
        raise ValueError("release bundle must be a private file inside this exact isolated owner directory") from None
    current = directory.resolve()
    while current != resolved.parent:
        if bootstrap.is_reparse_point(current):
            raise ValueError("release bundle path may not traverse symlinks, junctions or reparse points")
        current = current.parent
    if bootstrap.is_reparse_point(resolved):
        raise ValueError("release bundle must be a regular owner-private file")
    bootstrap.verify_private_file(resolved)
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ValueError("private release bundle is invalid JSON") from None
    if not isinstance(value, dict) or value.get("schema") != "example-release-bundle/v1" or not re.fullmatch(r"sha256:[a-f0-9]{64}", value.get("manifest_hash", "")):
        raise ValueError("release bundle is not a verified public example-release-bundle/v1 plan")
    requests = value.get("requests")
    if not isinstance(requests, list) or not all(isinstance(item, dict) for item in requests):
        raise ValueError("release bundle request list is invalid")
    submissions = [item for item in requests if item.get("stage") == "submit" and item.get("method") == "POST"]
    definitions = [item for item in submissions if "/definitions" in item.get("path", "") and "/versions" not in item.get("path", "")]
    versions = [item for item in submissions if "/versions" in item.get("path", "")]
    if len(definitions) != 1 or len(versions) != 1:
        raise ValueError("isolated replay accepts only a new Definition and one new Version, not an existing-definition upgrade plan")
    definition, version = definitions[0].get("body"), versions[0].get("body")
    if not isinstance(definition, dict) or not isinstance(version, dict) or not isinstance(version.get("manifest"), dict):
        raise ValueError("Catalog Definition/Version request bodies are incomplete")
    agent = version["manifest"].get("agent_id")
    expected = next((entry for entry in bootstrap.MACHINES if entry[1] == expected_agent), None)
    if expected is None or agent != expected_agent or version["manifest"].get("version") != version.get("semantic_version"):
        raise ValueError("release bundle Agent identity does not match the requested public example")
    installations = [item for item in requests if item.get("stage") == "install" and item.get("method") == "POST"]
    deployments = [item for item in requests if item.get("stage") == "deploy" and item.get("method") == "POST"]
    if len(installations) != 1 or len(deployments) != 1:
        raise ValueError("release bundle must contain exactly one installation and deployment request")
    install_body = installations[0].get("body")
    deployment_body = deployments[0].get("body")
    service = {"example-go-operations": "example-go", "example-python-documents": "example-python", "example-java-tickets": "example-java"}[expected_agent]
    if not isinstance(install_body, dict) or not isinstance(deployment_body, dict) or any(install_body.get(key) != expected_value for key, expected_value in {
        "id": expected[2], "tenant_id": bootstrap.BUSINESS_SCOPE["tenant_id"],
        "department_id": bootstrap.BUSINESS_SCOPE["department_id"], "application_id": bootstrap.BUSINESS_SCOPE["application_id"],
        "agent_id": expected_agent, "version_id": version.get("id"), "status": "provisioning", "revision": 1,
    }.items()):
        raise ValueError("Catalog installation request is not the exact isolated public example target")
    if any(deployment_body.get(key) != expected_value for key, expected_value in {
        "tenant_id": bootstrap.BUSINESS_SCOPE["tenant_id"], "department_id": bootstrap.BUSINESS_SCOPE["department_id"],
        "application_id": bootstrap.BUSINESS_SCOPE["application_id"], "agent_installation_id": expected[2],
        "agent_version_id": version.get("id"), "endpoint_ref": "http://" + service + ":8080", "status": "pending",
        "desired_revision": 1, "artifact_digest": version.get("artifact_digest"),
        "manifest_hash": value.get("manifest_hash"),
    }.items()):
        raise ValueError("Catalog deployment request does not match the built isolated example and Compose endpoint")
    return {"bundle": value, "requests": requests, "definition": definition, "version": version,
            "installation": install_body, "deployment": deployment_body,
            "agent_id": expected_agent, "machine": expected}


def owner_human_api(project: str, directory: Path, username: str, scope: dict) -> bootstrap.BrowserAPI:
    _directory, _owner, passwords = read_manifest(project)
    if username not in HUMANS:
        raise ValueError("API stages accept only one of the five independently prepared human identities")
    origin = "http://127.0.0.1:" + str(_owner["ports"]["FRONTEND_HOST_PORT"])
    if not isinstance(scope, dict) or any(not isinstance(key, str) or not isinstance(value, str) or not value
                                          for key, value in scope.items()):
        raise ValueError("owner browser session requires one exact string-valued workspace scope")
    key = (project, username, origin, tuple(sorted(scope.items())))
    session = _OWNER_HUMAN_API_SESSIONS.get(key)
    if session is not None:
        if session.get("invalid") is True:
            raise RuntimeError("cached owner browser session is invalid; stop and establish a fresh session after reviewing authentication")
        api = session["api"]
        expiry = session.get("access_expires_at")
        if isinstance(expiry, (int, float)) and time.time() >= expiry - _SESSION_REFRESH_SKEW_SECONDS:
            # Rotate through the public refresh endpoint only when the browser
            # cookie's recorded expiry proves the access token is expiring.
            # A rejected or ambiguous refresh is never retried or replaced by
            # another password login in this process.
            try:
                refreshed = api.call("POST", "/auth/refresh", {})
                bootstrap.verify_login_identity(refreshed, username, scope)
                session["access_expires_at"] = owner_session_cookie_expiry(api, "lexagent_session")
            except (bootstrap.APIError, RuntimeError, urllib.error.URLError):
                session["invalid"] = True
                raise RuntimeError("cached owner browser session refresh failed; no login or mutation retry was attempted") from None
        try:
            identity = api.call("GET", "/auth/me")
            bootstrap.verify_login_identity(identity, username, scope)
        except bootstrap.APIError as error:
            if error.status == 401:
                session["invalid"] = True
                raise RuntimeError("cached owner browser session is no longer authenticated; no password login was retried") from None
            raise
        except RuntimeError:
            session["invalid"] = True
            raise
        return api

    api = bootstrap.BrowserAPI(origin)
    api.login(username, passwords[username])
    api.select_workspace(scope)
    bootstrap.verify_login_identity(api.call("GET", "/auth/me"), username, scope)
    _OWNER_HUMAN_API_SESSIONS[key] = {"api": api,
                                      "access_expires_at": owner_session_cookie_expiry(api, "lexagent_session"),
                                      "invalid": False}
    return api


def owner_session_cookie_expiry(api: bootstrap.BrowserAPI, cookie_name: str) -> int | None:
    """Read only the in-memory CookieJar expiry; never serialize cookie values."""
    opener = getattr(api, "opener", None)
    handlers = getattr(opener, "handlers", ())
    processor = next((handler for handler in handlers
                      if isinstance(handler, urllib.request.HTTPCookieProcessor)), None)
    jar = getattr(processor, "cookiejar", None)
    if jar is None:
        return None
    matches = [cookie.expires for cookie in jar if cookie.name == cookie_name and cookie.expires is not None]
    return max(matches) if matches else None


def confirm_digest_phrase(phrase: str, confirm=None) -> bool:
    if confirm is not None:
        return bool(confirm(phrase))
    print("Confirmation required: " + phrase)
    return input("Type the exact confirmation: ") == phrase


def iso_utc(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc)
    base = normalized.strftime("%Y-%m-%dT%H:%M:%S")
    fraction = f"{normalized.microsecond:06d}".rstrip("0")
    return base + ("." + fraction if fraction else "") + "Z"


def appoint_permission_admin_phase(project: str, directory: Path, actor: str, confirm_resource: str, confirm=None) -> None:
    if actor != "system.admin" or confirm_resource != "permission.admin":
        raise ValueError("permission administrator appointment requires system.admin and the exact permission.admin target")
    _directory, owner, passwords = read_manifest(project)
    if (not owner.get("identity_complete") or owner.get("permission_admin_appointment") is not None
            or owner.get("permission_admin_appointment_attempt") is not None):
        raise RuntimeError("permission administrator appointment requires a fresh completed Identity stage")
    api = owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE)
    target = bootstrap.profile(api, "permission.admin")
    principal = target.get("principal") if isinstance(target, dict) else None
    if (not isinstance(principal, dict) or principal.get("type") != "user" or principal.get("id") != "permission.admin"
            or principal.get("is_active") is not True or not bootstrap.active_membership(target, "permission.admin", bootstrap.BUSINESS_SCOPE)
            or target.get("role_bindings") != [] or target.get("resource_grants") != []):
        raise RuntimeError("permission.admin must be an active app-demo member with no previous roles or business grants")
    revision = principal.get("revision")
    if type(revision) is not int or revision < 1:
        raise RuntimeError("permission.admin has no current principal CAS revision")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    expiry = now + timedelta(days=7)
    command = {"subject_id": "permission.admin", "expected_revision": revision,
               "idempotency_key": "public-replay-permission-admin-" + project[-12:],
               "reason": "Appoint the isolated permission administrator to issue only separately delegated app-demo grants",
               "role_code": "permission_admin",
               "scope": {"scope_type": "application", **bootstrap.BUSINESS_SCOPE},
               "expires_at": expiry.isoformat().replace("+00:00", "Z")}
    preview = api.call("POST", "/api/modules/identity/administrators:preview", command)
    if (not isinstance(preview, dict) or not re.fullmatch(r"[a-f0-9]{64}", str(preview.get("request_digest", "")))
            or preview.get("step_up_action") != "administrator.appoint" or preview.get("change") != command):
        raise RuntimeError("administrator appointment preview differs from the exact expiring app-demo role")
    phrase = project + " appoint permission.admin " + preview["request_digest"]
    print(json.dumps({"phase": "permission_admin_appointment_preview", "project": project,
                      "subject": "permission.admin", "role": "permission_admin", "scope": "app-demo",
                      "expires_at": command["expires_at"], "resource_grants": [],
                      "request_digest": preview["request_digest"], "confirmation": phrase,
                      "password_or_step_up_token_printed": False}, ensure_ascii=False))
    if not confirm_digest_phrase(phrase, confirm):
        raise RuntimeError("permission administrator appointment was not confirmed")
    proof = api.call("POST", "/api/modules/identity/step-up", {
        "current_password": passwords["system.admin"], "action": "administrator.appoint",
        "request_digest": preview["request_digest"],
    })
    token = proof.get("step_up_token") if isinstance(proof, dict) else None
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        raise RuntimeError("fresh action-bound administrator.appoint authentication did not verify")
    appointment_key = hashlib.sha256(("administrator.appoint\x00" + actor + "\x00" + command["idempotency_key"]).encode("utf-8")).hexdigest()
    owner["permission_admin_appointment_attempt"] = {
        "status": "commit_started", "request_digest": preview["request_digest"],
        "idempotency_hash": appointment_key, "expected_revision": revision,
        "subject_id": "permission.admin", "role_code": "permission_admin",
        "scope": command["scope"], "expires_at": command["expires_at"],
    }
    write_json_private(directory / "owner.json", owner)
    receipt = api.call("POST", "/api/modules/identity/administrators:appoint", dict(preview["change"], step_up_token=token))
    binding = receipt.get("role_binding") if isinstance(receipt, dict) else None
    if (not isinstance(receipt, dict) or receipt.get("actor_id") != actor or receipt.get("subject_id") != "permission.admin"
            or receipt.get("request_digest") != preview["request_digest"] or not isinstance(binding, dict)
            or binding.get("role_code") != "permission_admin" or binding.get("role_version") != 1
            or binding.get("scope") != command["scope"] or binding.get("status") != "active"
            or binding.get("expires_at") != command["expires_at"]):
        raise RuntimeError("administrator appointment receipt does not match the reviewed role, scope and expiry")
    after = bootstrap.profile(api, "permission.admin")
    after_principal = after.get("principal") if isinstance(after, dict) else None
    rows = after.get("role_bindings") if isinstance(after, dict) else None
    matches = [row for row in rows if isinstance(row, dict) and row.get("id") == binding.get("id")] if isinstance(rows, list) else []
    if (not isinstance(after_principal, dict) or after_principal.get("revision") != revision + 1
            or after.get("resource_grants") != [] or len(matches) != 1 or matches[0] != binding
            or not bootstrap.active_membership(after, "permission.admin", bootstrap.BUSINESS_SCOPE)):
        raise RuntimeError("permission administrator appointment failed exact profile readback")
    owner["permission_admin_appointment"] = {"binding_id": binding["id"], "request_digest": preview["request_digest"],
                                              "expires_at": binding["expires_at"], "revision": revision + 1,
                                              "role": "permission_admin", "scope": command["scope"]}
    owner["permission_admin_appointment_attempt"].update({"status": "verified", "receipt_id": receipt["id"],
                                                          "revision": receipt["revision"]})
    write_json_private(directory / "owner.json", owner)
    print(json.dumps({"result": "permission_admin_appointed_without_business_grants", "project": project,
                      "subject": "permission.admin", "role": "permission_admin", "scope": "app-demo",
                      "binding_id": binding["id"], "expires_at": binding["expires_at"],
                      "resource_grants": [], "step_up_token_printed": False}, ensure_ascii=False))


def verify_owner_frontend(project: str, directory: Path, owner: dict) -> None:
    """Prove that the only API origin belongs to this replay's loopback Compose frontend."""
    port = owner.get("ports", {}).get("FRONTEND_HOST_PORT")
    suffix = project.removeprefix("agentplug-test-public-")
    expected_image = f"agentplug:test-frontend-{suffix}"
    if type(port) is not int or not 1 <= port <= 65535 or expected_image not in owner.get("images", []):
        raise RuntimeError("owner manifest lacks its exact prepared frontend image/loopback port")
    listed = subprocess.run(compose_prefix(project, directory) + ["ps", "--format", "json", "frontend"],
                            cwd=ROOT, capture_output=True, timeout=30,
                            env=isolated_compose_environment(directory))
    if listed.returncode:
        raise RuntimeError("owner Compose frontend could not be enumerated")
    try:
        raw = listed.stdout.decode("utf-8", errors="strict").strip()
        if raw.startswith("["):
            rows = json.loads(raw)
        else:
            rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    except (UnicodeError, ValueError):
        raise RuntimeError("owner Compose frontend listing was not valid JSON") from None
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise RuntimeError("exactly one frontend container must belong to this Compose project")
    container_id = rows[0].get("ID") or rows[0].get("Id")
    if not isinstance(container_id, str) or not re.fullmatch(r"[a-f0-9]{12,64}", container_id):
        raise RuntimeError("Compose frontend container identity is invalid")
    inspected = subprocess.run(["docker", "inspect", container_id], cwd=ROOT, capture_output=True, timeout=30)
    if inspected.returncode:
        raise RuntimeError("owner frontend container metadata could not be inspected")
    try:
        values = json.loads(inspected.stdout)
    except (UnicodeError, ValueError):
        raise RuntimeError("owner frontend inspect response was not valid JSON") from None
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise RuntimeError("owner frontend inspect did not resolve exactly one container")
    container = values[0]
    labels = container.get("Config", {}).get("Labels", {})
    ports = container.get("NetworkSettings", {}).get("Ports", {}).get("80/tcp")
    bindings = ports if isinstance(ports, list) else []
    if (container.get("Id", "").startswith(container_id) is False
            or container.get("Config", {}).get("Image") != expected_image
            or labels.get("com.docker.compose.project") != project
            or labels.get("com.docker.compose.service") != "frontend"
            or container.get("State", {}).get("Status") != "running"
            or not any(row.get("HostIp") == "127.0.0.1" and row.get("HostPort") == str(port)
                       for row in bindings if isinstance(row, dict))):
        raise RuntimeError("frontend does not match the owner project, isolated image, running state and loopback-only port binding")


def private_plan_file(project: str, directory: Path, path: Path, schema: str) -> tuple[dict, str]:
    candidate = path if path.is_absolute() else directory / path
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(directory.resolve(strict=True))
    except (OSError, ValueError):
        raise ValueError("plan must be an owner-private file inside this exact replay directory") from None
    current = directory.resolve()
    while current != resolved.parent:
        if bootstrap.is_reparse_point(current):
            raise ValueError("plan path may not traverse a symlink, junction or reparse point")
        current = current.parent
    if bootstrap.is_reparse_point(resolved):
        raise ValueError("plan must be a regular owner-private file")
    bootstrap.verify_private_file(resolved)
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ValueError("owner-private plan is invalid JSON") from None
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise ValueError("owner-private plan schema does not match this isolated replay stage")
    return value, resolved.relative_to(directory.resolve()).as_posix()


def load_authorization_plan(project: str, directory: Path, path: Path) -> tuple[dict, str]:
    plan, relative = private_plan_file(project, directory, path, "public-example-authorization/v1")
    reviewed = example_authorization.validate_plan(plan, project, bootstrap.BUSINESS_SCOPE)
    _current_directory, owner, _passwords = read_manifest(project)
    pin = owner.get("authorization_plan")
    if (not isinstance(pin, dict) or pin.get("path") != relative
            or pin.get("plan_sha256") != hashlib.sha256(example_authorization.canonical(reviewed)).hexdigest()):
        raise ValueError("authorization plan must be the exact owner-pinned plan produced by authorization-plan-prepare")
    expected_subjects = set(example_authorization.SUBJECTS)
    if {item["subject_id"] for item in reviewed["changes"]} != expected_subjects:
        raise ValueError("clean replay authorization must explicitly cover all three demo users and all three matching machines")
    if set(reviewed["allowed_resources"]) != set(example_authorization.INSTALLATIONS):
        raise ValueError("authorization plan must separately enumerate the three exact public example installations")
    for change in reviewed["changes"]:
        for grant in change["resource_grants"]:
            if not grant.get("expires_at"):
                raise ValueError("every reviewed business grant needs an explicit short expiry so permission.admin can receive bounded temporary delegation")
            starts = example_authorization.timestamp(grant["starts_at"]) if grant.get("starts_at") else datetime.now(timezone.utc)
            expiry = example_authorization.timestamp(grant["expires_at"])
            now = datetime.now(timezone.utc)
            if expiry > now + timedelta(hours=24) or starts > now + timedelta(hours=24):
                raise ValueError("tutorial grants and their delegations are limited to a maximum 24-hour window")
    return reviewed, relative


def remember_release_plan(project: str, directory: Path, plan: dict, source_path: Path) -> None:
    candidate = source_path if source_path.is_absolute() else directory / source_path
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(directory.resolve(strict=True))
    relative = resolved.relative_to(directory.resolve()).as_posix()
    bootstrap.verify_private_file(resolved)
    _directory, owner, _passwords = read_manifest(project)
    plans = owner.setdefault("release_plans", {})
    agent_id = plan["agent_id"]
    record = {"path": relative, "manifest_hash": plan["bundle"]["manifest_hash"],
              "version_id": plan["version"]["id"], "installation_id": plan["installation"]["id"]}
    previous = plans.get(agent_id)
    if previous is not None and previous != record:
        raise RuntimeError("this replay Agent already has a different private release plan pin")
    plans[agent_id] = record
    write_json_private(directory / "owner.json", owner)


def require_permission_admin_appointment(profile: dict, owner: dict) -> dict:
    receipt = owner.get("permission_admin_appointment")
    principal = profile.get("principal") if isinstance(profile, dict) else None
    if (not isinstance(receipt, dict) or receipt.get("role") != "permission_admin"
            or receipt.get("scope") != {"scope_type": "application", **bootstrap.BUSINESS_SCOPE}
            or not isinstance(principal, dict) or principal.get("id") != "permission.admin"
            or principal.get("type") != "user" or principal.get("is_active") is not True
            or not bootstrap.active_membership(profile, "permission.admin", bootstrap.BUSINESS_SCOPE)):
        raise RuntimeError("permission.admin appointment and exact active app-demo membership must be recorded before delegated grants")
    rows = profile.get("role_bindings")
    matches = [row for row in rows if isinstance(row, dict) and row.get("id") == receipt.get("binding_id")] if isinstance(rows, list) else []
    expected_key = hashlib.sha256(("administrator.appoint\x00system.admin\x00public-replay-permission-admin-"
                                   + str(owner.get("owner", ""))[-12:]).encode("utf-8")).hexdigest()
    if (len(matches) != 1 or matches[0].get("subject_id") != "permission.admin"
            or matches[0].get("role_code") != "permission_admin" or matches[0].get("status") != "active"
            or matches[0].get("scope") != receipt["scope"] or matches[0].get("expires_at") != receipt.get("expires_at")
            or matches[0].get("id") != "administrator-" + expected_key
            or matches[0].get("source_id") != "appointment-" + expected_key
            or profile.get("resource_grants") != []):
        raise RuntimeError("permission.admin profile no longer matches its narrow appointment without business grants")
    return matches[0]


def permission_admin_appointment_key(project: str) -> tuple[str, str, str]:
    idempotency_key = "public-replay-permission-admin-" + project_name(project)[-12:]
    key = hashlib.sha256(("administrator.appoint\x00system.admin\x00" + idempotency_key).encode("utf-8")).hexdigest()
    return idempotency_key, key, "administrator-" + key


def validate_persisted_permission_admin_appointment(project: str, persisted: dict,
                                                    profile: dict, now: datetime | None = None) -> dict:
    """Validate the durable idempotency receipt against the exact live profile."""
    now = now or datetime.now(timezone.utc)
    idempotency_key, key, binding_id = permission_admin_appointment_key(project)
    receipt = persisted.get("receipt") if isinstance(persisted, dict) else None
    command = receipt.get("change") if isinstance(receipt, dict) else None
    binding = receipt.get("role_binding") if isinstance(receipt, dict) else None
    expected_scope = {"scope_type": "application", **bootstrap.BUSINESS_SCOPE}
    if not isinstance(receipt, dict) or not isinstance(command, dict) or not isinstance(binding, dict):
        raise RuntimeError("persisted permission-admin receipt is incomplete")
    expected_command = {
        "subject_id": "permission.admin", "expected_revision": command.get("expected_revision"),
        "idempotency_key": idempotency_key,
        "reason": "Appoint the isolated permission administrator to issue only separately delegated app-demo grants",
        "role_code": "permission_admin", "scope": expected_scope,
        "expires_at": command.get("expires_at"),
    }
    encoded_command = json.dumps(expected_command, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    expected_digest = hashlib.sha256(encoded_command).hexdigest()
    principal = profile.get("principal") if isinstance(profile, dict) else None
    rows = profile.get("role_bindings") if isinstance(profile, dict) else None
    matches = [row for row in rows if isinstance(row, dict) and row.get("id") == binding_id] if isinstance(rows, list) else []
    if (persisted.get("id") != "appointment-" + key or persisted.get("actor_id") != "system.admin"
            or persisted.get("subject_id") != "permission.admin" or persisted.get("idempotency_hash") != key
            or receipt.get("id") != persisted.get("id") or receipt.get("actor_id") != "system.admin"
            or receipt.get("subject_id") != "permission.admin" or receipt.get("action") != "administrator.appoint"
            or receipt.get("request_digest") != persisted.get("request_digest")
            or persisted.get("request_digest") != expected_digest
            or command != expected_command
            or type(receipt.get("revision")) is not int or receipt.get("revision") != command.get("expected_revision", 0) + 1
            or not isinstance(principal, dict) or principal.get("id") != "permission.admin"
            or principal.get("type") != "user" or principal.get("is_active") is not True
            or receipt.get("revision") != principal.get("revision")
            or not bootstrap.active_membership(profile, "permission.admin", bootstrap.BUSINESS_SCOPE)
            or len(rows) != 1 or len(matches) != 1 or matches[0] != binding
            or binding.get("id") != binding_id or binding.get("source_id") != "appointment-" + key
            or binding.get("subject_id") != "permission.admin" or binding.get("role_code") != "permission_admin"
            or binding.get("role_version") != 1 or binding.get("scope") != expected_scope
            or binding.get("status") != "active" or binding.get("revision") != 1
            or binding.get("expires_at") != command.get("expires_at")
            or profile.get("resource_grants") != [] or profile.get("delegations") != []
            or profile.get("task_assignments") != []):
        raise RuntimeError("persisted permission-admin idempotency receipt differs from its exact owner profile")
    expiry = example_authorization.timestamp(binding["expires_at"])
    if expiry <= now or expiry > now + timedelta(days=7, minutes=15):
        raise RuntimeError("permission-admin appointment is expired or exceeds its seven-day validity")
    starts = binding.get("starts_at")
    if starts is not None and example_authorization.timestamp(starts) > now + timedelta(minutes=2):
        raise RuntimeError("permission-admin appointment has a future start time")
    return {"binding_id": binding_id, "request_digest": expected_digest,
            "expires_at": binding["expires_at"], "revision": receipt["revision"],
            "role": "permission_admin", "scope": expected_scope,
            "receipt_id": receipt["id"], "idempotency_hash": key,
            "reconciled_from_persisted_receipt": True}


def reconcile_permission_admin_appointment(project: str, directory: Path, persisted: dict) -> dict:
    """Recover an already committed appointment only from its exact server receipt and live profile."""
    _directory, owner, _passwords = read_manifest(project)
    if (owner.get("permission_admin_appointment") is not None
            or owner.get("permission_admin_delegations") not in (None, [])
            or owner.get("authorization_attempt") is not None):
        raise RuntimeError("appointment receipt cannot be reconstructed after a later IAM operation has started")
    verify_owner_frontend(project, directory, owner)
    api = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    profile = bootstrap.profile(api, "permission.admin")
    appointment = validate_persisted_permission_admin_appointment(project, persisted, profile)
    _current_directory, current_owner, _current_passwords = read_manifest(project)
    if (current_owner.get("permission_admin_appointment") is not None
            or current_owner.get("permission_admin_delegations") not in (None, [])
            or current_owner.get("authorization_attempt") is not None):
        raise RuntimeError("owner IAM journal changed during appointment reconciliation")
    current_owner["permission_admin_appointment"] = appointment
    current_owner["permission_admin_appointment_attempt"] = {
        "status": "reconciled", "request_digest": appointment["request_digest"],
        "idempotency_hash": appointment["idempotency_hash"], "expected_revision": appointment["revision"] - 1,
        "subject_id": "permission.admin", "role_code": "permission_admin", "scope": appointment["scope"],
        "expires_at": appointment["expires_at"], "receipt_id": appointment["receipt_id"],
        "revision": appointment["revision"],
        "reconciliation_basis": "read-only persisted idempotency receipt matched the exact live Identity profile",
    }
    write_json_private(directory / "owner.json", current_owner)
    return appointment


def delegation_command(project: str, ordinal: int, grant: dict, actor_profile: dict) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    starts = example_authorization.timestamp(grant["starts_at"]) if grant.get("starts_at") else now
    expiry = example_authorization.timestamp(grant["expires_at"])
    effective_start = max(now, starts)
    seconds = math.ceil((expiry - effective_start).total_seconds())
    if seconds < 1 or seconds > 24 * 60 * 60:
        raise ValueError("grant expiry cannot be represented as a short bounded permission delegation")
    starts_at = starts if starts > now else now
    delegation = {
        "id": "replay-delegation-" + project.removeprefix("agentplug-test-public-") + "-" + str(ordinal).zfill(3),
        "subject_id": "permission.admin",
        "scope": {"scope_type": "application", **bootstrap.BUSINESS_SCOPE},
        "roles": [], "actions": [grant["action"]], "resources": [],
        "data_scope_types": [grant["data_scope"]["type"]],
        "management_actions": ["authorization.change"],
        "max_duration_seconds": seconds, "allow_permanent": False,
        "starts_at": iso_utc(starts_at),
        "expires_at": iso_utc(expiry),
        "status": "active", "revision": 1,
    }
    if grant["resource_type"] == "agent_installation":
        # Identity maps installation Grants to their app scope; Delegation.Covers
        # therefore checks these exact IDs through Resources. Typed capability
        # grants use the installation-specific ResourceBindings below.
        if grant["resource_id"] != grant["agent_instance_id"]:
            raise ValueError("agent-installation Grant must target its own installation ID")
        delegation["resources"] = [grant["resource_id"]]
    else:
        delegation["resource_bindings"] = [{"resource_type": grant["resource_type"],
                                             "resource_id": grant["resource_id"],
                                             "installation_id": grant["agent_instance_id"]}]
    ids = grant["data_scope"].get("ids", [])
    if ids:
        delegation["data_ids"] = list(ids)
    principal = actor_profile.get("principal") if isinstance(actor_profile, dict) else None
    revision = principal.get("revision") if isinstance(principal, dict) else None
    if type(revision) is not int or revision < 1:
        raise RuntimeError("permission.admin principal has no live CAS revision")
    return {"subject_id": "permission.admin", "expected_revision": revision,
            "idempotency_key": "replay-delegation-" + project[-12:] + "-" + str(ordinal).zfill(3),
            "reason": "Issue only this reviewed short-lived public example resource/action/data-scope grant",
            "delegation": delegation}


def assert_delegation_preview(preview: dict, command: dict) -> str:
    digest = preview.get("request_digest") if isinstance(preview, dict) else None
    if (not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)
            or preview.get("step_up_action") != "delegation.manage"
            or preview.get("change") != command or preview.get("delegation") != command["delegation"]):
        raise RuntimeError("delegation preview differs from the one exact application/resource/action/data-scope window")
    return digest


def verified_delegation_prefix(project: str, plan: dict, owner: dict, profile: dict,
                               now: datetime | None = None) -> tuple[int, list[dict]]:
    """Validate a contiguous, fully read-back delegation prefix before resuming."""
    now = now or datetime.now(timezone.utc)
    pin = owner.get("authorization_plan")
    plan_digest = hashlib.sha256(example_authorization.canonical(plan)).hexdigest()
    if (not isinstance(pin, dict) or pin.get("plan_sha256") != plan_digest
            or not isinstance(pin.get("path"), str) or not pin["path"]
            or owner.get("authorization_attempt") is not None
            or owner.get("authorization_journal") not in (None, [])
            or owner.get("permission_admin_delegation_replacement_attempt") is not None
            or owner.get("superseded_permission_admin_delegations") not in (None, [])):
        raise RuntimeError("delegation resume requires the same pinned plan and no other or unresolved IAM write")

    changes = plan.get("changes") if isinstance(plan, dict) else None
    grants = [(change.get("subject_id"), grant)
              for change in changes if isinstance(change, dict)
              for grant in change.get("resource_grants", []) if isinstance(grant, dict)] if isinstance(changes, list) else []
    if len(grants) != 57 or len({grant.get("id") for _, grant in grants}) != 57:
        raise RuntimeError("delegation resume plan must contain the exact 57 unique minimum grants")
    grant_starts = {grant.get("starts_at") for _, grant in grants}
    grant_expiries = {grant.get("expires_at") for _, grant in grants}
    if len(grant_starts) != 1 or len(grant_expiries) != 1:
        raise RuntimeError("delegation resume plan validity must be shared across all 57 grants")
    try:
        plan_start = example_authorization.timestamp(next(iter(grant_starts)))
        plan_expiry = example_authorization.timestamp(next(iter(grant_expiries)))
    except (TypeError, ValueError):
        raise RuntimeError("delegation resume plan validity is malformed") from None
    if (plan_start > now + timedelta(minutes=2) or plan_expiry <= now
            or plan_expiry <= plan_start or plan_expiry > now + timedelta(hours=24)):
        raise RuntimeError("delegation resume plan is expired or exceeds its bounded validity window")

    raw_journal = owner.get("permission_admin_delegations", [])
    if raw_journal is None:
        raw_journal = []
    if not isinstance(raw_journal, list) or len(raw_journal) > len(grants):
        raise RuntimeError("delegation owner journal is malformed or longer than the exact plan")
    journal = raw_journal
    appointment = owner.get("permission_admin_appointment")
    appointment_revision = appointment.get("revision") if isinstance(appointment, dict) else None
    if type(appointment_revision) is not int or appointment_revision < 1:
        raise RuntimeError("delegation resume has no exact permission.admin appointment revision")
    require_permission_admin_appointment(profile, owner)
    principal = profile.get("principal") if isinstance(profile, dict) else None
    role_bindings = profile.get("role_bindings") if isinstance(profile, dict) else None
    live_rows = profile.get("delegations") if isinstance(profile, dict) else None
    if (not isinstance(principal, dict) or principal.get("revision") != appointment_revision + len(journal)
            or profile.get("resource_grants") != [] or profile.get("task_assignments") != []
            or not isinstance(role_bindings, list) or len(role_bindings) != 1
            or not isinstance(live_rows, list) or len(live_rows) != len(journal)):
        raise RuntimeError("permission.admin live profile is not the exact appointment-plus-prefix state")

    receipts: list[dict] = []
    seen_ids: set[str] = set()
    live_by_id: dict[str, dict] = {}
    for row in live_rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or row["id"] in live_by_id:
            raise RuntimeError("permission.admin live Delegation list is malformed or contains duplicate IDs")
        live_by_id[row["id"]] = row

    project_suffix = project.removeprefix("agentplug-test-public-")
    expected_scope = {"scope_type": "application", **bootstrap.BUSINESS_SCOPE}
    for index, (subject, grant) in enumerate(grants[:len(journal)], start=1):
        row = journal[index - 1]
        delegation_id = "replay-delegation-" + project_suffix + "-" + str(index).zfill(3)
        grant_digest = hashlib.sha256(example_authorization.canonical(
            {"subject": subject, "grant": grant})).hexdigest()
        expected_row_keys = {"grant_id", "subject_id", "delegation_id", "request_digest",
                             "expected_revision", "expires_at", "plan_digest", "grant_digest",
                             "delegation", "status", "revision"}
        delegation = row.get("delegation") if isinstance(row, dict) else None
        expected_delegation_keys = {"id", "subject_id", "scope", "roles", "actions", "resources",
                                    "data_scope_types", "management_actions", "max_duration_seconds",
                                    "allow_permanent", "starts_at", "expires_at", "status", "revision"}
        if grant.get("resource_type") != "agent_installation":
            expected_delegation_keys.add("resource_bindings")
        if grant.get("data_scope", {}).get("ids"):
            expected_delegation_keys.add("data_ids")
        try:
            start = example_authorization.timestamp(delegation.get("starts_at"))
            expiry = example_authorization.timestamp(delegation.get("expires_at"))
        except (AttributeError, TypeError, ValueError):
            raise RuntimeError("verified delegation prefix contains an invalid time boundary") from None
        expected_binding = [{"resource_type": grant["resource_type"],
                             "resource_id": grant["resource_id"],
                             "installation_id": grant["agent_instance_id"]}]
        expected_resources = [grant["resource_id"]] if grant["resource_type"] == "agent_installation" else []
        expected_duration = math.ceil((expiry - start).total_seconds())
        request_digest = row.get("request_digest") if isinstance(row, dict) else None
        expected_revision = appointment_revision + index - 1
        if (not isinstance(row, dict) or set(row) != expected_row_keys
                or row.get("grant_id") != grant.get("id") or row.get("subject_id") != subject
                or row.get("delegation_id") != delegation_id
                or not isinstance(request_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", request_digest)
                or request_digest in seen_ids
                or row.get("expected_revision") != expected_revision or row.get("revision") != expected_revision + 1
                or row.get("expires_at") != grant.get("expires_at") or row.get("plan_digest") != plan_digest
                or row.get("grant_digest") != grant_digest or row.get("status") != "verified"
                or not isinstance(delegation, dict) or set(delegation) != expected_delegation_keys
                or delegation.get("id") != delegation_id or delegation.get("subject_id") != "permission.admin"
                or delegation.get("scope") != expected_scope or delegation.get("roles") != []
                or delegation.get("actions") != [grant.get("action")]
                or delegation.get("resources") != expected_resources
                or (grant["resource_type"] != "agent_installation"
                    and delegation.get("resource_bindings") != expected_binding)
                or delegation.get("data_scope_types") != [grant.get("data_scope", {}).get("type")]
                or delegation.get("data_ids", []) != grant.get("data_scope", {}).get("ids", [])
                or delegation.get("management_actions") != ["authorization.change"]
                or type(delegation.get("max_duration_seconds")) is not int
                or delegation.get("max_duration_seconds") != expected_duration
                or not 1 <= expected_duration <= 24 * 60 * 60
                or delegation.get("allow_permanent") is not False
                or delegation.get("status") != "active" or delegation.get("revision") != 1
                or example_authorization.timestamp(grant["expires_at"]) != expiry
                or start < example_authorization.timestamp(grant["starts_at"])
                or start > now + timedelta(minutes=2) or expiry != plan_expiry):
            raise RuntimeError("delegation owner journal is not an exact contiguous verified prefix of the pinned plan")
        live = live_by_id.get(delegation_id)
        if live != delegation:
            raise RuntimeError("live permission.admin Delegations differ from the exact verified owner prefix")
        seen_ids.add(request_digest)
        receipts.append({"grant_id": grant["id"], "subject_id": subject,
                         "delegation_id": delegation_id, "request_digest": request_digest,
                         "revision": expected_revision + 1, "expires_at": grant["expires_at"]})
    if set(live_by_id) != {row["delegation_id"] for row in receipts}:
        raise RuntimeError("live permission.admin profile contains a Delegation outside the verified plan prefix")
    return len(journal), receipts


def assert_delegation_revoke_preview(preview: dict, command: dict, current: dict) -> str:
    digest = preview.get("request_digest") if isinstance(preview, dict) else None
    if (not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)
            or preview.get("step_up_action") != "delegation.manage"
            or preview.get("change") != command or preview.get("delegation") != current):
        raise RuntimeError("delegation revoke preview differs from the exact active installation grant")
    return digest


def expected_replacement_delegation(project: str, ordinal: int, grant: dict,
                                    old: dict) -> dict:
    """Preserve every existing boundary while fixing only the installation target encoding."""
    if grant.get("resource_type") != "agent_installation" or grant.get("resource_id") != grant.get("agent_instance_id"):
        raise ValueError("only a grant for the subject's own installation can be rebound")
    replacement = deepcopy(old)
    replacement["id"] = ("replay-delegation-" + project.removeprefix("agentplug-test-public-")
                         + "-r2-" + str(ordinal).zfill(3))
    replacement["resources"] = [grant["resource_id"]]
    # The platform Delegation DTO marks resource_bindings as omitempty. Keep
    # the empty installation binding absent so preview/receipt echo matches
    # the canonical server JSON while Resources carries the exact own ID.
    replacement.pop("resource_bindings", None)
    return replacement


def validate_previous_installation_delegation(project: str, ordinal: int, subject: str,
                                              grant: dict, row: dict, plan_digest: str) -> dict:
    old = row.get("delegation") if isinstance(row, dict) else None
    expected_id = ("replay-delegation-" + project.removeprefix("agentplug-test-public-")
                   + "-" + str(ordinal).zfill(3))
    binding = {"resource_type": "agent_installation", "resource_id": grant["resource_id"],
               "installation_id": grant["agent_instance_id"]}
    expected_scope = {"scope_type": "application", **bootstrap.BUSINESS_SCOPE}
    expiry = example_authorization.timestamp(grant["expires_at"])
    if (not isinstance(row, dict) or row.get("status") != "verified"
            or row.get("subject_id") != subject or row.get("delegation_id") != expected_id
            or row.get("plan_digest") != plan_digest
            or row.get("grant_digest") != hashlib.sha256(example_authorization.canonical(
                {"subject": subject, "grant": grant})).hexdigest()
            or not isinstance(old, dict) or old.get("id") != expected_id
            or old.get("subject_id") != "permission.admin" or old.get("scope") != expected_scope
            or old.get("roles") != [] or old.get("actions") != [grant["action"]]
            or old.get("resources") != [] or old.get("resource_bindings") != [binding]
            or old.get("data_scope_types") != [grant["data_scope"]["type"]]
            or old.get("data_ids", []) != grant["data_scope"].get("ids", [])
            or old.get("management_actions") != ["authorization.change"]
            or type(old.get("max_duration_seconds")) is not int
            or not 1 <= old["max_duration_seconds"] <= 24 * 60 * 60
            or old.get("allow_permanent") is not False
            or old.get("status") != "active" or old.get("revision") != 1
            or example_authorization.timestamp(old.get("expires_at")) != expiry
            or example_authorization.timestamp(old.get("starts_at")) >= expiry):
        raise RuntimeError("historical installation delegation is not the exact bounded pre-fix tuple")
    return old


def rebind_installation_delegations(project: str, directory: Path, plan: dict,
                                    confirm=None) -> list[dict]:
    """Replace only the 15 known mis-shaped own-installation Delegations through normal APIs."""
    _directory, owner, passwords = read_manifest(project)
    denied = owner.get("authorization_attempt")
    if (not owner.get("identity_complete") or not owner.get("services_ready")
            or not owner.get("machines_complete") or not owner.get("business_roles_complete")
            or owner.get("authorization_complete") is True
            or owner.get("permission_admin_appointment") is None
            or not isinstance(denied, dict) or denied.get("status") != "preview_denied"
            or denied.get("last_failure", {}).get("grant_commit_attempted") is not False
            or owner.get("authorization_journal") not in (None, [])):
        raise RuntimeError("delegation repair requires the known Grant-preview denial and no Grant commit")
    replacement_attempt = owner.get("permission_admin_delegation_replacement_attempt")
    superseded = owner.get("superseded_permission_admin_delegations")
    if (replacement_attempt is None) != (superseded is None):
        raise RuntimeError("delegation replacement has a partial owner pin; inspect it read-only")
    if replacement_attempt is not None and (
            not isinstance(replacement_attempt, dict) or replacement_attempt.get("status") != "in_progress"):
        raise RuntimeError("delegation replacement already completed or has an ambiguous write; inspect it read-only")
    verify_owner_frontend(project, directory, owner)
    verify_example_container_health(project, directory)
    manager = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    bootstrap.verify_login_identity(manager.call("GET", "/auth/me"), "system.admin", bootstrap.BUSINESS_SCOPE)
    installations = verify_catalog_installation_readiness(manager)
    catalog_pins = owner.get("catalog_lifecycle", {})
    for item in installations:
        agent_id = next(row[1] for row in bootstrap.MACHINES if row[0] == item["machine_id"])
        release = catalog_pins.get(agent_id, {}).get("release", {})
        if release.get("version_id") != item["agent_version_id"] or release.get("installation_id") != item["installation_id"]:
            raise RuntimeError("active Catalog installation differs from the owner-pinned public release version")
    release_plans = load_pinned_release_plans(project, directory, owner)
    policies = {agent_id: live_policy_inventory(manager, project, directory, owner, release)
                for agent_id, release in release_plans.items()}
    verify_plan_allowlist(plan, policies)
    verify_business_role_profiles(manager, owner, project)
    expected_plan = expected_minimum_authorization_plan(project, policies, plan)
    plan = example_authorization.validate_plan(plan, project, bootstrap.BUSINESS_SCOPE)
    assert_minimum_authorization_plan(plan, expected_plan)
    plan_digest = hashlib.sha256(example_authorization.canonical(plan)).hexdigest()
    old_journal = superseded if isinstance(superseded, list) else owner.get("permission_admin_delegations")
    ordered = [(change["subject_id"], grant) for change in plan["changes"]
               for grant in change["resource_grants"]]
    if (not isinstance(old_journal, list) or len(old_journal) != 57
            or len(ordered) != 57 or sum(1 for _, grant in ordered
                                         if grant["resource_type"] == "agent_installation") != 15):
        raise RuntimeError("repair requires the exact historical 57-Delegation owner plan")
    rows_by_grant = {row.get("grant_id"): row for row in old_journal if isinstance(row, dict)}
    if len(rows_by_grant) != 57 or set(rows_by_grant) != {grant["id"] for _, grant in ordered}:
        raise RuntimeError("historical Delegation receipts do not cover the exact pinned 57 grants")
    prior_items = replacement_attempt.get("items") if isinstance(replacement_attempt, dict) else None
    if replacement_attempt is not None:
        if (replacement_attempt.get("plan_digest") != plan_digest or not isinstance(prior_items, list)
                or len(prior_items) != 15
                or example_authorization.canonical(owner.get("permission_admin_delegations"))
                != example_authorization.canonical(superseded)):
            raise RuntimeError("durable replacement intent differs from the original 57-receipt snapshot")
    prior_by_ordinal = {row.get("ordinal"): row for row in prior_items or [] if isinstance(row, dict)}
    if replacement_attempt is not None and len(prior_by_ordinal) != 15:
        raise RuntimeError("replacement intent has duplicate or malformed tuple ordinals")
    completed_before = sum(1 for row in prior_by_ordinal.values() if row.get("status") == "verified")
    revoked_waiting = sum(1 for row in prior_by_ordinal.values() if row.get("status") == "revoked_verified")
    if any(row.get("status") not in {"planned", "revoked_verified", "verified"}
           for row in prior_by_ordinal.values()):
        raise RuntimeError("replacement attempt contains an ambiguous write state; reconcile read-only")
    identity = owner_human_api(project, directory, "permission.admin", bootstrap.BUSINESS_SCOPE)
    current = bootstrap.profile(identity, "permission.admin")
    require_permission_admin_appointment(current, owner)
    expected_live_count = 57 + completed_before
    expected_active_count = 57 - revoked_waiting
    if (current.get("resource_grants") != [] or current.get("task_assignments") != []
            or not isinstance(current.get("delegations"), list)
            or len(current["delegations"]) != expected_live_count
            or sum(1 for row in current["delegations"] if isinstance(row, dict) and row.get("status") == "active") != expected_active_count):
        raise RuntimeError("permission.admin live profile differs from the exact persisted replacement progress")
    live_by_id = {row.get("id"): row for row in current["delegations"] if isinstance(row, dict)}
    if len(live_by_id) != expected_live_count:
        raise RuntimeError("permission.admin has duplicate or malformed live Delegation IDs")

    planned = []
    install_ordinals = []
    for ordinal, (subject, grant) in enumerate(ordered, start=1):
        row = rows_by_grant[grant["id"]]
        if grant["resource_type"] == "agent_installation":
            old = validate_previous_installation_delegation(project, ordinal, subject, grant, row, plan_digest)
            replacement = expected_replacement_delegation(project, ordinal, grant, old)
            if example_authorization.timestamp(replacement["expires_at"]) <= datetime.now(timezone.utc):
                raise RuntimeError("existing Delegation expiry passed; repair cannot extend its validity")
            prior = prior_by_ordinal.get(ordinal)
            prior_status = prior.get("status") if isinstance(prior, dict) else "planned"
            if (isinstance(prior, dict) and (prior.get("subject_id") != subject
                    or prior.get("grant_id") != grant["id"] or prior.get("old_delegation_id") != old["id"]
                    or prior.get("new_delegation_id") != replacement["id"])):
                raise RuntimeError("replacement item pin differs from this exact subject/grant tuple")
            if prior_status == "planned":
                if live_by_id.get(old["id"]) != old:
                    raise RuntimeError("unstarted installation Delegation is not the exact active historical receipt")
                if isinstance(prior, dict) and any(prior.get(key) is not None for key in ("revoke_intent", "create_intent")):
                    raise RuntimeError("planned replacement item contains an unexplained prior write intent")
            elif prior_status == "revoked_verified":
                revoked = deepcopy(old)
                revoked["status"], revoked["revision"] = "revoked", 2
                if (live_by_id.get(old["id"]) != revoked
                        or (prior.get("revoke_intent") or {}).get("status") != "verified"
                        or prior.get("create_intent") is not None):
                    raise RuntimeError("only a precisely read-back revoke with no create intent may resume")
            elif prior_status == "verified":
                revoked = deepcopy(old)
                revoked["status"], revoked["revision"] = "revoked", 2
                if (live_by_id.get(old["id"]) != revoked or live_by_id.get(replacement["id"]) != replacement
                        or (prior.get("revoke_intent") or {}).get("status") != "verified"
                        or (prior.get("create_intent") or {}).get("status") != "verified"):
                    raise RuntimeError("completed replacement item does not match exact old/new live receipts")
            else:
                raise RuntimeError("replacement has an ambiguous or unsupported operation state; reconcile read-only")
            planned.append({"ordinal": ordinal, "subject_id": subject, "grant": grant,
                            "old_row": deepcopy(row), "old": old, "replacement": replacement,
                            "status": prior_status})
            install_ordinals.append(ordinal)
        else:
            if (row.get("status") != "verified" or row.get("plan_digest") != plan_digest
                    or live_by_id.get(row.get("delegation_id")) != row.get("delegation")):
                raise RuntimeError("one of the 42 correct typed capability Delegations changed unexpectedly")
    if len(planned) != 15:
        raise RuntimeError("replacement set is not exactly the 15 own-installation tuples")
    if replacement_attempt is not None and set(prior_by_ordinal) != {item["ordinal"] for item in planned}:
        raise RuntimeError("replacement intent does not cover exactly the 15 own-installation tuple ordinals")

    expected_installations = catalog_installations_by_id(installations)
    for subject, grant in ordered:
        if grant["resource_type"] != "agent_installation":
            continue
        if grant["resource_id"] != example_authorization.SUBJECTS[subject][1]:
            raise RuntimeError("installation Grant targets a different subject installation")
        if grant["resource_id"] not in expected_installations:
            raise RuntimeError("replacement target is not one of the ready owner-pinned installations")

    if replacement_attempt is None:
        owner["superseded_permission_admin_delegations"] = deepcopy(old_journal)
        owner["permission_admin_delegation_replacement_attempt"] = {
            "status": "in_progress", "plan_digest": plan_digest,
            "preserved_delegation_ids": [row["delegation_id"] for row in old_journal
                                         if row.get("grant_id") not in {item["grant"]["id"] for item in planned}],
            "items": [{"ordinal": item["ordinal"], "subject_id": item["subject_id"],
                       "grant_id": item["grant"]["id"], "old_delegation_id": item["old"]["id"],
                       "new_delegation_id": item["replacement"]["id"], "status": "planned"}
                      for item in planned],
        }
        write_json_private(directory / "owner.json", owner)

    def confirm_exact(phrase: str) -> bool:
        return confirm_digest_phrase(phrase, confirm)

    receipts = []
    attempt_key = "permission_admin_delegation_replacement_attempt"

    def persist_attempt() -> dict:
        _dir, latest, _pw = read_manifest(project)
        active = latest.get(attempt_key)
        if not isinstance(active, dict) or active.get("plan_digest") != plan_digest:
            raise RuntimeError("delegation replacement owner intent changed during the operation")
        return latest

    for item in planned:
        ordinal, subject, grant = item["ordinal"], item["subject_id"], item["grant"]
        old, replacement = item["old"], item["replacement"]
        old_row = item["old_row"]
        initial_status = item["status"]
        if initial_status == "planned":
            operations = ("revoke", "create")
        elif initial_status == "revoked_verified":
            operations = ("create",)
        elif initial_status == "verified":
            operations = ()
        else:
            raise RuntimeError("replacement has an ambiguous operation state; reconcile read-only")
        for operation in operations:
            latest = persist_attempt()
            active = latest[attempt_key]
            journal_item = next(row for row in active["items"] if row["ordinal"] == ordinal)
            expected_status = "planned" if operation == "revoke" else "revoked_verified"
            if journal_item.get("status") != expected_status:
                raise RuntimeError("replacement attempt contains a prior or ambiguous operation; inspect live state only")
            target = bootstrap.profile(identity, "permission.admin")
            require_permission_admin_appointment(target, latest)
            if target.get("resource_grants") != [] or target.get("task_assignments") != []:
                raise RuntimeError("permission.admin acquired business grants while repairing Delegations")
            principal = target.get("principal") if isinstance(target, dict) else None
            if not isinstance(principal, dict) or type(principal.get("revision")) is not int:
                raise RuntimeError("permission.admin lacks a live CAS revision")
            if operation == "revoke":
                live_old = [row for row in target["delegations"] if isinstance(row, dict) and row.get("id") == old["id"]]
                if len(live_old) != 1 or live_old[0] != old:
                    raise RuntimeError("old installation Delegation is not exactly active before revocation")
                command = {"subject_id": "permission.admin", "expected_revision": principal["revision"],
                           "idempotency_key": "replay-delegation-revoke-" + project[-12:] + "-" + str(ordinal).zfill(3),
                           "reason": "Revoke only the superseded installation-target encoding before exact replacement",
                           "revoke_delegation_id": old["id"]}
                expected_preview_delegate = old
                preview = manager.call("POST", "/api/modules/identity/delegations:preview", command)
                digest = assert_delegation_revoke_preview(preview, command, expected_preview_delegate)
                phrase = project + " delegation-rebind revoke " + subject + " " + grant["id"] + " " + digest
            else:
                old_after = [row for row in target["delegations"] if isinstance(row, dict) and row.get("id") == old["id"]]
                if (len(old_after) != 1 or old_after[0].get("status") != "revoked"
                        or old_after[0].get("revision") != 2
                        or any(row.get("id") == replacement["id"] for row in target["delegations"] if isinstance(row, dict))):
                    raise RuntimeError("old Delegation revocation has not been precisely verified")
                command = {"subject_id": "permission.admin", "expected_revision": principal["revision"],
                           "idempotency_key": "replay-delegation-rebind-" + project[-12:] + "-" + str(ordinal).zfill(3),
                           "reason": "Replace the revoked tuple with the same bounded authority and exact own-installation resource",
                           "delegation": replacement}
                preview = manager.call("POST", "/api/modules/identity/delegations:preview", command)
                digest = assert_delegation_preview(preview, command)
                phrase = project + " delegation-rebind create " + subject + " " + grant["id"] + " " + digest
            print(json.dumps({"phase": "permission_admin_delegation_rebind_preview", "operation": operation,
                              "subject": subject, "grant_id": grant["id"],
                              "old_delegation_id": old["id"], "new_delegation_id": replacement["id"],
                              "request_digest": digest, "confirmation": phrase,
                              "credentials_printed": False}, ensure_ascii=False))
            if not confirm_exact(phrase):
                raise RuntimeError("exact installation Delegation replacement was not confirmed")
            proof = manager.call("POST", "/api/modules/identity/step-up", {
                "current_password": passwords["system.admin"], "action": "delegation.manage",
                "request_digest": digest,
            })
            token = proof.get("step_up_token") if isinstance(proof, dict) else None
            if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
                raise RuntimeError("fresh system.admin delegation.manage step-up did not verify")
            latest = persist_attempt()
            active = latest[attempt_key]
            journal_item = next(row for row in active["items"] if row["ordinal"] == ordinal)
            journal_item[operation + "_intent"] = {
                "status": "commit_started", "request_digest": digest,
                "expected_revision": command["expected_revision"],
                "idempotency_key": command["idempotency_key"],
                "command": {key: value for key, value in command.items() if key != "step_up_token"},
            }
            journal_item["status"] = operation + "_commit_started"
            write_json_private(directory / "owner.json", latest)
            try:
                receipt = manager.call("POST", "/api/modules/identity/delegations", dict(command, step_up_token=token))
            except Exception as exc:
                latest = persist_attempt()
                active = latest[attempt_key]
                current_item = next(row for row in active["items"] if row["ordinal"] == ordinal)
                current_item[operation + "_intent"]["failure"] = {
                    "exception_type": type(exc).__name__, "commit_outcome": "unknown_requires_readonly_reconciliation"}
                active["status"] = "commit_outcome_unknown"
                write_json_private(directory / "owner.json", latest)
                raise
            after = bootstrap.profile(identity, "permission.admin")
            after_principal = after.get("principal") if isinstance(after, dict) else None
            if operation == "revoke":
                expected_delegate = deepcopy(old)
                expected_delegate["status"] = "revoked"
                expected_delegate["revision"] = old["revision"] + 1
            else:
                expected_delegate = replacement
            if (not isinstance(receipt, dict) or receipt.get("actor_id") != "system.admin"
                    or receipt.get("subject_id") != "permission.admin"
                    or receipt.get("revision") != command["expected_revision"] + 1
                    or receipt.get("request_digest") != digest
                    or receipt.get("change") != command or receipt.get("delegation") != expected_delegate
                    or not isinstance(after_principal, dict)
                    or after_principal.get("revision") != command["expected_revision"] + 1
                    or after.get("resource_grants") != [] or after.get("task_assignments") != []):
                raise RuntimeError("Delegation mutation receipt or exact profile CAS readback differs")
            rows = after.get("delegations")
            ids = [row.get("id") for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
            if operation == "revoke":
                expected_rows = deepcopy(target["delegations"])
                expected_rows = [expected_delegate if isinstance(row, dict) and row.get("id") == old["id"] else row
                                 for row in expected_rows]
                if (len(rows) != len(target["delegations"]) or len(ids) != len(set(ids))
                        or example_authorization.canonical(sorted(rows, key=lambda row: row["id"]))
                        != example_authorization.canonical(sorted(expected_rows, key=lambda row: row["id"]))
                        or any(row.get("id") == replacement["id"] for row in rows if isinstance(row, dict))):
                    raise RuntimeError("revocation readback changed unrelated Delegations or failed to revoke the exact old ID")
                journal_item["status"] = "revoked_verified"
            else:
                expected_rows = deepcopy(target["delegations"]) + [replacement]
                if (len(rows) != len(target["delegations"]) + 1 or len(ids) != len(set(ids))
                        or example_authorization.canonical(sorted(rows, key=lambda row: row["id"]))
                        != example_authorization.canonical(sorted(expected_rows, key=lambda row: row["id"]))
                        or sum(1 for row in rows if isinstance(row, dict) and row.get("id") == old["id"]
                               and row.get("status") == "revoked" and row.get("revision") == 2) != 1):
                    raise RuntimeError("replacement readback differs or changed unrelated Delegations")
                journal_item["status"] = "verified"
                journal_item["replacement_request_digest"] = digest
                journal_item["replacement_revision"] = after_principal["revision"]
                journal_item["revoke_request_digest"] = journal_item.get("revoke_intent", {}).get("request_digest")
            journal_item[operation + "_intent"]["status"] = "verified"
            journal_item[operation + "_intent"]["receipt_id"] = receipt.get("id")
            journal_item[operation + "_intent"]["revision"] = after_principal["revision"]
            active["last_verified_ordinal"] = ordinal
            write_json_private(directory / "owner.json", latest)
        receipts.append({"ordinal": ordinal, "subject_id": subject, "grant_id": grant["id"],
                         "old_delegation_id": old["id"], "new_delegation_id": replacement["id"],
                         "old_status": "revoked", "new_status": "active"})

    _dir, owner, _pw = read_manifest(project)
    attempt = owner.get(attempt_key)
    if (not isinstance(attempt, dict) or attempt.get("status") != "in_progress"
            or any(row.get("status") != "verified" for row in attempt.get("items", []))):
        raise RuntimeError("all 15 exact replacement receipts are not durably verified")
    final_profile = bootstrap.profile(identity, "permission.admin")
    final_delegations = final_profile.get("delegations")
    if (not isinstance(final_delegations, list) or len(final_delegations) != 72
            or sum(1 for row in final_delegations if isinstance(row, dict) and row.get("status") == "active") != 57
            or final_profile.get("resource_grants") != [] or final_profile.get("task_assignments") != []):
        raise RuntimeError("final permission.admin profile is not 57 exact active delegations plus 15 revoked history rows")
    new_by_grant = {}
    by_old_id = {item["old"]["id"]: item for item in planned}
    for row in old_journal:
        item = by_old_id.get(row.get("delegation_id"))
        if item is None:
            new_by_grant[row["grant_id"]] = row
            continue
        ordinal, grant, replacement = item["ordinal"], item["grant"], item["replacement"]
        live = [entry for entry in final_delegations if isinstance(entry, dict) and entry.get("id") == replacement["id"]]
        if len(live) != 1 or live[0] != replacement:
            raise RuntimeError("corrected active installation Delegation lacks exact final profile readback")
        op_item = next(entry for entry in attempt["items"] if entry["ordinal"] == ordinal)
        new_by_grant[row["grant_id"]] = {
            "grant_id": row["grant_id"], "subject_id": row["subject_id"],
            "delegation_id": replacement["id"],
            "request_digest": op_item["replacement_request_digest"],
            "expected_revision": op_item["create_intent"]["expected_revision"],
            "expires_at": replacement["expires_at"], "plan_digest": plan_digest,
            "grant_digest": row["grant_digest"], "delegation": replacement,
            "status": "verified", "revision": op_item["replacement_revision"],
            "generation": 2, "supersedes_delegation_id": row["delegation_id"],
        }
    if len(new_by_grant) != 57:
        raise RuntimeError("replacement journal does not preserve one active Delegation per exact planned Grant")
    owner["permission_admin_delegations"] = [new_by_grant[grant["id"]] for _, grant in ordered]
    attempt["status"] = "complete"
    attempt["replaced_count"] = 15
    attempt["preserved_typed_count"] = 42
    attempt["active_delegation_count"] = 57
    attempt["revoked_history_count"] = 15
    history = owner.setdefault("authorization_attempt_history", [])
    history.append(deepcopy(denied))
    owner["authorization_attempt"] = None
    write_json_private(directory / "owner.json", owner)
    print(json.dumps({"result": "installation_delegations_rebound", "project": project,
                      "replaced_installation_delegations": 15, "preserved_typed_delegations": 42,
                      "active_delegations": 57, "revoked_old_delegations": 15,
                      "system_admin_business_grants": 0, "receipts": receipts,
                      "credentials_printed": False}, ensure_ascii=False))
    return receipts


def delegation_generation_mode(project: str, plan: dict, owner: dict) -> int:
    """Return the only two accepted complete Delegation layouts: fresh or verified replacement."""
    ordered = [(change["subject_id"], grant) for change in plan.get("changes", [])
               if isinstance(change, dict) for grant in change.get("resource_grants", [])
               if isinstance(grant, dict)]
    rows = owner.get("permission_admin_delegations")
    plan_digest = hashlib.sha256(example_authorization.canonical(plan)).hexdigest()
    pin = owner.get("authorization_plan")
    if (len(ordered) != 57 or not isinstance(rows, list) or len(rows) != 57
            or not isinstance(pin, dict) or pin.get("plan_sha256") != plan_digest
            or not isinstance(pin.get("path"), str) or not pin["path"]
            or owner.get("authorization_attempt") is not None
            or owner.get("authorization_journal") not in (None, [])
            or owner.get("authorization_complete") is True):
        raise RuntimeError("complete Delegation layout requires the exact ordered 57-grant plan and receipt list")
    replacement = owner.get("permission_admin_delegation_replacement_attempt")
    superseded = owner.get("superseded_permission_admin_delegations")
    if replacement is None:
        if superseded not in (None, []):
            raise RuntimeError("fresh Delegation layout cannot contain superseded authority history")
        generation = 1
    else:
        if (not isinstance(replacement, dict) or replacement.get("status") != "complete"
                or replacement.get("plan_digest") != plan_digest
                or replacement.get("replaced_count") != 15
                or replacement.get("preserved_typed_count") != 42
                or replacement.get("active_delegation_count") != 57
                or replacement.get("revoked_history_count") != 15
                or not isinstance(superseded, list) or len(superseded) != 57):
            raise RuntimeError("replacement Delegation layout lacks its exact completed 15/42 owner receipts")
        generation = 2

    old_by_grant: dict[str, dict] = {}
    attempt_items: dict[int, dict] = {}
    if generation == 2:
        old_by_grant = {row.get("grant_id"): row for row in superseded if isinstance(row, dict)}
        items = replacement.get("items")
        if (len(old_by_grant) != 57 or set(old_by_grant) != {grant["id"] for _, grant in ordered}
                or not isinstance(items, list) or len(items) != 15
                or replacement.get("last_verified_ordinal") != max(
                    index for index, (_, grant) in enumerate(ordered, start=1)
                    if grant["resource_type"] == "agent_installation")):
            raise RuntimeError("completed replacement journal does not cover the exact 15 installation and 42 typed Grants")
        attempt_items = {item.get("ordinal"): item for item in items if isinstance(item, dict)}
        install_ordinals = {index for index, (_, grant) in enumerate(ordered, start=1)
                            if grant["resource_type"] == "agent_installation"}
        typed_ids = [row.get("delegation_id") for (subject, grant), row in zip(ordered, superseded, strict=True)
                     if grant["resource_type"] != "agent_installation"]
        if (len(attempt_items) != 15 or set(attempt_items) != install_ordinals
                or replacement.get("preserved_delegation_ids") != typed_ids):
            raise RuntimeError("replacement journal has missing or extra tuple receipts")

    base = "replay-delegation-" + project.removeprefix("agentplug-test-public-") + "-"
    seen: set[str] = set()
    for ordinal, ((subject, grant), row) in enumerate(zip(ordered, rows, strict=True), start=1):
        install = grant.get("resource_type") == "agent_installation"
        expected_id = base + (("r2-" if generation == 2 else "") if install else "") + str(ordinal).zfill(3)
        expected_generation = 2 if generation == 2 and install else None
        expected_superseded = base + str(ordinal).zfill(3) if generation == 2 and install else None
        grant_digest = hashlib.sha256(example_authorization.canonical(
            {"subject": subject, "grant": grant})).hexdigest()
        if (not isinstance(row, dict) or row.get("grant_id") != grant.get("id")
                or row.get("grant_id") in seen or row.get("subject_id") != subject
                or row.get("delegation_id") != expected_id or row.get("status") != "verified"
                or row.get("plan_digest") != plan_digest or row.get("grant_digest") != grant_digest
                or example_authorization.timestamp(row.get("expires_at"))
                != example_authorization.timestamp(grant.get("expires_at"))
                or row.get("generation") != expected_generation
                or row.get("supersedes_delegation_id") != expected_superseded):
            raise RuntimeError("Delegation receipt sequence or generation metadata differs from the pinned plan")
        seen.add(row["grant_id"])
        delegated = row.get("delegation")
        expected_resources = [grant["resource_id"]] if install else []
        expected_binding = [{"resource_type": grant["resource_type"],
                             "resource_id": grant["resource_id"],
                             "installation_id": grant["agent_instance_id"]}]
        if (not isinstance(delegated, dict) or delegated.get("id") != expected_id
                or delegated.get("subject_id") != "permission.admin"
                or delegated.get("actions") != [grant.get("action")]
                or delegated.get("resources") != expected_resources
                or (install and delegated.get("resource_bindings") is not None)
                or (not install and delegated.get("resource_bindings") != expected_binding)):
            raise RuntimeError("Delegation generation does not use the exact own-installation or typed-resource shape")
        if generation == 1:
            if (type(row.get("expected_revision")) is not int or type(row.get("revision")) is not int
                    or row["revision"] != row["expected_revision"] + 1):
                raise RuntimeError("fresh Delegation receipt has no exact per-item CAS revision")
        elif install:
            old_row = superseded[ordinal - 1]
            if old_row != old_by_grant.get(grant["id"]):
                raise RuntimeError("replacement history order differs from the pinned plan")
            validate_previous_installation_delegation(project, ordinal, subject, grant, old_row, plan_digest)
            expected_replacement = expected_replacement_delegation(
                project, ordinal, grant, old_row["delegation"])
            item = attempt_items.get(ordinal)
            revoke_intent = item.get("revoke_intent") if isinstance(item, dict) else None
            create_intent = item.get("create_intent") if isinstance(item, dict) else None
            revoke_command = revoke_intent.get("command") if isinstance(revoke_intent, dict) else None
            create_command = create_intent.get("command") if isinstance(create_intent, dict) else None
            revoke_revision = revoke_intent.get("expected_revision") if isinstance(revoke_intent, dict) else None
            create_revision = create_intent.get("expected_revision") if isinstance(create_intent, dict) else None
            revoke_digest = revoke_intent.get("request_digest") if isinstance(revoke_intent, dict) else None
            create_digest = create_intent.get("request_digest") if isinstance(create_intent, dict) else None
            if (set(row) != {"grant_id", "subject_id", "delegation_id", "request_digest",
                             "expected_revision", "expires_at", "plan_digest", "grant_digest",
                             "delegation", "status", "revision", "generation", "supersedes_delegation_id"}
                    or row.get("delegation") != expected_replacement
                    or row.get("delegation_id") != expected_replacement["id"]
                    or row.get("supersedes_delegation_id") != old_row["delegation_id"]
                    or row.get("expected_revision") != create_revision
                    or row.get("revision") != (create_revision + 1 if type(create_revision) is int else None)
                    or row.get("request_digest") != create_digest
                    or not isinstance(item, dict) or item.get("status") != "verified"
                    or item.get("subject_id") != subject or item.get("grant_id") != grant["id"]
                    or item.get("old_delegation_id") != old_row["delegation_id"]
                    or item.get("new_delegation_id") != expected_replacement["id"]
                    or not isinstance(revoke_command, dict) or not isinstance(create_command, dict)
                    or type(revoke_revision) is not int or type(create_revision) is not int
                    or create_revision != revoke_revision + 1
                    or not isinstance(revoke_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", revoke_digest)
                    or not isinstance(create_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", create_digest)
                    or revoke_intent.get("status") != "verified" or create_intent.get("status") != "verified"
                    or revoke_intent.get("revision") != revoke_revision + 1
                    or create_intent.get("revision") != create_revision + 1
                    or revoke_command.get("subject_id") != "permission.admin"
                    or revoke_command.get("expected_revision") != revoke_revision
                    or revoke_command.get("idempotency_key") != (
                        "replay-delegation-revoke-" + project[-12:] + "-" + str(ordinal).zfill(3))
                    or revoke_command.get("reason") != "Revoke only the superseded installation-target encoding before exact replacement"
                    or revoke_command.get("revoke_delegation_id") != old_row["delegation_id"]
                    or create_command.get("subject_id") != "permission.admin"
                    or create_command.get("expected_revision") != create_revision
                    or create_command.get("idempotency_key") != (
                        "replay-delegation-rebind-" + project[-12:] + "-" + str(ordinal).zfill(3))
                    or create_command.get("reason") != "Replace the revoked tuple with the same bounded authority and exact own-installation resource"
                    or create_command.get("delegation") != expected_replacement):
                raise RuntimeError("installation replacement receipts or exact same-authority CAS commands differ")
        elif superseded[ordinal - 1] != row:
            raise RuntimeError("one of the 42 typed Delegations changed during installation-only replacement")
    return generation


def grant_preview_smoke(project: str, directory: Path, plan: dict) -> dict:
    """Run one read-only first-subject Grant preview after a complete exact Delegation set."""
    _directory, owner, _passwords = read_manifest(project)
    generation = delegation_generation_mode(project, plan, owner)
    verify_owner_frontend(project, directory, owner)
    verify_example_container_health(project, directory)
    resource_api = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    installations = verify_catalog_installation_readiness(resource_api)
    plans = load_pinned_release_plans(project, directory, owner)
    policies = {agent_id: live_policy_inventory(resource_api, project, directory, owner, release)
                for agent_id, release in plans.items()}
    verify_plan_allowlist(plan, policies)
    verify_business_role_profiles(resource_api, owner, project)
    assert_minimum_authorization_plan(plan, expected_minimum_authorization_plan(project, policies, plan))
    pins = catalog_installations_by_id(installations)
    ordered = [(change["subject_id"], grant) for change in plan["changes"] for grant in change["resource_grants"]]
    plan_digest = hashlib.sha256(example_authorization.canonical(plan)).hexdigest()
    rows_by_grant = {row["grant_id"]: row for row in owner["permission_admin_delegations"]}
    for ordinal, (subject, grant) in enumerate(ordered, start=1):
        row = rows_by_grant.get(grant["id"])
        if not isinstance(row, dict) or row.get("status") != "verified" or row.get("plan_digest") != plan_digest:
            raise RuntimeError("owner Delegation mapping is incomplete for the exact pinned Grant plan")
        prefix = "replay-delegation-" + project.removeprefix("agentplug-test-public-") + "-"
        expected_id = prefix + (("r2-" if generation == 2 else "")
                                if grant["resource_type"] == "agent_installation" else "") + str(ordinal).zfill(3)
        expected_generation = 2 if generation == 2 and grant["resource_type"] == "agent_installation" else None
        if row.get("delegation_id") != expected_id or row.get("generation") != expected_generation:
            raise RuntimeError("active owner Delegation mapping does not use the one exact corrected installation generation")
        delegated = row.get("delegation")
        binding = {"resource_type": grant["resource_type"], "resource_id": grant["resource_id"],
                   "installation_id": grant["agent_instance_id"]}
        if (not isinstance(delegated, dict) or delegated.get("actions") != [grant["action"]]
                or delegated.get("data_scope_types") != [grant["data_scope"]["type"]]
                or delegated.get("data_ids", []) != grant["data_scope"].get("ids", [])
                or delegated.get("management_actions") != ["authorization.change"]
                or delegated.get("max_duration_seconds") > 24 * 60 * 60
                or delegated.get("expires_at") != grant.get("expires_at")
                or delegated.get("resources") != ([grant["resource_id"]] if grant["resource_type"] == "agent_installation" else [])
                or (delegated.get("resource_bindings") or [])
                != ([] if grant["resource_type"] == "agent_installation" else [binding])):
            raise RuntimeError("active Delegation expands or differs from its exact plan tuple")
        installation_id = example_authorization.SUBJECTS[subject][1]
        if installation_id not in pins or grant.get("agent_instance_id") != installation_id:
            raise RuntimeError("Grant preview subject is not pinned to its ready own installation")
    identity = owner_human_api(project, directory, "permission.admin", bootstrap.BUSINESS_SCOPE)
    manager_profile = bootstrap.profile(identity, "permission.admin")
    require_permission_admin_appointment(manager_profile, owner)
    if (manager_profile.get("resource_grants") != [] or manager_profile.get("task_assignments") != []
            or not isinstance(manager_profile.get("delegations"), list)):
        raise RuntimeError("permission.admin gained business access or lacks live Delegation visibility")
    active = {row.get("id"): row for row in manager_profile["delegations"]
              if isinstance(row, dict) and row.get("status") == "active"}
    if len(active) != 57 or any(active.get(row["delegation_id"]) != row["delegation"]
                                for row in owner["permission_admin_delegations"]):
        raise RuntimeError("permission.admin current active Delegations differ from all 57 exact owner receipts")
    if generation == 1:
        prefix_count, _prefix_receipts = verified_delegation_prefix(
            project, plan, owner, manager_profile)
        if prefix_count != 57:
            raise RuntimeError("fresh Delegation layout is not a fully verified 57-row live prefix")
    subject, grants = plan["changes"][0]["subject_id"], plan["changes"][0]["resource_grants"]
    subject_type = plan["changes"][0]["subject_type"]
    if len(grants) != (11 if subject_type == "user" else 8):
        raise RuntimeError("Grant preview smoke subject does not contain its exact bounded 11/8 tuple set")
    before = bootstrap.profile(identity, subject, subject_type)
    principal = before.get("principal") if isinstance(before, dict) else None
    if (not isinstance(principal, dict) or principal.get("id") != subject
            or principal.get("type") != subject_type or principal.get("is_active") is not True
            or not isinstance(before.get("resource_grants"), list)
            or before.get("resource_grants") != [] or before.get("task_assignments") != []):
        raise RuntimeError("Grant preview target is not the exact active clean owner business principal")
    delegation_ids = {row["grant_id"]: row["delegation_id"] for row in owner["permission_admin_delegations"]}
    command = {"subject_type": subject_type, "subject_id": subject,
               "expected_revision": principal["revision"], "reason": plan["changes"][0]["reason"],
               "resource_grants": grants,
               "idempotency_key": "tutorial-grants-" + plan_digest[:32] + "-" + subject}
    preview = identity.call("POST", "/api/modules/identity/authorization-changes:preview", command)
    expected_additions = [dict(grant, delegation_id=delegation_ids[grant["id"]]) for grant in grants]
    example_authorization.assert_preview(preview, command, "permission.admin", expected_additions)
    smoke = {"status": "verified_read_only_preview", "subject_id": subject,
             "grant_count": len(grants), "principal_revision": principal["revision"],
             "plan_digest": plan_digest, "preview_digest": preview["plan_digest"],
             "actor": "permission.admin", "commit_sent": False}
    _dir, latest, _pw = read_manifest(project)
    latest["authorization_preview_smoke"] = smoke
    old_attempt = latest.get("authorization_attempt")
    if (isinstance(old_attempt, dict) and old_attempt.get("status") == "preview_denied"
            and old_attempt.get("plan_digest") == plan_digest
            and old_attempt.get("last_failure", {}).get("grant_commit_attempted") is False):
        latest.setdefault("authorization_attempt_history", []).append(deepcopy(old_attempt))
        latest["authorization_attempt"] = None
    write_json_private(directory / "owner.json", latest)
    print(json.dumps({"result": "grant_preview_smoke_passed", "project": project,
                      "subject_id": subject, "grant_count": len(grants),
                      "plan_digest": plan_digest, "preview_digest": preview["plan_digest"],
                      "commit_sent": False, "credentials_printed": False}, ensure_ascii=False))
    return smoke


def delegate_reviewed_grants(project: str, directory: Path, plan: dict, confirm=None) -> list[dict]:
    _directory, owner, passwords = read_manifest(project)
    if (not owner.get("identity_complete") or not owner.get("services_ready")
            or not owner.get("machines_complete")):
        raise RuntimeError("grant delegation requires the completed identity/machine stages")
    if not owner.get("business_roles_complete"):
        raise RuntimeError("grant delegation requires the separately previewed and committed own-installation role stage")
    if owner.get("permission_admin_appointment") is None:
        raise RuntimeError("system.admin must appoint permission.admin before creating grant-making delegations")
    verify_owner_frontend(project, directory, owner)
    verify_example_container_health(project, directory)
    manager = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    bootstrap.verify_login_identity(manager.call("GET", "/auth/me"), "system.admin", bootstrap.BUSINESS_SCOPE)
    installations = verify_catalog_installation_readiness(manager)
    catalog_pins = owner.get("catalog_lifecycle", {})
    for item in installations:
        agent_id = next(row[1] for row in bootstrap.MACHINES if row[0] == item["machine_id"])
        release = catalog_pins.get(agent_id, {}).get("release", {})
        if release.get("version_id") != item["agent_version_id"] or release.get("installation_id") != item["installation_id"]:
            raise RuntimeError("active Catalog installation differs from the owner-pinned public release version")
    release_plans = load_pinned_release_plans(project, directory, owner)
    policies = {agent_id: live_policy_inventory(manager, project, directory, owner, release)
                for agent_id, release in release_plans.items()}
    verify_plan_allowlist(plan, policies)
    verify_business_role_profiles(manager, owner, project)
    assert_minimum_authorization_plan(plan, expected_minimum_authorization_plan(project, policies, plan))
    pins = catalog_installations_by_id(installations)
    ordered_grants = []
    for change in plan["changes"]:
        ordered_grants.extend((change["subject_id"], grant) for grant in change["resource_grants"])
    plan_digest = hashlib.sha256(example_authorization.canonical(plan)).hexdigest()
    existing = bootstrap.profile(manager, "permission.admin")
    require_permission_admin_appointment(existing, owner)
    prefix_count, prefix_receipts = verified_delegation_prefix(project, plan, owner, existing)

    pending: list[tuple[str, dict]] = []
    ordinal = 0
    for subject, grant in ordered_grants:
        ordinal += 1
        installation_id = example_authorization.SUBJECTS[subject][1]
        grant_pin = pins.get(installation_id)
        if not isinstance(grant_pin, dict):
            raise RuntimeError("live readiness did not include this grant's exact Catalog installation")
        # The actual published PolicyAsset snapshot is checked here immediately
        # before permissions are delegated; caller plans cannot introduce IDs.
        allow = plan["allowed_resources"].get(installation_id, [])
        if not any(row == {"resource_type": grant["resource_type"], "resource_id": grant["resource_id"], "action": grant["action"]} for row in allow):
            raise RuntimeError("grant tuple is not one exact entry in the reviewed installation allowlist")
        pending.append((subject, grant))

    receipts = list(prefix_receipts)
    for ordinal, (subject, grant) in enumerate(pending[prefix_count:], start=prefix_count + 1):
        # Read target principal fresh for every CAS. A delegated grant changes
        # its revision, so a stale batch command is never reused.
        _current_directory, current_owner, _current_passwords = read_manifest(project)
        target = bootstrap.profile(manager, "permission.admin")
        current_prefix, _ = verified_delegation_prefix(project, plan, current_owner, target)
        if current_prefix != ordinal - 1:
            raise RuntimeError("delegation state changed before this preview; reconcile the exact verified prefix")
        journal = current_owner["permission_admin_delegations"]
        command = delegation_command(project, ordinal, grant, target)
        preview = manager.call("POST", "/api/modules/identity/delegations:preview", command)
        digest = assert_delegation_preview(preview, command)
        phrase = project + " delegate " + subject + " " + grant["id"] + " " + digest
        print(json.dumps({"phase": "permission_admin_delegation_preview", "project": project,
                          "subject": subject, "resource_type": grant["resource_type"],
                          "resource_id": grant["resource_id"], "action": grant["action"],
                          "data_scope": grant["data_scope"], "expires_at": grant["expires_at"],
                          "roles": [], "extra_resource_grants": [], "request_digest": digest,
                          "confirmation": phrase, "step_up_token_printed": False}, ensure_ascii=False))
        if not confirm_digest_phrase(phrase, confirm):
            raise RuntimeError("explicit permission.admin delegation was not confirmed")
        proof = manager.call("POST", "/api/modules/identity/step-up", {
            "current_password": passwords["system.admin"], "action": "delegation.manage",
            "request_digest": digest,
        })
        token = proof.get("step_up_token") if isinstance(proof, dict) else None
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            raise RuntimeError("fresh action-bound system.admin delegation.manage authentication did not verify")

        row = {"grant_id": grant["id"], "subject_id": subject, "delegation_id": command["delegation"]["id"],
               "request_digest": digest, "expected_revision": command["expected_revision"],
               "expires_at": command["delegation"]["expires_at"], "plan_digest": plan_digest,
               "grant_digest": hashlib.sha256(example_authorization.canonical({"subject": subject, "grant": grant})).hexdigest(),
               "delegation": command["delegation"], "status": "commit_started"}
        journal.append(row)
        write_json_private(directory / "owner.json", current_owner)
        receipt = manager.call("POST", "/api/modules/identity/delegations", dict(command, step_up_token=token))
        delegated = receipt.get("delegation") if isinstance(receipt, dict) else None
        if (not isinstance(receipt, dict) or receipt.get("actor_id") != "system.admin"
                or receipt.get("subject_id") != "permission.admin" or receipt.get("revision") != command["expected_revision"] + 1
                or receipt.get("request_digest") != digest or delegated != command["delegation"]):
            raise RuntimeError("permission delegation receipt differs from the exact reviewed change")
        after = bootstrap.profile(manager, "permission.admin")
        after_principal = after.get("principal") if isinstance(after, dict) else None
        before_delegations = target.get("delegations")
        after_delegations = after.get("delegations")
        if (not isinstance(after_principal, dict) or after_principal.get("revision") != command["expected_revision"] + 1
                or not isinstance(before_delegations, list) or not isinstance(after_delegations, list)
                or len(after_delegations) != len(before_delegations) + 1
                or sum(1 for item in after_delegations if isinstance(item, dict) and item.get("id") == delegated["id"] and item == delegated) != 1
                or after.get("resource_grants") != [] or after.get("task_assignments") != []):
            raise RuntimeError("permission.admin delegation failed exact CAS profile readback")
        row["status"] = "verified"
        row["revision"] = after_principal["revision"]
        owner = current_owner
        write_json_private(directory / "owner.json", owner)
        receipts.append({"grant_id": grant["id"], "subject_id": subject, "delegation_id": delegated["id"],
                         "request_digest": digest, "revision": after_principal["revision"], "expires_at": row["expires_at"]})
    return receipts


def load_business_plan(project: str, directory: Path, owner: dict) -> tuple[dict, str]:
    pin = owner.get("business_replay_plan")
    if not isinstance(pin, dict) or not isinstance(pin.get("path"), str):
        raise RuntimeError("owner has no prepared public business replay plan")
    value, relative = private_plan_file(project, directory, Path(pin["path"]), "public-business-replay/v1")
    plan = public_business.validate_plan(value, project, bootstrap.BUSINESS_SCOPE)
    if relative != pin["path"] or pin.get("plan_sha256") != public_business.digest(plan):
        raise RuntimeError("business replay plan file differs from the owner-private immutable plan pin")
    pinned_versions = {language: owner.get("catalog_lifecycle", {}).get("example-" + agent_directory, {}).get("release", {}).get("version_id")
                       for language, agent_directory in public_business.DIRECTORIES.items()}
    actual_versions = {case["language"]: case["agent_version_id"] for case in plan["cases"] if case["case"] == "baseline"}
    if actual_versions != pinned_versions:
        raise RuntimeError("business replay case Versions differ from actual owner-pinned Catalog releases")
    return plan, relative


def verify_runtime_processes(project: str, directory: Path, owner: dict) -> None:
    if owner.get("runtime_prepared") is not True or owner.get("runtime_process_started") is not True:
        raise RuntimeError("basic public business replay requires the isolated Code Runtime overlay and process startup stage")
    result = subprocess.run(compose_prefix(project, directory, include_runtime=True) + ["ps", "--status", "running", "--services"],
                            cwd=ROOT, capture_output=True, timeout=30,
                            env=isolated_compose_environment(directory, include_runtime=True))
    services = set(result.stdout.decode("utf-8", errors="replace").splitlines())
    if result.returncode or not {"platform-app", "code-runtime"}.issubset(services):
        raise RuntimeError("owner Code Runtime overlay no longer has both platform-app and code-runtime running")


def verify_live_minimum_grants(api: bootstrap.BrowserAPI, project: str, plan: dict, owner: dict) -> None:
    journal = owner.get("permission_admin_delegations")
    by_grant = {row.get("grant_id"): row.get("delegation_id") for row in journal if isinstance(row, dict)} if isinstance(journal, list) else {}
    requested = {grant["id"] for change in plan["changes"] for grant in change["resource_grants"]}
    if not requested.issubset(by_grant):
        raise RuntimeError("live business replay has no exact complete Grant-to-delegation owner receipt map")
    for change in plan["changes"]:
        subject = change["subject_id"]
        kind = change["subject_type"]
        profile = bootstrap.profile(api, subject, kind)
        principal = profile.get("principal") if isinstance(profile, dict) else None
        if (not isinstance(principal, dict) or principal.get("id") != subject or principal.get("type") != kind
                or principal.get("is_active") is not True or principal.get("tenant_id") != bootstrap.BUSINESS_SCOPE["tenant_id"]
                or kind == "user" and not bootstrap.active_membership(profile, subject, bootstrap.BUSINESS_SCOPE)):
            raise RuntimeError("minimum Grant subject is not the exact active app-demo identity")
        if kind == "user":
            ids = {row.get("id") for row in profile.get("role_bindings", []) if isinstance(row, dict) and row.get("status") == "active"}
            business = {row["id"] for row in owner["business_role_lifecycle"][subject]["bindings"]}
            temporary = {entry.get("binding_id") for entry in owner.get("temporary_author_roles", {}).values()
                         if isinstance(entry, dict) and entry.get("subject") == subject and entry.get("status") == "active"}
            if ids != business | temporary:
                raise RuntimeError("human business principal has a missing or unexpected active role")
        elif profile.get("role_bindings") != []:
            raise RuntimeError("machine principal must never receive a human business role")
        grants = profile.get("resource_grants")
        expected = [dict(grant, delegation_id=by_grant[grant["id"]]) for grant in change["resource_grants"]]
        key = lambda item: item.get("id", "") if isinstance(item, dict) else ""
        if not isinstance(grants, list) or sorted(grants, key=key) != sorted(expected, key=key):
            raise RuntimeError("live IAM profile differs from the exact owner-scoped minimum Resource Grants")
        if profile.get("task_assignments") != []:
            raise RuntimeError("public example principals cannot acquire task assignments from the replay grants")
    manager = bootstrap.profile(api, "system.admin")
    if manager.get("resource_grants") != [] or manager.get("task_assignments") != []:
        raise RuntimeError("system.admin must remain without business Resource Grants or task assignments")


def verified_grant_subject_prefix(owner: dict, plan: dict, plan_digest: str) -> tuple[list[str], list[dict]]:
    """Accept only whole, ordered preview/commit/readback triples from the pinned plan."""
    events = owner.get("authorization_journal", [])
    if not isinstance(events, list):
        raise RuntimeError("authorization owner journal is malformed")
    grouped: dict[str, list[dict]] = {}
    for event in events:
        if not isinstance(event, dict) or event.get("phase") not in {"preview", "commit_started", "verified"}:
            raise RuntimeError("authorization journal contains an unknown or ambiguous phase")
        grouped.setdefault(event.get("subject_id"), []).append(event)
    completed = []
    receipts = []
    remaining_seen = False
    expected_subjects = [change["subject_id"] for change in plan["changes"]]
    if len(set(expected_subjects)) != len(expected_subjects):
        raise RuntimeError("authorization plan repeats a subject")
    for change in plan["changes"]:
        subject = change["subject_id"]
        rows = grouped.pop(subject, [])
        if not rows:
            remaining_seen = True
            continue
        if remaining_seen or [row.get("phase") for row in rows] != ["preview", "commit_started", "verified"]:
            raise RuntimeError("authorization journal is not a verified prefix; reconcile the first incomplete subject")
        preview, started, verified = rows
        digest = preview.get("plan_digest")
        baseline = preview.get("baseline_revision")
        expected_count = len(change["resource_grants"])
        if (not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)
                or preview.get("grant_count") != expected_count
                or type(baseline) is not int or baseline < 1
                or started.get("plan_digest") != digest or verified.get("plan_digest") != digest
                or verified.get("grant_count") != expected_count
                or verified.get("revision") != baseline + 1
                or not isinstance(verified.get("change_id"), str)
                or not verified["change_id"].startswith("change-")):
            raise RuntimeError("verified subject journal does not prove exact preview digest, CAS revision and Grant count")
        completed.append(subject)
        receipts.append({"phase": "verified", "subject_id": subject,
                         "change_id": verified["change_id"], "revision": verified["revision"],
                         "plan_digest": digest, "grant_count": expected_count})
    if grouped:
        raise RuntimeError("authorization journal names a subject outside the exact six-principal plan")
    return completed, receipts


def business_versions_by_language(releases: dict) -> dict[str, str]:
    return {language: releases["example-" + directory]["version"]["id"]
            for language, directory in public_business.DIRECTORIES.items()}


def verify_business_prerequisites(project: str, directory: Path, owner: dict, plan: dict) -> dict:
    if (not owner.get("identity_complete") or not owner.get("services_ready")
            or not owner.get("machines_complete") or not owner.get("business_roles_complete")
            or not owner.get("authorization_complete")):
        raise RuntimeError("business replay requires isolated identities, machines, role-only setup and exact Grants")
    indexes = owner.get("knowledge_index_lifecycle", {})
    if set(indexes) != {row[1] for row in bootstrap.MACHINES} or any(
        indexes.get(row[1], {}).get("index_publication_verified") is not True
        or indexes.get(row[1], {}).get("last_observed_status") != "succeeded" for row in bootstrap.MACHINES
    ):
        raise RuntimeError("business replay requires each of the three live Knowledge index runs to have a verified succeeded receipt")
    verify_owner_frontend(project, directory, owner)
    verify_example_container_health(project, directory)
    verify_runtime_processes(project, directory, owner)
    manager = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    admin_profile = bootstrap.profile(manager, "system.admin")
    if admin_profile.get("resource_grants") != [] or admin_profile.get("task_assignments") != []:
        raise RuntimeError("system.admin cannot hold a business grant or task assignment")
    installation_rows = verify_catalog_installation_readiness(manager)
    installation_versions = {row["installation_id"]: row["agent_version_id"] for row in installation_rows}
    access_policies = verify_model_access_policy_receipts(manager, owner, installation_versions)
    releases = load_pinned_release_plans(project, directory, owner)
    policies = {agent_id: live_policy_inventory(manager, project, directory, owner, release)
                for agent_id, release in releases.items()}
    verify_business_role_profiles(manager, owner, project)
    grant_record = owner.get("authorization_plan")
    if not isinstance(grant_record, dict):
        raise RuntimeError("business replay has no owner-pinned Resource Grant plan")
    grant_plan, _ = load_authorization_plan(project, directory, Path(grant_record["path"]))
    verify_plan_allowlist(grant_plan, policies)
    assert_minimum_authorization_plan(grant_plan, expected_minimum_authorization_plan(project, policies, grant_plan))
    verify_live_minimum_grants(manager, project, grant_plan, owner)
    if set(access_policies) != set(example_authorization.SUBJECTS):
        raise RuntimeError("business replay requires a distinct approved Model AccessPolicy for each of five users/machines")
    cases = public_business.validate_plan(plan, project, bootstrap.BUSINESS_SCOPE)
    expected_versions = business_versions_by_language(releases)
    if {row["language"]: row["agent_version_id"] for row in cases["cases"] if row["case"] == "baseline"} != expected_versions:
        raise RuntimeError("business replay plan no longer targets the exact active published Catalog Versions")
    return {"manager": manager, "releases": releases, "policies": policies,
            "access_policies": access_policies, "grant_plan": grant_plan}


def prepare_business_plan(project: str, directory: Path, output: Path, scenario_batch: str | None = None) -> Path:
    _directory, owner, _passwords = read_manifest(project)
    if owner.get("business_replay_plan") is not None and scenario_batch is None:
        raise RuntimeError("business replay plan is immutable and has already been prepared for this owner")
    previous = None
    if owner.get("business_replay_plan") is not None:
        prior, _ = load_business_plan(project, directory, owner)
        if prior.get('scenario_batch') == scenario_batch or any(row.get('plan', {}).get('scenario_batch') == scenario_batch for row in owner.get('business_replay_history', [])):
            raise RuntimeError('business scenario batch is already used; never replace or replay it')
        previous = {'pin': deepcopy(owner['business_replay_plan']), 'plan': prior,
                    'journal': deepcopy(owner.get('business_replay_journal') or {})}
    inventory = verify_business_prerequisites(project, directory, owner,
                                              public_business.build_plan(project, bootstrap.BUSINESS_SCOPE,
                                                  {language: owner.get("catalog_lifecycle", {}).get("example-" + agent_directory, {}).get("release", {}).get("version_id")
                                                   for language, agent_directory in public_business.DIRECTORIES.items()}, scenario_batch))
    versions = business_versions_by_language(inventory["releases"])
    plan = public_business.validate_plan(public_business.build_plan(project, bootstrap.BUSINESS_SCOPE, versions, scenario_batch),
                                         project, bootstrap.BUSINESS_SCOPE)
    target = owner_private_output(directory, output)
    bootstrap.write_new_private_file(target, json.dumps(plan, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    relative = target.relative_to(directory.resolve()).as_posix()
    _current_directory, current_owner, _current_passwords = read_manifest(project)
    if previous is not None:
        if current_owner.get('business_replay_plan') != owner.get('business_replay_plan') or current_owner.get('business_replay_journal') != owner.get('business_replay_journal'):
            raise RuntimeError('previous business plan changed during fresh preparation; reconcile read-only')
        current_owner.setdefault('business_replay_history', []).append(previous)
        current_owner['business_replay_journal'] = {}
        current_owner['business_audit_complete'] = False
    current_owner["business_replay_plan"] = {"path": relative, "plan_sha256": public_business.digest(plan),
                                             "case_count": 6, "version_ids": versions}
    write_json_private(directory / "owner.json", current_owner)
    print(json.dumps({"result": "six_case_owner_bound_business_plan_saved", "project": project,
                      "path": relative, "cases": 6, "languages": ["go", "python", "java"],
                      "run_ids_printed": False}, ensure_ascii=False))
    return target


def run_business_stage(project: str, directory: Path, stage: str, language: str,
                       case: str | None = None, confirm=None) -> dict:
    _directory, owner, _passwords = read_manifest(project)
    plan, _relative = load_business_plan(project, directory, owner)
    verify_business_prerequisites(project, directory, owner, plan)
    if language not in public_business.DIRECTORIES:
        raise ValueError("business replay requires one exact public example language")
    selected_case = "cancel" if stage == "business-cancel" else (case or "baseline")
    item = public_business.selected(plan, language, selected_case)
    target = item["installation_id"]
    journal = owner.get("business_replay_journal") or {}

    def persist(value: dict) -> None:
        _current_directory, current_owner, _current_passwords = read_manifest(project)
        current_owner["business_replay_journal"] = value
        write_json_private(directory / "owner.json", current_owner)

    def approve(owner_project: str, selected_language: str, selected_case: str, digest: str) -> bool:
        return confirm_digest_phrase(f"{owner_project} business {selected_language} {selected_case} {digest}", confirm)

    if stage == "business-submit":
        if case not in {"baseline", "cancel"}:
            raise ValueError("business-submit requires the exact baseline or cancel case")
        actor = item["owner"]
        owner_api = owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE)
        result = public_business.submit(owner_api, inventory=owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE),
                                       plan=plan, project=project, scope=bootstrap.BUSINESS_SCOPE,
                                       language=language, case=case, journal=journal, confirm=approve, record=persist)
    elif stage == "business-observe":
        actor = item["owner"]
        result = public_business.observe(owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE),
                                         plan, project, bootstrap.BUSINESS_SCOPE, language, selected_case, journal, persist)
    elif stage == "business-cancel":
        actor = item["owner"]
        result = public_business.request_cancel(owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE),
                                               plan, project, bootstrap.BUSINESS_SCOPE, language, journal, approve, persist)
    elif stage == "business-verify":
        actor = item["owner"]
        admin = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
        verify_audit_role(admin, owner, project)
        result = public_business.verify_success_and_replay(
            owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE), admin, plan, project,
            bootstrap.BUSINESS_SCOPE, language, journal, approve, persist)
    elif stage == "business-denials":
        actor = item["owner"]
        foreign = "demo." + {"go": "python", "python": "java", "java": "go"}[language] + ".user"
        result = public_business.verify_denials(owner_human_api(project, directory, foreign, bootstrap.BUSINESS_SCOPE),
                                                owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE),
                                                plan, project, bootstrap.BUSINESS_SCOPE, language, journal, persist)
    else:
        raise ValueError("unknown public business replay stage")
    _current_directory, current_owner, _current_passwords = read_manifest(project)
    current_owner["business_replay_journal"] = journal
    if stage == "business-verify" or stage == "business-denials":
        entries = journal.get("cases", {}) if isinstance(journal, dict) else {}
        baselines_verified = all(
            entries.get(public_business.selected(plan, lang, "baseline")["run_id"], {}).get("replay_receipt", {}).get("replay_verified") is True
            for lang in public_business.DIRECTORIES)
        denials_verified = all(
            len(entries.get(public_business.selected(plan, lang, "baseline")["run_id"], {}).get("denials", [])) == 8
            for lang in public_business.DIRECTORIES)
        current_owner["business_audit_complete"] = baselines_verified and denials_verified
    write_json_private(directory / "owner.json", current_owner)
    print(json.dumps({"result": "public_business_stage_observed", "stage": stage, "project": project,
                      "language": language, "case": selected_case,
                      "details": result, "sandbox_containment_proven": False,
                      "knowledge_answer_quality_proven": False}, ensure_ascii=False))
    return result


def role_binding_id(project: str, agent_id: str) -> str:
    if agent_id not in {entry[1] for entry in bootstrap.MACHINES}:
        raise ValueError("temporary author role is limited to the three public example Agents")
    suffix = project.removeprefix("agentplug-test-public-")
    return "replay-author-" + suffix + "-" + agent_id.removeprefix("example-")


def exact_role_binding(profile: dict, binding_id: str, subject: str, project: str, agent_id: str, active: bool = True) -> dict:
    rows = profile.get("role_bindings") if isinstance(profile, dict) else None
    if not isinstance(rows, list):
        raise RuntimeError("Identity profile has no role binding list")
    matches = [row for row in rows if isinstance(row, dict) and row.get("id") == binding_id]
    if len(matches) != 1:
        raise RuntimeError("temporary author role binding is not uniquely visible")
    row = matches[0]
    expected = {
        "id": binding_id, "subject_id": subject, "role_code": AUTHOR_ROLE, "role_version": 1,
        "scope": {"scope_type": "application", **bootstrap.BUSINESS_SCOPE},
        "status": "active" if active else "revoked", "revision": 1 if active else 2,
        "source_id": "public-replay:" + project + ":" + agent_id,
    }
    if any(row.get(key) != value for key, value in expected.items()):
        raise RuntimeError("Identity profile role binding differs from the exact temporary author grant")
    expiry = row.get("expires_at")
    if active:
        if not isinstance(expiry, str):
            raise RuntimeError("temporary author role has no expiry")
        try:
            ends = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
        except ValueError:
            raise RuntimeError("temporary author role expiry is invalid") from None
        now = datetime.now(timezone.utc)
        if ends.tzinfo is None or not now < ends.astimezone(timezone.utc) <= now + ROLE_DURATION + timedelta(minutes=2):
            raise RuntimeError("temporary author role is expired or exceeds its short owner window")
    return row


def assert_role_preview(preview: dict, command: dict, actor: str, binding: dict | None) -> None:
    if not isinstance(preview, dict) or not re.fullmatch(r"[a-f0-9]{64}", str(preview.get("plan_digest", ""))):
        raise RuntimeError("Identity role preview lacks a valid digest")
    if preview.get("actor_id") != actor or preview.get("subject_id") != command["subject_id"] or preview.get("baseline_revision") != command["expected_revision"]:
        raise RuntimeError("Identity role preview actor, subject or CAS revision differs")
    for key in ("expanded_resource_grants", "expanded_task_assignments", "expanded_memberships", "automatic_revoke_binding_ids", "automatic_revoke_grant_ids", "automatic_revoke_assignment_ids"):
        if preview.get(key) not in (None, []):
            raise RuntimeError("Identity role preview contains an unplanned grant, assignment, membership or revocation")
    normalized = preview.get("change")
    if not isinstance(normalized, dict) or normalized.get("preset") is not None or any(normalized.get(key) not in (None, []) for key in (
        "resource_grants", "task_assignments", "memberships", "revoke_grant_ids", "revoke_assignment_ids",
    )):
        raise RuntimeError("Identity role preview changed fields outside the exact role binding")
    for key in ("subject_type", "subject_id", "expected_revision", "idempotency_key", "reason"):
        if normalized.get(key) != command[key]:
            raise RuntimeError("Identity role preview changed the reviewed command")
    if binding is None:
        if normalized.get("role_bindings") not in (None, []) or normalized.get("revoke_binding_ids") != command["revoke_binding_ids"] or preview.get("expanded_role_bindings") not in (None, []):
            raise RuntimeError("Identity revoke preview includes an additional role change")
    else:
        if normalized.get("revoke_binding_ids") not in (None, []) or normalized.get("role_bindings") != command["role_bindings"]:
            raise RuntimeError("Identity role preview differs from the single requested role binding")
        expanded = preview.get("expanded_role_bindings")
        if not isinstance(expanded, list) or len(expanded) != 1 or any(expanded[0].get(key) != value for key, value in binding.items()):
            raise RuntimeError("Identity expanded role preview differs from the one exact temporary binding")
    try:
        expires = datetime.fromisoformat(str(preview.get("plan_expires_at", "")).replace("Z", "+00:00"))
    except ValueError:
        raise RuntimeError("Identity role preview expiry is invalid") from None
    if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
        raise RuntimeError("Identity role preview has expired")


def assert_business_role_preview(preview: dict, command: dict, expected_bindings: list[dict]) -> str:
    digest = preview.get("plan_digest") if isinstance(preview, dict) else None
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise RuntimeError("business role preview lacks an exact plan digest")
    normalized_change = preview.get("change")
    if not isinstance(normalized_change, dict):
        raise RuntimeError("business role preview lacks its normalized change")
    normalized_change = deepcopy(normalized_change)
    if "plan_expires_at" in normalized_change:
        if normalized_change["plan_expires_at"] != "0001-01-01T00:00:00Z":
            raise RuntimeError("business role preview contains an unexpected change expiration")
        normalized_change.pop("plan_expires_at")
    if "plan_digest" in normalized_change:
        if normalized_change["plan_digest"] != "":
            raise RuntimeError("business role preview contains an unexpected nested digest")
        normalized_change.pop("plan_digest")
    if (preview.get("actor_id") != "system.admin" or preview.get("subject_id") != command["subject_id"]
            or preview.get("baseline_revision") != command["expected_revision"]
            or normalized_change != command or preview.get("expanded_role_bindings") != expected_bindings):
        raise RuntimeError("business role preview differs from the two exact own-installation role bindings")
    for key in ("expanded_resource_grants", "expanded_task_assignments", "expanded_memberships",
                "automatic_revoke_binding_ids", "automatic_revoke_grant_ids", "automatic_revoke_assignment_ids"):
        if preview.get(key) not in (None, []):
            raise RuntimeError("role-only change expanded into an unplanned business grant, assignment, membership or revoke")
    normalized = normalized_change
    if (not isinstance(normalized, dict) or normalized.get("role_bindings") != expected_bindings
            or any(normalized.get(key) not in (None, []) for key in ("resource_grants", "task_assignments", "memberships",
                                                                       "revoke_binding_ids", "revoke_grant_ids", "revoke_assignment_ids"))
            or normalized.get("preset") not in (None, "")):
        raise RuntimeError("role-only preview includes default preset grants or another identity mutation")
    try:
        expiry = datetime.fromisoformat(str(preview.get("plan_expires_at", "")).replace("Z", "+00:00"))
    except ValueError:
        raise RuntimeError("business role preview expiry is invalid") from None
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
        raise RuntimeError("business role preview has expired")
    return digest


def business_role_bindings(project: str, subject: str, installation_id: str) -> list[dict]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    scope = {"scope_type": "agent_installation", **bootstrap.BUSINESS_SCOPE, "resource_id": installation_id}
    expires = now + BUSINESS_ROLE_DURATION
    bindings = []
    for role_code, role_version in (("operator", 1), ("skill_user", 2)):
        suffix = "operator-v1" if role_code == "operator" else "skill-user-v2"
        bindings.append({"id": "public-replay-role-" + project[-12:] + "-" + subject.replace(".", "-") + "-" + suffix,
                         "subject_id": subject, "role_code": role_code, "role_version": role_version,
                         "scope": scope, "starts_at": iso_utc(now), "expires_at": iso_utc(expires),
                         "status": "active", "revision": 1,
                         "source_id": "public-replay-business-role:" + project + ":" + subject + ":" + installation_id})
    return bindings


def verify_business_role_profiles(api: bootstrap.BrowserAPI, owner: dict, project: str) -> None:
    records = owner.get("business_role_lifecycle")
    if owner.get("business_roles_complete") is not True or not isinstance(records, dict) or set(records) != set(bootstrap.DEMO_USERS):
        raise RuntimeError("all three demo users require verified own-installation operator and Skill role bindings")
    allowed_extra: dict[str, dict[str, str]] = {subject: {} for subject in bootstrap.DEMO_USERS}
    for agent_id, temporary in owner.get("temporary_author_roles", {}).items():
        if isinstance(temporary, dict) and temporary.get("status") == "active":
            subject = temporary.get("subject")
            if subject not in allowed_extra or temporary.get("binding_id") != role_binding_id(project, agent_id):
                raise RuntimeError("temporary author role journal has an unknown subject or binding")
            allowed_extra[subject][temporary["binding_id"]] = agent_id
    now = datetime.now(timezone.utc)
    for subject in bootstrap.DEMO_USERS:
        state = records[subject]
        installation_id = example_authorization.SUBJECTS[subject][1]
        if (not isinstance(state, dict) or state.get("status") != "verified"
                or state.get("installation_id") != installation_id or not isinstance(state.get("bindings"), list)):
            raise RuntimeError("demo human role record differs from the exact own installation")
        expected = business_role_bindings(project, subject, installation_id)
        pinned = state["bindings"]
        if (len(pinned) != 2 or any(
            any(pinned_item.get(key) != value for key, value in expected_item.items()
                if key not in {"starts_at", "expires_at"})
            for pinned_item, expected_item in zip(pinned, expected)
        )):
            raise RuntimeError("owner role receipt does not pin exactly operator/v1 and skill_user/v2")
        profile = bootstrap.profile(api, subject)
        rows = profile.get("role_bindings")
        if not isinstance(rows, list):
            raise RuntimeError("demo user profile omitted current role bindings")
        expected_ids = {item["id"] for item in pinned} | set(allowed_extra[subject])
        active_ids = {item.get("id") for item in rows if isinstance(item, dict) and item.get("status") == "active"}
        if active_ids != expected_ids:
            raise RuntimeError("demo human has a missing or unplanned active role binding")
        for binding in pinned:
            live = [item for item in rows if isinstance(item, dict) and item.get("id") == binding["id"]]
            if len(live) != 1 or any(live[0].get(key) != value for key, value in binding.items()):
                raise RuntimeError("live own-installation business role differs from its exact owner receipt")
            try:
                starts = example_authorization.timestamp(binding["starts_at"])
                expiry = example_authorization.timestamp(binding["expires_at"])
            except (KeyError, ValueError):
                raise RuntimeError("own-installation role expiry is missing or invalid") from None
            if (starts > now + timedelta(minutes=2) or expiry <= now
                    or expiry > starts + BUSINESS_ROLE_DURATION + timedelta(minutes=2)):
                raise RuntimeError("own-installation role is expired or exceeds its bounded validity")
        for binding_id, agent_id in allowed_extra[subject].items():
            live = [item for item in rows if isinstance(item, dict) and item.get("id") == binding_id]
            if len(live) != 1:
                raise RuntimeError("temporary author binding is not uniquely visible")
            exact_role_binding(profile, binding_id, subject, project, agent_id, active=True)


def business_roles_phase(project: str, directory: Path, confirm=None) -> list[dict]:
    _directory, owner, _passwords = read_manifest(project)
    if not owner.get("identity_complete"):
        raise RuntimeError("business operator/Skill roles require completed isolated identities")
    if set(owner.get("policy_lifecycle", {})) != {row[1] for row in bootstrap.MACHINES} or any(
        owner.get("policy_lifecycle", {}).get(row[1], {}).get("published") is not True for row in bootstrap.MACHINES
    ):
        raise RuntimeError("business roles are assigned only after all three reviewed six-policy releases are published")
    verify_owner_frontend(project, directory, owner)
    api = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    definitions = api.call("GET", "/api/modules/identity/role-definitions")
    rows = definitions.get("items") if isinstance(definitions, dict) else None
    expected_roles = {("operator", 1): {"run", "discover", "cancel", "history.read", "model.generate", "model.embed", "tool.invoke", "knowledge.search", "memory.read", "memory.write"},
                      ("skill_user", 2): {"skill.load"}}
    for identity, actions in expected_roles.items():
        selected = [row for row in rows if isinstance(row, dict) and row.get("role_code") == identity[0]
                    and row.get("role_version") == identity[1]] if isinstance(rows, list) else []
        if (len(selected) != 1 or selected[0].get("assignable") is not True
                or "agent_installation" not in selected[0].get("scope_types", [])
                or not actions.issubset(set(selected[0].get("actions", [])))):
            raise RuntimeError("Identity role catalog does not expose the exact assignable installation-scoped operator/v1 and skill_user/v2 roles")
    records = owner.get("business_role_lifecycle") or {}
    if not isinstance(records, dict) or set(records) - set(bootstrap.DEMO_USERS):
        raise RuntimeError("owner business-role receipts contain an unknown principal")
    temporary_by_subject: dict[str, list[dict]] = {subject: [] for subject in bootstrap.DEMO_USERS}
    for agent_id, temporary in owner.get("temporary_author_roles", {}).items():
        if not isinstance(temporary, dict) or temporary.get("status") != "active":
            continue
        subject = temporary.get("subject")
        if subject not in temporary_by_subject:
            raise RuntimeError("active temporary author role is not assigned to an exact public demo user")
        profile = bootstrap.profile(api, subject)
        binding_id = temporary.get("binding_id")
        exact_role_binding(profile, binding_id, subject, project, agent_id, active=True)
        matches = [row for row in profile.get("role_bindings", []) if row.get("id") == binding_id]
        temporary_by_subject[subject].extend(matches)
    results = []
    for subject in bootstrap.DEMO_USERS:
        installation_id = example_authorization.SUBJECTS[subject][1]
        agent_id = next(row[1] for row in bootstrap.MACHINES if row[2] == installation_id)
        state = records.get(subject)
        profile = bootstrap.profile(api, subject)
        expected = business_role_bindings(project, subject, installation_id) if state is None else state.get("bindings")
        if not isinstance(expected, list) or len(expected) != 2:
            raise RuntimeError("owner did not pin the two exact role bindings for this human's own installation")
        current_prior_bindings = temporary_by_subject[subject]
        if state is None:
            current_bindings = profile.get("role_bindings")
            if (profile.get("principal", {}).get("is_active") is not True
                    or not bootstrap.active_membership(profile, subject, bootstrap.BUSINESS_SCOPE)
                    or not isinstance(current_bindings, list)
                    or sorted(row.get("id") for row in current_bindings if isinstance(row, dict)) != sorted(row["id"] for row in current_prior_bindings)
                    or profile.get("resource_grants") != [] or profile.get("task_assignments") != []):
                raise RuntimeError("business role-only assignment requires an active own-workspace user with no unexpected role/grant/assignment")
            principal_revision = profile["principal"].get("revision")
            if type(principal_revision) is not int or principal_revision < 1:
                raise RuntimeError("business role subject has no current Identity CAS revision")
            command = {"subject_type": "user", "subject_id": subject, "expected_revision": principal_revision,
                       "idempotency_key": "public-replay-business-role-" + project[-12:] + "-" + subject.replace(".", "-"),
                       "reason": "Assign only own-installation operator/v1 and Skill load role/v2 before separate explicit Resource Grants and indexing",
                       "role_bindings": expected}
            preview = api.call("POST", "/api/modules/identity/authorization-changes:preview", command)
            digest = assert_business_role_preview(preview, command, expected)
            phrase = project + " business roles " + subject + " " + digest
            print(json.dumps({"operation": "assign_exact_installation_scoped_business_roles", "subject": subject,
                              "installation_id": installation_id, "roles": ["operator/v1", "skill_user/v2"],
                              "preset": None, "default_grants": [], "confirmation": phrase}, ensure_ascii=False))
            if not confirm_digest_phrase(phrase, confirm):
                raise RuntimeError("business role-only Identity change was not confirmed")
            commit = dict(preview["change"], plan_digest=digest, plan_expires_at=preview["plan_expires_at"])
            receipt = api.call("POST", "/api/modules/identity/authorization-changes", commit)
            if (not isinstance(receipt, dict) or receipt.get("subject_id") != subject
                    or receipt.get("actor_id") != "system.admin" or receipt.get("revision") != principal_revision + 1
                    or receipt.get("plan_digest") != digest):
                raise RuntimeError("business role assignment receipt differs from exact Identity CAS preview")
            state = {"installation_id": installation_id, "agent_id": agent_id, "bindings": expected,
                     "preserved_temporary_bindings": current_prior_bindings,
                     "expected_revision": receipt["revision"],
                     "plan_digest": digest, "status": "committed", "receipt": receipt}
            records[subject] = state
            owner["business_role_lifecycle"] = records
            write_json_private(directory / "owner.json", owner)
        elif (not isinstance(state, dict) or state.get("installation_id") != installation_id
              or state.get("agent_id") != agent_id or state.get("status") not in {"committed", "verified"}
              or state.get("preserved_temporary_bindings") != current_prior_bindings
              or not isinstance(state.get("receipt"), dict)):
            raise RuntimeError("owner business role state differs from the live isolated author/binding lifecycle")
        expected_final_bindings = sorted(current_prior_bindings + expected, key=lambda row: row.get("id", ""))
        actual = bootstrap.profile(api, subject)
        if (actual.get("principal", {}).get("revision") != state.get("expected_revision")
                or actual.get("resource_grants") != profile.get("resource_grants")
                or actual.get("task_assignments") != profile.get("task_assignments")
                or actual.get("memberships") != profile.get("memberships")
                or actual.get("delegations") != profile.get("delegations")
                or sorted(actual.get("role_bindings", []), key=lambda row: row.get("id", "")) != expected_final_bindings):
            raise RuntimeError("business role readback changed other identity state or differs from the two own-installation bindings")
        state["status"] = "verified"
        owner["business_role_lifecycle"] = records
        write_json_private(directory / "owner.json", owner)
        results.append({"subject_id": subject, "installation_id": installation_id,
                        "role_bindings": [{"id": item["id"], "role_code": item["role_code"], "role_version": item["role_version"]} for item in expected],
                        "resource_grants_created": False})
    owner["business_roles_complete"] = True
    owner["business_role_lifecycle"] = records
    write_json_private(directory / "owner.json", owner)
    return results


def grant_id(project: str, subject: str, kind: str, action: str) -> str:
    suffix = project.removeprefix("agentplug-test-public-")
    value = "replay-grant-" + suffix + "-" + subject.replace(".", "-") + "-" + kind + "-" + action.replace(".", "-")
    if not example_authorization.token(value):
        raise ValueError("generated authorization Grant identifier is invalid")
    return value


def build_minimum_authorization_plan(project: str, policies: dict[str, tuple[dict, dict, dict]],
                                     expires_at: str, now: datetime | None = None) -> dict:
    """Create a reviewable, owner-scoped minimum Grant plan from live policy receipts."""
    owner = project_name(project)
    now = now or datetime.now(timezone.utc)
    expiry = example_authorization.timestamp(expires_at)
    if expiry <= now or expiry > now + timedelta(hours=24):
        raise ValueError("business Grants need an explicit expiry within the next 24 hours")
    expected_agents = {row[1] for row in bootstrap.MACHINES}
    if set(policies) != expected_agents:
        raise ValueError("minimum Grant plan requires live policy inventory for all three exact examples")
    allowed_resources: dict[str, list[dict]] = {}
    for machine_id, agent_id, installation_id, _prefix in bootstrap.MACHINES:
        snapshot, assets, _proof = policies[agent_id]
        model_id = public_policy.snapshot_value(snapshot, "ModelProfileID")
        memory_id = public_policy.snapshot_value(snapshot, "MemoryPolicyID")
        tool_content = assets.get("tool", {}).get("content")
        knowledge_content = assets.get("knowledge", {}).get("content")
        runtime_content = assets.get("runtime", {}).get("content")
        tools = tool_content.get("allowed_tools") if isinstance(tool_content, dict) else None
        scopes = knowledge_content.get("allowed_scopes") if isinstance(knowledge_content, dict) else None
        bindings = knowledge_content.get("document_bindings") if isinstance(knowledge_content, dict) else None
        skills = runtime_content.get("allowed_skills") if isinstance(runtime_content, dict) else None
        if (not example_authorization.token(model_id) or not example_authorization.token(memory_id)
                or not isinstance(tools, list) or "runtime.inspect" not in tools
                or not isinstance(scopes, list) or len(scopes) != 1 or not example_authorization.token(scopes[0])
                or not isinstance(bindings, list) or not bindings
                or any(not isinstance(item, dict) or item.get("knowledge_scope") != scopes[0]
                       or not item.get("provider_document_id") or not item.get("document_version")
                       or item.get("status") != "active" for item in bindings)
                or not isinstance(skills, list) or len(skills) != 1 or not example_authorization.token(skills[0])):
            raise RuntimeError("published model/memory/tool/knowledge/Skill policies do not expose the exact minimum replay resources")
        tuples = [
            {"resource_type": "model", "resource_id": model_id, "action": "model.generate"},
            {"resource_type": "model", "resource_id": model_id, "action": "model.embed"},
            {"resource_type": "tool", "resource_id": "runtime.inspect", "action": "tool.invoke"},
            {"resource_type": "knowledge", "resource_id": scopes[0], "action": "knowledge.search"},
            {"resource_type": "memory", "resource_id": memory_id, "action": "memory.read"},
            {"resource_type": "memory", "resource_id": memory_id, "action": "memory.write"},
            {"resource_type": "skill", "resource_id": skills[0], "action": "skill.load"},
        ]
        tuples.extend({"resource_type": "agent_installation", "resource_id": installation_id, "action": action}
                      for action in ("discover", "run", "cancel", "history.read"))
        # The resource allowlist describes reviewable platform policy tuples,
        # while each subject receives only its own minimum capability subset.
        allowed_resources[installation_id] = tuples

    changes = []
    starts_at = iso_utc(now)
    expiry_text = iso_utc(expiry)
    for subject, (subject_type, installation_id) in example_authorization.SUBJECTS.items():
        machine_id = next(row[0] for row in bootstrap.MACHINES if row[2] == installation_id)
        agent_id = next(row[1] for row in bootstrap.MACHINES if row[0] == machine_id)
        tuples = list(allowed_resources[installation_id])
        if subject_type == "service_principal":
            # Workload start goes through AuthenticateMachine(..., "run") and
            # checks the service principal's own installation permission.
            # Keep only that exact `run` tuple for machines; binding alone is
            # not sufficient, and machines still get no discover/cancel/
            # history or cross-installation permission.
            tuples = [row for row in tuples
                      if row["resource_type"] != "agent_installation"
                      or (row["resource_id"] == installation_id and row["action"] == "run")]
        grants = []
        for item in tuples:
            data_scope = {"type": "approved_organization"} if subject_type == "service_principal" else {"type": "owner"}
            grant = {"id": grant_id(project, subject, item["resource_type"], item["action"]),
                     **bootstrap.BUSINESS_SCOPE, "agent_instance_id": installation_id,
                     "subject_type": subject_type, "subject_id": subject,
                     **item, "effect": "allow", "status": "active", "revision": 1,
                     "source_id": "public-replay:" + project + ":minimum-grant-plan",
                     "data_scope": data_scope, "starts_at": starts_at, "expires_at": expiry_text}
            grants.append(grant)
        changes.append({"subject_id": subject, "subject_type": subject_type,
                        "scope": deepcopy(bootstrap.BUSINESS_SCOPE),
                        "reason": "Explicit time-bounded minimum Grant for the isolated public example replay",
                        "resource_grants": grants})
    plan = {"schema": "public-example-authorization/v1", "owner": project,
            "changes": changes, "allowed_resources": allowed_resources}
    return example_authorization.validate_plan(plan, owner, bootstrap.BUSINESS_SCOPE)


def expected_minimum_authorization_plan(project: str, policies: dict[str, tuple[dict, dict, dict]],
                                        plan: dict, now: datetime | None = None) -> dict:
    """Rebuild the expected tuples using the pinned plan's bounded validity window."""
    now = now or datetime.now(timezone.utc)
    changes = plan.get("changes") if isinstance(plan, dict) else None
    if not isinstance(changes, list):
        raise RuntimeError("minimum Grant plan has no pinned subject changes")
    grants = [grant for change in changes if isinstance(change, dict)
              for grant in change.get("resource_grants", []) if isinstance(grant, dict)]
    if len(grants) != 57:
        raise RuntimeError("minimum Grant plan must contain exactly 57 explicit grants")
    starts = {grant.get("starts_at") for grant in grants}
    expiries = {grant.get("expires_at") for grant in grants}
    if len(starts) != 1 or len(expiries) != 1 or not all(isinstance(value, str) and value for value in starts | expiries):
        raise RuntimeError("minimum Grant plan must pin one shared start and expiry across all subjects")
    start_text = next(iter(starts))
    expiry_text = next(iter(expiries))
    try:
        starts_at = example_authorization.timestamp(start_text)
        expires_at = example_authorization.timestamp(expiry_text)
    except (TypeError, ValueError):
        raise RuntimeError("minimum Grant plan validity window is malformed") from None
    if (starts_at > now + timedelta(minutes=2) or expires_at <= now
            or expires_at <= starts_at or expires_at > now + timedelta(hours=24)):
        raise RuntimeError("minimum Grant plan validity window is expired, future-dated or exceeds 24 hours")
    return build_minimum_authorization_plan(project, policies, iso_utc(expires_at), starts_at)


def audit_role_binding(project: str) -> dict:
    starts = datetime.now(timezone.utc).replace(microsecond=0)
    expires = starts + AUDIT_ROLE_DURATION
    return {"id": "public-replay-auditor-" + project.removeprefix("agentplug-test-public-"),
            "subject_id": "system.admin", "role_code": "auditor", "role_version": 1,
            "scope": {"scope_type": "application", **bootstrap.BUSINESS_SCOPE},
            "starts_at": iso_utc(starts), "expires_at": iso_utc(expires),
            "status": "active", "revision": 1,
            "source_id": "public-replay-auditor:" + project}


def verify_audit_role(api: bootstrap.BrowserAPI, owner: dict, project: str, require_active: bool = True) -> dict:
    state = owner.get("audit_role")
    binding = state.get("binding") if isinstance(state, dict) else None
    if not isinstance(binding, dict) or state.get("status") not in {"active", "revoked"}:
        raise RuntimeError("system.admin has no owner-journaled explicit auditor role lifecycle")
    expected = audit_role_binding(project)
    if any(binding.get(key) != value for key, value in expected.items()
           if key not in {"starts_at", "expires_at", "status", "revision"}):
        raise RuntimeError("audit role journal differs from the exact system.admin app-demo binding")
    expected_status = "active" if state.get("status") == "active" else "revoked"
    expected_revision = 1 if expected_status == "active" else 2
    if binding.get("status") != expected_status or binding.get("revision") != expected_revision:
        raise RuntimeError("audit role lifecycle status/revision differs from its exact normal API receipt")
    try:
        starts = example_authorization.timestamp(binding["starts_at"])
        expiry = example_authorization.timestamp(binding["expires_at"])
    except (KeyError, ValueError):
        raise RuntimeError("audit role validity is missing or malformed") from None
    now = datetime.now(timezone.utc)
    if (starts > now + timedelta(minutes=2) or expiry > starts + AUDIT_ROLE_DURATION + timedelta(minutes=2)
            or (require_active and expiry <= now)):
        raise RuntimeError("system.admin auditor binding is expired or exceeds its short validity")
    profile = bootstrap.profile(api, "system.admin")
    rows = profile.get("role_bindings")
    matches = [row for row in rows if isinstance(row, dict) and row.get("id") == binding["id"]] if isinstance(rows, list) else []
    if len(matches) != 1 or matches[0] != binding:
        raise RuntimeError("live system.admin auditor binding differs from its exact receipt")
    return binding


def audit_role_phase(project: str, directory: Path, revoke: bool = False, confirm=None) -> dict:
    _directory, owner, _passwords = read_manifest(project)
    if not owner.get("identity_complete"):
        raise RuntimeError("auditor role requires the isolated system.admin identity")
    verify_owner_frontend(project, directory, owner)
    api = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    existing = owner.get("audit_role")
    if revoke:
        if not isinstance(existing, dict) or existing.get("status") != "active":
            raise RuntimeError("no exact active owner-journaled auditor role is available to revoke")
        journals = owner.get("business_replay_journal", {})
        if not owner.get("business_audit_complete"):
            raise RuntimeError("the temporary auditor role remains until all three replay, usage and isolation checks are complete")
        binding = verify_audit_role(api, owner, project)
        command = {"subject_type": "user", "subject_id": "system.admin",
                   "expected_revision": bootstrap.profile(api, "system.admin")["principal"]["revision"],
                   "idempotency_key": "public-replay-auditor-revoke-" + project[-12:],
                   "reason": "Revoke the short-lived auditor role after the isolated replay audit is complete",
                   "revoke_binding_ids": [binding["id"]]}
    else:
        if existing is not None:
            if not isinstance(existing, dict) or existing.get("status") != "active":
                raise RuntimeError("owner has an earlier auditor lifecycle; it cannot be silently replaced")
            return verify_audit_role(api, owner, project)
        principal = bootstrap.profile(api, "system.admin")
        p = principal.get("principal") if isinstance(principal, dict) else None
        if (not isinstance(p, dict) or p.get("id") != "system.admin" or p.get("type") != "user"
                or p.get("is_active") is not True or principal.get("resource_grants") != []
                or principal.get("task_assignments") != [] or not bootstrap.active_membership(principal, "system.admin", bootstrap.BUSINESS_SCOPE)):
            raise RuntimeError("system.admin must remain an active workspace member without business grants or assignments")
        definitions = api.call("GET", "/api/modules/identity/role-definitions")
        roles = definitions.get("items") if isinstance(definitions, dict) else None
        matches = [row for row in roles if isinstance(row, dict) and row.get("role_code") == "auditor" and row.get("role_version") == 1] if isinstance(roles, list) else []
        expected_actions = {"audit.metadata.read", "authorization.read", "audit.content.read", "audit.export"}
        if (len(matches) != 1 or matches[0].get("assignable") is not True
                or "application" not in matches[0].get("scope_types", [])
                or set(matches[0].get("actions", [])) != expected_actions):
            raise RuntimeError("Identity auditor/v1 catalog differs from the exact currently published audit action set")
        binding = audit_role_binding(project)
        revision = p.get("revision")
        if type(revision) is not int or revision < 1:
            raise RuntimeError("system.admin principal has no current Identity CAS revision")
        command = {"subject_type": "user", "subject_id": "system.admin", "expected_revision": revision,
                   "idempotency_key": "public-replay-auditor-grant-" + project[-12:],
                   "reason": "Temporarily grant exact app-demo auditor role for Usage metadata verification",
                   "role_bindings": [binding]}
    if revoke and (type(command["expected_revision"]) is not int or command["expected_revision"] < 1):
        raise RuntimeError("system.admin principal has no current Identity CAS revision")
    preview = api.call("POST", "/api/modules/identity/authorization-changes:preview", command)
    expected_bindings = [] if revoke else [binding]
    if revoke:
        # A revoke preview has no expanded additions. Validate its exact
        # journaled revoke IDs rather than the grant-only role preview shape.
        assert_role_preview(preview, command, "system.admin", None)
        digest = preview["plan_digest"]
    else:
        digest = assert_business_role_preview(preview, command, expected_bindings)
    phrase = project + (" revoke auditor system.admin " if revoke else " grant auditor system.admin ") + digest
    print(json.dumps({"operation": "revoke_short_lived_auditor_role" if revoke else "grant_short_lived_auditor_role",
                      "subject": "system.admin", "role": "auditor/v1", "scope": "app-demo",
                      "expires_at": binding.get("expires_at"), "resource_grants": [],
                      "confirmation": phrase}, ensure_ascii=False))
    if not confirm_digest_phrase(phrase, confirm):
        raise RuntimeError("explicit auditor role change was not confirmed")
    before = bootstrap.profile(api, "system.admin")
    before_bindings = before.get("role_bindings")
    if not isinstance(before_bindings, list):
        raise RuntimeError("system.admin role profile omitted role binding readback")
    commit = dict(preview["change"], plan_digest=digest, plan_expires_at=preview["plan_expires_at"])
    receipt = api.call("POST", "/api/modules/identity/authorization-changes", commit)
    principal_revision = before["principal"].get("revision")
    if (not isinstance(receipt, dict) or receipt.get("actor_id") != "system.admin"
            or receipt.get("subject_id") != "system.admin" or receipt.get("revision") != principal_revision + 1
            or receipt.get("plan_digest") != digest):
        raise RuntimeError("auditor role CAS receipt differs from its separately confirmed preview")
    after = bootstrap.profile(api, "system.admin")
    if revoke:
        expected_profile_bindings = [dict(row, status="revoked", revision=row.get("revision", 1) + 1)
                                     if isinstance(row, dict) and row.get("id") == binding["id"] else row
                                     for row in before_bindings]
    else:
        expected_profile_bindings = before_bindings + [binding]
    if (after.get("principal", {}).get("revision") != principal_revision + 1
            or after.get("memberships") != before.get("memberships")
            or after.get("resource_grants") != [] or after.get("resource_grants") != before.get("resource_grants")
            or after.get("task_assignments") != before.get("task_assignments")
            or after.get("delegations") != before.get("delegations")
            or sorted(after.get("role_bindings", []), key=lambda row: row.get("id", ""))
               != sorted(expected_profile_bindings, key=lambda row: row.get("id", ""))):
        raise RuntimeError("auditor role mutation changed business Grants or unrelated system.admin identity state")
    if revoke:
        revoked = [row for row in after["role_bindings"] if row.get("id") == binding["id"]]
        if (len(revoked) != 1 or revoked[0].get("status") != "revoked"
                or revoked[0].get("revision") != binding["revision"] + 1):
            raise RuntimeError("auditor role revoke did not read back the exact revoked binding")
        owner["audit_role"]["status"] = "revoked"
        owner["audit_role"]["revoke_plan_digest"] = digest
        owner["audit_role"]["binding"] = revoked[0]
    else:
        owner["audit_role"] = {"status": "active", "binding": binding, "grant_plan_digest": digest}
    write_json_private(directory / "owner.json", owner)
    return owner["audit_role"]


def assert_minimum_authorization_plan(plan: dict, expected: dict) -> None:
    if plan.get("allowed_resources") != expected.get("allowed_resources"):
        raise RuntimeError("authorization plan is not the exact per-installation policy-backed minimum allowlist")
    actual_changes = {row["subject_id"]: row for row in plan.get("changes", [])}
    expected_changes = {row["subject_id"]: row for row in expected.get("changes", [])}
    if set(actual_changes) != set(example_authorization.SUBJECTS) or set(expected_changes) != set(actual_changes):
        raise RuntimeError("authorization plan must cover exactly the three demo users and three matching machines")
    for subject, expected_change in expected_changes.items():
        actual_change = actual_changes[subject]
        actual_grants = actual_change.get("resource_grants")
        expected_grants = expected_change["resource_grants"]
        expected_tuples = sorted(example_authorization.resource_tuple(item) for item in expected_grants)
        actual_tuples = sorted(example_authorization.resource_tuple(item) for item in actual_grants)
        expected_scope = {"type": "owner"} if expected_change["subject_type"] == "user" else {"type": "approved_organization"}
        expected_by_tuple = {example_authorization.resource_tuple(item): item for item in expected_grants}
        if (actual_tuples != expected_tuples
                or any(item.get("data_scope") != expected_scope for item in actual_grants)
                or any(item.get("id") != expected_by_tuple[example_authorization.resource_tuple(item)].get("id")
                       or item.get("source_id") != "public-replay:" + plan["owner"] + ":minimum-grant-plan"
                       or item.get("starts_at") != expected_by_tuple[example_authorization.resource_tuple(item)].get("starts_at")
                       or item.get("expires_at") != expected_by_tuple[example_authorization.resource_tuple(item)].get("expires_at")
                       for item in actual_grants)):
            raise RuntimeError("authorization plan adds, omits or broadens a minimum Grant, data scope or provenance")


def mark_authorization_attempt_failure(owner: dict, exc: Exception) -> bool:
    """Record a denied read-only preview without claiming a Grant commit was attempted."""
    attempt = owner.get("authorization_attempt") if isinstance(owner, dict) else None
    journal = owner.get("authorization_journal") if isinstance(owner, dict) else None
    if not isinstance(attempt, dict) or (journal not in (None, [])):
        return False
    if not isinstance(exc, bootstrap.APIError):
        return False
    match = re.match(r"^([A-Z]+) (\S+) failed:", str(exc))
    if (match is None or match.group(1) != "POST"
            or match.group(2) != "/api/modules/identity/authorization-changes:preview"
            or exc.status != 403 or exc.code != "PERMISSION_DENIED"):
        return False
    prior = attempt.get("status")
    history = attempt.setdefault("status_history", [])
    if not isinstance(history, list):
        raise RuntimeError("authorization attempt status history is malformed")
    if prior and prior not in history:
        history.append(prior)
    attempt["status"] = "preview_denied"
    attempt["last_failure"] = {"stage": "preview", "method": "POST",
                               "path": "/api/modules/identity/authorization-changes:preview",
                               "http_status": exc.status, "api_code": exc.code,
                               "grant_commit_attempted": False}
    return True


def verify_supersedable_minimum_authorization_plan(project: str, directory: Path, owner: dict) -> dict | None:
    """Allow only the known, uncommitted 54-grant plan to be replaced once."""
    pin = owner.get("authorization_plan")
    if pin is None:
        return None
    if (not isinstance(pin, dict) or owner.get("authorization_complete") is True
            or owner.get("authorization_attempt") is not None
            or owner.get("permission_admin_delegations") != []):
        raise RuntimeError("an authorization plan is already in use; it cannot be replaced after delegation or Grant application starts")
    old_plan, relative = private_plan_file(
        project, directory, Path(pin.get("path", "")), "public-example-authorization/v1")
    old_plan = example_authorization.validate_plan(old_plan, project, bootstrap.BUSINESS_SCOPE)
    digest = hashlib.sha256(example_authorization.canonical(old_plan)).hexdigest()
    old_grants = [grant for change in old_plan["changes"] for grant in change["resource_grants"]]
    old_changes = {change["subject_id"]: change for change in old_plan["changes"]}
    expected_subjects = set(example_authorization.SUBJECTS)
    expected_counts = {subject: (7 if kind == "service_principal" else 11)
                       for subject, (kind, _installation) in example_authorization.SUBJECTS.items()}
    exact_minimum = set(old_changes) == expected_subjects
    for subject, (kind, installation) in example_authorization.SUBJECTS.items():
        change = old_changes.get(subject)
        if not isinstance(change, dict):
            exact_minimum = False
            continue
        allowed = old_plan["allowed_resources"].get(installation, [])
        expected_tuples = {example_authorization.resource_tuple(item) for item in allowed
                           if item["resource_type"] != "agent_installation"}
        if kind == "user":
            expected_tuples |= {example_authorization.resource_tuple(item) for item in allowed
                                if item["resource_type"] == "agent_installation"}
        actual_tuples = {example_authorization.resource_tuple(item) for item in change["resource_grants"]}
        expected_scope = {"type": "owner"} if kind == "user" else {"type": "approved_organization"}
        if (len(change["resource_grants"]) != expected_counts[subject]
                or actual_tuples != expected_tuples
                or any(grant.get("data_scope") != expected_scope
                       or grant.get("id") != grant_id(project, subject, grant["resource_type"], grant["action"])
                       or grant.get("source_id") != "public-replay:" + project + ":minimum-grant-plan"
                       for grant in change["resource_grants"])):
            exact_minimum = False
    if (relative != pin.get("path") or digest != pin.get("plan_sha256")
            or len(old_plan["changes"]) != 6 or len(old_grants) != 54
            or not exact_minimum
            or any(grant["resource_type"] == "agent_installation"
                   for change in old_plan["changes"] if change["subject_type"] == "service_principal"
                   for grant in change["resource_grants"])):
        raise RuntimeError("existing authorization plan is not the known unapplied 54-Grant plan revision")
    return deepcopy(pin)


def prepare_authorization_plan(project: str, directory: Path, output: Path,
                               duration_minutes: int) -> Path:
    _directory, owner, _passwords = read_manifest(project)
    if (not owner.get("identity_complete") or not owner.get("services_ready")
            or not owner.get("machines_complete") or not owner.get("business_roles_complete")
            or owner.get("authorization_complete")):
        raise RuntimeError("minimum Grant planning requires identities, services, machines and the separate own-install role-only stage")
    if type(duration_minutes) is not int or not 5 <= duration_minutes <= 24 * 60:
        raise ValueError("Grant plan expiry must be explicitly bounded from 5 minutes through 24 hours")
    superseded_pin = verify_supersedable_minimum_authorization_plan(project, directory, owner)
    verify_owner_frontend(project, directory, owner)
    verify_example_container_health(project, directory)
    api = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    profile = bootstrap.profile(api, "system.admin")
    if profile.get("resource_grants") != [] or profile.get("task_assignments") != []:
        raise RuntimeError("system.admin cannot receive business resource grants or task assignments")
    verify_catalog_installation_readiness(api)
    plans = load_pinned_release_plans(project, directory, owner)
    policies = {agent_id: live_policy_inventory(api, project, directory, owner, release)
                for agent_id, release in plans.items()}
    versions = {row[0]: plans[row[1]]["version"]["id"] for row in bootstrap.MACHINES}
    installation_versions = {plans[row[1]]["installation"]["id"]: plans[row[1]]["version"]["id"]
                             for row in bootstrap.MACHINES}
    verify_model_access_policy_receipts(api, owner, installation_versions)
    instant = datetime.now(timezone.utc).replace(microsecond=0)
    expires_at = iso_utc(instant + timedelta(minutes=duration_minutes))
    plan = build_minimum_authorization_plan(project, policies, expires_at, instant)
    plan = example_authorization.validate_plan(plan, project, bootstrap.BUSINESS_SCOPE)
    if len(plan["changes"]) != 6 or sum(len(row["resource_grants"]) for row in plan["changes"]) != 57:
        raise RuntimeError("minimum authorization plan did not enumerate the exact six-principal 57-Grant boundary")
    target = owner_private_output(directory, output)
    relative = target.relative_to(directory.resolve()).as_posix()
    pin = {"path": relative, "plan_sha256": hashlib.sha256(example_authorization.canonical(plan)).hexdigest(),
           "expires_at": expires_at, "subject_count": 6, "grant_count": 57,
           "policy_snapshot_revisions": {agent_id: public_policy.snapshot_value(value[0], "Revision")
                                          for agent_id, value in policies.items()}}
    _current_directory, current_owner, _current_passwords = read_manifest(project)
    if current_owner.get("authorization_plan") != owner.get("authorization_plan"):
        raise RuntimeError("owner authorization plan changed during preparation; no plan was repinned")
    if superseded_pin is not None and (current_owner.get("authorization_complete") is True
            or current_owner.get("authorization_attempt") is not None
            or current_owner.get("permission_admin_delegations") != []):
        raise RuntimeError("delegation or authorization began during plan preparation; no plan was repinned")
    bootstrap.write_new_private_file(target, json.dumps(plan, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    if superseded_pin is not None:
        current_owner.setdefault("superseded_authorization_plans", []).append({
            **superseded_pin,
            "superseded_by": relative,
            "reason": "source audit requires each workload principal's own-installation run grant",
            "replacement_plan_sha256": pin["plan_sha256"],
        })
    current_owner["authorization_plan"] = pin
    write_json_private(directory / "owner.json", current_owner)
    print(json.dumps({"result": "exact_minimum_authorization_plan_saved", "project": project,
                      "path": relative, "subjects": 6, "grants": 57,
                      "expires_at": expires_at, "manager_business_grants": 0,
                      "api_writes": False}, ensure_ascii=False))
    return target


def temporary_author_role_phase(project: str, directory: Path, agent_id: str, actor: str, subject: str,
                                confirm_resource: str, revoke: bool = False, confirm=None) -> None:
    if actor != "system.admin" or subject not in bootstrap.DEMO_USERS:
        raise ValueError("only system.admin may manage a temporary role for one of the three demo authors")
    if confirm_resource != ("revoke:" if revoke else "grant:") + agent_id + ":" + subject:
        raise ValueError("temporary role stage requires exact Agent and author confirmation")
    _directory, owner, _passwords = read_manifest(project)
    if not owner.get("identity_complete") or not owner.get("services_ready"):
        raise RuntimeError("temporary role lifecycle requires isolated human identities and healthy source example services")
    binding_id = role_binding_id(project, agent_id)
    history = owner.setdefault("temporary_author_roles", {})
    previous = history.get(agent_id)
    api = owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE)
    current = bootstrap.profile(api, subject)
    principal = current["principal"]
    if principal.get("is_active") is not True or not bootstrap.active_membership(current, subject, bootstrap.BUSINESS_SCOPE):
        raise RuntimeError("temporary author role requires the exact active demo user and app-demo membership")
    revision = principal.get("revision")
    if type(revision) is not int or revision < 1:
        raise RuntimeError("temporary author principal has no usable CAS revision")
    if revoke:
        if not isinstance(previous, dict) or previous.get("subject") != subject or previous.get("binding_id") != binding_id or previous.get("status") != "active":
            raise RuntimeError("no matching owner-recorded active temporary author role can be revoked")
        if owner.get("catalog_lifecycle", {}).get(agent_id, {}).get("author") != subject:
            raise RuntimeError("only the exact recorded Catalog author may have its temporary role revoked")
        catalog = owner.get("catalog_lifecycle", {}).get(agent_id, {})
        skill_records = owner.get("skill_lifecycle", {}).get(agent_id, {})
        policy = owner.get("policy_lifecycle", {}).get(agent_id, {})
        index = owner.get("knowledge_index_lifecycle", {}).get(agent_id, {})
        if (not owner.get("business_roles_complete") or not owner.get("authorization_complete")
                or not catalog.get("active_installation") or policy.get("published") is not True
                or not index.get("index_publication_verified")
                or not any(isinstance(row, dict) and row.get("author") == subject and row.get("reviewer") == "system.admin" and row.get("publisher") == "system.admin" for row in skill_records.values())):
            raise RuntimeError("temporary author role remains until exact policy, Skill, Grant and Knowledge indexing stages verify")
        exact_role_binding(current, binding_id, subject, project, agent_id, active=True)
        business_state = owner.get("business_role_lifecycle", {}).get(subject, {})
        business_bindings = business_state.get("bindings") if isinstance(business_state, dict) else None
        if (not isinstance(business_bindings, list) or len(business_bindings) != 2
                or sorted(item.get("id") for item in current.get("role_bindings", []) if isinstance(item, dict))
                != sorted([binding_id, *(item.get("id") for item in business_bindings)])):
            raise RuntimeError("temporary role revocation refuses to modify any role except its own author binding and two pinned business roles")
        command = {"subject_type": "user", "subject_id": subject, "expected_revision": revision,
                   "idempotency_key": "public-replay-role-revoke-" + project[-12:] + "-" + agent_id,
                   "reason": "Revoke the isolated public release author role after exact policy, Skill, Grant and Knowledge indexing stages",
                   "revoke_binding_ids": [binding_id]}
        binding = None
    else:
        if previous is not None:
            raise RuntimeError("temporary author role stage cannot be replayed or overwrite an existing role")
        if current.get("role_bindings") != [] or current.get("resource_grants") != []:
            raise RuntimeError("temporary role may only be added to a demo user with no prior roles or capability grants")
        roles = api.call("GET", "/api/modules/identity/role-definitions")
        definitions = roles.get("items") if isinstance(roles, dict) else None
        selected = [row for row in definitions if isinstance(row, dict) and row.get("role_code") == AUTHOR_ROLE and row.get("role_version") == 1] if isinstance(definitions, list) else []
        if len(selected) != 1 or not selected[0].get("assignable") or "application" not in selected[0].get("scope_types", []) or not {"agent.develop", "release.submit", "policy.manage"}.issubset(set(selected[0].get("actions", []))):
            raise RuntimeError("current Identity role definition does not match the narrowly intended Agent/Skill author role")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        binding = {"id": binding_id, "subject_id": subject, "role_code": AUTHOR_ROLE, "role_version": 1,
                   "scope": {"scope_type": "application", **bootstrap.BUSINESS_SCOPE},
                   "starts_at": now.isoformat().replace("+00:00", "Z"),
                   "expires_at": (now + ROLE_DURATION).isoformat().replace("+00:00", "Z"),
                   "status": "active", "revision": 1, "source_id": "public-replay:" + project + ":" + agent_id}
        command = {"subject_type": "user", "subject_id": subject, "expected_revision": revision,
                   "idempotency_key": "public-replay-role-grant-" + project[-12:] + "-" + agent_id,
                   "reason": "Temporarily authorize the selected public Agent author to submit Catalog and register its Skill",
                   "role_bindings": [binding]}
    preview = api.call("POST", "/api/modules/identity/authorization-changes:preview", command)
    assert_role_preview(preview, command, actor, binding)
    phrase = project + (" revoke " if revoke else " grant ") + subject + " " + binding_id + " " + preview["plan_digest"]
    if confirm is None:
        confirm = lambda expected: input("Type the exact Identity preview confirmation shown above: ") == expected
    print(json.dumps({"phase": "revoke_preview" if revoke else "grant_preview", "project": project,
                      "subject": subject, "role": AUTHOR_ROLE, "scope": "app-demo", "binding_id": binding_id,
                      "plan_digest": preview["plan_digest"], "confirmation": phrase,
                      "business_resource_grants": [], "credential_values_printed": False}, ensure_ascii=False))
    if not confirm(phrase):
        raise RuntimeError("temporary author role change was not confirmed")
    commit = dict(preview["change"], plan_digest=preview["plan_digest"], plan_expires_at=preview["plan_expires_at"])
    receipt = api.call("POST", "/api/modules/identity/authorization-changes", commit)
    if not isinstance(receipt, dict) or receipt.get("subject_id") != subject or receipt.get("actor_id") != actor or receipt.get("revision") != revision + 1 or receipt.get("plan_digest") != preview["plan_digest"]:
        raise RuntimeError("temporary role authorization CAS receipt differs from the reviewed plan")
    after = bootstrap.profile(api, subject)
    after_principal = after.get("principal")
    before_principal = dict(principal)
    actual_principal = dict(after_principal) if isinstance(after_principal, dict) else {}
    before_principal.pop("revision", None)
    before_principal.pop("roles", None)
    actual_principal.pop("revision", None)
    actual_principal.pop("roles", None)
    if (not isinstance(after_principal, dict) or after_principal.get("revision") != revision + 1
            or actual_principal != before_principal or after.get("memberships") != current.get("memberships")
            or after.get("delegations") != current.get("delegations")
            or after.get("task_assignments") != current.get("task_assignments")
            or after.get("resource_grants") != current.get("resource_grants")):
        raise RuntimeError("temporary role authorization changed identity, membership, delegation, assignment or business grant state")
    expected_binding_ids = ({item["id"] for item in owner.get("business_role_lifecycle", {}).get(subject, {}).get("bindings", [])} | {binding_id}) if revoke else {binding_id}
    if (not isinstance(after.get("role_bindings"), list)
            or {row.get("id") for row in after["role_bindings"] if isinstance(row, dict)} != expected_binding_ids):
        raise RuntimeError("temporary role mutation readback contains a missing or additional role binding")
    if revoke:
        exact_role_binding(after, binding_id, subject, project, agent_id, active=False)
        previous["status"] = "revoked"
        previous["revoke_plan_digest"] = preview["plan_digest"]
    else:
        exact_role_binding(after, binding_id, subject, project, agent_id, active=True)
        history[agent_id] = {"subject": subject, "binding_id": binding_id, "status": "active",
                             "grant_plan_digest": preview["plan_digest"]}
    write_json_private(directory / "owner.json", owner)
    print(json.dumps({"result": "temporary_author_role_revoked" if revoke else "temporary_author_role_verified",
                      "project": project, "agent_id": agent_id, "subject": subject, "role": AUTHOR_ROLE,
                      "binding_id": binding_id, "business_resource_grants": [], "plan_digest": preview["plan_digest"]}, ensure_ascii=False))


def require_temporary_author_role(project: str, directory: Path, agent_id: str, subject: str) -> dict:
    _directory, owner, _passwords = read_manifest(project)
    state = owner.get("temporary_author_roles", {}).get(agent_id)
    binding_id = role_binding_id(project, agent_id)
    if not isinstance(state, dict) or state.get("subject") != subject or state.get("binding_id") != binding_id or state.get("status") != "active":
        raise RuntimeError("Catalog/Skill author stage requires the exact owner-recorded active temporary Agent developer role")
    api = owner_human_api(project, directory, subject, bootstrap.BUSINESS_SCOPE)
    current = bootstrap.profile(api, subject)
    exact_role_binding(current, binding_id, subject, project, agent_id, active=True)
    return state


def catalog_single_request(plan: dict, stage: str, suffix: str | None = None) -> dict:
    candidates = [item for item in plan["requests"] if item.get("stage") == stage and item.get("method") == "POST"]
    if suffix is not None:
        candidates = [item for item in candidates if item.get("path", "").split("?", 1)[0].endswith(suffix)]
    if len(candidates) != 1:
        raise RuntimeError(f"public Catalog plan has no unique {stage} request for the exact phase")
    return candidates[0]


def catalog_optional_request(plan: dict, stage: str, suffix: str) -> dict | None:
    candidates = [item for item in plan["requests"] if item.get("stage") == stage and item.get("method") == "POST" and item.get("path", "").split("?", 1)[0].endswith(suffix)]
    if len(candidates) > 1:
        raise RuntimeError(f"public Catalog plan has duplicate {stage} requests")
    return candidates[0] if candidates else None


def catalog_request_for_kind(plan: dict, stage: str, kind: str, action: str) -> dict | None:
    prefix = "/api/modules/catalog/{}/".format("definitions" if kind == "definition" else "versions")
    candidates = [item for item in plan["requests"] if item.get("stage") == stage and item.get("method") == "POST" and item.get("path", "").split("?", 1)[0].startswith(prefix) and item.get("path", "").split("?", 1)[0].endswith("/" + action)]
    if len(candidates) > 1:
        raise RuntimeError(f"public Catalog plan has duplicate {stage} requests for {kind}")
    return candidates[0] if candidates else None


def save_catalog_receipt(project: str, directory: Path, plan: dict, field: str, actor: str) -> None:
    agent_id = plan["agent_id"]
    _directory, owner, _passwords = read_manifest(project)
    records = owner.setdefault("catalog_lifecycle", {})
    record = records.setdefault(agent_id, {})
    pin = {"agent_id": agent_id, "definition_id": plan["definition"]["id"],
           "version_id": plan["version"]["id"], "installation_id": plan["installation"]["id"],
           "deployment_id": plan["deployment"]["id"], "artifact_digest": plan["version"]["artifact_digest"],
           "manifest_hash": plan["bundle"]["manifest_hash"]}
    if record.get("release") not in (None, pin):
        raise RuntimeError("isolated Catalog lifecycle already pins a different immutable release")
    record["release"] = pin
    previous = record.get(field)
    if previous is not None and previous != actor:
        raise RuntimeError("isolated Catalog lifecycle already records a different human for this phase")
    record[field] = actor
    write_json_private(directory / "owner.json", owner)


def maybe_get(api: bootstrap.BrowserAPI, path: str) -> dict | None:
    try:
        value = api.call("GET", path)
    except bootstrap.APIError as error:
        if error.status == 404 and error.code in {"RESOURCE_NOT_FOUND", "NOT_FOUND"}:
            return None
        raise
    if not isinstance(value, dict):
        raise RuntimeError("Catalog/Skill GET returned an invalid object")
    return value


def catalog_version_path(plan: dict) -> str:
    return "/api/modules/catalog/versions/" + bootstrap.urllib.parse.quote(plan["version"]["id"], safe="")


def catalog_definition_path(plan: dict) -> str:
    return "/api/modules/catalog/definitions/" + bootstrap.urllib.parse.quote(plan["definition"]["id"], safe="")


def catalog_install_path(plan: dict) -> str:
    return "/api/modules/catalog/installations/" + bootstrap.urllib.parse.quote(plan["installation"]["id"], safe="")


def check_catalog_revision(value: dict, expected_id: str) -> int:
    if value.get("id") != expected_id or type(value.get("revision")) is not int or value["revision"] < 1:
        raise RuntimeError("live Catalog object identity or revision is invalid")
    return value["revision"]


def verify_catalog_author_draft(current: dict | None, expected: dict, actor: str, label: str) -> None:
    if (not isinstance(current, dict)
            or any(current.get(key) != value for key, value in expected.items())
            or current.get("submitted_by") != actor
            or current.get("status") != "draft"):
        raise RuntimeError(f"Catalog {label} does not match the exact release request as this author's Draft")


def catalog_submit_phase(project: str, directory: Path, plan: dict, actor: str, confirm_resource: str) -> None:
    expected_id = plan["version"]["id"]
    if confirm_resource != expected_id or plan["definition"].get("publisher_id") != actor:
        raise ValueError("Catalog submit requires the exact new Version ID and the plan's authenticated publisher")
    require_temporary_author_role(project, directory, plan["agent_id"], actor)
    api = owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE)
    # Definitions and Versions form the platform-wide Catalog. A scoped
    # release.submit author may create its own release but intentionally lacks
    # global Catalog read access. Use the separate control-plane administrator
    # only for exact-ID preflight/readback; all author-bound POSTs remain under
    # the independently authenticated demo author.
    reader = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    def_path, ver_path = catalog_definition_path(plan), catalog_version_path(plan)
    definition = maybe_get(reader, def_path)
    version = maybe_get(reader, ver_path)
    for current, expected, label in ((definition, plan["definition"], "Definition"), (version, plan["version"], "Version")):
        if current is None:
            continue
        verify_catalog_author_draft(current, expected, actor, label)
    submit_definition = catalog_optional_request(plan, "submit", "/definitions")
    submit_version = catalog_single_request(plan, "submit", "/versions")
    if definition is None:
        if submit_definition is None:
            raise RuntimeError("fresh-project Catalog plan lacks a new Definition submission")
        api.call("POST", submit_definition["path"], submit_definition["body"])
        definition = maybe_get(reader, def_path)
        verify_catalog_author_draft(definition, plan["definition"], actor, "Definition")
    if version is None:
        if not isinstance(submit_version.get("body"), dict) or submit_version["body"].get("manifest", {}).get("agent_id") != plan["agent_id"]:
            raise RuntimeError("Catalog Version submission is outside the reviewed example plan")
        api.call("POST", submit_version["path"], submit_version["body"])
        version = maybe_get(reader, ver_path)
        verify_catalog_author_draft(version, plan["version"], actor, "Version")
    save_catalog_receipt(project, directory, plan, "author", actor)
    print(json.dumps({"result": "catalog_definition_and_version_drafts_verified", "project": project,
                      "agent_id": plan["agent_id"], "definition_id": plan["definition"]["id"],
                      "version_id": expected_id, "author": actor, "global_catalog_readback_by": "system.admin"}, ensure_ascii=False))


def catalog_evaluate_phase(project: str, directory: Path, plan: dict, actor: str, confirm_resource: str) -> None:
    if actor != "system.admin":
        raise ValueError("Catalog evaluation is a control-plane operation for the separately authenticated system.admin")
    if confirm_resource != plan["version"]["id"]:
        raise ValueError("Catalog evaluation requires the exact public Version ID")
    api = owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE)
    requests = [catalog_request_for_kind(plan, "evaluate", "definition", "evaluate"),
                catalog_request_for_kind(plan, "evaluate", "version", "evaluate")]
    preflight = []
    for request in requests:
        if request is None:
            continue
        object_id = request["path"].rsplit("/", 2)[-2]
        is_definition = "/definitions/" in request["path"]
        path = (catalog_definition_path(plan) if is_definition else catalog_version_path(plan))
        current = maybe_get(api, path)
        if current is None or not current.get("submitted_by") or current.get("submitted_by") == actor:
            raise RuntimeError("Catalog evaluator must be a different human from the recorded submitter")
        revision = check_catalog_revision(current, object_id)
        if current.get("status") not in {"draft", "evaluated"}:
            raise RuntimeError("Catalog evaluation requires the exact current Draft state")
        preflight.append((request, path, current))
    run_example_source_tests(plan["agent_id"], plan["version"]["id"])
    for request, path, current in preflight:
        if current.get("status") == "evaluated":
            continue
        revision = check_catalog_revision(current, current.get("id", ""))
        api.call("POST", request["path"], {"expected_revision": revision})
        after = maybe_get(api, path)
        if after is None or after.get("status") != "evaluated" or after.get("revision") != revision + 1:
            raise RuntimeError("Catalog evaluation did not verify at its next live revision")
    save_catalog_receipt(project, directory, plan, "evaluator", actor)
    print(json.dumps({"result": "catalog_definition_and_version_evaluation_verified", "project": project,
                      "agent_id": plan["agent_id"], "evaluator": actor}, ensure_ascii=False))


def java_maven_invocation(executable: str, arguments: list[str], windows: bool | None = None) -> list[str]:
    """Build a safely quoted command line for Maven, including Windows batch launchers."""
    is_windows = os.name == "nt" if windows is None else windows
    executable = str(executable)
    if is_windows and Path(executable).suffix.lower() in {".cmd", ".bat"}:
        command_processor = os.environ.get("COMSPEC", "cmd.exe")
        return [command_processor, "/d", "/c", subprocess.list2cmdline([executable, *arguments])]
    return [executable, *arguments]


def run_java_catalog_source_tests(version_id: str) -> dict:
    # shutil.which honors PATHEXT on Windows and returns the actual mvn.cmd
    # path where Maven is installed as a Windows batch launcher.
    maven = shutil.which("mvn") or shutil.which("mvn.cmd") or shutil.which("mvn.bat")
    if maven:
        local_repository = ROOT / ".cache" / "m2" / "repository"
        common = ["--batch-mode", "--no-transfer-progress", "--offline",
                  "-Dmaven.repo.local=" + str(local_repository)]
        # Build the repository reactor from source so the example cannot pass
        # by resolving a previously installed agent-platform-sdk artifact.
        commands = (
            ["-f", "sdk/java/pom.xml", "package"],
            ["-f", "templates/java-generic/pom.xml", "test"],
            ["-f", "templates/java-spring-ai/pom.xml", "test"],
        )
        for arguments in commands:
            result = subprocess.run(java_maven_invocation(maven, [*common, *arguments]), cwd=ROOT,
                                    capture_output=True, timeout=900)
            if result.returncode:
                raise RuntimeError("Java repository reactor tests failed; Catalog status was not changed")
        return {"runner": "repository-maven-reactor", "maven_executable": Path(maven).name,
                "source_reactor": "sdk/java", "templates_tested": 2}

    # On Windows developer hosts without Maven, use the reviewed network-
    # isolated verifier. It mounts the shared .cache/m2 repository, builds
    # the SDK reactor from source and checks the full 55-test suite.
    batch_id = "catalog-eval-" + hashlib.sha256((version_id + uuid.uuid4().hex).encode("utf-8")).hexdigest()[:16]
    verifier = ROOT / "scripts" / "verify_java_ticket_example.py"
    result = subprocess.run([sys.executable, str(verifier), "--full-reactor", "--batch-id", batch_id],
                            cwd=ROOT, capture_output=True, timeout=1200)
    try:
        receipt = json.loads(result.stdout.decode("utf-8").strip())
    except (UnicodeError, ValueError):
        raise RuntimeError("Java repository reactor verifier returned invalid evidence; Catalog status was not changed") from None
    totals = receipt.get("test_totals") if isinstance(receipt, dict) else None
    suites = receipt.get("suites") if isinstance(receipt, dict) else None
    required_suites = {
        "com.lexagent.sdk.HarnessRunnerTest",
        "com.lexagent.sdk.spring.ExecutionServerAutoConfigurationTest",
        "com.lexagent.examples.tickets.TicketAssistantTest",
        "com.lexagent.examples.tickets.TicketTransportTest",
        "generated.CapabilityFixtureTest",
        "generated.WorkflowTest",
    }
    valid_suites = isinstance(suites, list) and all(
        isinstance(suite, dict) and isinstance(suite.get("name"), str)
        and all(type(suite.get(key)) is int and suite[key] >= 0
                for key in ("tests", "failures", "errors", "skipped"))
        for suite in suites
    )
    suite_names = {suite["name"] for suite in suites if isinstance(suite, dict) and isinstance(suite.get("name"), str)} if valid_suites else set()
    suite_totals = ({key: sum(suite[key] for suite in suites) for key in ("tests", "failures", "errors", "skipped")}
                    if valid_suites else {})
    valid_totals = (isinstance(totals, dict)
                    and all(type(totals.get(key)) is int and totals[key] >= 0
                            for key in ("tests", "failures", "errors", "skipped"))
                    and totals.get("tests", 0) > 0 and totals == suite_totals)
    source_digest = receipt.get("source_workspace_sha256") if isinstance(receipt, dict) else None
    if (not isinstance(receipt, dict) or result.returncode or receipt.get("result") != "PASS"
            or receipt.get("batch_id") != batch_id
            or not isinstance(receipt.get("owner"), str) or not re.fullmatch(r"java-ticket-[a-f0-9]{32}", receipt["owner"])
            or receipt.get("full_sdk_reactor") is not True or receipt.get("tests_passed") is not True
            or receipt.get("command_exit_codes") != [0, 0, 0]
            or not isinstance(source_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", source_digest)
            or not valid_suites or not required_suites.issubset(suite_names) or not valid_totals
            or any(totals.get(key) != 0 for key in ("failures", "errors", "skipped"))
            or receipt.get("example_jar_built") is not True or receipt.get("runtime_sdk_dependency_present") is not True
            or receipt.get("temporary_workspace_removed") is not True or receipt.get("cleanup_errors") != []
            or receipt.get("external_provider_calls") != 0 or receipt.get("development_database_changed") is not False):
        raise RuntimeError("Java full repository reactor verification failed; Catalog status was not changed")
    return {"runner": "isolated-cached-java-verifier", "test_count": totals["tests"],
            "suite_count": len(suites), "failures": totals["failures"], "errors": totals["errors"],
            "skipped": totals["skipped"], "batch_id": batch_id,
            "source_workspace_sha256": source_digest, "owner": receipt["owner"]}


def run_example_source_tests(agent_id: str, version_id: str | None = None) -> None:
    if agent_id == "example-java-tickets":
        if not isinstance(version_id, str) or not version_id:
            raise ValueError("Java source evaluation requires the exact planned Catalog Version ID")
        evidence = run_java_catalog_source_tests(version_id)
        print(json.dumps({"result": "public_example_source_tests_passed", "agent_id": agent_id,
                          "test_command": evidence, "credentials_or_test_output_printed": False}, ensure_ascii=False))
        return
    commands = {
        "example-go-operations": (["go", "test", "./..."], ROOT / "examples" / "go-operations"),
        "example-python-documents": ([sys.executable, "-m", "pytest", "-p", "no:cacheprovider",
                                      "--import-mode=importlib", "-q", "tests"], ROOT / "examples" / "python-documents"),
    }
    if agent_id not in commands:
        raise ValueError("source evaluation is limited to the three reviewed public examples")
    command, cwd = commands[agent_id]
    env = None
    if agent_id == "example-python-documents":
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(str(ROOT / relative) for relative in (
            "sdk/python", ".cache/sdk-postgres", "examples/python-documents"))
        env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=600, env=env)
    if result.returncode:
        raise RuntimeError("current public example source tests failed; Catalog status was not changed")
    print(json.dumps({"result": "public_example_source_tests_passed", "agent_id": agent_id,
                      "test_command": command[:3], "credentials_or_test_output_printed": False}, ensure_ascii=False))


def catalog_publish_phase(project: str, directory: Path, plan: dict, actor: str, confirm_resource: str) -> None:
    if actor != "system.admin":
        raise ValueError("Catalog approval is a control-plane operation for the separately authenticated system.admin")
    if confirm_resource != plan["version"]["id"]:
        raise ValueError("Catalog publication requires the exact public Version ID")
    api = owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE)
    _directory, owner, _passwords = read_manifest(project)
    lifecycle = owner.get("catalog_lifecycle", {}).get(plan["agent_id"], {})
    if not isinstance(lifecycle, dict) or not lifecycle.get("author") or lifecycle.get("evaluator") != "system.admin" or actor == lifecycle.get("author"):
        raise RuntimeError("Catalog approval requires system.admin and a different recorded human author")
    requests = [catalog_request_for_kind(plan, "approve", "definition", "publish"),
                catalog_request_for_kind(plan, "approve", "version", "publish")]
    for request in requests:
        if request is None:
            continue
        is_definition = "/definitions/" in request["path"]
        path = catalog_definition_path(plan) if is_definition else catalog_version_path(plan)
        current = maybe_get(api, path)
        if current is None or current.get("submitted_by") == actor:
            raise RuntimeError("Catalog approver must be a different human from the recorded submitter")
        object_id = plan["definition"]["id"] if is_definition else plan["version"]["id"]
        revision = check_catalog_revision(current, object_id)
        if current.get("status") == "published":
            if current.get("approved_by") != actor:
                raise RuntimeError("Catalog object was published by a different approver")
            continue
        if current.get("status") != "evaluated":
            raise RuntimeError("Catalog publication requires the live evaluated revision")
        api.call("POST", request["path"], {"expected_revision": revision})
        after = maybe_get(api, path)
        if after is None or after.get("status") != "published" or after.get("revision") != revision + 1 or after.get("approved_by") != actor:
            raise RuntimeError("Catalog publication did not verify under the independent approver")
    save_catalog_receipt(project, directory, plan, "approver", actor)
    print(json.dumps({"result": "catalog_definition_and_version_published", "project": project,
                      "agent_id": plan["agent_id"], "approver": actor}, ensure_ascii=False))


def catalog_install_phase(project: str, directory: Path, plan: dict, actor: str, confirm_resource: str) -> None:
    if actor != "system.admin":
        raise ValueError("Catalog installation is a control-plane operation for the separately authenticated system.admin")
    installation_id = plan["installation"]["id"]
    if confirm_resource != installation_id:
        raise ValueError("Catalog installation requires the exact new Installation ID")
    api = owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE)
    version = maybe_get(api, catalog_version_path(plan))
    if version is None or version.get("status") != "published":
        raise RuntimeError("only the exact live published Catalog Version may be installed")
    path = "/api/modules/catalog/installations/" + urllib.parse.quote(installation_id, safe="")
    current = maybe_get(api, path)
    if current is None:
        api.call("POST", "/api/modules/catalog/installations", plan["installation"])
        current = maybe_get(api, path)
    if current is None or any(current.get(key) != plan["installation"].get(key) for key in ("id", "tenant_id", "department_id", "application_id", "agent_id", "version_id")) or current.get("status") not in {"provisioning", "active"}:
        raise RuntimeError("Catalog Installation does not match the exact published public version")
    print(json.dumps({"result": "catalog_installation_verified", "project": project,
                      "installation_id": installation_id, "status": current["status"], "actor": actor}, ensure_ascii=False))


def catalog_deploy_phase(project: str, directory: Path, plan: dict, actor: str, confirm_resource: str) -> None:
    if actor != "system.admin":
        raise ValueError("Catalog deployment is a control-plane operation for the separately authenticated system.admin")
    deployment_id = plan["deployment"]["id"]
    if confirm_resource != deployment_id:
        raise ValueError("Catalog deployment requires the exact new Deployment ID")
    verify_example_container_health(project, directory)
    api = owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE)
    installation_path = catalog_install_path(plan)
    installation = maybe_get(api, installation_path)
    if installation is None or installation.get("status") != "provisioning":
        raise RuntimeError("Catalog deployment requires this new Installation to remain provisioning")
    path = installation_path + "/deployments?limit=100"
    items = catalog_deployment_items(api.call("GET", path))
    current = next((item for item in items if item.get("id") == deployment_id), None)
    if current is None:
        api.call("POST", installation_path + "/deployments", plan["deployment"])
        items = catalog_deployment_items(api.call("GET", path))
        current = next((item for item in items if item.get("id") == deployment_id), None)
    if not isinstance(current, dict) or any(current.get(key) != plan["deployment"].get(key) for key in (
        "id", "tenant_id", "department_id", "application_id", "agent_installation_id", "agent_version_id",
        "artifact_digest", "endpoint_ref", "manifest_hash", "desired_revision",
    )):
        raise RuntimeError("desired Catalog Deployment does not match the exact source image, version, scope and health-probed endpoint")
    print(json.dumps({"result": "catalog_deployment_desired_state_verified", "project": project,
                      "deployment_id": deployment_id, "status": current.get("status"),
                      "actual_example_health_probes": True, "observed": False}, ensure_ascii=False))


def observe_catalog_with_owner_compose(project: str, directory: Path, observation: dict, include_runtime: bool) -> dict:
    command = compose_prefix(project, directory, include_runtime=include_runtime) + ["exec", "-T", "platform-app", "/app/deployment-observe"]
    env = isolated_compose_environment(directory, include_runtime=include_runtime)
    def invoke(extra: list[str]) -> dict:
        result = subprocess.run(command + extra, input=json.dumps(observation), text=True, capture_output=True,
                                cwd=ROOT, timeout=45, env=env)
        if result.returncode:
            raise RuntimeError("platform-owned Catalog observer failed; source readiness and exact revisions were retained for review")
        try:
            reply = json.loads(result.stdout)
        except ValueError:
            raise RuntimeError("platform-owned Catalog observer returned invalid JSON") from None
        if not isinstance(reply, dict) or reply.get("observation") != observation:
            raise RuntimeError("platform-owned Catalog observer receipt differs from the exact health probe")
        return reply
    preview = invoke([])
    digest = preview.get("source_hash")
    if preview.get("applied") is not False or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise RuntimeError("Catalog observer preview did not return a valid current source hash")
    receipt = invoke(["--apply", "--expected-source-hash", digest])
    if receipt.get("applied") is not True or receipt.get("source_hash") != digest:
        raise RuntimeError("Catalog observer did not commit its CAS-confirmed readiness")
    return receipt


def catalog_observe_phase(project: str, directory: Path, plan: dict, actor: str, confirm_resource: str, include_runtime: bool) -> None:
    if actor != "system.admin":
        raise ValueError("Catalog readiness observation is a control-plane operation for system.admin")
    deployment_id = plan["deployment"]["id"]
    if confirm_resource != deployment_id:
        raise ValueError("Catalog readiness observation requires the exact Deployment ID")
    verify_example_container_health(project, directory)
    api = owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE)
    path = catalog_install_path(plan) + "/deployments?limit=100"
    items = catalog_deployment_items(api.call("GET", path))
    matches = [item for item in items if item.get("id") == deployment_id]
    if len(matches) != 1:
        raise RuntimeError("the exact Catalog Deployment is not uniquely visible before controller observation")
    current = matches[0]
    expected = plan["deployment"]
    if any(current.get(key) != expected.get(key) for key in ("tenant_id", "department_id", "application_id", "agent_installation_id", "agent_version_id", "endpoint_ref", "artifact_digest")) or current.get("status") not in {"pending", "ready"}:
        raise RuntimeError("Catalog desired Deployment differs from the real isolated service")
    if current.get("status") != "ready":
        observation = {"kind": "catalog", "installation_id": plan["installation"]["id"], "deployment_id": deployment_id,
                       "revision": current.get("desired_revision"), "health": "ready", **bootstrap.BUSINESS_SCOPE}
        if type(observation["revision"]) is not int or observation["revision"] < 1:
            raise RuntimeError("Catalog desired revision is invalid before observation")
        observe_catalog_with_owner_compose(project, directory, observation, include_runtime)
    items = catalog_deployment_items(api.call("GET", path))
    matches = [item for item in items if item.get("id") == deployment_id]
    if len(matches) != 1 or matches[0].get("status") != "ready" or matches[0].get("observed_revision") != matches[0].get("desired_revision"):
        raise RuntimeError("Catalog readiness did not verify at the current desired revision")
    print(json.dumps({"result": "catalog_actual_readiness_observed", "project": project,
                      "deployment_id": deployment_id, "desired_revision": matches[0]["desired_revision"],
                      "observed_revision": matches[0]["observed_revision"], "health_probe": True}, ensure_ascii=False))


def catalog_activate_phase(project: str, directory: Path, plan: dict, actor: str, confirm_resource: str) -> None:
    if actor != "system.admin":
        raise ValueError("Catalog activation is a control-plane operation for the separately authenticated system.admin")
    installation_id = plan["installation"]["id"]
    if confirm_resource != installation_id:
        raise ValueError("Catalog activation requires the exact Installation ID")
    api = owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE)
    installation_path = catalog_install_path(plan)
    current = maybe_get(api, installation_path)
    if current is None or current.get("status") not in {"provisioning", "active"}:
        raise RuntimeError("Catalog Installation is not in the expected new-release lifecycle")
    deployment_response = api.call("GET", installation_path + "/deployments?limit=100")
    items = catalog_deployment_items(deployment_response)
    matches = [item for item in items if item.get("id") == plan["deployment"]["id"]]
    if len(matches) != 1 or matches[0].get("status") != "ready" or matches[0].get("observed_revision") != matches[0].get("desired_revision"):
        raise RuntimeError("Installation cannot activate until its exact live Deployment is observed ready at the desired revision")
    if current.get("status") == "provisioning":
        revision = check_catalog_revision(current, installation_id)
        api.call("POST", installation_path + "/transition", {"from": "provisioning", "to": "active", "expected_revision": revision})
        current = maybe_get(api, installation_path)
    if current is None or current.get("status") != "active":
        raise RuntimeError("Catalog Installation activation did not verify")
    save_catalog_receipt(project, directory, plan, "active_installation", actor)
    print(json.dumps({"result": "catalog_installation_active_after_real_observation", "project": project,
                      "installation_id": installation_id, "deployment_id": plan["deployment"]["id"],
                      "actor": actor}, ensure_ascii=False))


def skill_result(api: bootstrap.BrowserAPI, operation: str, body: dict) -> dict:
    response = api.call("POST", "/api/modules/skills/" + operation, body)
    if not isinstance(response, dict) or response.get("code") != 0 or not isinstance(response.get("data"), dict):
        raise RuntimeError("Skill control API response envelope is invalid")
    return response["data"]


def skill_plan(plan: dict) -> dict:
    publications = plan["bundle"].get("skill_publications")
    if not isinstance(publications, list) or len(publications) != 1:
        raise ValueError("release bundle must contain exactly one public Skill publication plan")
    item = publications[0]
    bundle = item.get("bundle")
    if not isinstance(bundle, dict) or bundle.get("skill_id") != item.get("skill_id") or bundle.get("version_id") != item.get("version_id") or not re.fullmatch(r"[a-f0-9]{64}", item.get("bundle_digest", "")):
        raise ValueError("public Skill bundle ID, immutable version and digest are invalid")
    return item


def save_skill_receipt(project: str, directory: Path, agent_id: str, item: dict, field: str, actor: str) -> None:
    _directory, owner, _passwords = read_manifest(project)
    records = owner.setdefault("skill_lifecycle", {})
    record = records.setdefault(agent_id, {})
    skill_key = item["skill_id"] + "/" + item["version_id"]
    saved = record.setdefault(skill_key, {})
    pin = {"skill_id": item["skill_id"], "version_id": item["version_id"],
           "bundle_digest": item["bundle_digest"]}
    if saved.get("release") not in (None, pin):
        raise RuntimeError("isolated Skill lifecycle already pins a different immutable release")
    saved["release"] = pin
    previous = saved.get(field)
    if previous is not None and previous != actor:
        raise RuntimeError("isolated Skill lifecycle already records a different human for this phase")
    saved[field] = actor
    write_json_private(directory / "owner.json", owner)


def skill_namespace() -> dict:
    return {"tenant_id": bootstrap.BUSINESS_SCOPE["tenant_id"], "department_id": bootstrap.BUSINESS_SCOPE["department_id"], "application_id": bootstrap.BUSINESS_SCOPE["application_id"]}


def skill_inspect(api: bootstrap.BrowserAPI, item: dict, version: str = "") -> dict:
    request = {"namespace": skill_namespace(), "skill_id": item["skill_id"]}
    if version:
        request["version_id"] = version
    return skill_result(api, "inspect", request)


def skill_register_phase(project: str, directory: Path, plan: dict, actor: str, confirm_resource: str) -> None:
    item = skill_plan(plan)
    if confirm_resource != item["skill_id"] + "/" + item["version_id"]:
        raise ValueError("Skill registration requires the exact immutable Skill ID/version confirmation")
    require_temporary_author_role(project, directory, plan["agent_id"], actor)
    api = owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE)
    result = skill_result(api, "register", {"namespace": skill_namespace(), "bundle": item["bundle"]})
    if result.get("digest") != item["bundle_digest"] or result.get("author_id") != actor or result.get("status") not in {"submitted", "approved"} or type(result.get("revision")) is not int:
        raise RuntimeError("Skill registration did not verify against the exact public bundle and human author")
    inspected = skill_inspect(api, item, item["version_id"]).get("version")
    if not isinstance(inspected, dict) or inspected.get("digest") != item["bundle_digest"] or inspected.get("author_id") != actor:
        raise RuntimeError("persisted immutable Skill Version did not verify")
    save_skill_receipt(project, directory, plan["agent_id"], item, "author", actor)
    print(json.dumps({"result": "skill_bundle_registered_and_inspected", "project": project,
                      "skill_id": item["skill_id"], "version_id": item["version_id"],
                      "author": actor, "digest": item["bundle_digest"]}, ensure_ascii=False))


def skill_review_phase(project: str, directory: Path, plan: dict, actor: str, confirm_resource: str) -> None:
    if actor != "system.admin":
        raise ValueError("Skill review requires the separately authenticated release approver system.admin")
    item = skill_plan(plan)
    target = item["skill_id"] + "/" + item["version_id"]
    if confirm_resource != target:
        raise ValueError("Skill review requires the exact immutable Skill ID/version confirmation")
    api = owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE)
    _directory, owner, _passwords = read_manifest(project)
    author_state = owner.get("temporary_author_roles", {}).get(plan["agent_id"])
    if not isinstance(author_state, dict) or author_state.get("status") != "active":
        raise RuntimeError("Skill review requires an owner-recorded temporary human author")
    current = skill_inspect(api, item, item["version_id"]).get("version")
    if not isinstance(current, dict) or current.get("digest") != item["bundle_digest"] or current.get("status") not in {"submitted", "approved"} or current.get("author_id") == actor:
        raise RuntimeError("Skill reviewer must be an independent human and inspect the exact submitted digest")
    if current.get("status") == "submitted":
        revision = current.get("revision")
        if type(revision) is not int or revision < 1:
            raise RuntimeError("Skill submitted Version has no current revision")
        skill_result(api, "review", {"namespace": skill_namespace(), "skill_id": item["skill_id"],
                                      "version_id": item["version_id"], "digest": item["bundle_digest"],
                                      "expected_revision": revision, "decision": "approved"})
        current = skill_inspect(api, item, item["version_id"]).get("version")
    if not isinstance(current, dict) or current.get("status") != "approved" or current.get("reviewer_id") != actor or current.get("author_id") == actor:
        raise RuntimeError("Skill approval did not verify with the distinct reviewer identity")
    save_skill_receipt(project, directory, plan["agent_id"], item, "reviewer", actor)
    print(json.dumps({"result": "skill_digest_reviewed_by_independent_human", "project": project,
                      "skill_id": item["skill_id"], "version_id": item["version_id"], "reviewer": actor,
                      "revision": current.get("revision")}, ensure_ascii=False))


def skill_publish_phase(project: str, directory: Path, plan: dict, actor: str, confirm_resource: str) -> None:
    if actor != "system.admin":
        raise ValueError("Skill publication requires the separately authenticated release approver system.admin")
    item = skill_plan(plan)
    target = item["skill_id"] + "/" + item["version_id"]
    if confirm_resource != target:
        raise ValueError("Skill publication requires the exact immutable Skill ID/version confirmation")
    api = owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE)
    _directory, owner, _passwords = read_manifest(project)
    lifecycle = owner.get("skill_lifecycle", {}).get(plan["agent_id"], {}).get(target, {})
    if not isinstance(lifecycle, dict) or not lifecycle.get("author") or lifecycle.get("reviewer") != "system.admin" or actor == lifecycle.get("author"):
        raise RuntimeError("Skill publication requires the exact owner-recorded human author and independent system.admin reviewer")
    version = skill_inspect(api, item, item["version_id"]).get("version")
    if not isinstance(version, dict) or version.get("status") != "approved" or version.get("digest") != item["bundle_digest"] or version.get("reviewer_id") != "system.admin" or version.get("author_id") == actor:
        raise RuntimeError("Skill release requires the exact digest reviewed by system.admin, independently from its human author")
    release_info = skill_inspect(api, item).get("release")
    if release_info is not None and (not isinstance(release_info, dict) or release_info.get("stable_version") != item["version_id"]):
        raise RuntimeError("Skill ID already has a different release; the immutable new project must stop")
    if isinstance(release_info, dict) and type(release_info.get("revision")) is int and release_info["revision"] >= 1:
        save_skill_receipt(project, directory, plan["agent_id"], item, "publisher", actor)
        print(json.dumps({"result": "exact_skill_release_already_active", "project": project,
                          "skill_id": item["skill_id"], "version_id": item["version_id"],
                          "release_revision": release_info["revision"]}, ensure_ascii=False))
        return
    expected_revision = 0 if release_info is None else release_info.get("revision")
    if type(expected_revision) is not int or expected_revision < 0:
        raise RuntimeError("current Skill Release revision is invalid")
    if release_info is None:
        skill_result(api, "publish", {"namespace": skill_namespace(), "skill_id": item["skill_id"],
                                       "expected_revision": 0, "release": {"stable_version": item["version_id"],
                                       "candidate_version": "", "candidate_basis_points": 0, "revision": 0}})
        release_info = skill_inspect(api, item).get("release")
    if not isinstance(release_info, dict) or release_info.get("stable_version") != item["version_id"] or release_info.get("revision") != expected_revision + 1:
        raise RuntimeError("Skill Release CAS did not verify at the expected next revision")
    save_skill_receipt(project, directory, plan["agent_id"], item, "publisher", actor)
    print(json.dumps({"result": "skill_release_published_with_reviewed_stable_version", "project": project,
                      "skill_id": item["skill_id"], "version_id": item["version_id"],
                      "publisher": actor, "release_revision": release_info["revision"]}, ensure_ascii=False))


def model_governance_phase(project: str, directory: Path, path: Path, confirm=None) -> dict:
    _directory, owner, _passwords = read_manifest(project)
    if (not owner.get("identity_complete") or not owner.get("services_ready")
            or not owner.get("model_secrets_ready") or owner.get("model_governance") is not None):
        raise RuntimeError("Model Governance requires the prepared owner-secret mount, healthy local project and a one-time publication")
    value, relative = private_plan_file(project, directory, path, "public-model-governance/v1")
    plan = public_model_governance.validate_plan(value, project, bootstrap.BUSINESS_SCOPE)
    expected_refs = {"chat": ("service://example-chat", "secret://deepseek.key"),
                     "embedding": ("service://example-embedding", "secret://embedding.key")}
    metadata = verify_model_plan_mount(project, directory, plan)
    for item in plan["models"]:
        if (item["endpoint_ref"], item["secret_ref"]) != expected_refs[item["kind"]]:
            raise ValueError("Model Governance plan must use this owner's separately prepared exact provider endpoint and secret references")
    verify_owner_frontend(project, directory, owner)
    api = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    admin_profile = bootstrap.profile(api, "system.admin")
    if admin_profile.get("resource_grants") != [] or admin_profile.get("task_assignments") != []:
        raise RuntimeError("system.admin may manage model policies but may not hold business resource grants or task assignments")
    journal = owner.get("model_governance_journal") or {}

    def persist(value_to_save: dict) -> None:
        _current_directory, current_owner, _current_passwords = read_manifest(project)
        current_owner["model_governance_journal"] = value_to_save
        write_json_private(directory / "owner.json", current_owner)

    def approve(owner_project: str, provider_key: str, stage: str, digest: str) -> bool:
        phrase = owner_project + " model " + provider_key + " " + stage + " " + digest
        return confirm_digest_phrase(phrase, confirm)

    published = public_model_governance.publish_models(api, plan, project, bootstrap.BUSINESS_SCOPE,
                                                        journal, approve, persist)
    if (not isinstance(published, dict) or set(published.get("models", {})) != {"chat", "embedding"}
            or published.get("model_deployment_readiness_proven") is not False
            or published.get("business_execution_proven") is not False):
        raise RuntimeError("Model Governance publication returned an incomplete or overclaimed result")
    price_refs = {}
    for kind in ("chat", "embedding"):
        item = published["models"][kind]
        version = item.get("version")
        price = item.get("price")
        deployment = item.get("deployment")
        if (not isinstance(version, dict) or version.get("status") != "approved"
                or not isinstance(price, dict) or price.get("status") != "approved"
                or not isinstance(deployment, dict) or deployment.get("status") not in {"pending", "ready"}
                or deployment.get("health_status") == "ready"
                and (type(deployment.get("observed_revision")) is not int or deployment["observed_revision"] < 1)):
            raise RuntimeError("Model Governance model/price/deployment records did not verify against their real lifecycle states")
        current_price = public_policy.current_effective_price(api, version["id"])
        if (current_price.get("id") != price.get("id")
                or any(current_price.get(field) != price.get(field) for field in (
                    "currency", "input_micros_per_1k_tokens", "output_micros_per_1k_tokens"))):
            raise RuntimeError("published model does not have the exact current approved PriceVersion")
        plan_item = next(row for row in plan["models"] if row["kind"] == kind)
        provider, definition = item.get("provider"), item.get("definition")
        if (not isinstance(provider, dict) or provider.get("provider_key") != plan_item["provider_key"]
                or not isinstance(definition, dict) or definition.get("model_key") != plan_item["model_key"]
                or definition.get("provider_id") != provider.get("id")):
            raise RuntimeError("published Model Governance provider/definition does not match the reviewed key-free model plan")
        price_refs[kind] = {"provider_id": provider["id"], "provider_key": provider["provider_key"],
                            "definition_id": definition["id"], "model_key": definition["model_key"],
                            "version_id": version["id"], "price_version_id": price["id"],
                            "currency": price["currency"],
                            "input_micros_per_1k_tokens": price["input_micros_per_1k_tokens"],
                            "output_micros_per_1k_tokens": price["output_micros_per_1k_tokens"],
                            "deployment_id": deployment["id"], "deployment_status": deployment["status"],
                            "health_status": deployment.get("health_status", "unknown")}
    _current_directory, owner, _current_passwords = read_manifest(project)
    owner["model_governance"] = {"plan_path": relative, "models": price_refs,
                                 "endpoint_references": sorted(metadata["endpoints"]),
                                 "model_deployment_readiness_proven": False,
                                 "business_execution_proven": False}
    write_json_private(directory / "owner.json", owner)
    safe = {"result": "two_governed_models_prices_and_desired_deployments_verified", "project": project,
            "models": price_refs, "provider_connectivity_proven": False, "business_execution_proven": False,
            "secret_values_printed": False}
    print(json.dumps(safe, ensure_ascii=False))
    return safe


def validate_provider_probe_response(kind: str, value: dict, dimensions: int | None = None) -> dict:
    if not isinstance(value, dict):
        raise RuntimeError("provider probe returned a non-object response")
    if kind == "chat":
        choices = value.get("choices")
        if (not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict)
                or not isinstance(choices[0].get("message"), dict)
                or not isinstance(choices[0]["message"].get("content"), str)
                or not choices[0]["message"]["content"].strip()):
            raise RuntimeError("chat provider readiness response has an invalid safe output shape")
        return {"kind": "chat", "nonempty_message": True}
    if kind == "embedding":
        rows = value.get("data")
        vector = rows[0].get("embedding") if isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict) else None
        if (not isinstance(vector, list) or type(dimensions) is not int or len(vector) != dimensions
                or any(type(number) not in (int, float) or not math.isfinite(number) for number in vector)):
            raise RuntimeError("embedding provider readiness response has a wrong-sized or non-finite vector")
        return {"kind": "embedding", "dimensions": len(vector), "finite_vector": True}
    raise ValueError("provider probe kind must be chat or embedding")


class _NoProviderRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise RuntimeError("provider redirects are refused so credentials stay on the reviewed HTTPS origin")


def provider_readiness_probe(directory: Path, model_plan: dict, kind: str) -> dict:
    by_kind = {item["kind"]: item for item in model_plan["models"]}
    item = by_kind.get(kind)
    if not isinstance(item, dict):
        raise RuntimeError("owner Model Governance plan has no exact requested provider")
    metadata_path = directory / "model-metadata.json"
    bootstrap.verify_private_file(metadata_path)
    if bootstrap.is_reparse_point(metadata_path):
        raise RuntimeError("owner model provider metadata cannot be a link")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    endpoint_ref = "service://example-chat" if kind == "chat" else "service://example-embedding"
    endpoint = metadata.get("endpoints", {}).get(endpoint_ref) if isinstance(metadata, dict) else None
    key_file = "deepseek.key" if kind == "chat" else "embedding.key"
    if (not isinstance(metadata, dict) or metadata.get("schema") != "public-model-metadata/v1"
            or not isinstance(endpoint, str) or metadata.get("key_files", {}).get(kind) != key_file):
        raise RuntimeError("owner private provider metadata does not match the prepared endpoint/secret aliases")
    verified_mount = verify_model_plan_mount(model_plan["owner_project"], directory, model_plan)
    descriptor = {"model": item["model_key"], "endpoint": endpoint, "capabilities": item["capabilities"]}
    if (item["secret_ref"] != "secret://" + key_file
            or item["endpoint_ref"] != endpoint_ref
            or item["descriptor_sha256"] != public_model_governance.digest(descriptor)
            or verified_mount.get("endpoints", {}).get(item["endpoint_ref"]) != endpoint):
        raise RuntimeError("provider probe target does not match its exact approved deployment descriptor")
    parsed_endpoint = urllib.parse.urlsplit(endpoint)
    if (parsed_endpoint.scheme != "https" or not parsed_endpoint.hostname or parsed_endpoint.username
            or parsed_endpoint.password or parsed_endpoint.query or parsed_endpoint.fragment):
        raise RuntimeError("provider readiness endpoint must be an HTTPS origin without embedded credentials or query data")
    secret_path = directory / "model-secrets" / key_file
    if bootstrap.is_reparse_point(secret_path):
        raise RuntimeError("provider secret mount cannot contain a link or reparse point")
    bootstrap.verify_private_file(secret_path)
    key = secret_path.read_text(encoding="ascii").strip()
    if not key or len(key) > 8192 or any(ord(char) < 33 or ord(char) > 126 for char in key):
        raise RuntimeError("provider credential file is empty or malformed")
    if kind == "chat":
        payload = {"model": item["model_key"], "messages": [{"role": "user", "content": "Reply with one short readiness word."}],
                   "max_tokens": min(32, item["context_limit"]), "temperature": 0,
                   "thinking": {"type": "disabled"}}
        path = "/chat/completions"
    else:
        dimensions = item["capabilities"].get("dimensions")
        payload = {"model": item["model_key"], "input": ["Public Knowledge index readiness"],
                   "encoding_format": "float", "dimensions": dimensions}
        path = "/embeddings"
    request = urllib.request.Request(endpoint.rstrip("/") + path,
                                     data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                                     headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
                                     method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoProviderRedirect())
    try:
        with opener.open(request, timeout=60) as response:
            if response.status != 200:
                raise RuntimeError("provider readiness endpoint did not return HTTP 200")
            raw = response.read((1 << 20) + 1)
            if len(raw) > 1 << 20:
                raise RuntimeError("provider readiness response exceeds its one-megabyte limit")
        value = json.loads(raw.decode("utf-8"))
        return validate_provider_probe_response(kind, value, item["capabilities"].get("dimensions"))
    except (OSError, UnicodeError, ValueError, urllib.error.URLError, urllib.error.HTTPError):
        raise RuntimeError("provider readiness probe failed; response, endpoint details and credentials were suppressed") from None


def owner_service_container_id(project: str, directory: Path, service: str, image: str) -> str:
    listing = subprocess.run(compose_prefix(project, directory, include_runtime=True) + ["ps", "--format", "json", service],
                             cwd=ROOT, capture_output=True, timeout=30,
                             env=isolated_compose_environment(directory, include_runtime=True))
    if listing.returncode:
        raise RuntimeError("owner Compose service could not be enumerated for the trusted deployment observer")
    try:
        raw = listing.stdout.decode("utf-8", errors="strict").strip()
        rows = json.loads(raw) if raw.startswith("[") else [json.loads(line) for line in raw.splitlines() if line.strip()]
    except (UnicodeError, ValueError):
        raise RuntimeError("owner Compose service listing was invalid") from None
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise RuntimeError("trusted deployment observer requires exactly one owner platform-app container")
    container_id = rows[0].get("ID") or rows[0].get("Id")
    if not isinstance(container_id, str) or not re.fullmatch(r"[a-f0-9]{12,64}", container_id):
        raise RuntimeError("owner platform-app container identifier is invalid")
    inspected = subprocess.run(["docker", "inspect", container_id], cwd=ROOT, capture_output=True, timeout=30)
    if inspected.returncode:
        raise RuntimeError("owner platform-app container metadata could not be inspected")
    try:
        values = json.loads(inspected.stdout)
    except (UnicodeError, ValueError):
        raise RuntimeError("owner platform-app container inspect was invalid") from None
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise RuntimeError("platform-app inspect did not resolve exactly one container")
    current = values[0]
    labels = current.get("Config", {}).get("Labels", {})
    if (not current.get("Id", "").startswith(container_id) or current.get("Config", {}).get("Image") != image
            or labels.get("com.docker.compose.project") != project
            or labels.get("com.docker.compose.service") != service
            or current.get("State", {}).get("Status") != "running"):
        raise RuntimeError("deployment observer container is not the running platform-app for this isolated project")
    return container_id


def model_deployment_observation_phase(project: str, directory: Path, kind: str, confirm=None) -> dict:
    _directory, owner, _passwords = read_manifest(project)
    if (not owner.get("identity_complete") or not owner.get("services_ready")
            or not owner.get("model_secrets_ready") or not owner.get("model_governance")
            or kind not in {"chat", "embedding"}):
        raise RuntimeError("model deployment observation requires the isolated Model Governance records and mounted secret refs")
    verify_owner_frontend(project, directory, owner)
    verify_runtime_processes(project, directory, owner)
    plan_path = Path(owner["model_governance"].get("plan_path", ""))
    value, _relative = private_plan_file(project, directory, plan_path, "public-model-governance/v1")
    model_plan = public_model_governance.validate_plan(value, project, bootstrap.BUSINESS_SCOPE)
    verify_model_plan_mount(project, directory, model_plan)
    by_kind = {item["kind"]: item for item in model_plan["models"]}
    item = by_kind[kind]
    pin = owner["model_governance"]["models"].get(kind)
    if not isinstance(pin, dict) or not isinstance(pin.get("deployment_id"), str):
        raise RuntimeError("owner Model Governance receipt lacks this model's exact Deployment ID")
    recorded = owner.setdefault("model_deployment_observations", {})
    if kind in recorded:
        if recorded[kind].get("status") == "verified":
            admin = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
            current = admin.call("GET", public_model_governance.PREFIX + "/deployments/" + bootstrap.urllib.parse.quote(pin["deployment_id"], safe=""))
            verify_one_model_deployment(current, kind, item, pin, recorded[kind])
            return deepcopy(recorded[kind])
        raise RuntimeError("model provider probe or trusted deployment observation already started; inspect its live owner journal and never repeat the paid probe")
    admin = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    admin_profile = bootstrap.profile(admin, "system.admin")
    if admin_profile.get("resource_grants") != [] or admin_profile.get("task_assignments") != []:
        raise RuntimeError("system.admin may observe model readiness but cannot receive business grants or assignments")
    current = admin.call("GET", public_model_governance.PREFIX + "/deployments/" + bootstrap.urllib.parse.quote(pin["deployment_id"], safe=""))
    if (not isinstance(current, dict) or current.get("id") != pin["deployment_id"]
            or current.get("model_version_id") != pin["version_id"]
            or current.get("endpoint_ref") != item["endpoint_ref"]
            or current.get("status") != "pending" or current.get("health_status") not in {"unknown", "pending"}
            or type(current.get("revision")) is not int or current["revision"] < 1
            or current.get("observed_revision") not in (None, 0)):
        raise RuntimeError("fresh model Deployment is not the exact unobserved desired revision")
    probe_digest = public_model_governance.digest({"project": project, "kind": kind,
                                                   "model_key": item["model_key"], "endpoint_ref": item["endpoint_ref"],
                                                   "descriptor_sha256": item["descriptor_sha256"],
                                                   "purpose": "safe readiness request; external provider usage may be billed"})
    probe_phrase = f"{project} provider-probe {kind} {pin['deployment_id']} {probe_digest}"
    print(json.dumps({"phase": "external_provider_readiness_probe", "project": project,
                      "kind": kind, "model_key": item["model_key"], "endpoint_ref": item["endpoint_ref"],
                      "may_incur_provider_usage": True, "secret_values_printed": False,
                      "provider_url_printed": False, "confirmation": probe_phrase}, ensure_ascii=False))
    if not confirm_digest_phrase(probe_phrase, confirm):
        raise RuntimeError("provider readiness probe was not explicitly confirmed")
    state = {"deployment_id": pin["deployment_id"], "model_version_id": pin["version_id"],
             "probe_digest": probe_digest, "status": "probe_started", "prior_revision": current["revision"]}
    recorded[kind] = state
    write_json_private(directory / "owner.json", owner)
    try:
        probe = provider_readiness_probe(directory, model_plan, kind)
    except RuntimeError:
        # A failed or timed-out request may already have consumed provider
        # usage, so the owner must inspect before attempting another probe.
        raise
    state["probe"] = probe
    state["status"] = "probe_verified"
    write_json_private(directory / "owner.json", owner)
    current = admin.call("GET", public_model_governance.PREFIX + "/deployments/" + bootstrap.urllib.parse.quote(pin["deployment_id"], safe=""))
    if (not isinstance(current, dict) or current.get("revision") != state["prior_revision"]
            or current.get("health_status") not in {"unknown", "pending"}):
        raise RuntimeError("Model Governance deployment changed while its external provider readiness probe was running")
    observation = {**bootstrap.BUSINESS_SCOPE, "kind": "model", "deployment_id": pin["deployment_id"],
                   "revision": current["revision"], "health": "ready"}
    image = "agentplug:test-platform-" + project.removeprefix("agentplug-test-public-")
    container_id = owner_service_container_id(project, directory, "platform-app", image)
    wire = json.dumps(observation, separators=(",", ":")).encode("utf-8")

    def invoke(arguments: list[str]) -> dict:
        result = subprocess.run(["docker", "exec", "-i", container_id, "/app/deployment-observe", *arguments],
                                input=wire, capture_output=True, timeout=45, cwd=ROOT)
        if result.returncode:
            raise RuntimeError("trusted deployment observer failed; diagnostics were suppressed")
        try:
            return json.loads(result.stdout)
        except (UnicodeError, ValueError):
            raise RuntimeError("trusted deployment observer returned invalid JSON") from None

    preview = invoke([])
    source_hash = preview.get("source_hash") if isinstance(preview, dict) else None
    if (preview.get("observation") != observation or preview.get("resource_version") != pin["version_id"]
            or preview.get("applied") is not False or not isinstance(source_hash, str)
            or not re.fullmatch(r"[a-f0-9]{64}", source_hash)):
        raise RuntimeError("trusted controller preview differs from the exact scoped model health observation")
    phrase = f"{project} apply model-health {pin['deployment_id']} revision:{current['revision']} {source_hash}"
    print(json.dumps({"phase": "trusted_model_health_observation_preview", "kind": kind,
                      "deployment_id": pin["deployment_id"], "revision": current["revision"],
                      "probe_shape": probe, "source_hash": source_hash,
                      "confirmation": phrase, "browser_health_write": False}, ensure_ascii=False))
    if not confirm_digest_phrase(phrase, confirm):
        raise RuntimeError("trusted controller health observation was not confirmed")
    state.update({"status": "controller_commit_started", "source_hash": source_hash,
                  "observation_revision": current["revision"]})
    write_json_private(directory / "owner.json", owner)
    applied = invoke(["--apply", "--expected-source-hash", source_hash])
    if (applied.get("observation") != observation or applied.get("resource_version") != pin["version_id"]
            or applied.get("source_hash") != source_hash or applied.get("applied") is not True):
        raise RuntimeError("trusted controller apply receipt differs from its exact current source-hash preview")
    updated = admin.call("GET", public_model_governance.PREFIX + "/deployments/" + bootstrap.urllib.parse.quote(pin["deployment_id"], safe=""))
    verify_one_model_deployment(updated, kind, item, pin,
                                {"status": "verified", "prior_revision": current["revision"],
                                 "observation_revision": current["revision"], "revision": current["revision"] + 1})
    state.update({"status": "verified", "revision": updated["revision"],
                  "observed_revision": updated["observed_revision"], "controller_source_hash": source_hash})
    pin.update({"deployment_status": updated["status"], "health_status": updated["health_status"],
                "revision": updated["revision"], "observed_revision": updated["observed_revision"],
                "provider_probe_verified": True})
    all_ready = all(isinstance(owner["model_governance"]["models"].get(name), dict)
                    and owner["model_governance"]["models"][name].get("deployment_status") == "ready"
                    and owner["model_governance"]["models"][name].get("health_status") == "ready"
                    and type(owner["model_governance"]["models"][name].get("observed_revision")) is int
                    and owner["model_governance"]["models"][name]["observed_revision"] >= 1
                    for name in ("chat", "embedding"))
    owner["model_governance"]["model_deployment_readiness_proven"] = all_ready
    owner["model_governance"]["provider_connectivity_proven"] = all(
        owner["model_governance"]["models"][name].get("provider_probe_verified") is True for name in ("chat", "embedding"))
    write_json_private(directory / "owner.json", owner)
    return deepcopy(state)


def verify_one_model_deployment(current: dict, kind: str, item: dict, pin: dict, observation: dict) -> None:
    observed = observation.get("observation_revision", observation.get("prior_revision"))
    expected_revision = observation.get("revision", observed + 1 if type(observed) is int else None)
    if (not isinstance(current, dict) or current.get("id") != pin.get("deployment_id")
            or current.get("model_version_id") != pin.get("version_id") or current.get("endpoint_ref") != item.get("endpoint_ref")
            or any(current.get(key) != value for key, value in bootstrap.BUSINESS_SCOPE.items())
            or current.get("status") != "ready" or current.get("health_status") != "ready"
            or type(observed) is not int or type(expected_revision) is not int
            or current.get("observed_revision") != observed or current.get("revision") != expected_revision):
        raise RuntimeError(f"{kind} Deployment did not verify ready at the exact trusted observed revision")


def verify_model_deployment_observations(api: bootstrap.BrowserAPI, project: str,
                                         directory: Path, owner: dict) -> None:
    recorded = owner.get("model_governance")
    if not isinstance(recorded, dict) or recorded.get("model_deployment_readiness_proven") is not True:
        raise RuntimeError("both model Deployments require actual provider probes and trusted ready observations before business policy use")
    plan, pins = model_governance_pins(project, directory, owner)
    by_kind = {row["kind"]: row for row in plan["models"]}
    for kind in ("chat", "embedding"):
        pin = pins[kind]
        item = by_kind[kind]
        receipt = owner.get("model_deployment_observations", {}).get(kind)
        if (not isinstance(receipt, dict) or receipt.get("status") != "verified"
                or receipt.get("probe", {}).get("kind") != kind
                or receipt.get("observed_revision") != pin.get("observed_revision")):
            raise RuntimeError("owner model deployment observation lacks its exact probe and controller receipt")
        current = api.call("GET", public_model_governance.PREFIX + "/deployments/" + bootstrap.urllib.parse.quote(pin["deployment_id"], safe=""))
        verify_one_model_deployment(current, kind, item, pin, receipt)


def model_access_policy_create_readback_matches(created: dict, live: dict, expected: dict) -> bool:
    """Compare the public DTO fields while accounting for PostgreSQL timestamp precision.

    The create receipt carries Go nanoseconds, while PostgreSQL timestamptz
    readback is microsecond precision. datetime.fromisoformat truncates excess
    fractional digits to that shared precision; all policy fields and identity
    fields remain exact.
    """
    if not isinstance(created, dict) or not isinstance(live, dict):
        return False
    if any(created.get(key) != value or live.get(key) != value for key, value in expected.items()):
        return False
    if (not isinstance(created.get("id"), str) or not created["id"] or live.get("id") != created["id"]
            or created.get("status") != "draft" or live.get("status") != "draft"
            or created.get("revision") != 1 or live.get("revision") != 1):
        return False
    timestamps = []
    for key in ("created_at", "updated_at"):
        values = []
        for response in (created, live):
            value = response.get(key)
            if not isinstance(value, str) or not value.endswith("Z"):
                return False
            try:
                parsed = datetime.fromisoformat(value[:-1] + "+00:00")
            except ValueError:
                return False
            if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
                return False
            values.append(parsed)
        if values[0] != values[1]:
            return False
        timestamps.append(values[0])
    return timestamps[0] <= timestamps[1]


def model_access_policies_phase(project: str, directory: Path, confirm=None) -> list[dict]:
    """Create and approve only the six exact subject/installation model policies.

    Model Governance has no preview endpoint for AccessPolicy. Each normal API
    write is therefore shown and confirmed separately, then pinned by GET
    readback. No wildcard principal or blanket application policy is created.
    """
    _directory, owner, _passwords = read_manifest(project)
    if (not owner.get("identity_complete") or not owner.get("services_ready")
            or not owner.get("machines_complete") or owner.get("model_governance") is None):
        raise RuntimeError("Model AccessPolicy requires the completed owner project, Catalog readiness and approved models")
    verify_owner_frontend(project, directory, owner)
    verify_example_container_health(project, directory)
    api = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    installations = verify_catalog_installation_readiness(api)
    pinned_plans = load_pinned_release_plans(project, directory, owner)
    catalog = owner.get("catalog_lifecycle", {})
    version_by_installation = {}
    for row in installations:
        agent_id = next(item[1] for item in bootstrap.MACHINES if item[0] == row["machine_id"])
        release = catalog.get(agent_id, {}).get("release", {})
        if (release.get("installation_id") != row["installation_id"]
                or release.get("version_id") != row["agent_version_id"]
                or agent_id not in pinned_plans):
            raise RuntimeError("AccessPolicy target does not match the current owner-pinned active Catalog version")
        version_by_installation[row["installation_id"]] = row["agent_version_id"]
    _model_plan, model_pins = model_governance_pins(project, directory, owner)
    verify_model_deployment_observations(api, project, directory, owner)
    providers = sorted({model_pins[kind]["provider_id"] for kind in ("chat", "embedding")})
    definitions = sorted({model_pins[kind]["definition_id"] for kind in ("chat", "embedding")})
    if len(providers) != 2 or len(definitions) != 2:
        raise RuntimeError("two distinct approved model providers and definitions are required")
    rows = public_model_governance.rows(api, public_model_governance.PREFIX + "/access-policies")
    receipt_map = owner.get("model_access_policies") or {"schema": "public-model-access-policies/v1", "policies": {}}
    if not isinstance(receipt_map, dict) or receipt_map.get("schema") != "public-model-access-policies/v1" or not isinstance(receipt_map.get("policies"), dict):
        raise RuntimeError("owner Model AccessPolicy journal has an unknown schema")
    policy_records = receipt_map["policies"]
    if set(policy_records) - set(example_authorization.SUBJECTS):
        raise RuntimeError("owner AccessPolicy journal names a subject outside the six public user/machine principals")

    def persist() -> None:
        _current_directory, current_owner, _current_passwords = read_manifest(project)
        current_owner["model_access_policies"] = receipt_map
        write_json_private(directory / "owner.json", current_owner)

    results = []
    for subject, (subject_type, installation_id) in example_authorization.SUBJECTS.items():
        version_id = version_by_installation.get(installation_id)
        if not version_id:
            raise RuntimeError("AccessPolicy has no observed active Catalog version for this principal's installation")
        expected = {"tenant_id": bootstrap.BUSINESS_SCOPE["tenant_id"],
                    "department_id": bootstrap.BUSINESS_SCOPE["department_id"],
                    "application_id": bootstrap.BUSINESS_SCOPE["application_id"],
                    "installation_id": installation_id, "agent_version_id": version_id,
                    "principal_id": subject, "allow_local": False, "allow_private": False,
                    "allow_external": True, "allowed_providers": providers,
                    "allowed_models": definitions}
        previous = policy_records.get(subject)
        if previous is None:
            matches = [row for row in rows if row.get("principal_id") == subject
                       and row.get("installation_id") == installation_id
                       and row.get("agent_version_id") == version_id]
            if matches:
                raise RuntimeError("unrecorded AccessPolicy already targets this exact public principal and installation; inspect it before replay")
            previous = {"request": expected, "create": None, "approve": None}
            policy_records[subject] = previous
        if not isinstance(previous, dict) or previous.get("request") != expected:
            raise RuntimeError("owner AccessPolicy journal differs from the exact principal/model/installation allowlist")
        policy_id = (previous.get("create") or {}).get("id")
        live = api.call("GET", public_model_governance.PREFIX + "/access-policies/" + bootstrap.urllib.parse.quote(policy_id, safe="")) if policy_id else None
        if live is None:
            if previous.get("create_intent"):
                raise RuntimeError("AccessPolicy create response is ambiguous; inspect live rows and do not retry blindly")
            candidates = [row for row in rows if row.get("principal_id") == subject
                          and row.get("installation_id") == installation_id
                          and row.get("agent_version_id") == version_id]
            if candidates:
                raise RuntimeError("an unpinned existing AccessPolicy prevents a fresh exact create")
            create_digest = public_model_governance.digest({"path": public_model_governance.PREFIX + "/access-policies", "body": expected})
            phrase = project + " Model AccessPolicy " + subject + " create " + create_digest
            print(json.dumps({"operation": "create_model_access_policy", "principal_id": subject,
                              "principal_type": subject_type, "installation_id": installation_id,
                              "agent_version_id": version_id, "allow_external": True,
                              "allowed_provider_count": len(providers), "allowed_model_count": len(definitions),
                              "confirmation": phrase}, ensure_ascii=False))
            if not confirm_digest_phrase(phrase, confirm):
                raise RuntimeError("AccessPolicy creation was not confirmed")
            previous["create_intent"] = {"request_sha256": create_digest}
            persist()
            created = api.call("POST", public_model_governance.PREFIX + "/access-policies", expected)
            if not isinstance(created, dict) or any(created.get(key) != value for key, value in expected.items()) or created.get("status") != "draft" or created.get("revision") != 1 or not isinstance(created.get("id"), str):
                raise RuntimeError("AccessPolicy create receipt differs from the exact requested principal/model scope")
            previous["create"] = deepcopy(created)
            persist()
            live = api.call("GET", public_model_governance.PREFIX + "/access-policies/" + bootstrap.urllib.parse.quote(created["id"], safe=""))
            if not model_access_policy_create_readback_matches(created, live, expected):
                raise RuntimeError("AccessPolicy exact create GET readback differs from its receipt")
        if not isinstance(live, dict) or any(live.get(key) != value for key, value in expected.items()):
            raise RuntimeError("live AccessPolicy exceeds or differs from its exact principal/model/installation boundary")
        if live.get("status") == "draft":
            if previous.get("approve_intent"):
                raise RuntimeError("AccessPolicy approval response is ambiguous; do not repeat the CAS mutation")
            if live.get("revision") != 1:
                raise RuntimeError("new AccessPolicy Draft has an unexpected revision")
            approve_body = {"revision": live["revision"]}
            approve_digest = public_model_governance.digest({"path": public_model_governance.PREFIX + "/access-policies/" + live["id"] + "/approve", "body": approve_body})
            phrase = project + " Model AccessPolicy " + subject + " approve " + approve_digest
            print(json.dumps({"operation": "approve_model_access_policy", "principal_id": subject,
                              "installation_id": installation_id, "policy_id": live["id"],
                              "expected_revision": live["revision"], "confirmation": phrase}, ensure_ascii=False))
            if not confirm_digest_phrase(phrase, confirm):
                raise RuntimeError("AccessPolicy approval was not confirmed")
            previous["approve_intent"] = {"request_sha256": approve_digest}
            persist()
            receipt = api.call("POST", public_model_governance.PREFIX + "/access-policies/" + live["id"] + "/approve", approve_body)
            if not isinstance(receipt, dict) or receipt.get("status") != "approved" or receipt.get("revision") != 2:
                raise RuntimeError("AccessPolicy approval receipt is not the exact revision-1 CAS transition")
            previous["approve"] = deepcopy(receipt)
            persist()
            live = api.call("GET", public_model_governance.PREFIX + "/access-policies/" + live["id"])
        if (not isinstance(live, dict) or any(live.get(key) != value for key, value in expected.items())
                or live.get("status") != "approved" or live.get("revision") != 2
                or (previous.get("create") or {}).get("id") != live.get("id")):
            raise RuntimeError("approved AccessPolicy does not read back the exact versioned principal scope")
        if previous.get("approve") is None:
            previous["approve"] = {"status": "approved", "revision": live["revision"], "reconciled_from_exact_get": True}
        previous["verified"] = {"id": live["id"], "revision": live["revision"], "status": live["status"]}
        persist()
        results.append(previous["verified"] | {"principal_id": subject, "installation_id": installation_id,
                                               "agent_version_id": version_id})
    return results


def load_knowledge_plan(project: str, directory: Path, owner: dict) -> dict:
    record = owner.get("knowledge_plan")
    if not isinstance(record, dict) or not isinstance(record.get("path"), str):
        raise RuntimeError("owner-private three-source Knowledge plan has not been prepared")
    value, relative = private_plan_file(project, directory, Path(record["path"]), "public-knowledge-replay/v1")
    plan = public_knowledge.validate_plan(value, project, bootstrap.BUSINESS_SCOPE)
    if (relative != record["path"] or record.get("plan_sha256") != public_knowledge.digest(plan)
            or record.get("embedding_dimensions") != plan["items"][0]["config"]["dimensions"]):
        raise RuntimeError("owner Knowledge plan file/hash/dimensions differ from its private pin")
    return plan


def prepare_knowledge_plan(project: str, directory: Path, output: Path) -> Path:
    _directory, owner, _passwords = read_manifest(project)
    if not owner.get("model_governance"):
        raise RuntimeError("Knowledge plan requires approved embedding model metadata and dimensions")
    plan_path = Path(owner["model_governance"]["plan_path"])
    model_plan, _relative = private_plan_file(project, directory, plan_path, "public-model-governance/v1")
    model_plan = public_model_governance.validate_plan(model_plan, project, bootstrap.BUSINESS_SCOPE)
    embeddings = [row for row in model_plan["models"] if row["kind"] == "embedding"]
    if len(embeddings) != 1:
        raise RuntimeError("exactly one approved embedding model must drive the source index dimensions")
    dimensions = embeddings[0]["capabilities"].get("dimensions")
    plan = public_knowledge.validate_plan(public_knowledge.build_plan(project, bootstrap.BUSINESS_SCOPE, dimensions),
                                          project, bootstrap.BUSINESS_SCOPE)
    target = owner_private_output(directory, output)
    bootstrap.write_new_private_file(target, json.dumps(plan, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    relative = target.relative_to(directory.resolve()).as_posix()
    _current_directory, current_owner, _current_passwords = read_manifest(project)
    current_owner["knowledge_plan"] = {"path": relative, "plan_sha256": public_knowledge.digest(plan),
                                       "embedding_dimensions": dimensions}
    write_json_private(directory / "owner.json", current_owner)
    print(json.dumps({"result": "repository_knowledge_source_plan_saved", "project": project,
                      "path": relative, "source_count": 3, "embedding_dimensions": dimensions,
                      "source_files_modified": False, "api_called": False}, ensure_ascii=False))
    return target


def knowledge_source_phase(project: str, directory: Path, language: str, confirm=None) -> dict:
    _directory, owner, _passwords = read_manifest(project)
    if (not owner.get("identity_complete") or not owner.get("services_ready")
            or language not in public_knowledge.EXAMPLES):
        raise RuntimeError("source publication requires an isolated initialized owner and one exact repository teaching language")
    verify_owner_frontend(project, directory, owner)
    verify_example_container_health(project, directory)
    plan = load_knowledge_plan(project, directory, owner)
    api = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    admin_profile = bootstrap.profile(api, "system.admin")
    if admin_profile.get("resource_grants") != [] or admin_profile.get("task_assignments") != []:
        raise RuntimeError("system.admin may manage the teaching source but cannot receive business run grants or task assignments")
    journal = owner.get("knowledge_replay_journal") or {}

    def approve(owner_project: str, selected_language: str, stage: str, request_digest: str) -> bool:
        phrase = f"{owner_project} knowledge {selected_language} {stage} {request_digest}"
        return confirm_digest_phrase(phrase, confirm)

    def persist(value: dict) -> None:
        _current_directory, current_owner, _current_passwords = read_manifest(project)
        current_owner["knowledge_replay_journal"] = value
        write_json_private(directory / "owner.json", current_owner)

    receipt = public_knowledge.publish_source(api, plan, project, bootstrap.BUSINESS_SCOPE,
                                               language, journal, approve, persist)
    _current_directory, current_owner, _current_passwords = read_manifest(project)
    current_owner["knowledge_replay_journal"] = journal
    write_json_private(directory / "owner.json", current_owner)
    print(json.dumps({"result": "repository_teaching_source_receipt_verified", "project": project,
                      "language": language, "document_id": receipt["document_id"],
                      "document_version": receipt["document_version"], "source_revision": receipt["source_revision"],
                      "acl_revision": receipt["acl_revision"], "content_digest": receipt["content_digest"],
                      "raw_body_printed": False}, ensure_ascii=False))
    return receipt


def knowledge_source_provenance(project: str, receipt: dict) -> str:
    required = ("source_revision", "acl_revision", "content_digest")
    if (not isinstance(receipt, dict) or any(type(receipt.get(key)) is not int or receipt[key] < 1 for key in required[:2])
            or not re.fullmatch(r"[a-f0-9]{64}", str(receipt.get("content_digest", "")))):
        raise RuntimeError("Knowledge source receipt lacks its exact source/ACL revision and content digest")
    return (f"public-knowledge-receipt:{project}:source={receipt['source_revision']}"
            f":acl={receipt['acl_revision']}:sha256={receipt['content_digest']}")


def verify_policy_knowledge_receipt(project: str, directory: Path, owner: dict, plan: dict,
                                   release: dict) -> dict:
    source_plan = load_knowledge_plan(project, directory, owner)
    language = {"example-go-operations": "go", "example-python-documents": "python",
                "example-java-tickets": "java"}.get(plan["agent_id"])
    if not language:
        raise RuntimeError("Policy Knowledge binding belongs to an unknown teaching Agent")
    source_item = next(row for row in source_plan["items"] if row["language"] == language)
    journal = owner.get("knowledge_replay_journal", {})
    source = journal.get("languages", {}).get(language, {}) if isinstance(journal, dict) else {}
    receipt = source.get("source_receipt") if isinstance(source, dict) else None
    if not isinstance(receipt, dict):
        raise RuntimeError("Policy publication requires the actual normal-API source/ACL receipt for this Agent")
    # The public source manager stores immutable receipt facts in the binding
    # provenance because the current KnowledgeDocumentBinding DTO has no
    # dedicated content-digest/ACL-revision fields.
    knowledge = policy_plan_asset_content(release, "knowledge")
    bindings = knowledge.get("document_bindings") if isinstance(knowledge, dict) else None
    expected_binding = {"knowledge_scope": source_item["knowledge_id"], "provider_id": "platform-knowledge",
                        "knowledge_base_id": source_item["knowledge_id"],
                        "provider_document_id": receipt.get("document_id"), "owner_id": source_item["owner"],
                        "ownership_source": knowledge_source_provenance(project, receipt),
                        "document_version": str(receipt.get("document_version")), "status": "active"}
    if (knowledge.get("allowed_scopes") != [source_item["knowledge_id"]]
            or not isinstance(bindings, list) or bindings != [expected_binding]
            or receipt.get("document_id") != source_item["document_id"]):
        raise RuntimeError("Policy KnowledgeBinding does not pin the actual source receipt, content digest, ACL and document version")
    return receipt


def verify_live_knowledge_source(api: bootstrap.BrowserAPI, project: str, directory: Path,
                                 owner: dict, plan: dict, release: dict) -> dict:
    receipt = verify_policy_knowledge_receipt(project, directory, owner, plan, release)
    source_plan = load_knowledge_plan(project, directory, owner)
    language = {"example-go-operations": "go", "example-python-documents": "python",
                "example-java-tickets": "java"}[plan["agent_id"]]
    source_item = next(row for row in source_plan["items"] if row["language"] == language)
    public_knowledge.verify_document(public_knowledge.source_snapshot(api, source_item), source_item, receipt)
    return receipt


def verify_catalog_release_author(api: bootstrap.BrowserAPI, owner: dict, plan: dict,
                                 expected_author: str) -> str:
    """Bind the document owner to the exact Catalog submitter and publication receipts."""
    agent_id = plan.get("agent_id") if isinstance(plan, dict) else None
    definition = plan.get("definition") if isinstance(plan, dict) else None
    version = plan.get("version") if isinstance(plan, dict) else None
    installation = plan.get("installation") if isinstance(plan, dict) else None
    deployment = plan.get("deployment") if isinstance(plan, dict) else None
    bundle = plan.get("bundle") if isinstance(plan, dict) else None
    manifest = version.get("manifest") if isinstance(version, dict) else None
    author = definition.get("publisher_id") if isinstance(definition, dict) else None
    if (agent_id not in {row[1] for row in bootstrap.MACHINES}
            or not isinstance(author, str) or author not in bootstrap.DEMO_USERS
            or author != expected_author or not isinstance(version, dict) or not isinstance(bundle, dict)
            or not isinstance(definition, dict) or not isinstance(installation, dict)
            or not isinstance(deployment, dict) or not isinstance(manifest, dict)
            or version.get("definition_id") != definition.get("id")
            or manifest.get("agent_id") != agent_id):
        raise RuntimeError("release bundle does not identify the exact human Catalog Definition publisher for this Knowledge owner")
    catalog_records = owner.get("catalog_lifecycle") if isinstance(owner, dict) else None
    policy_records = owner.get("policy_lifecycle") if isinstance(owner, dict) else None
    skill_records = owner.get("skill_lifecycle") if isinstance(owner, dict) else None
    catalog = catalog_records.get(agent_id, {}) if isinstance(catalog_records, dict) else None
    release_pin = {
        "agent_id": agent_id, "definition_id": definition.get("id"),
        "version_id": version.get("id"),
        "installation_id": installation.get("id"),
        "deployment_id": deployment.get("id"),
        "artifact_digest": version.get("artifact_digest"),
        "manifest_hash": bundle.get("manifest_hash"),
    }
    policy = policy_records.get(agent_id, {}) if isinstance(policy_records, dict) else None
    skills = plan.get("bundle", {}).get("skill_publications")
    if not isinstance(skills, list) or len(skills) != 1 or not isinstance(skills[0], dict):
        raise RuntimeError("release bundle does not contain the one exact independently reviewed Skill author receipt")
    skill = skills[0]
    skill_key = str(skill.get("skill_id", "")) + "/" + str(skill.get("version_id", ""))
    agent_skills = skill_records.get(agent_id, {}) if isinstance(skill_records, dict) else None
    skill_receipt = agent_skills.get(skill_key, {}) if isinstance(agent_skills, dict) else None
    skill_release = skill_receipt.get("release") if isinstance(skill_receipt, dict) else None
    if (not isinstance(catalog, dict) or catalog.get("author") != author
            or catalog.get("evaluator") != "system.admin" or catalog.get("approver") != "system.admin"
            or catalog.get("active_installation") != "system.admin" or catalog.get("release") != release_pin
            or not isinstance(policy, dict) or policy.get("published") is not True
            or policy.get("author") != author or policy.get("publisher") != "system.admin"
            or policy.get("version_id") != version.get("id")
            or policy.get("installation_id") != release_pin["installation_id"]
            or not isinstance(skill_receipt, dict) or skill_receipt.get("author") != author
            or skill_receipt.get("reviewer") != "system.admin" or skill_receipt.get("publisher") != "system.admin"
            or not isinstance(skill_release, dict)
            or skill_release.get("bundle_digest") != skill.get("bundle_digest")):
        raise RuntimeError("Catalog, Policy or Skill publication receipts do not preserve the exact independent human author")

    live_definition = maybe_get(api, catalog_definition_path(plan))
    live_version = maybe_get(api, catalog_version_path(plan))
    if (not isinstance(live_definition, dict) or live_definition.get("id") != definition.get("id")
            or live_definition.get("publisher_id") != author or live_definition.get("submitted_by") != author
            or live_definition.get("status") != "published" or live_definition.get("approved_by") != "system.admin"
            or not isinstance(live_version, dict) or live_version.get("id") != version.get("id")
            or live_version.get("definition_id") != definition.get("id")
            or live_version.get("submitted_by") != author
            or live_version.get("status") != "published" or live_version.get("approved_by") != "system.admin"
            or live_version.get("artifact_digest") != version.get("artifact_digest")
            or live_version.get("semantic_version") != version.get("semantic_version")
            or live_version.get("manifest") != version.get("manifest")):
        raise RuntimeError("live published Catalog Definition/Version author readback differs from the bundle and owner receipts")
    check_catalog_revision(live_definition, definition["id"])
    check_catalog_revision(live_version, version["id"])
    return author


def verify_model_access_policy_receipts(api: bootstrap.BrowserAPI, owner: dict,
                                        versions_by_installation: dict) -> dict:
    receipt_map = owner.get("model_access_policies")
    policies = receipt_map.get("policies") if isinstance(receipt_map, dict) else None
    if not isinstance(policies, dict) or set(policies) != set(example_authorization.SUBJECTS):
        raise RuntimeError("all six exact human/machine Model AccessPolicy receipts are required")
    model_pins = owner.get("model_governance", {}).get("models", {})
    provider_ids = sorted({model_pins[kind].get("provider_id") for kind in ("chat", "embedding")})
    definition_ids = sorted({model_pins[kind].get("definition_id") for kind in ("chat", "embedding")})
    if len(provider_ids) != 2 or len(definition_ids) != 2:
        raise RuntimeError("owner does not pin the exact two external provider and model definitions")
    live = {}
    for subject, (_subject_type, installation_id) in example_authorization.SUBJECTS.items():
        row = policies[subject]
        expected_request = {"tenant_id": bootstrap.BUSINESS_SCOPE["tenant_id"],
                            "department_id": bootstrap.BUSINESS_SCOPE["department_id"],
                            "application_id": bootstrap.BUSINESS_SCOPE["application_id"],
                            "installation_id": installation_id,
                            "agent_version_id": versions_by_installation.get(installation_id),
                            "principal_id": subject, "allow_local": False, "allow_private": False,
                            "allow_external": True, "allowed_providers": provider_ids,
                            "allowed_models": definition_ids}
        if (not isinstance(row, dict) or row.get("request") != expected_request
                or not isinstance(row.get("verified"), dict) or row["verified"].get("status") != "approved"):
            raise RuntimeError("owner Model AccessPolicy receipt does not bind the exact subject, version and approved model set")
        identifier = row["verified"].get("id")
        current = api.call("GET", public_model_governance.PREFIX + "/access-policies/" + bootstrap.urllib.parse.quote(identifier, safe=""))
        if (not isinstance(current, dict) or any(current.get(key) != value for key, value in expected_request.items())
                or current.get("status") != "approved" or current.get("revision") != row["verified"].get("revision")):
            raise RuntimeError("live Model AccessPolicy differs from its exact approved owner receipt")
        live[subject] = current
    return live


def verify_active_index_workload_credentials(project: str, directory: Path,
                                             api: bootstrap.BrowserAPI, journal: dict) -> dict:
    if (journal.get("owner") != project or not isinstance(journal.get("machines"), dict)
            or set(journal["machines"]) != {row[0] for row in bootstrap.MACHINES}
            or not isinstance(journal.get("mount_activation"), dict)
            or journal["mount_activation"].get("status") != "verified"):
        raise RuntimeError("index worker credential proof is incomplete for this owner")
    values = machine_environment_credentials(directory)
    inventory = validate_index_machine_credentials_for_rotation(
        api.call("GET", INDEX_WORKLOAD_ROTATION_PATH), journal, directory)
    sdk_ips = verify_sdk_process_machine_credentials(project, directory, values)
    secret_root = directory / "empty-secrets"
    expected_files = set()
    verified = {}
    for language in public_knowledge.EXAMPLES:
        machine_id, _agent_id, installation_id, prefix = index_workload_machine(language)
        entry = journal["machines"].get(machine_id)
        if (not isinstance(entry, dict) or entry.get("status") != "environment_updated"
                or entry.get("installation_id") != installation_id):
            raise RuntimeError("index workload credential journal lacks a completed exact rotation")
        receipt = read_index_rotation_receipt(project, directory, language,
                                              {"request_sha256": entry.get("request_sha256"),
                                               "machine_id": machine_id,
                                               "installation_id": installation_id})
        response = validate_index_machine_rotation_response(receipt["response"], machine_id,
                                                             entry["expected_revision"], entry["network_cidrs"])
        current = inventory.get(machine_id)
        if (not isinstance(current, dict) or current.get("revision") != response["revision"]
                or current.get("network_cidrs") != response["network_cidrs"]
                or values[prefix + "_CLIENT_ID"] != machine_id
                or values[prefix + "_CLIENT_SECRET"] != response["client_secret"]
                or sdk_ips.get(machine_id) + "/32" != entry["network_cidrs"][0]):
            raise RuntimeError("live machine credential, synchronized SDK environment and exact source CIDR do not agree")
        profile = bootstrap.profile(api, machine_id, "service_principal")
        revision, boundary = machine_access_boundary(profile, machine_id)
        digest = hashlib.sha256(example_authorization.canonical(boundary)).hexdigest()
        if (revision != entry.get("profile_revision_after")
                or digest != entry.get("access_boundary_sha256")):
            raise RuntimeError("machine role/Grant profile changed after credential rotation")
        filename = index_workload_secret_filename(bootstrap.BUSINESS_SCOPE, installation_id)
        expected_files.add(filename)
        path = secret_root / filename
        bootstrap.verify_private_file(path)
        expected_content = json.dumps({"client_id": machine_id, "client_secret": response["client_secret"]},
                                      separators=(",", ":")) + "\n"
        if path.read_text(encoding="utf-8") != expected_content:
            raise RuntimeError("active worker credential file differs from the exact rotated identity receipt")
        verified[machine_id] = {"credential_revision": response["revision"],
                                "profile_revision": revision, "sdk_ip": sdk_ips[machine_id],
                                "secret_file": filename}
    if {path.name for path in secret_root.iterdir()} != expected_files:
        raise RuntimeError("active workload credential mount has unexpected or missing files")
    return {"machines": verified, "count": len(verified), "secrets_printed": False}


def knowledge_index_phase(project: str, directory: Path, language: str, actor: str,
                          confirm_resource: str, observe: bool = False, confirm=None) -> dict:
    _directory, owner, _passwords = read_manifest(project)
    if (not owner.get("identity_complete") or not owner.get("services_ready")
            or not owner.get("machines_complete") or owner.get("business_roles_complete") is not True
            or owner.get("authorization_complete") is not True
            or language not in public_knowledge.EXAMPLES):
        raise RuntimeError("managed knowledge indexing requires identities, healthy isolated services, machines and exact completed grants")
    if owner.get("runtime_prepared") is not True or owner.get("runtime_process_started") is not True:
        raise RuntimeError("managed Knowledge indexing requires the owner-prepared dedicated Code Runtime Compose overlay and started services")
    rotation = index_rotation_journal(owner, project)
    if (owner.get("index_workload_secrets_active") is not True
            or not isinstance(rotation.get("mount_activation"), dict)
            or rotation["mount_activation"].get("status") != "verified"
            or not isinstance(rotation.get("deployment"), dict)
            or rotation["deployment"].get("status") not in {"verified", "corrected"}):
        raise RuntimeError("managed Knowledge indexing requires all three owner workload credentials activated after verified SDK process switching")
    verify_owner_frontend(project, directory, owner)
    verify_example_container_health(project, directory)
    plan = load_knowledge_plan(project, directory, owner)
    item = next(row for row in plan["items"] if row["language"] == language)
    expected_actor = item["owner"]
    if actor != expected_actor:
        raise ValueError("managed indexing must use the exact document owner human identity")
    target = item["knowledge_id"] + "@" + item["installation_id"]
    if confirm_resource != target:
        raise ValueError("managed indexing requires the exact Knowledge ID and active installation confirmation")
    machine_id = item["machine"]
    agent_id = next(row[1] for row in bootstrap.MACHINES if row[0] == machine_id)
    plans = load_pinned_release_plans(project, directory, owner)
    release = plans.get(agent_id)
    if not isinstance(release, dict):
        raise RuntimeError("Knowledge indexing has no pinned Catalog release bundle for this teaching Agent")
    verify_owner_frontend(project, directory, owner)
    source_reader = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    workload_credential_proof = verify_active_index_workload_credentials(project, directory, source_reader, rotation)
    release_author = verify_catalog_release_author(source_reader, owner, release, expected_actor)
    if release_author != expected_actor:
        raise RuntimeError("temporary policy.manage author must be the verified Catalog author who owns this teaching document")
    require_temporary_author_role(project, directory, agent_id, release_author)
    installations = verify_catalog_installation_readiness(source_reader)
    installation_versions = {row["installation_id"]: row["agent_version_id"] for row in installations}
    model_access = verify_model_access_policy_receipts(source_reader, owner, installation_versions)
    policy_inventory = {key: live_policy_inventory(source_reader, project, directory, owner, value)
                        for key, value in plans.items()}
    source_receipt = verify_live_knowledge_source(source_reader, project, directory, owner, release,
                                                  policy_release_for_plan(release))
    if not public_knowledge.source_snapshot(source_reader, item):
        raise RuntimeError("system administrator cannot read the exact source snapshot for indexing")
    installations_by_machine = {row["machine_id"]: row for row in installations}
    active = installations_by_machine.get(machine_id)
    if (not active or active["installation_id"] != item["installation_id"]
            or active["agent_version_id"] != release["version"]["id"]
            or not model_access.get(expected_actor) or not model_access.get(machine_id)):
        raise RuntimeError("owner and workload need exact active installation/version and approved per-principal Model AccessPolicies")
    authorization_attempt = owner.get("authorization_attempt", {})
    if authorization_attempt.get("status") != "complete" or authorization_attempt.get("plan_digest") is None:
        raise RuntimeError("managed indexing requires the complete owner-journaled explicit Grant plan")
    verify_business_role_profiles(source_reader, owner, project)
    grant_plan, _grant_path = load_authorization_plan(project, directory, Path(authorization_attempt["plan_path"]))
    verify_plan_allowlist(grant_plan, policy_inventory)
    subject_changes = {row["subject_id"]: row for row in grant_plan["changes"]}
    for principal in (expected_actor, machine_id):
        change = subject_changes.get(principal)
        if not isinstance(change, dict) or not any(
            grant["resource_type"] == "model" and grant["action"] == "model.embed"
            and grant["resource_id"] == policy_inventory[agent_id][0].get("model_profile_id")
            for grant in change["resource_grants"]
        ):
            raise RuntimeError("managed indexing requires explicit model.embed Grants for both document owner and bound machine")
    journal = owner.get("knowledge_replay_journal") or {}

    def approve(owner_project: str, selected_language: str, stage: str, request_digest: str) -> bool:
        phrase = f"{owner_project} knowledge {selected_language} {stage} {request_digest}"
        return confirm_digest_phrase(phrase, confirm)

    def persist(value: dict) -> None:
        _current_directory, current_owner, _current_passwords = read_manifest(project)
        current_owner["knowledge_replay_journal"] = value
        write_json_private(directory / "owner.json", current_owner)

    if observe:
        owner_api = owner_human_api(project, directory, expected_actor, bootstrap.BUSINESS_SCOPE)
        result = public_knowledge.observe_index(owner_api, source_reader, plan, project,
                                               bootstrap.BUSINESS_SCOPE, language, journal, persist)
    else:
        owner_api = owner_human_api(project, directory, expected_actor, bootstrap.BUSINESS_SCOPE)
        result = public_knowledge.submit_index(owner_api, source_reader, plan, project,
                                               bootstrap.BUSINESS_SCOPE, language, journal, approve, persist)
    _current_directory, current_owner, _current_passwords = read_manifest(project)
    current_owner["knowledge_replay_journal"] = journal
    lifecycle = current_owner.setdefault("knowledge_index_lifecycle", {})
    lifecycle[agent_id] = {"language": language, "actor": expected_actor, "machine": machine_id,
                           "installation_id": item["installation_id"],
                           "index_receipt": journal.get("languages", {}).get(language, {}).get("index_receipt"),
                           "last_observed_status": result.get("status"),
                           "index_publication_verified": result.get("index_publication_verified") is True,
                           "source_content_digest": source_receipt["content_digest"],
                           "business_retrieval_proven": result.get("business_retrieval_proven", False)}
    write_json_private(directory / "owner.json", current_owner)
    print(json.dumps({"result": "knowledge_index_observed" if observe else "knowledge_index_submitted",
                      "project": project, "language": language, **result,
                      "workload_credentials_verified": workload_credential_proof["count"],
                      "business_retrieval_proven": result.get("business_retrieval_proven", False)}, ensure_ascii=False))
    return result


def policy_release_for_plan(plan: dict) -> dict:
    prepared = public_policy.validate_plan(plan["bundle"])
    policy = prepared["plan"]
    expected_scope = {"tenant_id": bootstrap.BUSINESS_SCOPE["tenant_id"],
                      "department_id": bootstrap.BUSINESS_SCOPE["department_id"],
                      "application_id": bootstrap.BUSINESS_SCOPE["application_id"],
                      "agent_id": plan["agent_id"], "agent_version_id": plan["version"]["id"]}
    if (prepared["scope"] != expected_scope
            or policy.get("installation_id") != plan["installation"]["id"]
            or policy.get("schema") != "policyasset-preparation/v1"
            or policy.get("preparation_only") is not True):
        raise ValueError("six-policy preparation does not match this exact Catalog Agent, Version and Installation")
    return prepared


def policy_plan_asset_content(release: dict, asset_type: str) -> dict:
    """Read content from the public release-plan descriptor's canonical shape."""
    assets = release.get("assets") if isinstance(release, dict) else None
    item = assets.get(asset_type) if isinstance(assets, dict) else None
    template = item.get("create_request_template") if isinstance(item, dict) else None
    body = template.get("body") if isinstance(template, dict) else None
    content = body.get("content") if isinstance(body, dict) else None
    if not isinstance(content, dict):
        raise RuntimeError(f"prepared {asset_type} PolicyAsset lacks create_request_template.body.content")
    return content


def build_owner_policy_input(agent_id: str, version_id: str, installation_id: str,
                             model_pins: dict, prices: dict, knowledge_item: dict,
                             source_receipt: dict, owner_project: str, policy_fragments: list,
                             run_budget_tokens: int, run_budget_micros: int,
                             allow_external_provider: bool) -> dict:
    """Fill the reviewed repository policy template from exact owner receipts."""
    entry = next((row for row in bootstrap.MACHINES if row[1] == agent_id), None)
    language = {"example-go-operations": "go", "example-python-documents": "python",
                "example-java-tickets": "java"}.get(agent_id)
    templates = {"example-go-operations": "example-go-operations.policy-input.template.json",
                 "example-python-documents": "example-python-documents.policy-input.template.json",
                 "example-java-tickets": "example-java-tickets.policy-input.template.json"}
    if entry is None or language is None or not isinstance(version_id, str) or not version_id:
        raise ValueError("release preparation is limited to the three exact repository examples and an explicit Version ID")
    if installation_id != entry[2]:
        raise ValueError("release preparation must use the predeclared one-to-one public example Installation ID")
    if type(run_budget_tokens) is not int or not 1 <= run_budget_tokens <= public_policy.MAX_RUN_BUDGET_TOKENS:
        raise ValueError("per-Run token ceiling must be explicit, positive and at most 32000")
    if type(run_budget_micros) is not int or not 1 <= run_budget_micros <= public_policy.MAX_RUN_BUDGET_MICROS:
        raise ValueError("per-Run micro ceiling must be explicit, positive and at most 3200000")
    if allow_external_provider is not True:
        raise ValueError("external teaching-provider execution requires the explicit --allow-external-provider flag")
    template_path = ROOT / "deploy" / "local" / templates[agent_id]
    try:
        template = json.loads(template_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise RuntimeError("repository six-policy template is missing or invalid") from None
    scope = {"tenant_id": bootstrap.BUSINESS_SCOPE["tenant_id"],
             "department_id": bootstrap.BUSINESS_SCOPE["department_id"],
             "application_id": bootstrap.BUSINESS_SCOPE["application_id"],
             "agent_id": agent_id, "agent_version_id": version_id}
    if (not isinstance(template, dict) or set(template) != {"installation_id", "scope", "assets"}
            or template.get("installation_id") != installation_id
            or not isinstance(template.get("assets"), list) or len(template["assets"]) != 6):
        raise RuntimeError("repository six-policy template does not match the exact Installation and six asset families")
    assets = {row.get("type"): row for row in template["assets"] if isinstance(row, dict)}
    if set(assets) != set(public_policy.ASSET_TYPES):
        raise RuntimeError("repository policy template must contain each of the six current public asset families once")
    model_pin, embedding_pin = model_pins.get("chat"), model_pins.get("embedding")
    chat_price, embedding_price = prices.get("chat"), prices.get("embedding")
    for pin, price in ((model_pin, chat_price), (embedding_pin, embedding_price)):
        if (not isinstance(pin, dict) or not isinstance(price, dict)
                or pin.get("price_version_id") != price.get("id") or price.get("status") != "approved"
                or price.get("currency") != "USD"
                or any(type(price.get(key)) is not int or price[key] <= 0 for key in (
                    "input_micros_per_1k_tokens", "output_micros_per_1k_tokens"))):
            raise RuntimeError("both Model Governance prices must be the exact current approved USD PriceVersions")
    model = assets["model"].get("content")
    if not isinstance(model, dict):
        raise RuntimeError("model policy template is incomplete")
    model.update({"provider": model_pin["provider_key"], "model": model_pin["model_key"],
                  "model_version_id": model_pin["version_id"],
                  "embedding_provider": embedding_pin["provider_key"],
                  "embedding_model": embedding_pin["model_key"],
                  "embedding_model_version_id": embedding_pin["version_id"],
                  "input_micros_per_1k_tokens": chat_price["input_micros_per_1k_tokens"],
                  "output_micros_per_1k_tokens": chat_price["output_micros_per_1k_tokens"],
                  "allow_external": True})
    knowledge = assets["knowledge"].get("content")
    if (not isinstance(knowledge, dict) or not isinstance(knowledge_item, dict)
            or knowledge_item.get("language") != language
            or not isinstance(source_receipt, dict)
            or source_receipt.get("document_id") != knowledge_item.get("document_id")):
        raise RuntimeError("actual published Knowledge receipt does not match this example's planned source/document")
    knowledge["allowed_scopes"] = [knowledge_item["knowledge_id"]]
    knowledge["document_bindings"] = [{
        "knowledge_scope": knowledge_item["knowledge_id"], "provider_id": "platform-knowledge",
        "knowledge_base_id": knowledge_item["knowledge_id"],
        "provider_document_id": source_receipt["document_id"], "owner_id": knowledge_item["owner"],
        "ownership_source": knowledge_source_provenance(project=owner_project, receipt=source_receipt),
        "document_version": str(source_receipt["document_version"]), "status": "active",
    }]
    runtime = assets["runtime"].get("content")
    if not isinstance(runtime, dict):
        raise RuntimeError("runtime policy template is incomplete")
    runtime["run_budget"] = {"limit_tokens": run_budget_tokens, "limit_micros": run_budget_micros}
    expected_skill = next((item["skill_id"] for item in template_skill_rows(agent_id)), None)
    tool_fragment = next((row.get("tool_policy_fragment") for row in policy_fragments
                          if isinstance(row, dict) and row.get("skill_id") == next(
                              (item["skill_id"] for item in template_skill_rows(agent_id)), None)), None)
    runtime_fragment = next((row.get("runtime_policy_fragment") for row in policy_fragments
                             if isinstance(row, dict) and row.get("skill_id") == next(
                                 (item["skill_id"] for item in template_skill_rows(agent_id)), None)), None)
    if (not expected_skill or not isinstance(tool_fragment, dict) or not isinstance(runtime_fragment, dict)
            or not isinstance(tool_fragment.get("functions"), list)
            or not isinstance(tool_fragment.get("allowed_tools"), list)
            or not isinstance(tool_fragment.get("require_confirmation"), list)
            or not isinstance(runtime_fragment.get("allowed_skills"), list)):
        raise RuntimeError("offline example-release-bundle tool/runtime fragments are incomplete")
    assets["tool"]["content"] = deepcopy(tool_fragment)
    runtime["allowed_skills"] = deepcopy(runtime_fragment["allowed_skills"])
    return {"installation_id": installation_id, "scope": scope,
            "assets": [assets[asset_type] for asset_type in public_policy.ASSET_TYPES]}


def template_skill_rows(agent_id: str) -> list[dict]:
    relative = {"example-go-operations": "examples/go-operations/skills/guidance.v1.json",
                "example-python-documents": "examples/python-documents/skills/guidance.v1.json",
                "example-java-tickets": "examples/java-tickets/skills/guidance.v1.json"}.get(agent_id)
    if not relative:
        return []
    try:
        value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [value] if isinstance(value, dict) else []


def prepare_release_plan(project: str, directory: Path, agent_id: str, publisher: str,
                         artifact_digest: str, version_id: str, installation_id: str,
                         deployment_id: str, run_budget_tokens: int, run_budget_micros: int,
                         allow_external_provider: bool, policy_input_output: Path,
                         release_plan_output: Path) -> dict:
    _directory, owner, _passwords = read_manifest(project)
    if (not owner.get("identity_complete") or not owner.get("services_ready")
            or not owner.get("model_secrets_ready") or not owner.get("runtime_process_started")
            or publisher not in bootstrap.DEMO_USERS or not re.fullmatch(r"sha256:[a-f0-9]{64}", artifact_digest)):
        raise RuntimeError("release generation requires initialized owner services, Runtime, explicit image digest and a demo human author")
    expected_author = {"example-go-operations": "demo.go.user",
                       "example-python-documents": "demo.python.user",
                       "example-java-tickets": "demo.java.user"}.get(agent_id)
    entry = next((row for row in bootstrap.MACHINES if row[1] == agent_id), None)
    if entry is None or publisher != expected_author:
        raise ValueError("each public example release must use its matching demo human as the author")
    verify_owner_frontend(project, directory, owner)
    verify_example_container_health(project, directory)
    model_plan, model_pins = model_governance_pins(project, directory, owner)
    admin = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    admin_profile = bootstrap.profile(admin, "system.admin")
    if admin_profile.get("resource_grants") != [] or admin_profile.get("task_assignments") != []:
        raise RuntimeError("release preparation may read control-plane resources but system.admin must remain without business grants")
    verify_model_deployment_observations(admin, project, directory, owner)
    prices = {kind: public_policy.current_effective_price(admin, model_pins[kind]["version_id"])
              for kind in ("chat", "embedding")}
    knowledge_plan = load_knowledge_plan(project, directory, owner)
    language = {"example-go-operations": "go", "example-python-documents": "python",
                "example-java-tickets": "java"}[agent_id]
    knowledge_item = next(row for row in knowledge_plan["items"] if row["language"] == language)
    knowledge_journal = owner.get("knowledge_replay_journal", {}).get("languages", {}).get(language, {})
    source_receipt = knowledge_journal.get("source_receipt") if isinstance(knowledge_journal, dict) else None
    if not isinstance(source_receipt, dict):
        raise RuntimeError("publish the exact repository Knowledge source before preparing its policy bundle")
    endpoint = "http://" + entry[3].lower().replace("_", "-") + ":8080"
    base_args = ["go", "run", "./cmd/example-release-bundle", "--example",
                 str(ROOT / {"example-go-operations": "examples/go-operations",
                             "example-python-documents": "examples/python-documents",
                             "example-java-tickets": "examples/java-tickets"}[agent_id]),
                 "--artifact-digest", artifact_digest, "--publisher", publisher,
                 "--tenant", bootstrap.BUSINESS_SCOPE["tenant_id"],
                 "--department", bootstrap.BUSINESS_SCOPE["department_id"],
                 "--application", bootstrap.BUSINESS_SCOPE["application_id"],
                 "--version-id", version_id, "--installation-id", installation_id,
                 "--deployment-id", deployment_id, "--endpoint", endpoint]
    first = subprocess.run(base_args, cwd=ROOT / "platform", capture_output=True, timeout=600)
    if first.returncode:
        raise RuntimeError("public example-release-bundle source/manifest preparation failed; diagnostics were suppressed")
    try:
        prepared = json.loads(first.stdout.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise RuntimeError("public example-release-bundle generator returned invalid JSON") from None
    fragments = prepared.get("policy_fragments") if isinstance(prepared, dict) else None
    policy_input = build_owner_policy_input(agent_id, version_id, installation_id, model_pins, prices,
                                           knowledge_item, source_receipt, project, fragments or [],
                                           run_budget_tokens, run_budget_micros, allow_external_provider)
    metadata = verify_model_plan_mount(project, directory, model_plan)
    mode = owner_chat_reasoning_mode(metadata['endpoints']['service://example-chat'])
    if mode is not None:
        next(row for row in policy_input['assets'] if row['type'] == 'model')['content']['reasoning_mode'] = mode
    policy_path = write_or_reuse_exact_private_json(directory, policy_input_output, policy_input)
    # The public CLI itself verifies an existing plan byte-for-byte against
    # the regenerated value and never overwrites it. Allow the exact existing
    # path through so a caller can resume after offline generation completed
    # but a later readback assertion failed.
    output_path = owner_private_output(directory, release_plan_output, allow_existing=True)
    args = argparse.Namespace(example=str(ROOT / {"example-go-operations": "examples/go-operations",
                                                   "example-python-documents": "examples/python-documents",
                                                   "example-java-tickets": "examples/java-tickets"}[agent_id]),
                              artifact_digest=artifact_digest, publisher=publisher,
                              tenant=bootstrap.BUSINESS_SCOPE["tenant_id"],
                              department=bootstrap.BUSINESS_SCOPE["department_id"],
                              application=bootstrap.BUSINESS_SCOPE["application_id"],
                              version_id=version_id, installation_id=installation_id,
                              deployment_id=deployment_id, endpoint=endpoint,
                              policy_input=policy_path, output=output_path)
    public_policy.prepare_plan(args)
    plan = load_release_bundle(directory, output_path, agent_id)
    if plan["deployment"].get("endpoint_ref") != endpoint:
        raise RuntimeError("prepared Catalog deployment endpoint differs from the exact example Compose service")
    release = policy_release_for_plan(plan)
    public_policy.ensure_publishable_policy(release)
    verify_policy_knowledge_receipt(project, directory, owner, plan, release)
    verify_live_knowledge_source(admin, project, directory, owner, plan, release)
    remember_release_plan(project, directory, plan, output_path)
    return {"plan": plan, "policy_input_path": policy_path, "release_plan_path": output_path,
            "model_plan": model_plan, "prices": prices}


def owner_chat_reasoning_mode(endpoint: str) -> str | None:
    # DeepSeek defaults can spend a bounded retrieval stage entirely on hidden
    # reasoning. Publish its supported non-thinking mode explicitly. Other
    # vendors retain their own dialect; never send a DeepSeek extension to them.
    parsed = bootstrap.urllib.parse.urlsplit(endpoint)
    return 'disabled' if parsed.scheme == 'https' and parsed.hostname == 'api.deepseek.com' else None


def verify_model_plan_mount(project: str, directory: Path, plan: dict) -> dict:
    """Bind each key-free model descriptor to this owner's private endpoint mount."""
    metadata_path = directory / "model-metadata.json"
    if bootstrap.is_reparse_point(metadata_path):
        raise RuntimeError("owner model metadata must be a regular private file")
    bootstrap.verify_private_file(metadata_path)
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise RuntimeError("owner model metadata is unreadable") from None
    expected = {"schema": "public-model-metadata/v1",
                "endpoints": {"service://example-chat", "service://example-embedding"},
                "key_files": {"chat": "deepseek.key", "embedding": "embedding.key"}}
    if (not isinstance(metadata, dict) or set(metadata) != set(expected)
            or metadata.get("schema") != expected["schema"]
            or not isinstance(metadata.get("endpoints"), dict)
            or set(metadata["endpoints"]) != expected["endpoints"]
            or metadata.get("key_files") != expected["key_files"]):
        raise RuntimeError("owner model metadata is incomplete or outside the two-provider replay boundary")
    env = read_owner_env(directory)
    try:
        mounted = json.loads(env.get("PLATFORM_MODEL_ENDPOINTS_JSON", ""))
    except ValueError:
        raise RuntimeError("private Compose model endpoint mapping is invalid") from None
    if mounted != metadata["endpoints"] or env.get("PLATFORM_POLICY_RESOLVER") != "sql":
        raise RuntimeError("Compose model endpoint mount differs from the owner-prepared metadata or policy resolver")
    for filename in expected["key_files"].values():
        key_path = directory / "model-secrets" / filename
        if bootstrap.is_reparse_point(key_path):
            raise RuntimeError("owner model credential mount may not contain links or reparse points")
        bootstrap.verify_private_file(key_path)
    by_kind = {item["kind"]: item for item in plan.get("models", []) if isinstance(item, dict)}
    if set(by_kind) != {"chat", "embedding"}:
        raise RuntimeError("model plan must contain exactly one chat and embedding descriptor")
    for kind, ref in (("chat", "service://example-chat"), ("embedding", "service://example-embedding")):
        item = by_kind[kind]
        descriptor = {"model": item["model_key"], "endpoint": metadata["endpoints"][ref],
                      "capabilities": item["capabilities"]}
        if (item["endpoint_ref"] != ref
                or item["secret_ref"] != "secret://" + expected["key_files"][kind]
                or item["descriptor_sha256"] != public_model_governance.digest(descriptor)):
            raise RuntimeError("Model Governance descriptor is not bound to the exact owner-mounted provider endpoint, model and capabilities")
    return metadata


def model_governance_pins(project: str, directory: Path, owner: dict) -> tuple[dict, dict]:
    recorded = owner.get("model_governance")
    if not isinstance(recorded, dict) or recorded.get("model_deployment_readiness_proven") is not True:
        raise RuntimeError("policy lifecycle requires both provider probes and trusted ready observations")
    path = Path(recorded.get("plan_path", ""))
    plan, _relative = private_plan_file(project, directory, path, "public-model-governance/v1")
    checked = public_model_governance.validate_plan(plan, project, bootstrap.BUSINESS_SCOPE)
    models = recorded.get("models")
    if not isinstance(models, dict) or set(models) != {"chat", "embedding"}:
        raise RuntimeError("owner model Governance receipt does not pin both current models")
    for item in checked["models"]:
        pin = models[item["kind"]]
        if (not isinstance(pin, dict) or pin.get("provider_key") != item["provider_key"]
                or pin.get("model_key") != item["model_key"]
                or not isinstance(pin.get("version_id"), str) or not pin["version_id"]
                or not isinstance(pin.get("price_version_id"), str) or not pin["price_version_id"]
                or pin.get("deployment_status") != "ready" or pin.get("health_status") != "ready"
                or type(pin.get("observed_revision")) is not int or pin["observed_revision"] < 1
                or type(pin.get("revision")) is not int or pin["revision"] != pin["observed_revision"] + 1
                or pin.get("provider_probe_verified") is not True):
            raise RuntimeError("owner model Governance receipt differs from the reviewed provider/model descriptor")
    verify_model_plan_mount(project, directory, checked)
    return checked, models


def verify_policy_model_governance(api: bootstrap.BrowserAPI, project: str, directory: Path,
                                   owner: dict, release: dict) -> dict:
    checked, pins = model_governance_pins(project, directory, owner)
    verify_model_deployment_observations(api, project, directory, owner)
    by_kind = {item["kind"]: item for item in checked["models"]}
    model_content = policy_plan_asset_content(release, "model")
    expected_pairs = (
        ("chat", "provider", "model", "model_version_id"),
        ("embedding", "embedding_provider", "embedding_model", "embedding_model_version_id"),
    )
    prices = {}
    for kind, provider_field, model_field, version_field in expected_pairs:
        configured, pin, planned = model_content, pins[kind], by_kind[kind]
        if (configured.get(version_field) != pin["version_id"]
                or configured.get(provider_field) not in {pin["provider_key"], pin["provider_id"]}
                or configured.get(model_field) not in {pin["model_key"], pin["definition_id"]}):
            raise RuntimeError("published policy model/embedding selection does not match the approved Model Governance version")
        current = public_policy.current_effective_price(api, pin["version_id"])
        if (current.get("id") != pin["price_version_id"]
                or current.get("currency") != planned["price"]["currency"]
                or any(current.get(field) != planned["price"].get(field) for field in (
                    "input_micros_per_1k_tokens", "output_micros_per_1k_tokens"))):
            raise RuntimeError("current Model Governance PriceVersion differs from the owner-approved model plan")
        if kind == "chat" and any(model_content.get(field) != current.get(field) for field in (
            "input_micros_per_1k_tokens", "output_micros_per_1k_tokens")):
            raise RuntimeError("published chat policy rates differ from the currently approved PriceVersion")
        prices[kind] = current
    return prices


def policy_draft_phase(project: str, directory: Path, plan: dict, actor: str, confirm_resource: str, confirm=None) -> None:
    release = policy_release_for_plan(plan)
    target = plan["agent_id"] + "@" + plan["version"]["id"]
    if confirm_resource != target or actor != release["author"]:
        raise ValueError("PolicyAsset Draft creation requires the exact Version and the author recorded by offline preparation")
    require_temporary_author_role(project, directory, plan["agent_id"], actor)
    _directory, owner, _passwords = read_manifest(project)
    model_governance_pins(project, directory, owner)
    admin_api = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    verify_model_deployment_observations(admin_api, project, directory, owner)
    api = owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE)
    verify_live_knowledge_source(api, project, directory, owner, plan, release)
    catalog = owner.get("catalog_lifecycle", {}).get(plan["agent_id"], {})
    if catalog.get("author") != actor:
        raise RuntimeError("PolicyAsset author must be the exact temporary Catalog author for this public Agent")
    saved_confirm = public_policy.confirm
    try:
        public_policy.confirm = lambda phrase: confirm_digest_phrase(phrase, confirm)
        public_policy.create_drafts(api, release, actor)
    finally:
        public_policy.confirm = saved_confirm
    lifecycle = owner.setdefault("policy_lifecycle", {}).setdefault(plan["agent_id"], {})
    record = {"author": actor, "version_id": plan["version"]["id"],
              "installation_id": plan["installation"]["id"], "manifest_hash": plan["bundle"]["manifest_hash"],
              "asset_ids": {key: item["id"] for key, item in release["assets"].items()},
              "drafts_verified": True}
    previous = {key: value for key, value in lifecycle.items() if key in record}
    if previous and previous != record:
        raise RuntimeError("PolicyAsset lifecycle already records a different immutable author release")
    lifecycle.update(record)
    write_json_private(directory / "owner.json", owner)
    print(json.dumps({"result": "six_public_policy_drafts_verified", "project": project,
                      "agent_id": plan["agent_id"], "author": actor, "asset_count": 6}, ensure_ascii=False))


def policy_publish_phase(project: str, directory: Path, plan: dict, actor: str, confirm_resource: str, confirm=None) -> None:
    if actor != "system.admin":
        raise ValueError("PolicyAsset publication requires the separately authenticated system.admin reviewer")
    release = policy_release_for_plan(plan)
    target = plan["agent_id"] + "@" + plan["version"]["id"]
    if confirm_resource != target:
        raise ValueError("PolicyAsset publication requires the exact Agent/Version scope")
    api = owner_human_api(project, directory, actor, bootstrap.BUSINESS_SCOPE)
    _directory, owner, _passwords = read_manifest(project)
    verify_policy_model_governance(api, project, directory, owner, release)
    verify_live_knowledge_source(api, project, directory, owner, plan, release)
    catalog = owner.get("catalog_lifecycle", {}).get(plan["agent_id"], {})
    lifecycle = owner.get("policy_lifecycle", {}).get(plan["agent_id"], {})
    if (catalog.get("author") != release["author"] or release["author"] == actor
            or lifecycle.get("author") != release["author"] or lifecycle.get("drafts_verified") is not True):
        raise RuntimeError("policy publisher must be system.admin, distinct from the recorded author, after all six exact Drafts")
    saved_confirm = public_policy.confirm
    try:
        public_policy.confirm = lambda phrase: confirm_digest_phrase(phrase, confirm)
        public_policy.publish_release(api, release, actor)
    finally:
        public_policy.confirm = saved_confirm
    assets = {}
    for asset_type, item in release["assets"].items():
        live = public_policy.read_live_asset(api, item, release["scope"])
        if live is None or live.get("status") != "published":
            raise RuntimeError("six-asset publication did not verify every exact PolicyAsset as published")
        assets[asset_type] = {"id": live["id"], "revision": live["revision"], "content_hash": live["content_hash"]}
    snapshot = public_policy.current_snapshot(api, release["scope"])
    if not public_policy.snapshot_already_uses(snapshot, release):
        raise RuntimeError("PolicyAsset publisher returned without the exact current CAS snapshot")
    revision = public_policy.snapshot_value(snapshot, "Revision")
    digest = public_policy.snapshot_value(snapshot, "Hash")
    if type(revision) is not int or revision < 1 or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise RuntimeError("PolicyAsset current snapshot revision/hash did not verify")
    price = public_policy.verify_policy_price(api, release)
    lifecycle = owner.setdefault("policy_lifecycle", {}).setdefault(plan["agent_id"], {})
    lifecycle.update({"author": release["author"], "publisher": actor, "version_id": plan["version"]["id"],
                      "installation_id": plan["installation"]["id"], "manifest_hash": plan["bundle"]["manifest_hash"],
                      "asset_ids": {key: item["id"] for key, item in release["assets"].items()},
                      "assets": assets, "snapshot_revision": revision, "snapshot_hash": digest,
                      "price_version_id": price["id"], "published": True})
    write_json_private(directory / "owner.json", owner)
    print(json.dumps({"result": "six_policy_assets_and_current_snapshot_verified", "project": project,
                      "agent_id": plan["agent_id"], "publisher": actor, "snapshot_revision": revision,
                      "snapshot_hash": digest, "price_version_id": price["id"],
                      "provider_secret_printed": False}, ensure_ascii=False))


def load_pinned_release_plans(project: str, directory: Path, owner: dict) -> dict[str, dict]:
    records = owner.get("release_plans")
    expected_agents = {entry[1] for entry in bootstrap.MACHINES}
    if not isinstance(records, dict) or set(records) != expected_agents:
        raise RuntimeError("all three owner-private Catalog/Policy/Skill release plans must be pinned")
    plans = {}
    for agent_id in sorted(expected_agents):
        record = records[agent_id]
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise RuntimeError("owner release-plan pin is invalid")
        plan = load_release_bundle(directory, Path(record["path"]), agent_id)
        if any(record.get(key) != expected for key, expected in {
            "manifest_hash": plan["bundle"]["manifest_hash"], "version_id": plan["version"]["id"],
            "installation_id": plan["installation"]["id"],
        }.items()):
            raise RuntimeError("owner release plan file no longer matches its immutable manifest/version/installation pin")
        policy_release_for_plan(plan)
        plans[agent_id] = plan
    return plans


def live_policy_inventory(api: bootstrap.BrowserAPI, project: str, directory: Path, owner: dict,
                          plan: dict) -> tuple[dict, dict, dict]:
    release = policy_release_for_plan(plan)
    catalog = owner.get("catalog_lifecycle", {}).get(plan["agent_id"], {})
    recorded = owner.get("policy_lifecycle", {}).get(plan["agent_id"], {})
    if (catalog.get("author") != release["author"] or catalog.get("active_installation") != "system.admin"
            or catalog.get("approver") != "system.admin" or catalog.get("release", {}).get("version_id") != plan["version"]["id"]
            or catalog.get("release", {}).get("installation_id") != plan["installation"]["id"]):
        raise RuntimeError("actual Catalog lifecycle receipts do not pin the independent author/approver and active installation")
    if (recorded.get("published") is not True or recorded.get("author") != release["author"]
            or recorded.get("publisher") != "system.admin" or recorded.get("version_id") != plan["version"]["id"]
            or recorded.get("installation_id") != plan["installation"]["id"]):
        raise RuntimeError("owner journal lacks the completed independent six-policy publication stage")
    expected_scope = release["scope"]
    verify_live_knowledge_source(api, project, directory, owner, plan, release)
    current = public_policy.current_snapshot(api, expected_scope)
    if not public_policy.snapshot_already_uses(current, release):
        raise RuntimeError("live policy snapshot is not the exact reviewed six-asset release")
    revision, digest = public_policy.snapshot_value(current, "Revision"), public_policy.snapshot_value(current, "Hash")
    if revision != recorded.get("snapshot_revision") or digest != recorded.get("snapshot_hash") or not re.fullmatch(r"[a-f0-9]{64}", str(digest)):
        raise RuntimeError("live policy snapshot differs from the owner-pinned CAS revision/hash")
    assets = {}
    for asset_type, item in release["assets"].items():
        live = public_policy.read_live_asset(api, item, expected_scope)
        expected_pin = recorded.get("assets", {}).get(asset_type, {})
        if (live is None or live.get("status") != "published" or live.get("id") != expected_pin.get("id")
                or live.get("revision") != expected_pin.get("revision")
                or live.get("content_hash") != expected_pin.get("content_hash")):
            raise RuntimeError("one or more live immutable PolicyAsset revisions differ from the owner publication receipt")
        assets[asset_type] = live
    price = public_policy.verify_policy_price(api, release)
    if price.get("id") != recorded.get("price_version_id"):
        raise RuntimeError("current Model Governance PriceVersion differs from the release-time owner receipt")
    skill_items = plan["bundle"].get("skill_publications")
    if not isinstance(skill_items, list) or len(skill_items) != 1:
        raise RuntimeError("public example release does not contain exactly one reviewed Skill publication")
    skill = skill_items[0]
    skill_key = skill["skill_id"] + "/" + skill["version_id"]
    skill_record = owner.get("skill_lifecycle", {}).get(plan["agent_id"], {}).get(skill_key, {})
    if (skill_record.get("author") != release["author"] or skill_record.get("reviewer") != "system.admin"
            or skill_record.get("publisher") != "system.admin" or skill_record.get("release", {}).get("bundle_digest") != skill.get("bundle_digest")):
        raise RuntimeError("owner journal lacks the distinct author/reviewer/stable publisher Skill lifecycle")
    version = skill_inspect(api, skill, skill["version_id"]).get("version")
    stable = skill_inspect(api, skill).get("release")
    runtime = assets["runtime"]["content"]
    allowed_skills = runtime.get("allowed_skills") if isinstance(runtime, dict) else None
    if (not isinstance(version, dict) or version.get("status") != "approved" or version.get("digest") != skill["bundle_digest"]
            or version.get("author_id") != release["author"] or version.get("reviewer_id") != "system.admin"
            or not isinstance(stable, dict) or stable.get("stable_version") != skill["version_id"]
            or skill["skill_id"] not in (allowed_skills or [])):
        raise RuntimeError("live Skill approval/stable release is missing from the published Runtime policy")
    knowledge = assets["knowledge"]["content"]
    if not isinstance(knowledge, dict) or not knowledge.get("document_bindings") or not knowledge.get("allowed_scopes"):
        raise RuntimeError("published KnowledgePolicy has no actual source/document binding")
    for knowledge_scope in knowledge["allowed_scopes"]:
        response = api.call("GET", "/api/modules/knowledge/sources/" + bootstrap.urllib.parse.quote(knowledge_scope, safe="") + "?limit=1000")
        docs = response.get("documents") if isinstance(response, dict) else None
        if (response.get("schema_version") != "knowledge-source-snapshot/v1" or type(response.get("revision")) is not int
                or response["revision"] < 1 or not isinstance(docs, list) or not docs):
            raise RuntimeError("published KnowledgePolicy scope has no live nonempty platform knowledge-source snapshot")
        active_documents = {row.get("id"): row for row in docs if isinstance(row, dict) and row.get("deleted") is not True}
        matching = [binding for binding in knowledge["document_bindings"] if binding.get("knowledge_scope") == knowledge_scope]
        if not matching:
            raise RuntimeError("KnowledgePolicy scope is not backed by an explicit published document binding")
        # Source snapshots and provider-document IDs can have different namespaces.
        # Require live source rows and rely on the published exact binding for the
        # connector ID/version/ownership tuple; do not infer a cross-system ID.
        if any(not binding.get("provider_document_id") or not binding.get("document_version") or binding.get("status") != "active" for binding in matching) or not active_documents:
            raise RuntimeError("published knowledge bindings or source documents are inactive")
    return current, assets, {"price_version_id": price["id"], "skill_id": skill["skill_id"],
                             "skill_version_id": skill["version_id"], "knowledge_scope_count": len(knowledge["allowed_scopes"])}


def verify_plan_allowlist(plan: dict, policies: dict[str, tuple[dict, dict, dict]]) -> None:
    """Require each IAM tuple to match the latest published policy of its installation."""
    for installation_id, tuples in plan["allowed_resources"].items():
        subject = next((name for name, values in example_authorization.SUBJECTS.items() if values[1] == installation_id), None)
        if not subject:
            raise RuntimeError("authorization allowlist names no known public example installation")
        agent_id = next(row[1] for row in bootstrap.MACHINES if row[2] == installation_id)
        policy_pair = policies.get(agent_id)
        if policy_pair is None:
            raise RuntimeError("live published policy inventory is incomplete")
        _snapshot, assets, _proof = policy_pair
        snapshot = _snapshot
        content = {key: row["content"] for key, row in assets.items()}
        model_id = public_policy.snapshot_value(snapshot, "ModelProfileID")
        memory_id = public_policy.snapshot_value(snapshot, "MemoryPolicyID")
        for item in tuples:
            typ, resource, action = item["resource_type"], item["resource_id"], item["action"]
            if typ == "agent_installation":
                if action == "agent.delegate":
                    target = next((row[1] for row in bootstrap.MACHINES if row[2] == resource), None)
                    delegation = content["runtime"].get("delegation")
                    if not target or not isinstance(delegation, dict) or target not in delegation.get("allowed_agent_ids", []):
                        raise RuntimeError("agent.delegate allowlist tuple is outside the published Runtime delegation policy")
                elif resource != installation_id:
                    raise RuntimeError("direct Agent run/history permission cannot target another installation")
            elif typ == "model" and resource != model_id:
                raise RuntimeError("model allowlist tuple is outside the published Model profile")
            elif typ == "tool" and resource not in content["tool"].get("allowed_tools", []):
                raise RuntimeError("tool allowlist tuple is outside the published ToolPolicy")
            elif typ == "knowledge" and resource not in content["knowledge"].get("allowed_scopes", []):
                raise RuntimeError("knowledge allowlist tuple is outside the published KnowledgePolicy")
            elif typ == "memory" and resource != memory_id:
                raise RuntimeError("memory allowlist tuple is outside the published MemoryPolicy")
            elif typ == "skill" and resource not in content["runtime"].get("allowed_skills", []):
                raise RuntimeError("Skill allowlist tuple is outside the published Runtime policy")


def authorize_reviewed_grants(project: str, directory: Path, plan: dict, plan_relative_path: str,
                              confirm=None) -> list[dict]:
    _directory, owner, passwords = read_manifest(project)
    if (not owner.get("identity_complete") or not owner.get("services_ready") or not owner.get("machines_complete")
            or not owner.get("business_roles_complete")
            or owner.get("authorization_complete") is True):
        raise RuntimeError("grant application requires completed Identity/machine and separate role-only stages and is single-application")
    journal = owner.get("permission_admin_delegations")
    grants = [(change["subject_id"], grant) for change in plan["changes"] for grant in change["resource_grants"]]
    if (not isinstance(journal, list) or len(journal) != len(grants)
            or any(not isinstance(row, dict) or row.get("status") != "verified" for row in journal)):
        raise RuntimeError("every explicit grant requires one owner-journaled exact permission.admin delegation first")
    recorded_by_grant = {row.get("grant_id"): row for row in journal}
    if len(recorded_by_grant) != len(grants) or set(recorded_by_grant) != {grant["id"] for _, grant in grants}:
        raise RuntimeError("delegation receipt map does not match the exact six-subject authorization plan")
    plan_digest = hashlib.sha256(example_authorization.canonical(plan)).hexdigest()
    generation = delegation_generation_mode(project, plan, owner)
    for grant_index, (subject, grant) in enumerate(grants, start=1):
        item = recorded_by_grant[grant["id"]]
        id_prefix = "replay-delegation-" + project.removeprefix("agentplug-test-public-") + "-"
        if grant["resource_type"] == "agent_installation":
            expected_delegation_id = (id_prefix + ("r2-" if generation == 2 else "")
                                      + str(grant_index).zfill(3))
            expected_generation = 2 if generation == 2 else None
            expected_superseded_id = id_prefix + str(grant_index).zfill(3) if generation == 2 else None
        else:
            expected_delegation_id = id_prefix + str(grant_index).zfill(3)
            expected_generation = None
            expected_superseded_id = None
        expected_grant_digest = hashlib.sha256(example_authorization.canonical({"subject": subject, "grant": grant})).hexdigest()
        if (item.get("subject_id") != subject or item.get("delegation_id") != expected_delegation_id
                or item.get("plan_digest") != plan_digest or item.get("grant_digest") != expected_grant_digest
                or item.get("generation") != expected_generation
                or item.get("supersedes_delegation_id") != expected_superseded_id
                or example_authorization.timestamp(item.get("expires_at")) != example_authorization.timestamp(grant.get("expires_at"))):
            raise RuntimeError("delegation journal differs from this subject's exact resource/action/expiry tuple")
    verify_owner_frontend(project, directory, owner)
    verify_example_container_health(project, directory)
    resource_api = owner_human_api(project, directory, "system.admin", bootstrap.BUSINESS_SCOPE)
    installation_rows = verify_catalog_installation_readiness(resource_api)
    plans = load_pinned_release_plans(project, directory, owner)
    policies = {agent_id: live_policy_inventory(resource_api, project, directory, owner, release)
                for agent_id, release in plans.items()}
    verify_plan_allowlist(plan, policies)
    verify_business_role_profiles(resource_api, owner, project)
    expected_minimum = expected_minimum_authorization_plan(project, policies, plan)
    assert_minimum_authorization_plan(plan, expected_minimum)
    identity_api = owner_human_api(project, directory, "permission.admin", bootstrap.BUSINESS_SCOPE)
    profile = bootstrap.profile(identity_api, "permission.admin")
    require_permission_admin_appointment(profile, owner)
    if profile.get("task_assignments") != []:
        raise RuntimeError("permission.admin has unplanned task assignments")
    live_delegations = profile.get("delegations")
    if not isinstance(live_delegations, list):
        raise RuntimeError("permission.admin profile does not expose delegated authority for readback")
    if generation == 1:
        prefix_count, _prefix_receipts = verified_delegation_prefix(project, plan, owner, profile)
        if prefix_count != 57:
            raise RuntimeError("fresh Delegation layout is not a fully verified 57-row live prefix")
    for grant_id, item in recorded_by_grant.items():
        matches = [row for row in live_delegations if isinstance(row, dict) and row.get("id") == item.get("delegation_id")]
        if (len(matches) != 1 or matches[0].get("status") != "active"
                or matches[0] != item.get("delegation") or matches[0].get("management_actions") != ["authorization.change"]):
            raise RuntimeError("live permission.admin delegation does not match its owner-private receipt")
        grant = next(grant for _, grant in grants if grant["id"] == grant_id)
        binding = matches[0].get("resource_bindings")
        expected_binding = {"resource_type": grant["resource_type"], "resource_id": grant["resource_id"],
                            "installation_id": grant["agent_instance_id"]}
        expected_resources = [grant["resource_id"]] if grant["resource_type"] == "agent_installation" else []
        expected_bindings = [] if grant["resource_type"] == "agent_installation" else [expected_binding]
        if (matches[0].get("resources") != expected_resources or (binding or []) != expected_bindings
                or matches[0].get("actions") != [grant["action"]]
                or matches[0].get("data_scope_types") != [grant["data_scope"]["type"]]
                or matches[0].get("data_ids", []) != grant["data_scope"].get("ids", [])
                or matches[0].get("management_actions") != ["authorization.change"]
                or matches[0].get("allow_permanent") is not False
                or type(matches[0].get("max_duration_seconds")) is not int
                or not 1 <= matches[0]["max_duration_seconds"] <= 24 * 60 * 60
                or example_authorization.timestamp(matches[0].get("expires_at")) != example_authorization.timestamp(grant["expires_at"])):
            raise RuntimeError("live permission.admin delegation exceeds or differs from the exact grant plan tuple")
    own = bootstrap.profile(resource_api, "system.admin")
    own_principal = own.get("principal") if isinstance(own, dict) else None
    if (not isinstance(own_principal, dict) or own_principal.get("id") != "system.admin"
            or own_principal.get("type") != "user" or own_principal.get("is_active") is not True
            or own.get("resource_grants") != [] or own.get("task_assignments") != []):
        raise RuntimeError("system.admin has a business task assignment; release manager may not run business work")

    active = owner.get("authorization_attempt")
    if isinstance(active, dict):
        if active.get("plan_digest") != plan_digest:
            raise RuntimeError("an earlier authorization attempt belongs to another immutable plan")
        if active.get("status") == "complete":
            return active.get("receipts", [])
    completed_subjects, prior_receipts = verified_grant_subject_prefix(owner, plan, plan_digest)
    if isinstance(active, dict):
        if (not completed_subjects or active.get("status") != "grant_subject_verified"
                or active.get("last_subject_id") != completed_subjects[-1]):
            raise RuntimeError("earlier authorization attempt is not a fully verified prefix; reconcile the first incomplete subject")
    elif completed_subjects:
        raise RuntimeError("verified Grant commits exist without their matching durable owner attempt")
    remaining_changes = plan["changes"][len(completed_subjects):]
    if not remaining_changes:
        raise RuntimeError("all subjects have receipts but authorization completion was not recorded; reconcile read-only")
    if completed_subjects:
        prefix_plan = deepcopy(plan)
        prefix_plan["changes"] = plan["changes"][:len(completed_subjects)]
        verify_live_minimum_grants(resource_api, project, prefix_plan, owner)
    if active is None:
        owner["authorization_attempt"] = {"plan_digest": plan_digest, "plan_path": plan_relative_path,
                                           "status": "preview_started", "subjects": [subject for subject, _ in grants]}
        write_json_private(directory / "owner.json", owner)
    apply_plan = deepcopy(plan)
    apply_plan["changes"] = deepcopy(remaining_changes)
    remaining_grant_ids = {grant["id"] for change in remaining_changes for grant in change["resource_grants"]}
    receipts = list(prior_receipts)

    confirm_callback = confirm

    def approve(phrase: str) -> bool:
        return confirm_digest_phrase(phrase, confirm_callback)

    def record(entry: dict) -> None:
        _current_directory, current_owner, _current_passwords = read_manifest(project)
        events = current_owner.setdefault("authorization_journal", [])
        safe = {key: entry.get(key) for key in ("phase", "subject_id", "plan_digest", "baseline_revision",
                                                 "grant_count", "confirmation", "change_id", "revision") if key in entry}
        events.append(safe)
        active_attempt = current_owner.get("authorization_attempt")
        if isinstance(active_attempt, dict) and active_attempt.get("plan_digest") == plan_digest:
            active_attempt["status"] = ("grant_commit_started" if entry.get("phase") == "commit_started"
                                         else "grant_subject_verified" if entry.get("phase") == "verified"
                                         else "preview_ready")
            active_attempt["last_subject_id"] = entry.get("subject_id")
        write_json_private(directory / "owner.json", current_owner)

    try:
        receipts.extend(example_authorization.apply_changes(
            identity_api, apply_plan, project, bootstrap.BUSINESS_SCOPE,
            approve, record, actor="permission.admin", resource_api=resource_api,
            profile_api=resource_api,
            delegation_ids={grant_id: item["delegation_id"]
                            for grant_id, item in recorded_by_grant.items()
                            if grant_id in remaining_grant_ids}))
    except Exception as exc:
        # Preview denial is distinct from a Grant write. A failed commit or
        # ambiguous transport remains journaled for exact receipt inspection.
        _current_directory, current_owner, _current_passwords = read_manifest(project)
        if mark_authorization_attempt_failure(current_owner, exc):
            write_json_private(directory / "owner.json", current_owner)
        raise
    verify_live_minimum_grants(resource_api, project, plan, owner)
    _current_directory, owner, _current_passwords = read_manifest(project)
    owner["authorization_attempt"] = {"plan_digest": plan_digest, "plan_path": plan_relative_path,
                                       "status": "complete", "receipts": receipts,
                                       "installation_count": len(installation_rows),
                                       "subject_count": len(plan["changes"]),
                                       "grant_count": sum(len(change["resource_grants"]) for change in plan["changes"])}
    owner["authorization_complete"] = True
    write_json_private(directory / "owner.json", owner)
    print(json.dumps({"result": "six_subject_permission_admin_grants_verified", "project": project,
                      "actor": "permission.admin", "resource_manager": "system.admin",
                      "subject_count": len(plan["changes"]), "grant_count": len(grants),
                      "delegated_grant_count": len(journal), "business_grants_for_system_admin": 0,
                      "receipts": receipts, "credentials_printed": False}, ensure_ascii=False))
    return receipts


def cleanup_phase(project: str, apply_confirmation: str) -> None:
    directory, owner, _passwords = read_manifest(project)
    if apply_confirmation != project:
        raise ValueError("cleanup requires the exact isolated project confirmation")
    if owner.get("runtime_prepared"):
        result = subprocess.run(compose_prefix(project, directory, include_runtime=True) + ["down", "--volumes", "--remove-orphans"], cwd=ROOT, capture_output=True, timeout=180, env=isolated_compose_environment(directory, include_runtime=True))
    else:
        result = subprocess.run(compose_prefix(project, directory) + ["down", "--volumes", "--remove-orphans"], cwd=ROOT, capture_output=True, timeout=180, env=isolated_compose_environment(directory))
    containers = subprocess.run(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project], capture_output=True, check=True)
    volumes = subprocess.run(["docker", "volume", "ls", "-q", "--filter", "label=com.docker.compose.project=" + project], capture_output=True, check=True)
    networks = subprocess.run(["docker", "network", "ls", "-q", "--filter", "label=com.docker.compose.project=" + project], capture_output=True, check=True)
    if containers.stdout.strip() or volumes.stdout.strip() or networks.stdout.strip():
        raise RuntimeError("isolated Compose cleanup left project-labeled containers, volumes or networks; private state was retained")
    suffix = project.removeprefix("agentplug-test-public-")
    for image in owner.get("images", []):
        if not isinstance(image, str) or not re.fullmatch(r"agentplug:test-(?:platform|frontend|metric-runner|example-go|example-python|example-java|code-runtime)-" + suffix, image):
            raise RuntimeError("private owner record contains an unexpected temporary image tag")
        inspected = subprocess.run(["docker", "image", "inspect", image], capture_output=True)
        if inspected.returncode == 0:
            removed = subprocess.run(["docker", "image", "rm", image], capture_output=True)
            if removed.returncode:
                raise RuntimeError("an isolated temporary image is still in use; private state was retained")
    state_root = STATE_ROOT.resolve()
    resolved_directory = directory.resolve()
    if resolved_directory.parent != state_root or resolved_directory.name != project or bootstrap.is_reparse_point(directory):
        raise RuntimeError("private replay cleanup target escaped its exact owner directory")
    shutil.rmtree(resolved_directory)
    print(json.dumps({"result": "isolated_project_resources_and_private_state_removed", "project": project,
                      "containers": 0, "volumes": 0, "networks": 0, "credentials_printed": False}, ensure_ascii=False))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("prepare", "model-secret-prepare", "model-plan-prepare", "release-plan-prepare", "identity", "identity-reconcile", "services", "machine-principals", "machines", "runtime-prepare", "runtime-start",
                                           "permission-admin-appoint", "permission-admin-delegate",
                                           "permission-admin-delegation-rebind", "permission-admin-grant-preview", "authorize",
                                           "model-governance", "knowledge-plan-prepare", "knowledge-source-publish",
                                           "knowledge-index-submit", "knowledge-index-observe",
                                           "index-workload-credential-rotate", "index-workload-credential-deploy",
                                           "index-workload-credential-correct-ips", "index-workload-credential-activate", "business-roles",
                                           "audit-role-grant", "audit-role-revoke", "authorization-plan-prepare",
                                           "business-plan-prepare", "business-submit", "business-observe",
                                           "business-cancel", "business-verify", "business-denials", "model-deployment-observe", "model-access-policies",
                                           "catalog-role-grant", "catalog-role-revoke",
                                           "catalog-submit", "catalog-evaluate", "catalog-publish", "catalog-install",
                                           "catalog-deploy", "catalog-observe", "catalog-activate",
                                           "policy-draft", "policy-publish",
                                           "skill-register", "skill-review", "skill-publish", "cleanup"))
    parser.add_argument("--project", help="fresh project printed by prepare")
    parser.add_argument("--confirm-project", help="type the exact random project owner before any API mutation")
    parser.add_argument("--base-url", help="exact owner loopback frontend origin; used only by machine-principals")
    parser.add_argument("--agent-cidr", action="append", default=[], help="machine source network as MACHINE_ID=CIDR; repeat three times for machine-principals")
    parser.add_argument("--runtime-subnet", help="dedicated private IPv4 subnet for deploy/compose/compose.runtime.yaml")
    parser.add_argument("--runtime-private-ip", help="actual controller address in the dedicated private subnet")
    parser.add_argument("--runtime-python-image-id", help="actual immutable Python sandbox image ID")
    parser.add_argument("--runtime-javascript-image-id", help="actual immutable JavaScript sandbox image ID")
    parser.add_argument("--runtime-shell-image-id", help="actual immutable shell sandbox image ID")
    parser.add_argument("--docker-cli-image", help="verified immutable docker.io/library/docker@sha256 digest")
    parser.add_argument("--docker-socket-gid", help="verified numeric host Docker socket group ID")
    parser.add_argument("--release-plan", help="owner-private example-release-bundle/v1 plan under this isolated project")
    parser.add_argument("--model-plan", help="owner-private public-model-governance/v1 plan under this isolated project")
    parser.add_argument("--model-plan-output", help="owner-private output path for offline Model Governance plan preparation")
    parser.add_argument("--model-kind", choices=("chat", "embedding"), help="exact approved provider to probe and observe for model-deployment-observe")
    parser.add_argument("--artifact-digest", help="actual built example image sha256 digest for offline release-plan-prepare")
    parser.add_argument("--version-id", help="explicit immutable Catalog Version ID for release-plan-prepare")
    parser.add_argument("--installation-id", help="exact predeclared example Installation ID for release-plan-prepare")
    parser.add_argument("--deployment-id", help="explicit new Catalog Deployment ID for release-plan-prepare")
    parser.add_argument("--release-plan-output", help="owner-private output path for the generated full Catalog/Skill/Policy bundle")
    parser.add_argument("--policy-input-output", help="owner-private output path for the generated complete six-policy input")
    parser.add_argument("--run-budget-tokens", type=int, help="explicit per-Run token ceiling, at most 32000")
    parser.add_argument("--run-budget-micros", type=int, help="explicit per-Run internal micro ceiling, at most 3200000")
    parser.add_argument("--allow-external-provider", action="store_true", help="explicitly authorize the plan to use the owner-approved external teaching providers")
    parser.add_argument("--knowledge-plan-output", help="owner-private output path for the repository Knowledge plan")
    parser.add_argument("--knowledge-language", choices=tuple(public_knowledge.EXAMPLES), help="exact repository teaching source language for a Knowledge or machine-credential stage")
    parser.add_argument("--chat-model", help="approved external chat model key; used only in a key-free private plan")
    parser.add_argument("--embedding-model", help="approved external embedding model key; used only in a key-free private plan")
    parser.add_argument("--chat-input-micros-per-1k-tokens", type=int)
    parser.add_argument("--chat-output-micros-per-1k-tokens", type=int)
    parser.add_argument("--embedding-input-micros-per-1k-tokens", type=int)
    parser.add_argument("--embedding-output-micros-per-1k-tokens", type=int)
    parser.add_argument("--embedding-dimensions", type=int)
    parser.add_argument("--chat-context-limit", type=int)
    parser.add_argument("--embedding-context-limit", type=int)
    parser.add_argument("--price-effective-from", help="explicit effective UTC price instant, for example 2026-10-06T00:00:00Z")
    parser.add_argument("--model-semantic-version")
    parser.add_argument("--authorization-plan", help="owner-private public-example-authorization/v1 grant plan under this isolated project")
    parser.add_argument("--authorization-plan-output", help="owner-private output path for an exact minimum Grant plan")
    parser.add_argument("--grant-duration-minutes", type=int, help="explicit Grant/delegation validity, 5..1440 minutes")
    parser.add_argument("--business-plan-output", help="owner-private output path for the six public business cases")
    parser.add_argument("--business-scenario-batch", help="fresh bounded teaching batch; preserves the previous plan and journal")
    parser.add_argument("--business-language", choices=tuple(public_business.DIRECTORIES), help="one public example language for a business API replay stage")
    parser.add_argument("--business-case", choices=("baseline", "cancel"), help="exact baseline or independent cancellation case")
    parser.add_argument("--agent-id", help="exact public example Agent ID for Catalog lifecycle stages")
    parser.add_argument("--username", help="independently authenticated human for Catalog/Skill API stage")
    parser.add_argument("--author", help="demo user who receives or relinquishes the temporary author role")
    parser.add_argument("--confirm-resource", help="type the exact Version, Installation, Deployment or Skill ID before mutation")
    args = parser.parse_args()
    try:
        if args.stage == "prepare":
            if args.project or args.confirm_project or args.base_url or args.agent_cidr or any((args.runtime_subnet, args.runtime_private_ip, args.runtime_python_image_id, args.runtime_javascript_image_id, args.runtime_shell_image_id, args.docker_cli_image, args.docker_socket_gid, args.release_plan, args.model_plan, args.model_plan_output, args.knowledge_plan_output, args.knowledge_language, args.authorization_plan, args.authorization_plan_output, args.grant_duration_minutes, args.business_plan_output, args.business_scenario_batch, args.business_language, args.business_case, args.agent_id, args.username, args.author, args.confirm_resource, args.model_kind, args.artifact_digest, args.version_id, args.installation_id, args.deployment_id, args.release_plan_output, args.policy_input_output, args.run_budget_tokens, args.run_budget_micros, args.allow_external_provider)):
                parser.error("prepare generates its own project and accepts no API-stage arguments")
            print(json.dumps(prepare(), ensure_ascii=False, indent=2))
            return 0
        if not args.project or not args.confirm_project:
            parser.error("all project stages require --project and --confirm-project")
        if args.confirm_project != args.project:
            parser.error("--confirm-project must exactly match this isolated owner before any stage runs")
        if args.model_kind is not None and args.stage != "model-deployment-observe":
            parser.error("--model-kind is accepted only by model-deployment-observe")
        release_inputs = (args.artifact_digest, args.version_id, args.installation_id, args.deployment_id,
                          args.release_plan_output, args.policy_input_output, args.run_budget_tokens,
                          args.run_budget_micros)
        if (args.stage == "release-plan-prepare"
                and any(value is None for value in (args.artifact_digest, args.version_id,
                    args.installation_id, args.deployment_id, args.run_budget_tokens, args.run_budget_micros))):
            parser.error("release-plan-prepare requires explicit digest, Version/Installation/Deployment IDs and both RunBudget ceilings")
        if args.stage != "release-plan-prepare" and (any(value is not None for value in release_inputs)
                or args.allow_external_provider):
            parser.error("release bundle inputs and --allow-external-provider are accepted only by release-plan-prepare")
        model_plan_inputs = (args.model_plan_output, args.chat_model, args.embedding_model,
                             args.chat_input_micros_per_1k_tokens, args.chat_output_micros_per_1k_tokens,
                             args.embedding_input_micros_per_1k_tokens, args.embedding_output_micros_per_1k_tokens,
                             args.embedding_dimensions, args.chat_context_limit, args.embedding_context_limit,
                             args.price_effective_from, args.model_semantic_version)
        if args.stage != "model-plan-prepare" and any(value is not None for value in model_plan_inputs):
            parser.error("Model plan preparation fields are accepted only by model-plan-prepare")
        if args.stage != "knowledge-plan-prepare" and args.knowledge_plan_output is not None:
            parser.error("--knowledge-plan-output is accepted only by knowledge-plan-prepare")
        language_stages = {"knowledge-source-publish", "knowledge-index-submit", "knowledge-index-observe",
                           "index-workload-credential-rotate"}
        if args.stage not in language_stages and args.knowledge_language is not None:
            parser.error("--knowledge-language is accepted only by one exact Knowledge or workload-credential stage")
        if args.stage != "authorization-plan-prepare" and (args.authorization_plan_output is not None or args.grant_duration_minutes is not None):
            parser.error("authorization plan output and validity are accepted only by authorization-plan-prepare")
        if args.stage != "business-plan-prepare" and args.business_plan_output is not None:
            parser.error("--business-plan-output is accepted only by business-plan-prepare")
        if args.stage != "business-plan-prepare" and args.business_scenario_batch is not None:
            parser.error("--business-scenario-batch is accepted only by business-plan-prepare")
        if args.stage not in {"business-submit", "business-observe", "business-cancel", "business-verify", "business-denials"} and (args.business_language is not None or args.business_case is not None):
            parser.error("business language/case are accepted only by an exact business replay stage")
        if args.stage in {"business-submit", "business-observe"} and (args.business_language is None or args.business_case is None):
            parser.error("business submit/observe requires --business-language and --business-case")
        if args.stage in {"business-cancel", "business-verify", "business-denials"} and (args.business_language is None or args.business_case is not None):
            parser.error("business cancel/verify/denials requires --business-language and no --business-case")
        runtime_values = (args.runtime_subnet, args.runtime_private_ip, args.runtime_python_image_id,
                          args.runtime_javascript_image_id, args.runtime_shell_image_id, args.docker_cli_image,
                          args.docker_socket_gid)
        if args.stage == "model-secret-prepare":
            if args.base_url or args.agent_cidr or any(runtime_values) or any((args.release_plan, args.model_plan, args.model_plan_output, args.authorization_plan, args.agent_id, args.username, args.author, args.confirm_resource, args.chat_model, args.embedding_model, args.chat_input_micros_per_1k_tokens, args.chat_output_micros_per_1k_tokens, args.embedding_input_micros_per_1k_tokens, args.embedding_output_micros_per_1k_tokens, args.embedding_dimensions, args.chat_context_limit, args.embedding_context_limit, args.price_effective_from)):
                parser.error("model-secret-prepare accepts no API endpoint, external plan or unrelated stage inputs")
            prepare_model_secrets(args.project)
            return 0
        if args.stage == "model-plan-prepare":
            rates = (args.chat_input_micros_per_1k_tokens, args.chat_output_micros_per_1k_tokens,
                     args.embedding_input_micros_per_1k_tokens, args.embedding_output_micros_per_1k_tokens)
            if (not args.chat_model or not args.embedding_model or not args.embedding_dimensions
                    or not args.chat_context_limit or not args.embedding_context_limit
                    or not args.price_effective_from or any(value is None for value in rates)
                    or args.base_url or args.agent_cidr or any(runtime_values)
                    or any((args.release_plan, args.model_plan, args.authorization_plan, args.agent_id, args.username, args.author, args.confirm_resource))):
                parser.error("model-plan-prepare requires model keys, four explicit rates, embedding dimensions, both context limits and a price effective instant only")
            directory, _owner, _passwords = read_manifest(args.project)
            prepare_model_plan(args.project, directory, Path(args.model_plan_output or "model-governance.plan.json"),
                               args.chat_model, args.embedding_model,
                               {"chat": {"currency": "USD", "input_micros_per_1k_tokens": args.chat_input_micros_per_1k_tokens,
                                         "output_micros_per_1k_tokens": args.chat_output_micros_per_1k_tokens},
                                "embedding": {"currency": "USD", "input_micros_per_1k_tokens": args.embedding_input_micros_per_1k_tokens,
                                              "output_micros_per_1k_tokens": args.embedding_output_micros_per_1k_tokens}},
                               args.embedding_dimensions, args.chat_context_limit, args.embedding_context_limit,
                               args.price_effective_from, args.model_semantic_version or "0.1.0")
            return 0
        if args.stage == "model-governance":
            if not args.model_plan or any((args.release_plan, args.authorization_plan, args.base_url, args.agent_cidr, args.agent_id, args.username, args.author, args.confirm_resource)) or any(runtime_values):
                parser.error("model-governance requires only an owner-private --model-plan and exact project confirmation")
            directory, _owner, _passwords = read_manifest(args.project)
            model_governance_phase(args.project, directory, Path(args.model_plan))
            return 0
        if args.stage == "release-plan-prepare":
            if (args.agent_id is None or args.username is None or not args.allow_external_provider
                    or any((args.release_plan, args.model_plan, args.authorization_plan, args.base_url,
                            args.agent_cidr, args.author, args.confirm_resource)) or any(runtime_values)):
                parser.error("release-plan-prepare requires exact --agent-id, matching demo-human --username, --allow-external-provider and no other plan/target")
            directory, _owner, _passwords = read_manifest(args.project)
            language = {"example-go-operations": "go", "example-python-documents": "python",
                        "example-java-tickets": "java"}.get(args.agent_id)
            plan_output = Path(args.release_plan_output or f"release-{language}.json")
            policy_output = Path(args.policy_input_output or f"policy-input-{language}.json")
            result = prepare_release_plan(args.project, directory, args.agent_id, args.username,
                                          args.artifact_digest, args.version_id, args.installation_id,
                                          args.deployment_id, args.run_budget_tokens, args.run_budget_micros,
                                          args.allow_external_provider, policy_output, plan_output)
            print(json.dumps({"result": "owner_private_catalog_skill_six_policy_bundle_prepared",
                              "project": args.project, "agent_id": args.agent_id,
                              "release_plan": result["release_plan_path"].relative_to(directory).as_posix(),
                              "policy_input": result["policy_input_path"].relative_to(directory).as_posix(),
                              "version_id": args.version_id, "installation_id": args.installation_id,
                              "artifact_digest": args.artifact_digest, "api_mutations": False,
                              "credentials_or_document_body_printed": False}, ensure_ascii=False))
            return 0
        if args.stage == "model-deployment-observe":
            if (args.model_kind not in {"chat", "embedding"} or args.username != "system.admin"
                    or any((args.release_plan, args.model_plan, args.authorization_plan, args.base_url,
                            args.agent_cidr, args.agent_id, args.author, args.confirm_resource)) or any(runtime_values)):
                parser.error("model-deployment-observe requires --model-kind, the normal system.admin login, and no external target or release plan")
            directory, _owner, _passwords = read_manifest(args.project)
            result = model_deployment_observation_phase(args.project, directory, args.model_kind)
            print(json.dumps({"result": "one_exact_provider_probe_and_trusted_deployment_observation_verified",
                              "project": args.project, "kind": args.model_kind,
                              "deployment_id": result["deployment_id"], "revision": result["revision"],
                              "observed_revision": result["observed_revision"],
                              "secret_values_printed": False, "business_execution_proven": False}, ensure_ascii=False))
            return 0
        if args.stage == "model-access-policies":
            if any((args.release_plan, args.model_plan, args.authorization_plan, args.base_url, args.agent_cidr, args.agent_id, args.username, args.author, args.confirm_resource)) or any(runtime_values):
                parser.error("model-access-policies accepts no plan or external target; it reads the exact owner-pinned Model Governance and Catalog records")
            directory, _owner, _passwords = read_manifest(args.project)
            receipts = model_access_policies_phase(args.project, directory)
            print(json.dumps({"result": "six_exact_model_access_policies_verified", "project": args.project,
                              "policy_count": len(receipts), "principals": [row["principal_id"] for row in receipts],
                              "system_admin_business_grants": 0}, ensure_ascii=False))
            return 0
        if args.stage == "business-roles":
            if (args.username != "system.admin" or any((args.release_plan, args.model_plan, args.authorization_plan,
                    args.base_url, args.agent_cidr, args.agent_id, args.author, args.confirm_resource)) or any(runtime_values)):
                parser.error("business-roles requires only the normal system.admin login and exact project owner")
            directory, _owner, _passwords = read_manifest(args.project)
            result = business_roles_phase(args.project, directory)
            print(json.dumps({"result": "three_humans_have_exact_own_installation_roles", "subjects": result,
                              "resource_grants_created": False, "presets_used": False}, ensure_ascii=False))
            return 0
        if args.stage in {"audit-role-grant", "audit-role-revoke"}:
            if (args.username != "system.admin" or any((args.release_plan, args.model_plan, args.authorization_plan,
                    args.base_url, args.agent_cidr, args.agent_id, args.author, args.confirm_resource)) or any(runtime_values)):
                parser.error("auditor role lifecycle requires only system.admin and the exact project owner")
            directory, _owner, _passwords = read_manifest(args.project)
            result = audit_role_phase(args.project, directory, revoke=args.stage == "audit-role-revoke")
            print(json.dumps({"result": "short_lived_system_admin_auditor_role_verified", "status": result["status"],
                              "role_binding_id": result["binding"]["id"], "resource_grants": []}, ensure_ascii=False))
            return 0
        if args.stage == "authorization-plan-prepare":
            if (args.grant_duration_minutes is None or any((args.release_plan, args.model_plan, args.authorization_plan,
                    args.base_url, args.agent_cidr, args.agent_id, args.username, args.author, args.confirm_resource)) or any(runtime_values)):
                parser.error("authorization-plan-prepare requires only an explicit bounded --grant-duration-minutes and optional owner-private output path")
            directory, _owner, _passwords = read_manifest(args.project)
            output = Path(args.authorization_plan_output or "minimum-authorization.plan.json")
            prepare_authorization_plan(args.project, directory, output, args.grant_duration_minutes)
            return 0
        if args.stage == "business-plan-prepare":
            if any((args.release_plan, args.model_plan, args.authorization_plan, args.authorization_plan_output,
                    args.grant_duration_minutes, args.base_url, args.agent_cidr, args.agent_id, args.username,
                    args.author, args.confirm_resource)) or any(runtime_values):
                parser.error("business-plan-prepare accepts only an optional owner-private output path and reads the exact current release pins")
            directory, _owner, _passwords = read_manifest(args.project)
            prepare_business_plan(args.project, directory, Path(args.business_plan_output or "business-replay.plan.json"), args.business_scenario_batch)
            return 0
        if args.stage in {"business-submit", "business-observe", "business-cancel", "business-verify", "business-denials"}:
            if any((args.release_plan, args.model_plan, args.authorization_plan, args.authorization_plan_output,
                    args.grant_duration_minutes, args.business_plan_output, args.base_url, args.agent_cidr,
                    args.agent_id, args.author, args.confirm_resource)) or any(runtime_values):
                parser.error("business replay stages accept only the pinned business language/case and project confirmation")
            directory, _owner, _passwords = read_manifest(args.project)
            business_plan, _business_plan_path = load_business_plan(args.project, directory, _owner)
            business_case = "cancel" if args.stage == "business-cancel" else (args.business_case or "baseline")
            expected_username = "system.admin" if args.stage == "business-denials" else public_business.selected(business_plan, args.business_language, business_case)["owner"]
            if args.username != expected_username:
                parser.error("--username must equal the exact business owner for this case (or system.admin for denial verification)")
            result = run_business_stage(args.project, directory, args.stage, args.business_language,
                                        args.business_case)
            return 0
        if args.stage == "knowledge-plan-prepare":
            if any((args.release_plan, args.model_plan, args.authorization_plan, args.base_url, args.agent_cidr,
                    args.agent_id, args.username, args.author, args.confirm_resource)) or any(runtime_values):
                parser.error("knowledge-plan-prepare accepts only this owner's model metadata and an optional private output path")
            directory, _owner, _passwords = read_manifest(args.project)
            output = Path(args.knowledge_plan_output or "knowledge-replay.plan.json")
            prepare_knowledge_plan(args.project, directory, output)
            return 0
        if args.stage == "knowledge-source-publish":
            if (args.knowledge_language is None or args.username != "system.admin" or not args.confirm_resource
                    or any((args.release_plan, args.model_plan, args.authorization_plan, args.base_url, args.agent_cidr,
                            args.agent_id, args.author)) or any(runtime_values)):
                parser.error("knowledge-source-publish requires one language, system.admin, and its exact Knowledge ID only")
            directory, owner, _passwords = read_manifest(args.project)
            source_plan = load_knowledge_plan(args.project, directory, owner)
            source_item = next(row for row in source_plan["items"] if row["language"] == args.knowledge_language)
            if args.confirm_resource != source_item["knowledge_id"]:
                parser.error("--confirm-resource must equal the exact selected Knowledge ID")
            knowledge_source_phase(args.project, directory, args.knowledge_language)
            return 0
        if args.stage in {"knowledge-index-submit", "knowledge-index-observe"}:
            if (args.knowledge_language is None or not args.username or not args.confirm_resource
                    or any((args.release_plan, args.model_plan, args.authorization_plan, args.base_url, args.agent_cidr,
                            args.agent_id, args.author)) or any(runtime_values)):
                parser.error("knowledge indexing requires one language, its owner human, and exact Knowledge/install confirmation")
            directory, owner, _passwords = read_manifest(args.project)
            source_plan = load_knowledge_plan(args.project, directory, owner)
            source_item = next(row for row in source_plan["items"] if row["language"] == args.knowledge_language)
            target = source_item["knowledge_id"] + "@" + source_item["installation_id"]
            if args.confirm_resource != target or args.username != source_item["owner"]:
                parser.error("index operation requires the exact source-owner username and Knowledge@Installation target")
            knowledge_index_phase(args.project, directory, args.knowledge_language, args.username,
                                  args.confirm_resource, observe=args.stage == "knowledge-index-observe")
            return 0
        if args.stage == "index-workload-credential-rotate":
            if (args.knowledge_language is None or args.username != "system.admin" or not args.confirm_resource
                    or any((args.release_plan, args.model_plan, args.authorization_plan, args.base_url, args.agent_cidr,
                            args.agent_id, args.author)) or any(runtime_values)):
                parser.error("index-workload-credential-rotate requires one language, system.admin and its exact Machine@Installation target only")
            directory, _owner, _passwords = read_manifest(args.project)
            index_workload_credential_rotation_phase(args.project, directory, args.knowledge_language,
                                                     args.confirm_resource)
            return 0
        if args.stage in {"index-workload-credential-deploy", "index-workload-credential-correct-ips",
                          "index-workload-credential-activate"}:
            if (args.knowledge_language is not None or args.username or args.confirm_resource
                    or any((args.release_plan, args.model_plan, args.authorization_plan, args.base_url, args.agent_cidr,
                            args.agent_id, args.author)) or any(runtime_values)):
                parser.error("index workload deployment/correction/activation uses only the exact project owner and its pinned state")
            directory, _owner, _passwords = read_manifest(args.project)
            if args.stage == "index-workload-credential-deploy":
                index_workload_credential_deploy_phase(args.project, directory)
            elif args.stage == "index-workload-credential-correct-ips":
                index_workload_credential_correct_ips_phase(args.project, directory)
            else:
                index_workload_credential_activate_phase(args.project, directory)
            return 0
        if args.stage in {"catalog-role-grant", "catalog-role-revoke"}:
            if not args.agent_id or args.username != "system.admin" or not args.author or not args.confirm_resource or args.release_plan or args.model_plan or args.model_plan_output or args.authorization_plan or args.base_url or args.agent_cidr or any(runtime_values):
                parser.error("temporary role stages require --agent-id, --username system.admin, --author and exact --confirm-resource only")
            directory, _owner, _passwords = read_manifest(args.project)
            temporary_author_role_phase(args.project, directory, args.agent_id, args.username, args.author,
                                        args.confirm_resource, revoke=args.stage == "catalog-role-revoke")
            return 0
        if args.stage == "permission-admin-appoint":
            if args.username != "system.admin" or args.confirm_resource != "permission.admin" or any((args.release_plan, args.model_plan, args.authorization_plan, args.base_url, args.agent_cidr, args.agent_id, args.author)) or any(runtime_values):
                parser.error("permission-admin-appoint requires system.admin, the exact permission.admin target, and no external plan or endpoint")
            directory, _owner, _passwords = read_manifest(args.project)
            appoint_permission_admin_phase(args.project, directory, args.username, args.confirm_resource)
            return 0
        if args.stage in {"permission-admin-delegate", "permission-admin-delegation-rebind",
                          "permission-admin-grant-preview", "authorize"}:
            if not args.authorization_plan or args.release_plan or args.model_plan or args.username or args.agent_id or args.author or args.confirm_resource or args.base_url or args.agent_cidr or any(runtime_values):
                parser.error("delegation/authorization stages require only an owner-private --authorization-plan and exact project confirmation")
            directory, _owner, _passwords = read_manifest(args.project)
            grant_plan, grant_path = load_authorization_plan(args.project, directory, Path(args.authorization_plan))
            if args.stage == "permission-admin-delegate":
                results = delegate_reviewed_grants(args.project, directory, grant_plan)
                print(json.dumps({"delegation_receipts": results, "authorization_plan": grant_path,
                                  "business_resource_grants_created": False}, ensure_ascii=False))
            elif args.stage == "permission-admin-delegation-rebind":
                results = rebind_installation_delegations(args.project, directory, grant_plan)
                print(json.dumps({"delegation_replacements": results, "authorization_plan": grant_path,
                                  "business_resource_grants_created": False}, ensure_ascii=False))
            elif args.stage == "permission-admin-grant-preview":
                result = grant_preview_smoke(args.project, directory, grant_plan)
                print(json.dumps({"grant_preview_smoke": result, "authorization_plan": grant_path,
                                  "business_resource_grants_created": False}, ensure_ascii=False))
            else:
                results = authorize_reviewed_grants(args.project, directory, grant_plan, grant_path)
                print(json.dumps({"authorization_receipts": results, "authorization_plan": grant_path}, ensure_ascii=False))
            return 0
        plan_stages = {"catalog-submit", "catalog-evaluate", "catalog-publish", "catalog-install", "catalog-deploy",
                       "catalog-observe", "catalog-activate", "policy-draft", "policy-publish",
                       "skill-register", "skill-review", "skill-publish"}
        if args.stage in plan_stages:
            if not args.release_plan or not args.username or not args.confirm_resource or args.model_plan or args.authorization_plan or args.base_url or args.agent_cidr or any(runtime_values) or args.author:
                parser.error("Catalog/Skill stages require --release-plan, --username and exact --confirm-resource only")
            directory, owner, _passwords = read_manifest(args.project)
            agent_id = args.agent_id
            if args.stage.startswith("catalog-"):
                if not agent_id:
                    parser.error("Catalog lifecycle stages require --agent-id")
                plan = load_release_bundle(directory, Path(args.release_plan), agent_id)
                remember_release_plan(args.project, directory, plan, Path(args.release_plan))
                action = {
                    "catalog-submit": catalog_submit_phase, "catalog-evaluate": catalog_evaluate_phase,
                    "catalog-publish": catalog_publish_phase, "catalog-install": catalog_install_phase,
                    "catalog-deploy": catalog_deploy_phase, "catalog-observe": None,
                    "catalog-activate": catalog_activate_phase,
                }[args.stage]
                if args.stage == "catalog-observe":
                    catalog_observe_phase(args.project, directory, plan, args.username, args.confirm_resource, owner.get("runtime_prepared", False))
                else:
                    action(args.project, directory, plan, args.username, args.confirm_resource)
            else:
                if not agent_id:
                    parser.error("Skill/Policy stages require --agent-id to bind the plan to its public example Agent")
                plan = load_release_bundle(directory, Path(args.release_plan), agent_id)
                remember_release_plan(args.project, directory, plan, Path(args.release_plan))
                action = {"skill-register": skill_register_phase, "skill-review": skill_review_phase,
                          "skill-publish": skill_publish_phase, "policy-draft": policy_draft_phase,
                          "policy-publish": policy_publish_phase}[args.stage]
                action(args.project, directory, plan, args.username, args.confirm_resource)
            return 0
        if args.stage == "identity":
            if args.base_url or args.agent_cidr or any(runtime_values) or any((args.release_plan, args.model_plan, args.authorization_plan, args.agent_id, args.username, args.author, args.confirm_resource)):
                parser.error("identity owns its loopback endpoint and does not accept external targets")
            identity_phase(args.project, args.confirm_project)
        elif args.stage == "identity-reconcile":
            if args.base_url or args.agent_cidr or any(runtime_values) or any((args.release_plan, args.model_plan, args.authorization_plan, args.agent_id, args.username, args.author, args.confirm_resource)):
                parser.error("identity-reconcile uses only its exact owner-private endpoint and accepts no external target")
            identity_reconcile_phase(args.project, args.confirm_project)
        elif args.stage == "services":
            if args.base_url or args.agent_cidr or any(runtime_values) or any((args.release_plan, args.model_plan, args.authorization_plan, args.agent_id, args.username, args.author, args.confirm_resource)):
                parser.error("services stage owns its isolated Compose project and accepts no API target")
            services_phase(args.project, args.confirm_project)
        elif args.stage == "machine-principals":
            if (not args.base_url or not args.agent_cidr or args.username or any(runtime_values)
                    or any((args.release_plan, args.model_plan, args.authorization_plan, args.agent_id,
                            args.author, args.confirm_resource))):
                parser.error("machine-principals requires this owner's --base-url and three --agent-cidr values; no other inputs")
            machine_principals_phase(args.project, args.confirm_project, args.base_url, args.agent_cidr)
        elif args.stage == "machines":
            if (args.username != "system.admin" or args.base_url or args.agent_cidr or any(runtime_values)
                    or any((args.release_plan, args.model_plan, args.authorization_plan, args.agent_id,
                            args.author, args.confirm_resource))):
                parser.error("machines requires normal --username system.admin after policy publication, without a browser override or CIDRs")
            _directory, owner, _passwords = read_manifest(args.project)
            machines_phase(args.project, args.confirm_project,
                           "http://127.0.0.1:" + str(owner["ports"]["FRONTEND_HOST_PORT"]))
        elif args.stage == "runtime-prepare":
            if args.base_url or args.agent_cidr or not all(runtime_values) or any((args.release_plan, args.model_plan, args.authorization_plan, args.agent_id, args.username, args.author, args.confirm_resource)):
                parser.error("runtime-prepare requires all seven --runtime/--docker inputs and no browser or machine inputs")
            runtime_prepare_phase(args.project, args.confirm_project, args.runtime_subnet, args.runtime_private_ip,
                                  {"python": args.runtime_python_image_id, "javascript": args.runtime_javascript_image_id,
                                   "shell": args.runtime_shell_image_id}, args.docker_cli_image, args.docker_socket_gid)
        elif args.stage == "runtime-start":
            if args.base_url or args.agent_cidr or any(runtime_values) or any((args.release_plan, args.model_plan, args.authorization_plan, args.agent_id, args.username, args.author, args.confirm_resource)):
                parser.error("runtime-start accepts only the exact project confirmation")
            runtime_start_phase(args.project, args.confirm_project)
        else:
            if args.base_url or args.agent_cidr or any(runtime_values) or any((args.release_plan, args.model_plan, args.authorization_plan, args.agent_id, args.username, args.author, args.confirm_resource)):
                parser.error("cleanup accepts no API target or CIDRs")
            cleanup_phase(args.project, args.confirm_project)
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, bootstrap.APIError, KeyError, TypeError, AttributeError) as error:
        print("Public isolated replay stopped: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
