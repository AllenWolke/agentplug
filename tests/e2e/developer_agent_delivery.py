"""Actual custom-agent delivery in a new, owner-proven tutorial stack.

Invoked by developer_walkthrough.py; never targets an existing user deployment.
Uses separate authenticated author, approver, company and departmental actors.
"""

import argparse, hashlib, json, os, re, secrets, subprocess, sys, time
from pathlib import Path
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--workspace", type=Path, required=True)
args = parser.parse_args()
folder = args.workspace.resolve(strict=True)
folder.relative_to((ROOT / ".tmp").resolve())
if folder.is_symlink() or folder.is_junction():
    raise ValueError("regular owner workspace required")
state = json.loads((folder / "state.json").read_text(encoding="utf-8"))
source = Path(state["source"])
project = state["project"]
if source.resolve() != folder / "source" or not re.fullmatch(
    r"agentplug-test-public-[a-f0-9]{12}", project
):
    raise ValueError("exact isolated tutorial owner required")
sys.path.insert(0, str(ROOT / "scripts"))
from bootstrap_public_examples import BrowserAPI, APIError, profile, items

config = json.loads(
    (source / ".local-secrets/first-admin.json").read_text(encoding="utf-8")
)
origin = "http://127.0.0.1:" + str(state["ports"][0])
prefix = "/api/modules/identity"
private = source / ".local-secrets/tutorial-accounts.json"
if not private.exists():
    private.write_text(
        json.dumps(
            {
                name: secrets.token_urlsafe(24)
                for name in (
                    "company.admin",
                    "department.manager",
                    "agent.author",
                    "support.user",
                    "unassigned.user",
                )
            }
        ),
        encoding="utf-8",
    )
    private.chmod(0o600)
passwords = json.loads(private.read_text(encoding="utf-8"))
passwords[config["principal_id"]] = config["local_password"]
scope = {
    "tenant_id": config["tenant_id"],
    "department_id": "dept-support",
    "application_id": "department-home-" + hashlib.sha256(b"dept-support").hexdigest(),
}
scoped = {"scope_type": "application", **scope}
department = {
    "scope_type": "department",
    "tenant_id": scope["tenant_id"],
    "department_id": scope["department_id"],
}
receipts = folder / "delivery-receipts.json"
report = (
    json.loads(receipts.read_text(encoding="utf-8"))
    if receipts.exists()
    else {"operations": [], "completed": [], "scope": scope, "project": project}
)
report["origin"] = origin


def save():
    receipts.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def public_payload(value):
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if key
                in (
                    "password",
                    "current_password",
                    "client_secret",
                    "step_up_token",
                    "access_token",
                    "refresh_token",
                )
                else public_payload(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [public_payload(item) for item in value]
    return value


def call(api, method, path, body=None):
    result = api.call(method, path, body)
    report["operations"].append(
        {
            "method": method,
            "path": path,
            "result": "PASS",
            "request": public_payload(body),
        }
    )
    save()
    return result


def missing(api, path):
    try:
        return call(api, "GET", path)
    except APIError as e:
        if e.status == 404:
            return None
        raise


def login(name, select=True):
    api = BrowserAPI(origin)
    api.login(name, passwords[name])
    if select:
        api.select_workspace(scope)
    return api


def mark(name):
    if name not in report["completed"]:
        report["completed"].append(name)
    save()
    print("PASS " + name, flush=True)


def planned(api, path, command):
    plan = call(api, "POST", prefix + path + ":preview", command)
    submit = dict(
        command,
        plan_digest=plan["plan_digest"],
        plan_expires_at=plan["plan_expires_at"],
    )
    return call(api, "POST", prefix + path, submit)


admin = login(config["principal_id"], False)
if "organization" not in report["completed"]:
    deps = items(
        call(
            admin,
            "GET",
            prefix
            + "/departments?"
            + urlencode(
                {"tenant_id": scope["tenant_id"], "department_id": "dept-support"}
            ),
        ),
        "departments",
    )
    if not any(d["id"] == "dept-support" for d in deps):
        call(
            admin,
            "POST",
            prefix + "/departments",
            {
                "id": "dept-support",
                "tenant_id": scope["tenant_id"],
                "code": "support",
                "name": "Support",
                "status": "active",
                "revision": 1,
            },
        )
    apps = items(
        call(admin, "GET", prefix + "/applications?" + urlencode(scope)), "applications"
    )
    if not any(a["id"] == scope["application_id"] for a in apps):
        raise RuntimeError("new department has no internal administration context")
    mark("organization")
admin.select_workspace(scope)
if "accounts" not in report["completed"]:
    for name in passwords:
        if name == config["principal_id"]:
            continue
        if missing(admin, prefix + "/principals/" + name + "/access-profile") is None:
            command = {
                "username": name,
                "display_name": name,
                "password": passwords[name],
                "scope": scoped,
                "idempotency_key": "tutorial-create-" + name,
                "reason": "Create isolated tutorial actor",
            }
            plan = call(admin, "POST", prefix + "/principals:preview", command)
            call(
                admin,
                "POST",
                prefix + "/principals:create",
                dict(
                    command,
                    plan_digest=plan["plan_digest"],
                    plan_expires_at=plan["plan_expires_at"],
                ),
            )
        login(name)
    mark("accounts")
if "company-administrator" not in report["completed"]:
    command = {
        "subject_id": "company.admin",
        "expected_revision": profile(admin, "company.admin")["principal"]["revision"],
        "role_code": "tenant_admin",
        "role_version": 2,
        "scope": {"scope_type": "tenant", "tenant_id": scope["tenant_id"]},
        "idempotency_key": "tutorial-company-admin",
        "reason": "Appoint isolated company administrator",
    }
    preview = call(admin, "POST", prefix + "/administrators:preview", command)
    proof = call(
        admin,
        "POST",
        prefix + "/step-up",
        {
            "current_password": passwords[config["principal_id"]],
            "action": "administrator.appoint",
            "request_digest": preview["request_digest"],
        },
    )
    call(
        admin,
        "POST",
        prefix + "/administrators:appoint",
        dict(command, step_up_token=proof["step_up_token"]),
    )
    mark("company-administrator")
if "author" not in report["completed"]:
    planned(
        admin,
        "/authorization-changes",
        {
            "subject_type": "user",
            "subject_id": "agent.author",
            "expected_revision": profile(admin, "agent.author")["principal"][
                "revision"
            ],
            "preset": {
                "preset_code": "agent_developer",
                "preset_version": 1,
                "scope": scoped,
            },
            "idempotency_key": "tutorial-agent-author",
            "reason": "Grant scoped development and submission; no business execution",
        },
    )
    mark("author")
author = login("agent.author")
agent = source / "cli/agentctl/out/support-assistant"
base = [
    "docker",
    "compose",
    "--project-directory",
    str(source),
    "--project-name",
    project,
    "--env-file",
    str(source / ".env"),
    "-f",
    str(source / "compose.yaml"),
    "--profile",
    "modular",
]
image = "agentplug:tutorial-support-" + project.removeprefix("agentplug-test-public-")


def command(args, data=None, timeout=600):
    result = subprocess.run(
        args,
        cwd=source,
        input=None if data is None else json.dumps(data).encode(),
        capture_output=True,
        timeout=timeout,
    )
    if result.returncode:
        (folder / "delivery-command-failure.log").write_bytes(
            result.stdout + result.stderr
        )
        raise RuntimeError("owned command failed; diagnostic retained privately")
    return result.stdout


if "image" not in report["completed"]:
    command(
        [
            "docker",
            "build",
            "-f",
            str(agent / "Dockerfile.business"),
            "-t",
            image,
            str(agent),
        ]
    )
    report["image_digest"] = json.loads(
        command(["docker", "image", "inspect", image, "--format", "{{json .Id}}"])
    )
    mark("image")
manifest = json.loads((agent / "manifest.json").read_text(encoding="utf-8"))
schemas = {
    kind: json.loads(
        (agent / "eval" / (kind + ".schema.json")).read_text(encoding="utf-8")
    )
    for kind in ("input", "output")
}
defpath = "/api/modules/catalog/definitions/support-assistant-definition"
verpath = "/api/modules/catalog/versions/support-assistant-v1"
if "catalog" not in report["completed"]:
    if missing(admin, defpath) is None:
        call(
            author,
            "POST",
            "/api/modules/catalog/definitions?" + urlencode(scope),
            {
                "id": "support-assistant-definition",
                "publisher_id": "agent.author",
                "agent_key": "support-assistant",
                "display_name": "Support assistant",
                "description": "Deterministic support guidance without external providers",
                "status": "draft",
                "revision": 1,
            },
        )
    if missing(admin, verpath) is None:
        call(
            author,
            "POST",
            defpath + "/versions?" + urlencode(scope),
            {
                "id": "support-assistant-v1",
                "definition_id": "support-assistant-definition",
                "semantic_version": manifest["version"],
                "manifest": manifest,
                "artifact_digest": report["image_digest"],
                "input_schema": schemas["input"],
                "output_schema": schemas["output"],
                "status": "draft",
                "revision": 1,
            },
        )
    for path in (defpath, verpath):
        obj = call(admin, "GET", path)
        if obj["status"] == "draft":
            call(
                admin,
                "POST",
                path + "/evaluate",
                {"expected_revision": obj["revision"]},
            )
        obj = call(admin, "GET", path)
        if obj["status"] == "evaluated":
            call(
                admin, "POST", path + "/publish", {"expected_revision": obj["revision"]}
            )
        obj = call(admin, "GET", path)
        if (
            obj["status"] != "published"
            or obj["submitted_by"] != "agent.author"
            or obj["approved_by"] != config["principal_id"]
        ):
            raise RuntimeError("publication separation failed")
    report["version"] = call(admin, "GET", verpath)
    mark("catalog")
policy_scope = dict(
    scope, agent_id="support-assistant", agent_version_id="support-assistant-v1"
)
policy_contents = {
    "model": {
        "provider": "disabled",
        "model": "disabled",
        "max_tokens": 1,
        "temperature": 0,
        "allow_external": False,
        "budget_cents": 0,
        "input_micros_per_1k_tokens": 0,
        "output_micros_per_1k_tokens": 0,
    },
    "prompt": {
        "template": "Return deterministic support steps without provider calls.",
        "template_hash": hashlib.sha256(
            b"Return deterministic support steps without provider calls."
        ).hexdigest(),
    },
    "tool": {"allowed_tools": [], "require_confirmation": []},
    "memory": {
        "working_ttl_seconds": 0,
        "session_ttl_seconds": 0,
        "task_ttl_seconds": 0,
        "max_entries": 1,
        "long_term_enabled": False,
        "semantic_enabled": False,
    },
    "knowledge": {
        "allowed_scopes": [],
        "require_references": False,
        "allow_partial_degraded": False,
        "allow_replay": False,
    },
    "runtime": {
        "max_attempts": 1,
        "task_timeout_seconds": 30,
        "lease_seconds": 15,
        "cancel_grace_seconds": 2,
    },
}
if "policies" not in report["completed"]:
    refs = {}
    for typ, content in policy_contents.items():
        identifier = "tutorial-support-" + typ
        path = "/api/modules/policyasset/assets/" + typ + "/" + identifier
        asset = missing(admin, path + "?" + urlencode(policy_scope))
        if asset is None:
            asset = call(
                author,
                "POST",
                "/api/modules/policyasset/assets",
                {
                    "id": identifier,
                    "type": typ,
                    "scope": policy_scope,
                    "content": content,
                },
            )
        if asset["status"] == "draft":
            call(
                admin,
                "POST",
                path + "/publish",
                {"scope": policy_scope, "expected_revision": asset["revision"]},
            )
        asset = call(admin, "GET", path + "?" + urlencode(policy_scope))
        refs[typ] = {"id": identifier, "revision": asset["revision"]}
    snapshot = missing(
        admin, "/api/modules/policyasset/snapshots/current?" + urlencode(policy_scope)
    )
    if not snapshot or not snapshot.get("revision"):
        snapshot = call(
            admin,
            "POST",
            "/api/modules/policyasset/snapshots/publish",
            {"scope": policy_scope, "expected_revision": 0, "assets": refs},
        )
    if (snapshot.get("revision") != 1 or not re.fullmatch(r"[a-f0-9]{64}", snapshot.get("hash", ""))
        or snapshot.get("tool", {}).get("allowed_tools") != []
        or snapshot.get("knowledge", {}).get("allowed_scopes") != []):
        raise RuntimeError("published snapshot revision/hash or disabled capability lists differ")
    report["policy_snapshot"] = {k: v for k, v in snapshot.items()
                                 if k in ("revision", "hash") or k.endswith("_id")}
    mark("policies")
installation_path = "/api/modules/catalog/installations/support-assistant-installation"
if "installation" not in report["completed"]:
    if missing(admin, installation_path) is None:
        call(
            admin,
            "POST",
            "/api/modules/catalog/installations",
            {
                "id": "support-assistant-installation",
                **scope,
                "agent_id": "support-assistant",
                "version_id": "support-assistant-v1",
                "display_name": "Support assistant",
                "deployment_mode": "managed",
                "drain_policy": "wait",
                "retention_policy_id": "tutorial-retention",
                "status": "provisioning",
                "revision": 1,
            },
        )
    mark("installation")
if "service" not in report["completed"]:
    settings = dict(
        line.split("=", 1)
        for line in (source / ".env").read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.startswith("#")
    )
    public_key = source / ".local-secrets/tutorial-public-key.txt"
    public_key.write_text(settings["PLATFORM_CONTEXT_PUBLIC_KEY"], encoding="utf-8")
    overlay = source / ".local-secrets/tutorial.compose.json"
    overlay.write_text(
        json.dumps(
            {
                "services": {
                    "support-assistant": {
                        "image": image,
                        "restart": "unless-stopped",
                        "environment": {
                            "AGENT_PLATFORM_AGENT_ID": "support-assistant",
                            "AGENT_PLATFORM_ISSUER": "platform",
                            "AGENT_PLATFORM_AUDIENCE": "agent-runtime",
                            "AGENT_PLATFORM_PUBLIC_KEY_FILE": "/run/secrets/platform-public-key",
                        },
                        "volumes": [
                            {
                                "type": "bind",
                                "source": str(public_key),
                                "target": "/run/secrets/platform-public-key",
                                "read_only": True,
                            }
                        ],
                        "read_only": True,
                        "tmpfs": ["/tmp:size=16m,noexec,nosuid,nodev"],
                        "cap_drop": ["ALL"],
                        "security_opt": ["no-new-privileges:true"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    command(
        base
        + ["-f", str(overlay), "up", "-d", "--no-build", "--wait", "support-assistant"]
    )
    cid = (
        command(base + ["-f", str(overlay), "ps", "-q", "support-assistant"])
        .decode()
        .strip()
    )
    facts = json.loads(command(["docker", "inspect", cid]))[0]
    if (
        facts["Image"] != report["image_digest"]
        or facts["State"]["Health"]["Status"] != "healthy"
    ):
        raise RuntimeError("actual artifact health mismatch")
    report["agent_ip"] = next(iter(facts["NetworkSettings"]["Networks"].values()))[
        "IPAddress"
    ]
    report["agent_image"] = image
    mark("service")
if "deployment" not in report["completed"]:
    deployments = (
        call(admin, "GET", installation_path + "/deployments?limit=100")["items"] or []
    )
    if not deployments:
        deployments = [
            call(
                admin,
                "POST",
                installation_path + "/deployments",
                {
                    "id": "support-assistant-deployment",
                    **scope,
                    "agent_installation_id": "support-assistant-installation",
                    "agent_version_id": "support-assistant-v1",
                    "artifact_digest": report["image_digest"],
                    "manifest_hash": report["version"]["manifest_hash"],
                    "transport": "http",
                    "endpoint_ref": "http://support-assistant:8080",
                    "placement_policy": {"type": "compose"},
                    "resource_policy": {},
                    "status": "pending",
                    "desired_revision": 1,
                },
            )
        ]
    current = deployments[0]
    if current["status"] != "ready":
        observation = {
            "kind": "catalog",
            **scope,
            "installation_id": "support-assistant-installation",
            "deployment_id": current["id"],
            "revision": current["desired_revision"],
            "health": "ready",
        }
        preview = json.loads(
            command(
                base + ["exec", "-T", "platform-app", "/app/deployment-observe"],
                observation,
            )
        )
        receipt = json.loads(
            command(
                base
                + [
                    "exec",
                    "-T",
                    "platform-app",
                    "/app/deployment-observe",
                    "--apply",
                    "--expected-source-hash",
                    preview["source_hash"],
                ],
                observation,
            )
        )
        if not receipt["applied"]:
            raise RuntimeError("controller observation was not applied")
    install = call(admin, "GET", installation_path)
    if install["status"] == "provisioning":
        call(
            admin,
            "POST",
            installation_path + "/transition",
            {
                "from": "provisioning",
                "to": "active",
                "expected_revision": install["revision"],
            },
        )
    report["installation"] = call(admin, "GET", installation_path)
    mark("deployment")
company = login("company.admin")
if "workload" not in report["completed"]:
    machine_file = source / ".local-secrets/tutorial-workload.json"
    if not machine_file.exists():
        machine_file.write_text(
            json.dumps({"client_secret": secrets.token_urlsafe(40)}), encoding="utf-8"
        )
        machine_file.chmod(0o600)
    secret = json.loads(machine_file.read_text(encoding="utf-8"))["client_secret"]
    if (
        missing(
            admin,
            prefix
            + "/principals/support-assistant-machine/access-profile?principal_type=service_principal",
        )
        is None
    ):
        call(
            company,
            "POST",
            prefix + "/workload-principals",
            {
                "principal_id": "support-assistant-machine",
                "scope": scoped,
                "network_cidrs": [report["agent_ip"] + "/32"],
                "client_secret": secret,
                "idempotency_key": "tutorial-workload-principal",
                "reason": "Independent exact installation workload",
            },
        )
    bindings = (
        call(company, "GET", prefix + "/workload-bindings?" + urlencode(scope))["items"]
        or []
    )
    if not any(
        b.get("installation_id") == "support-assistant-installation"
        and b.get("status") == "active"
        for b in bindings
    ):
        call(
            company,
            "POST",
            prefix + "/workload-bindings",
            {
                "binding": dict(
                    scope,
                    installation_id="support-assistant-installation",
                    agent_id="support-assistant",
                    agent_version_id="support-assistant-v1",
                    principal_id="support-assistant-machine",
                ),
                "expected_revision": 0,
                "idempotency_key": "tutorial-workload-binding",
                "reason": "Bind exact independent workload to published policy and installation",
                "revoke": False,
            },
        )
    mark("workload")


def batch(api, body):
    plan = call(api, "POST", prefix + "/permission-batches:preview", body)
    if any(i["status"] != "pending" for i in plan["items"]):
        raise RuntimeError("permission batch contains blocked items")
    current = call(
        api,
        "POST",
        prefix + "/permission-batches",
        dict(
            body,
            plan_digest=plan["plan_digest"],
            plan_expires_at=plan["plan_expires_at"],
        ),
    )
    for _ in range(50):
        if not any(i["status"] == "pending" for i in current["items"]):
            break
        current = call(
            api,
            "POST",
            prefix + "/permission-batches/" + body["idempotency_key"] + ":continue",
            {},
        )
    if any(i["status"] != "succeeded" for i in current["items"]):
        report["failed_batch_items"] = [
            {
                "subject_id": i["subject_id"],
                "status": i["status"],
                "failure_code": i.get("failure_code"),
            }
            for i in current["items"]
        ]
        save()
        raise RuntimeError("batch failed")
    report.setdefault("batch_receipts", []).append(
        {
            "batch_id": current["batch_id"],
            "subjects": [i["subject_id"] for i in current["items"]],
        }
    )
    save()


if "department-members" not in report["completed"]:
    changes = []
    for name in ("department.manager", "support.user", "unassigned.user"):
        change = {
            "subject_type": "user",
            "subject_id": name,
            "expected_revision": profile(company, name)["principal"]["revision"],
            "memberships": [
                {
                    "id": "tutorial-department-member-" + name,
                    "scope": department,
                    "expected_revision": 0,
                    "status": "active",
                }
            ],
        }
        if name == "department.manager":
            change["preset"] = {
                "preset_code": "department_admin",
                "preset_version": 2,
                "scope": department,
            }
        changes.append({"authorization": change})
    batch(
        company,
        {
            "kind": "authorization",
            "scope": department,
            "items": changes,
            "idempotency_key": "tutorial-department-members",
            "reason": "Company assigns department manager and members in one bounded batch",
        },
    )
    mark("department-members")
if "department-agent-ceiling" not in report["completed"]:
    policy = call(
        company,
        "GET",
        prefix
        + "/department-agent-policy?"
        + urlencode(
            {"tenant_id": scope["tenant_id"], "department_id": scope["department_id"]}
        ),
    )
    body = {
        "tenant_id": scope["tenant_id"],
        "department_id": scope["department_id"],
        "expected_revision": policy["policy"]["revision"],
        "migrate_existing": not policy["managed"],
        "entries": [
            {
                "application_id": scope["application_id"],
                "installation_id": "support-assistant-installation",
                "actions": [
                    "discover",
                    "run",
                    "cancel",
                    "history.read",
                    "history.continue",
                    "model.generate",
                    "model.embed",
                    "memory.read",
                    "memory.write",
                ],
            }
        ],
        "idempotency_key": "tutorial-department-agent-ceiling",
        "reason": "Company approves the exact Agent for department members",
    }
    preview = call(company, "POST", prefix + "/department-agent-changes:preview", body)
    proof = call(
        company,
        "POST",
        prefix + "/step-up",
        {
            "current_password": passwords["company.admin"],
            "action": "delegation.manage",
            "request_digest": preview["digest"],
        },
    )
    call(
        company,
        "POST",
        prefix + "/department-agent-changes",
        dict(
            body,
            plan_digest=preview["digest"],
            plan_expires_at=preview["expires_at"],
            step_up_token=proof["step_up_token"],
        ),
    )
    mark("department-agent-ceiling")
if "workload-authorization" not in report["completed"]:
    machine = call(
        company,
        "GET",
        prefix
        + "/principals/support-assistant-machine/access-profile?principal_type=service_principal",
    )
    grants = [
        {
            "id": "tutorial-machine-" + action,
            "subject_type": "service_principal",
            "subject_id": "support-assistant-machine",
            **scope,
            "agent_instance_id": "support-assistant-installation",
            "resource_type": "agent_installation",
            "resource_id": "support-assistant-installation",
            "action": action,
            "effect": "allow",
            "status": "active",
            "revision": 1,
            "source_id": "tutorial-workload-lifecycle",
            "data_scope": {"type": "approved_organization"},
        }
        for action in ("run", "history.read", "cancel", "history.continue")
    ]
    planned(
        company,
        "/authorization-changes",
        {
            "subject_type": "service_principal",
            "subject_id": "support-assistant-machine",
            "expected_revision": machine["principal"]["revision"],
            "resource_grants": grants,
            "idempotency_key": "tutorial-machine-authorization",
            "reason": "Authorize only this installation lifecycle, separately from caller permission",
        },
    )
    report["machine_actions"] = [g["action"] for g in grants]
    mark("workload-authorization")


manager = login("department.manager")
if "user-agent-binding" not in report["completed"]:
    pack = call(
        manager,
        "GET",
        prefix
        + "/agent-use-package?"
        + urlencode(
            {
                "department_id": scope["department_id"],
                "application_id": scope["application_id"],
                "installation_id": "support-assistant-installation",
            }
        ),
    )
    report["package"] = {
        k: v
        for k, v in pack.items()
        if k in ("agent_version_id", "package_digest", "resources", "scope")
    }
    save()
    body = {
        "kind": "authorization",
        "scope": scoped,
        "items": [
            {
                "authorization": {
                    "subject_type": "user",
                    "subject_id": "support.user",
                    "expected_revision": profile(manager, "support.user")["principal"][
                        "revision"
                    ],
                    "agent_use": {
                        "scope": pack["scope"],
                        "agent_version_id": pack["agent_version_id"],
                        "package_digest": pack["package_digest"],
                    },
                }
            }
        ],
        "idempotency_key": "tutorial-user-agent-use",
        "reason": "Department manager enables daily use for another department member",
    }
    batch(manager, body)
    mark("user-agent-binding")
if "ordinary-user-run" not in report["completed"]:
    command(
        base
        + [
            "-f",
            str(source / ".local-secrets/tutorial.compose.json"),
            "up",
            "-d",
            "--no-build",
            "--no-recreate",
            "--wait",
            "--wait-timeout",
            "90",
            "support-assistant",
        ]
    )
    command(
        base
        + [
            "exec",
            "-T",
            "platform-app",
            "wget",
            "-qO-",
            "http://support-assistant:8080/health/ready",
        ]
    )
    user = login("support.user")
    available = call(user, "GET", "/api/modules/catalog/available?" + urlencode(scope))
    if not any(
        item.get("installation_id") == "support-assistant-installation"
        and item.get("access_status") == "granted"
        and item.get("permissions", {}).get("run") is True
        for item in items(available, "agents")
    ):
        raise RuntimeError("authorized Agent is not runnable for the ordinary user")
    report["available_agents"] = available
    save()
    if report.get("ordinary_run", {}).get("status") == "failed":
        report.setdefault("diagnosed_failures", []).append(
            {
                "run_id": report["ordinary_run"]["run_id"],
                "status": "failed",
                "code": "AUTHORIZATION_DENIED",
                "cause": "Workload binding was missing explicit installation resource grants",
            }
        )
        report.pop("ordinary_run")
        save()
    session_id = "tutorial-support-session-v2"
    run_id = "tutorial-support-run-v2"
    session_path = "/api/modules/conversation/sessions/" + session_id
    if missing(user, session_path) is None:
        call(
            user,
            "POST",
            "/api/modules/conversation/sessions",
            {
                "id": session_id,
                "kind": "qa",
                "agent_id": "support-assistant",
                "agent_version_id": "support-assistant-v1",
                "title": "New developer acceptance",
            },
        )
    run_path = "/api/modules/execution/platform/runs/" + run_id
    current = missing(user, run_path)
    if current is None:
        call(
            user,
            "POST",
            session_path + "/runs",
            {
                "run_id": run_id,
                "idempotency_key": run_id,
                "request": {"question": "How do I investigate a timeout?"},
            },
        )
    for _ in range(60):
        current = call(user, "GET", run_path)
        if current["status"] in ("succeeded", "failed", "cancelled"):
            break
        time.sleep(1)
    report["ordinary_run"] = current
    save()
    if current["status"] != "succeeded":
        raise RuntimeError("ordinary platform run did not succeed")
    mark("ordinary-user-run")
user = login("support.user")
session_path = "/api/modules/conversation/sessions/tutorial-support-session-v2"
run_path = "/api/modules/execution/platform/runs/tutorial-support-run-v2"
if "business-result-and-idempotency" not in report["completed"]:
    messages = call(user, "GET", session_path + "/messages?page_size=100")
    expected = {
        "question": "How do I investigate a timeout?",
        "answer": "Check service health, recent changes and authorized run history.",
        "source": "deterministic-local-example",
    }
    answers = [item for item in messages["items"] if item.get("role") == "assistant"]
    if (
        messages["total"] != 2
        or len(answers) != 1
        or answers[0].get("metadata") != expected
        or answers[0].get("content") != expected["answer"]
    ):
        raise RuntimeError("business result is incorrect or history is duplicated")
    before = call(user, "GET", run_path)
    replay = call(
        user,
        "POST",
        session_path + "/runs",
        {
            "run_id": "tutorial-support-run-v2",
            "idempotency_key": "tutorial-support-run-v2",
            "request": {"question": expected["question"]},
        },
    )
    after = call(user, "GET", run_path)
    if (
        replay.get("run_id") != before["run_id"]
        or after != before
        or call(user, "GET", session_path + "/messages?page_size=100") != messages
    ):
        raise RuntimeError(
            "same-key replay changed the completed run or duplicated messages"
        )
    report["business_result"] = expected
    report["message_count"] = messages["total"]
    report["same_key_replay_unchanged"] = True
    mark("business-result-and-idempotency")


def denied(api, method, path, body=None, allowed=(403, 404)):
    try:
        api.call(method, path, body)
    except APIError as error:
        if error.status not in allowed:
            raise
        report.setdefault("denials", []).append(
            {"method": method, "path": path, "status": error.status, "code": error.code}
        )
        save()
        return
    raise RuntimeError("operation unexpectedly permitted: " + path)


if "same-company-denials" not in report["completed"]:
    unassigned = login("unassigned.user")
    reply = call(
        unassigned, "GET", "/api/modules/catalog/available?" + urlencode(scope)
    )
    restricted = items(reply, "agents")
    if not restricted or any(
        item.get("access_status") != "restricted"
        or any(item.get("permissions", {}).values())
        for item in restricted
    ):
        raise RuntimeError("unassigned user has Agent permissions")
    report["unassigned_catalog_status"] = "restricted"
    denied(unassigned, "GET", session_path)
    denied(unassigned, "GET", run_path)
    denied(
        unassigned,
        "POST",
        "/api/modules/conversation/sessions",
        {
            "id": "tutorial-denied-session",
            "kind": "qa",
            "agent_id": "support-assistant",
            "agent_version_id": "support-assistant-v1",
            "title": "Must be denied",
        },
    )
    denied(
        manager,
        "POST",
        prefix + "/departments",
        {
            "id": "tutorial-forbidden-department",
            "tenant_id": scope["tenant_id"],
            "code": "forbidden",
            "name": "Must be denied",
            "status": "active",
            "revision": 1,
        },
    )
    mark("same-company-denials")
if "invalid-business-input" not in report["completed"]:
    invalid_session = "/api/modules/conversation/sessions/tutorial-invalid-session-v2"
    invalid_run = "/api/modules/execution/platform/runs/tutorial-invalid-input-v2"
    if missing(user, invalid_session) is None:
        call(
            user,
            "POST",
            "/api/modules/conversation/sessions",
            {
                "id": "tutorial-invalid-session-v2",
                "kind": "qa",
                "agent_id": "support-assistant",
                "agent_version_id": "support-assistant-v1",
                "title": "Invalid input acceptance",
            },
        )
    invalid = missing(user, invalid_run)
    if invalid is None:
        call(
            user,
            "POST",
            invalid_session + "/runs",
            {
                "run_id": "tutorial-invalid-input-v2",
                "idempotency_key": "tutorial-invalid-input-v2",
                "request": {"question": ""},
            },
        )
    for _ in range(60):
        invalid = call(user, "GET", invalid_run)
        if invalid["status"] in ("succeeded", "failed", "cancelled"):
            break
        time.sleep(1)
    if invalid["status"] != "failed":
        raise RuntimeError("invalid business input was not rejected during execution")
    invalid_messages = call(user, "GET", invalid_session + "/messages?page_size=100")
    if any(
        message.get("role") == "assistant"
        and message.get("metadata", {}).get("source") == "deterministic-local-example"
        for message in invalid_messages["items"]
    ):
        raise RuntimeError("invalid input produced a business answer")
    report["invalid_input_run"] = invalid
    mark("invalid-business-input")
if "cross-company-scope-denials" not in report["completed"]:
    foreign_scope = {
        "tenant_id": "tenant-foreign",
        "department_id": "dept-foreign",
        "application_id": "foreign-application",
    }
    denied(user, "POST", "/auth/workspace", foreign_scope)
    denied(
        user,
        "GET",
        prefix + "/departments?tenant_id=tenant-foreign",
        allowed=(400, 403),
    )
    denied(
        user,
        "GET",
        prefix + "/applications?tenant_id=tenant-foreign",
        allowed=(400, 403),
    )
    report["cross_company_check"] = (
        "Ordinary user forged-company scope rejected; no separately provisioned other-company account"
    )
    mark("cross-company-scope-denials")
print("DELIVERY COMPLETE", flush=True)
