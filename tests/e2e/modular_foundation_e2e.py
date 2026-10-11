"""Verify the modular platform bootstrap, identity and catalog boundaries.

This is deliberately a black-box current-source Docker probe.  It creates a
unique tenant tree, user/service-principal grants, then drives the catalog
definition/version/installation/deployment lifecycle through the registered
module HTTP ports.  No legacy Backend or Harness route is used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import uuid
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def call(base: str, token: str, method: str, path: str, body: dict[str, Any] | None = None, scope: dict[str, str] | None = None) -> tuple[int, Any]:
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}", "X-Internal-Token": token}
    if scope:
        headers.update({
            "X-Tenant-ID": scope["tenant_id"], "X-Department-ID": scope["department_id"],
            "X-Application-ID": scope["application_id"], "X-Agent-Instance-ID": scope.get("agent_instance_id", ""),
            "X-Principal-Type": scope.get("principal_type", "user"), "X-Principal-ID": scope.get("principal_id", ""),
            "X-Trace-ID": "modular-foundation-" + uuid.uuid4().hex,
        })
    request = Request(base.rstrip("/") + path, method=method, headers=headers,
                      data=None if body is None else json.dumps(body).encode("utf-8"))
    try:
        with urlopen(request, timeout=12) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if raw else None
    except HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        try:
            return error.code, json.loads(raw)
        except json.JSONDecodeError:
            return error.code, raw[:512]


def require(actual: int, expected: int, label: str, body: Any) -> Any:
    if actual != expected:
        raise RuntimeError(f"{label}: expected HTTP {expected}, got {actual}: {body}")
    return body


def checked(base: str, token: str, method: str, path: str, expected: int, label: str, body: dict[str, Any] | None = None, scope: dict[str, str] | None = None) -> Any:
    status, payload = call(base, token, method, path, body, scope)
    return require(status, expected, label, payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform-url", required=True)
    parser.add_argument("--internal-token", required=True)
    args = parser.parse_args()
    suffix = uuid.uuid4().hex[:16]
    tenant, department, application = (f"mm-tenant-{suffix}", f"mm-dept-{suffix}", f"mm-app-{suffix}")
    installation = f"mm-install-{suffix}"
    user, machine = f"mm-user-{suffix}", f"mm-machine-{suffix}"
    scope = {"tenant_id": tenant, "department_id": department, "application_id": application,
             "agent_instance_id": installation, "principal_type": "user", "principal_id": user}
    base, token = args.platform_url, args.internal_token

    # P03: a successful request proves the single process reached its shared
    # SQL bootstrap and registered module schema.  Invalid production and
    # secret fail-closed behavior is covered by bootstrap/config_test.go.
    checked(base, token, "POST", "/modules/identity/tenants", 201, "create tenant", {"id": tenant, "code": tenant, "name": "Foundation tenant", "status": "active", "revision": 1})
    checked(base, token, "POST", "/modules/identity/departments", 201, "create department", {"id": department, "tenant_id": tenant, "code": "compliance", "name": "Compliance", "status": "active", "revision": 1})
    checked(base, token, "POST", "/modules/identity/applications", 201, "create application", {"id": application, "tenant_id": tenant, "department_id": department, "code": "business-app", "name": "Business application", "status": "active", "revision": 1})
    checked(base, token, "POST", "/modules/identity/principals", 201, "create user", {"type": "user", "id": user, "tenant_id": tenant, "roles": ["operator"], "is_active": True})
    checked(base, token, "POST", "/modules/identity/principals", 201, "create machine principal", {"type": "service_principal", "id": machine, "tenant_id": tenant, "roles": [], "is_active": True})
    for subject_type, subject_id, grant_id in (("user", user, "user"), ("service_principal", machine, "machine")):
        checked(base, token, "POST", "/modules/identity/grants", 201, f"grant {grant_id}", {
            "id": f"mm-grant-{grant_id}-{suffix}", "tenant_id": tenant, "department_id": department,
            "application_id": application, "agent_instance_id": installation, "subject_type": subject_type,
            "subject_id": subject_id, "action": "run", "effect": "allow", "status": "active", "revision": 1,
        })
    decision = checked(base, token, "POST", "/modules/identity/access/check", 200, "user allow", {
        "scope": {"tenant_id": tenant, "department_id": department, "application_id": application, "agent_instance_id": installation},
        "principal_type": "user", "principal_id": user, "action": "run",
    })
    if not decision.get("allowed"):
        raise RuntimeError(f"user grant was not effective: {decision}")
    decision = checked(base, token, "POST", "/modules/identity/access/check", 200, "machine allow", {
        "scope": {"tenant_id": tenant, "department_id": department, "application_id": application, "agent_instance_id": installation},
        "principal_type": "service_principal", "principal_id": machine, "action": "run",
    })
    if not decision.get("allowed"):
        raise RuntimeError(f"machine grant was not effective: {decision}")
    denied = checked(base, token, "POST", "/modules/identity/access/check", 200, "cross tenant deny", {
        "scope": {"tenant_id": "other-tenant", "department_id": department, "application_id": application, "agent_instance_id": installation},
        "principal_type": "user", "principal_id": user, "action": "run",
    })
    if denied.get("allowed") or denied.get("reason") != "tenant_mismatch":
        raise RuntimeError(f"cross-tenant decision leaked or allowed access: {denied}")

    definition, version_one, version_two = f"mm-definition-{suffix}", f"mm-version-1-{suffix}", f"mm-version-2-{suffix}"
    agent_key = f"foundation-{suffix}"
    checked(base, token, "POST", "/modules/catalog/definitions", 201, "create definition", {
        "id": definition, "publisher_id": "foundation-e2e", "agent_key": agent_key,
        "display_name": "Foundation Agent", "description": "Isolated Catalog lifecycle E2E fixture.",
        "status": "draft", "revision": 1,
    })
    versions: dict[str, dict[str, Any]] = {}
    for version, semantic in ((version_one, "1.0.0"), (version_two, "1.1.0")):
        artifact_digest = "sha256:" + hashlib.sha256(f"{suffix}:{semantic}".encode()).hexdigest()
        manifest = {
            "manifest_version": "agent-manifest/v1", "agent_id": agent_key, "version": semantic,
            "execution_protocols": ["agent-execution/v2"], "capabilities": ["run", "resume", "cancel", "events"],
            "schemas": {
                "input": "schema://foundation/input/v1", "output": "schema://foundation/output/v1",
                "event": "schema://foundation/event/v1", "checkpoint": "schema://foundation/checkpoint/v1",
            },
            "runtime": {"transport": "http", "isolation": "container", "health_path": "/health/ready"},
        }
        versions[version] = checked(base, token, "POST", f"/modules/catalog/definitions/{definition}/versions", 201, f"create {semantic}", {
            "id": version, "definition_id": definition, "semantic_version": semantic,
            "manifest": manifest, "artifact_digest": artifact_digest,
            "input_schema": {"type": "object", "properties": {"batch_id": {"type": "string"}}},
            "output_schema": {"type": "object", "properties": {"status": {"type": "string"}}},
            "status": "draft", "revision": 1,
        })
        checked(base, token, "POST", f"/modules/catalog/versions/{version}/evaluate", 200, f"evaluate {semantic}", {"expected_revision": 1})
        versions[version] = checked(base, token, "POST", f"/modules/catalog/versions/{version}/publish", 200, f"publish {semantic}", {"expected_revision": 2})
    checked(base, token, "POST", f"/modules/catalog/definitions/{definition}/evaluate", 200, "evaluate definition", {"expected_revision": 1})
    checked(base, token, "POST", f"/modules/catalog/definitions/{definition}/publish", 200, "publish definition", {"expected_revision": 2})
    checked(base, token, "POST", "/modules/catalog/installations", 201, "create installation", {
        "id": installation, "tenant_id": tenant, "department_id": department, "application_id": application,
        "agent_id": f"foundation-{suffix}", "version_id": version_one,
        "display_name": "Foundation lifecycle E2E installation", "deployment_mode": "managed",
        "drain_policy": "wait", "retention_policy_id": "foundation-e2e-30d",
        "status": "provisioning", "revision": 1,
    })
    deployment = f"mm-deployment-{suffix}"
    checked(base, token, "POST", f"/modules/catalog/installations/{installation}/deployments", 201, "create deployment", {"id": deployment, "tenant_id": tenant, "department_id": department, "application_id": application, "agent_version_id": version_one, "agent_installation_id": installation, "artifact_digest": versions[version_one]["artifact_digest"], "manifest_hash": versions[version_one]["manifest_hash"], "transport": "http", "endpoint_ref": "http://agent.invalid", "placement_policy": {"mode": "single"}, "resource_policy": {"cpu": "100m"}, "status": "pending", "desired_revision": 1})
    checked(base, token, "POST", f"/modules/catalog/installations/{installation}/deployments/{deployment}/observe", 200, "observe deployment", {"desired_revision": 1, "status": "ready"})
    checked(base, token, "POST", f"/modules/catalog/installations/{installation}/transition", 200, "activate installation", {"from": "provisioning", "to": "active", "expected_revision": 1})
    checked(base, token, "POST", f"/modules/catalog/installations/{installation}/transition", 200, "suspend installation", {"from": "active", "to": "suspended", "expected_revision": 2})
    checked(base, token, "POST", f"/modules/catalog/installations/{installation}/transition", 200, "resume installation", {"from": "suspended", "to": "active", "expected_revision": 3})
    checked(base, token, "POST", f"/modules/catalog/installations/{installation}/transition", 200, "resuspend installation", {"from": "active", "to": "suspended", "expected_revision": 4})
    rolled = checked(base, token, "POST", f"/modules/catalog/installations/{installation}/rollback", 200, "rollback installation", {"version_id": version_two, "expected_revision": 5})
    if rolled.get("version_id") != version_two or int(rolled.get("revision", 0)) != 6:
        raise RuntimeError(f"rollback did not use CAS revision/version: {rolled}")
    uninstalled = checked(base, token, "POST", f"/modules/catalog/installations/{installation}/uninstall", 200, "uninstall installation", {"expected_revision": 6})
    if uninstalled.get("status") != "uninstalling":
        raise RuntimeError(f"uninstall lifecycle did not enter uninstalling: {uninstalled}")

    # Revocation uses the full scope header and CAS.  A revoked user grant
    # must immediately become ineffective without impacting the machine grant.
    checked(base, token, "POST", f"/modules/identity/grants/mm-grant-user-{suffix}/revoke", 200, "revoke user grant", {"expected_revision": 1}, scope)
    revoked = checked(base, token, "POST", "/modules/identity/access/check", 200, "revoked user deny", {"scope": {"tenant_id": tenant, "department_id": department, "application_id": application, "agent_instance_id": installation}, "principal_type": "user", "principal_id": user, "action": "run"})
    if revoked.get("allowed"):
        raise RuntimeError(f"revoked grant remained effective: {revoked}")
    print(json.dumps({"bootstrap": True, "identity_matrix": True, "catalog_lifecycle": True, "deployment_observed": True, "grant_revocation": True}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
