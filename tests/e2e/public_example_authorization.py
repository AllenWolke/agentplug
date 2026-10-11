"""Explicit, grant-only Identity changes for an isolated tutorial replay.

No credentials, inferred permissions, role changes, revocations or automatic
CAS retries. The caller supplies reviewed resource tuples from live published
policies, a human confirmation callback, and an owner-private receipt writer.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re
from urllib.parse import urlencode


IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
SUBJECTS = {
    "demo.go.user": ("user", "example-go-operations-installation"),
    "demo.python.user": ("user", "example-python-documents-installation"),
    "demo.java.user": ("user", "example-java-tickets-installation"),
    "example-go-machine": ("service_principal", "example-go-operations-installation"),
    "example-python-machine": ("service_principal", "example-python-documents-installation"),
    "example-java-machine": ("service_principal", "example-java-tickets-installation"),
}
INSTALLATIONS = {value[1] for value in SUBJECTS.values()}
ACTIONS = {
    "agent_installation": {"discover", "run", "cancel", "history.read", "agent.delegate"},
    "model": {"model.generate", "model.embed"},
    "tool": {"tool.invoke"},
    "knowledge": {"knowledge.search"},
    "memory": {"memory.read", "memory.write"},
    "skill": {"skill.load"},
}
GRANT_KEYS = {
    "id", "tenant_id", "department_id", "application_id", "agent_instance_id",
    "subject_type", "subject_id", "resource_type", "resource_id", "action",
    "effect", "status", "revision", "source_id", "data_scope", "starts_at", "expires_at",
}
EMPTY_PREVIEW_FIELDS = (
    "expanded_role_bindings", "expanded_task_assignments", "expanded_memberships",
    "automatic_revoke_binding_ids", "automatic_revoke_grant_ids", "automatic_revoke_assignment_ids",
)
EMPTY_COMMAND_FIELDS = (
    "role_bindings", "memberships", "task_assignments", "revoke_binding_ids",
    "revoke_grant_ids", "revoke_assignment_ids",
)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("validity timestamp must be explicit ISO8601")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("validity timestamp must include a timezone")
    return result.astimezone(timezone.utc)


def token(value):
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def resource_tuple(grant):
    return (grant["resource_type"], grant["resource_id"], grant["action"])


def validate_plan(plan, project, scope):
    if not re.fullmatch(r"agentplug-test-public-[a-f0-9]{12}", project):
        raise ValueError("authorization is restricted to an isolated replay owner")
    if set(scope) != {"tenant_id", "department_id", "application_id"} or not all(token(v) for v in scope.values()):
        raise ValueError("exact organization scope is required")
    if not isinstance(plan, dict) or set(plan) != {"schema", "owner", "changes", "allowed_resources"}:
        raise ValueError("authorization plan has unexpected or missing fields")
    if plan["schema"] != "public-example-authorization/v1" or plan["owner"] != project:
        raise ValueError("authorization plan owner/schema mismatch")
    allowed = plan["allowed_resources"]
    if not isinstance(allowed, dict) or not set(allowed).issubset(INSTALLATIONS):
        raise ValueError("resource allowlist contains an unknown installation")
    resource_sets = {}
    for installation, rows in allowed.items():
        if not isinstance(rows, list) or not rows or len(rows) > 128:
            raise ValueError("reviewed resource allowlist must be explicit and bounded")
        keys = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"resource_type", "resource_id", "action"}:
                raise ValueError("resource allowlist fields must be closed")
            kind, resource, action = resource_tuple(row)
            if kind not in ACTIONS or action not in ACTIONS[kind] or not token(resource):
                raise ValueError("resource/action is not permitted by the tutorial boundary")
            if kind == "agent_installation" and (resource not in INSTALLATIONS or (action != "agent.delegate" and resource != installation)):
                raise ValueError("direct business/history permission cannot target another installation")
            if (kind, resource, action) in keys:
                raise ValueError("duplicate reviewed resource tuple")
            keys.add((kind, resource, action))
        resource_sets[installation] = keys
    changes = plan["changes"]
    if not isinstance(changes, list) or not changes or len(changes) > 6:
        raise ValueError("one to six explicit subject changes are required")
    subjects, grant_ids = set(), set()
    for change in changes:
        if not isinstance(change, dict) or set(change) != {"subject_type", "subject_id", "scope", "reason", "resource_grants"}:
            raise ValueError("only grant additions are supported")
        subject = change["subject_id"]
        if subject not in SUBJECTS or subject in subjects or change["subject_type"] != SUBJECTS[subject][0]:
            raise ValueError("unknown, duplicate or mismatched business subject")
        subjects.add(subject)
        installation = SUBJECTS[subject][1]
        if change["scope"] != scope or not isinstance(change["reason"], str) or not 1 <= len(change["reason"].strip()) <= 1000:
            raise ValueError("subject change scope/reason mismatch")
        grants = change["resource_grants"]
        if not isinstance(grants, list) or not grants or len(grants) > 128:
            raise ValueError("explicit bounded grants are required")
        tuples = set()
        for grant in grants:
            required = GRANT_KEYS - {"starts_at", "expires_at"}
            if not isinstance(grant, dict) or not required.issubset(grant) or not set(grant).issubset(GRANT_KEYS):
                raise ValueError("grant fields are incomplete or unexpected")
            if not token(grant["id"]) or grant["id"] in grant_ids or not token(grant["source_id"]):
                raise ValueError("grant ID/source must be explicit, unique and bounded")
            grant_ids.add(grant["id"])
            if any(grant[key] != value for key, value in scope.items()):
                raise ValueError("grant organization scope differs from the owner plan")
            if grant["subject_id"] != subject or grant["subject_type"] != change["subject_type"] or grant["agent_instance_id"] != installation:
                raise ValueError("grant crosses a subject or installation boundary")
            if grant["effect"] != "allow" or grant["status"] != "active" or type(grant["revision"]) is not int or grant["revision"] != 1:
                raise ValueError("only new active allow grants are supported")
            key = resource_tuple(grant)
            if key not in resource_sets.get(installation, set()) or key in tuples:
                raise ValueError("grant is not an exact unique reviewed resource tuple")
            tuples.add(key)
            data = grant["data_scope"]
            if not isinstance(data, dict) or not set(data).issubset({"type", "ids"}):
                raise ValueError("data scope must be closed and explicit")
            kind = data.get("type")
            if change["subject_type"] == "user" and grant["resource_type"] != "knowledge" and kind != "owner":
                raise ValueError("human business/history/capability data must be owner-scoped")
            if kind == "explicit_set":
                ids = data.get("ids")
                if not isinstance(ids, list) or not ids or len(ids) > 128 or len(set(ids)) != len(ids) or not all(token(v) for v in ids):
                    raise ValueError("explicit data scope IDs must be bounded and unique")
            elif kind in {"owner", "approved_organization"}:
                if data.get("ids") not in (None, []):
                    raise ValueError("owner/organization data scope cannot include IDs")
                if kind == "approved_organization" and change["subject_type"] == "user" and grant["resource_type"] != "knowledge":
                    raise ValueError("human business/history/capability grants must stay owner-scoped")
            else:
                raise ValueError("unsupported data scope")
            if grant.get("starts_at") is not None:
                timestamp(grant["starts_at"])
            if grant.get("expires_at") is not None:
                expiry = timestamp(grant["expires_at"])
                if expiry <= datetime.now(timezone.utc) or (grant.get("starts_at") is not None and expiry <= timestamp(grant["starts_at"])):
                    raise ValueError("grant validity is expired or reversed")
    return deepcopy(plan)


def assert_preview(preview, command, actor, expected_grants=None):
    if not isinstance(preview, dict) or not re.fullmatch(r"[a-f0-9]{64}", str(preview.get("plan_digest", ""))):
        raise RuntimeError("authorization preview lacks a valid digest")
    if (preview.get("actor_id") != actor or preview.get("subject_id") != command["subject_id"]
            or preview.get("baseline_revision") != command["expected_revision"]):
        raise RuntimeError("authorization preview actor/subject/CAS mismatch")
    for key in EMPTY_PREVIEW_FIELDS:
        if preview.get(key) not in (None, []):
            raise RuntimeError("authorization preview added an unplanned identity effect")
    normalized = preview.get("change")
    if not isinstance(normalized, dict):
        raise RuntimeError("authorization preview lacks its exact normalized command")
    if normalized.get("preset") is not None or any(normalized.get(k) not in (None, []) for k in EMPTY_COMMAND_FIELDS):
        raise RuntimeError("authorization preview changed more than resource grants")
    for key in ("subject_type", "subject_id", "expected_revision", "idempotency_key", "reason"):
        if normalized.get(key) != command[key]:
            raise RuntimeError("authorization preview changed the reviewed command")
    expected_grants = command["resource_grants"] if expected_grants is None else expected_grants
    if canonical(normalized.get("resource_grants")) != canonical(expected_grants) or canonical(preview.get("expanded_resource_grants")) != canonical(expected_grants):
        raise RuntimeError("authorization preview resource grants differ from the explicit plan")
    if timestamp(preview.get("plan_expires_at")) <= datetime.now(timezone.utc):
        raise RuntimeError("authorization preview has expired")


def apply_changes(api, plan, project, scope, confirm, record, actor="system.admin", resource_api=None,
                  delegation_ids=None, profile_api=None):
    """Apply only confirmed normal API changes; ambiguous failures are not retried."""
    reviewed = validate_plan(plan, project, scope)
    # Identity assigns provenance; callers supply only a private journal of
    # previously approved exact Grant -> Delegation pairs, never a DTO override.
    grant_ids = {g["id"] for change in reviewed["changes"] for g in change["resource_grants"]}
    delegation_ids = {} if delegation_ids is None else deepcopy(delegation_ids)
    if not isinstance(delegation_ids, dict) or not set(delegation_ids).issubset(grant_ids) or any(not token(v) for v in delegation_ids.values()):
        raise ValueError("delegation mapping must contain only reviewed exact grant IDs")
    if actor != "system.admin" and (actor != "permission.admin" or set(delegation_ids) != grant_ids):
        raise ValueError("permission administrator requires exact delegation provenance for every grant")
    if actor == "system.admin" and delegation_ids:
        raise ValueError("direct super administrator grants cannot claim delegation provenance")
    # Resource inventory may be read by a separately authenticated manager.
    # This client is used ONLY for GET; all IAM preview/commit/readback calls
    # remain bound to the actual delegated authorizer and its receipt actor.
    inventory = resource_api if resource_api is not None else api
    # Principal profiles are control-plane read models. A delegated authorizer
    # may preview and commit exact Grants without holding principal.read over
    # service principals; callers can supply a separate read-only manager here.
    principal_reader = profile_api if profile_api is not None else api
    plan_hash = hashlib.sha256(canonical(reviewed)).hexdigest()
    receipts = []
    for change in reviewed["changes"]:
        subject, subject_type = change["subject_id"], change["subject_type"]
        installation_id = SUBJECTS[subject][1]
        installation = inventory.call("GET", "/api/modules/catalog/installations/" + installation_id)
        expected_installation = {"id": installation_id, "agent_id": installation_id.removesuffix("-installation"), "status": "active", **scope}
        if not isinstance(installation, dict) or any(installation.get(k) != v for k, v in expected_installation.items()) or not token(installation.get("version_id")):
            raise RuntimeError("subject's exact Catalog installation is not active in the reviewed scope")
        if subject_type == "service_principal":
            bindings = inventory.call("GET", "/api/modules/identity/workload-bindings?" + urlencode(scope))
            rows = bindings.get("items") if isinstance(bindings, dict) else None
            if not isinstance(rows, list):
                raise RuntimeError("current workload binding list is missing")
            current = [row for row in rows if row.get("status") == "active" and
                       (row.get("principal_id") == subject or row.get("installation_id") == installation_id)]
            expected_binding = {"principal_id": subject, "installation_id": installation_id,
                                "agent_version_id": installation["version_id"], **scope}
            if len(current) != 1 or any(current[0].get(k) != v for k, v in expected_binding.items()):
                raise RuntimeError("machine is not uniquely bound to this exact active installed version")
        path = "/api/modules/identity/principals/" + subject + "/access-profile?principal_type=" + subject_type
        before = principal_reader.call("GET", path)
        principal = before.get("principal") if isinstance(before, dict) else None
        if not isinstance(principal, dict) or principal.get("id") != subject or principal.get("type") != subject_type or principal.get("is_active") is not True or principal.get("tenant_id") != scope["tenant_id"]:
            raise RuntimeError("actual active principal does not match the exact subject pin")
        revision = principal.get("revision")
        if type(revision) is not int or revision < 1:
            raise RuntimeError("actual principal CAS revision is missing")
        old_grants = before.get("resource_grants")
        if not isinstance(old_grants, list):
            raise RuntimeError("actual principal resource grant list is missing")
        if any(row.get("id") in {g["id"] for g in change["resource_grants"]} for row in old_grants):
            raise RuntimeError("a planned grant already exists; read receipt instead of replaying this phase")
        command = {"subject_type": subject_type, "subject_id": subject, "expected_revision": revision,
                   "reason": change["reason"], "resource_grants": change["resource_grants"],
                   "idempotency_key": "tutorial-grants-" + plan_hash[:32] + "-" + subject}
        preview = api.call("POST", "/api/modules/identity/authorization-changes:preview", command)
        expected_additions = [dict(g, delegation_id=delegation_ids[g["id"]]) if g["id"] in delegation_ids else deepcopy(g)
                              for g in change["resource_grants"]]
        assert_preview(preview, command, actor, expected_additions)
        phrase = project + " grant " + subject + " " + preview["plan_digest"]
        record({"phase": "preview", "subject_id": subject, "plan_digest": preview["plan_digest"],
                "baseline_revision": revision, "grant_count": len(change["resource_grants"]), "confirmation": phrase})
        if not confirm(phrase):
            raise RuntimeError("reviewed subject authorization was not confirmed")
        commit = dict(preview["change"], plan_digest=preview["plan_digest"], plan_expires_at=preview["plan_expires_at"])
        record({"phase": "commit_started", "subject_id": subject, "plan_digest": preview["plan_digest"], "idempotency_key": command["idempotency_key"]})
        receipt = api.call("POST", "/api/modules/identity/authorization-changes", commit)
        if (not isinstance(receipt, dict) or receipt.get("subject_id") != subject or receipt.get("actor_id") != actor
                or receipt.get("revision") != revision + 1 or receipt.get("plan_digest") != preview["plan_digest"]):
            raise RuntimeError("authorization CAS receipt differs from the reviewed subject plan")
        after = principal_reader.call("GET", path)
        if after.get("principal", {}).get("revision") != revision + 1:
            raise RuntimeError("post-commit principal CAS revision differs")
        if canonical({k: v for k, v in after.get("principal", {}).items() if k != "revision"}) != canonical({k: v for k, v in principal.items() if k != "revision"}):
            raise RuntimeError("authorization changed the principal's identity or active state")
        for key in ("memberships", "role_bindings", "delegations", "task_assignments"):
            if canonical(after.get(key)) != canonical(before.get(key)):
                raise RuntimeError("authorization changed unrelated principal state")
        expected_grants = old_grants + expected_additions
        actual_grants = after.get("resource_grants")
        if not isinstance(actual_grants, list) or canonical(sorted(actual_grants, key=lambda r: r["id"])) != canonical(sorted(expected_grants, key=lambda r: r["id"])):
            raise RuntimeError("post-commit resource grant readback differs from exact additions")
        safe = {"phase": "verified", "subject_id": subject, "change_id": receipt.get("change_id"),
                "revision": revision + 1, "plan_digest": preview["plan_digest"], "grant_count": len(change["resource_grants"])}
        record(safe)
        receipts.append(safe)
    return receipts
