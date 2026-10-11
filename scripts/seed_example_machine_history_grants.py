"""Interactively approve the three example machines' installation history.read grants."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any
from urllib.request import HTTPRedirectHandler


ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "deploy/local/example-machine-history-grants.json"
EXPECTED_SCOPE = {
    "tenant_id": "tenant-demo",
    "department_id": "dept-demo",
    "application_id": "app-demo",
}
REQUIRED_GRANT_FIELDS = {
    "id", "subject_type", "subject_id", "agent_id", "agent_instance_id", "action", "data_scope",
}


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        # Never forward a password or session cookie to a redirected host.
        return None


class BrowserAPI:
    def __init__(self, base_url: str):
        parsed = urllib.parse.urlsplit(base_url)
        host = (parsed.hostname or "").lower()
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            raise ValueError("base URL must be an origin such as http://127.0.0.1:8080")
        if parsed.scheme != "https" and host not in local_hosts:
            raise ValueError("HTTP is allowed only for a loopback development server")
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        self.base_url = self.origin
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(CookieJar()), RejectRedirects(),
        )

    def call(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers = {"Origin": self.origin, "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(1 << 20)
                if len(raw) >= 1 << 20:
                    raise RuntimeError("API response exceeded the size limit")
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            # Error bodies may contain deployment details; expose only the API code.
            try:
                payload = json.loads(error.read(64 << 10))
                details = payload.get("error", {}) if isinstance(payload, dict) else {}
                code = details.get("code", payload.get("code", "API_ERROR")) if isinstance(details, dict) else "API_ERROR"
                if not isinstance(code, str) or not code.isascii() or not code.replace("_", "").isalnum():
                    code = "API_ERROR"
            except Exception:
                code = "API_ERROR"
            raise RuntimeError(f"{method} {path} failed: HTTP {error.code} {code}") from None

    def login_and_select_workspace(self, username: str, password: str) -> None:
        self.call("POST", "/auth/login", {"username": username, "password": password})
        claims = self.call("POST", "/auth/workspace", EXPECTED_SCOPE)
        if not isinstance(claims, dict) or any(claims.get(key) != value for key, value in EXPECTED_SCOPE.items()):
            raise RuntimeError("administrator could not enter the reviewed demo application workspace")


def load_seed() -> dict[str, Any]:
    seed = json.loads(SEED.read_text(encoding="utf-8"))
    if not isinstance(seed, dict) or set(seed) != {"version", "scope", "grants"} or seed["version"] != 1 or seed["scope"] != EXPECTED_SCOPE:
        raise ValueError("example machine history grant seed has an unsupported shape or scope")
    grants = seed["grants"]
    expected = {
        ("example-go-machine", "example-go-operations", "example-go-operations-installation"),
        ("example-python-machine", "example-python-documents", "example-python-documents-installation"),
        ("example-java-machine", "example-java-tickets", "example-java-tickets-installation"),
    }
    if not isinstance(grants, list) or len(grants) != 3:
        raise ValueError("seed must contain exactly three example machine grants")
    seen: set[tuple[str, str, str]] = set()
    for grant in grants:
        if not isinstance(grant, dict) or set(grant) != REQUIRED_GRANT_FIELDS:
            raise ValueError("seed grant contains missing or unsupported fields")
        if grant["subject_type"] != "service_principal" or grant["action"] != "history.read" or grant["data_scope"] != {"type": "approved_organization"}:
            raise ValueError("seed may grant only service-principal history.read with approved_organization scope")
        seen.add((grant["subject_id"], grant["agent_id"], grant["agent_instance_id"]))
    if seen != expected or len({grant["id"] for grant in grants}) != 3:
        raise ValueError("seed subjects and installations do not match the reviewed three-agent mapping")
    return seed


def grant_body(grant: dict[str, Any], scope: dict[str, str]) -> dict[str, Any]:
    installation = grant["agent_instance_id"]
    return {
        "id": grant["id"],
        "tenant_id": scope["tenant_id"],
        "department_id": scope["department_id"],
        "application_id": scope["application_id"],
        "agent_instance_id": installation,
        "subject_type": grant["subject_type"],
        "subject_id": grant["subject_id"],
        "resource_type": "agent_installation",
        "resource_id": installation,
        "action": grant["action"],
        "effect": "allow",
        "status": "active",
        "revision": 1,
        "source_id": "public-example-machine-history-read-v1",
        "data_scope": grant["data_scope"],
    }


def verify_installation(api: BrowserAPI, grant: dict[str, Any], scope: dict[str, str]) -> dict[str, Any]:
    installation_id = grant["agent_instance_id"]
    installation = api.call("GET", "/api/modules/catalog/installations/" + urllib.parse.quote(installation_id, safe=""))
    if not isinstance(installation, dict):
        raise RuntimeError(f"installation {installation_id} response is invalid")
    if any(installation.get(key) != value for key, value in {
        **scope, "id": installation_id, "agent_id": grant["agent_id"],
    }.items()):
        raise RuntimeError(f"installation {installation_id} does not match the reviewed seed mapping")
    if installation.get("status") != "active":
        raise RuntimeError(f"installation {installation_id} must be active before history access is approved")
    return installation


def verify_machine_binding(api: BrowserAPI, grant: dict[str, Any], scope: dict[str, str], installation: dict[str, Any]) -> None:
    query = urllib.parse.urlencode(scope)
    response = api.call("GET", "/api/modules/identity/workload-bindings?" + query)
    if not isinstance(response, dict) or not isinstance(response.get("items"), list):
        raise RuntimeError("workload binding response is invalid")
    active = [item for item in response["items"] if isinstance(item, dict) and item.get("principal_id") == grant["subject_id"] and item.get("status") == "active"]
    if len(active) != 1:
        raise RuntimeError(f"machine {grant['subject_id']} must have exactly one active workload binding")
    binding = active[0]
    if any(binding.get(key) != value for key, value in {
        "tenant_id": scope["tenant_id"], "department_id": scope["department_id"],
        "application_id": scope["application_id"], "installation_id": grant["agent_instance_id"],
        "agent_id": grant["agent_id"], "agent_version_id": installation.get("version_id"),
    }.items()):
        raise RuntimeError(f"machine {grant['subject_id']} is not bound only to its reviewed installation")


def exact_history_grant(grant: dict[str, Any], scope: dict[str, str]) -> dict[str, Any]:
    body = grant_body(grant, scope)
    return {
        key: body[key] for key in (
            "id", "tenant_id", "department_id", "application_id", "agent_instance_id", "subject_type",
            "subject_id", "resource_type", "resource_id", "action", "effect", "status", "revision", "data_scope",
        )
    }


def apply_one(api: BrowserAPI, grant: dict[str, Any], scope: dict[str, str]) -> str:
    subject_id = grant["subject_id"]
    query = urllib.parse.urlencode({"principal_type": "service_principal"})
    profile_path = "/api/modules/identity/principals/" + urllib.parse.quote(subject_id, safe="") + "/access-profile?" + query
    profile = api.call("GET", profile_path)
    if not isinstance(profile, dict) or not isinstance(profile.get("principal"), dict) or not isinstance(profile.get("resource_grants"), list):
        raise RuntimeError(f"machine {subject_id} access profile response is invalid")
    principal = profile.get("principal", {})
    if principal.get("type") != "service_principal" or principal.get("id") != subject_id or principal.get("tenant_id") != scope["tenant_id"] or principal.get("is_active") is not True:
        raise RuntimeError(f"machine {subject_id} is missing, disabled, or outside the reviewed tenant")
    if profile.get("policy_mode") != "v2" or principal.get("roles", []):
        raise RuntimeError(f"machine {subject_id} must be an unprivileged v2 workload principal")

    expected = exact_history_grant(grant, scope)
    installation = verify_installation(api, grant, scope)
    verify_machine_binding(api, grant, scope, installation)
    target_grants = [item for item in profile["resource_grants"] if isinstance(item, dict) and
        item.get("agent_instance_id") == grant["agent_instance_id"] and item.get("action") == "history.read"]
    expected_semantics = {key: value for key, value in expected.items() if key not in {"id", "revision"}}
    if target_grants:
        if any(item.get("status") == "active" and all(item.get(key) == value for key, value in expected_semantics.items()) for item in target_grants):
            return "already_granted"
        raise RuntimeError(f"machine {subject_id} has a conflicting history.read grant; review current IAM before proceeding")

    command = {
        "subject_type": "service_principal",
        "subject_id": subject_id,
        "expected_revision": principal.get("revision"),
        "idempotency_key": "public-example-machine-history-read:" + uuid.uuid4().hex,
        "reason": "Approve history reads for the bound example installation's signed runtime checkpoints",
        "resource_grants": [grant_body(grant, scope)],
    }
    plan = api.call("POST", "/api/modules/identity/authorization-changes:preview", command)
    if not isinstance(plan, dict) or not isinstance(plan.get("change"), dict) or not isinstance(plan.get("expanded_resource_grants"), list):
        raise RuntimeError("authorization preview response is invalid")
    if plan.get("subject_id") != subject_id or plan.get("change", {}).get("subject_type") != "service_principal":
        raise RuntimeError("authorization preview target does not match the machine seed")
    expanded = plan.get("expanded_resource_grants", [])
    if len(expanded) != 1 or not isinstance(expanded[0], dict) or any(expanded[0].get(key) != value for key, value in expected.items()):
        raise RuntimeError("authorization preview differs from the single expected installation history.read grant")
    if any(plan.get(key) for key in (
        "expanded_role_bindings", "expanded_assignments", "expanded_memberships",
        "automatic_revoke_grant_ids", "automatic_revoke_binding_ids", "automatic_revoke_assignment_ids",
    )):
        raise RuntimeError("authorization preview contains unexpected role, assignment, membership, or revocation changes")
    print(json.dumps({
        "actor_id": plan.get("actor_id"), "subject_id": subject_id,
        "installation_id": grant["agent_instance_id"], "action": "history.read",
        "data_scope": grant["data_scope"], "plan_digest": plan.get("plan_digest"),
    }, ensure_ascii=False))
    confirmation = input(f"Commit only this grant? Type {grant['agent_instance_id']} to continue: ")
    if confirmation != grant["agent_instance_id"]:
        print(f"Skipped {subject_id}; no grant was committed.")
        return "declined"
    commit = dict(plan.get("change", {}))
    commit["plan_digest"] = plan.get("plan_digest")
    commit["plan_expires_at"] = plan.get("plan_expires_at")
    receipt = api.call("POST", "/api/modules/identity/authorization-changes", commit)
    verified = api.call("GET", profile_path)
    if not isinstance(verified, dict) or not isinstance(verified.get("resource_grants"), list) or not any(
        isinstance(item, dict) and item.get("status") == "active" and all(item.get(key) == value for key, value in expected_semantics.items())
        for item in verified["resource_grants"]
    ):
        raise RuntimeError(f"machine {subject_id} grant was not visible after commit")
    return "committed:" + str(receipt.get("change_id", "recorded"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080", help="browser gateway origin; production must use HTTPS")
    parser.add_argument("--administrator", required=True, help="existing administrator username authorized in tenant-demo/dept-demo/app-demo")
    args = parser.parse_args()
    try:
        seed = load_seed()
        api = BrowserAPI(args.base_url)
        password = getpass.getpass("Administrator password: ")
        if not password:
            raise ValueError("administrator password is required")
        api.login_and_select_workspace(args.administrator, password)
        results = []
        for grant in seed["grants"]:
            results.append({"subject_id": grant["subject_id"], "result": apply_one(api, grant, seed["scope"])})
        print(json.dumps({"complete": all(item["result"] != "declined" for item in results), "results": results}, ensure_ascii=False))
        return 0 if all(item["result"] != "declined" for item in results) else 2
    except (OSError, ValueError, RuntimeError, urllib.error.URLError) as error:
        print("Machine history grant seed stopped: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
