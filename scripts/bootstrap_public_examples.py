"""Provision public example identities through the authenticated Identity API.

This is an operator helper, not an account or permission seed. Every mutation
is selected by an explicit flag; permission changes are previewed and require a
typed confirmation. It never grants an Agent run or capability permission.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sys
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from typing import Any
from urllib.request import HTTPRedirectHandler


ROOT = Path(__file__).resolve().parents[1]
ADMIN_SCOPE = {
    "tenant_id": "tenant-demo",
    "department_id": "dept-platform",
    "application_id": "app-platform-admin",
}
BUSINESS_SCOPE = {
    "tenant_id": "tenant-demo",
    "department_id": "dept-demo",
    "application_id": "app-demo",
}
ACCOUNTS = (
    ("permission.admin", "权限管理员"),
    ("demo.go.user", "Go 运维示例用户"),
    ("demo.python.user", "Python 文档示例用户"),
    ("demo.java.user", "Java 工单示例用户"),
)
DEMO_USERS = tuple(item[0] for item in ACCOUNTS if item[0].startswith("demo."))
FIRST_ADMIN_APPROVAL_REFERENCE = "isolated-public-initialization"
MACHINES = (
    ("example-go-machine", "example-go-operations", "example-go-operations-installation", "EXAMPLE_GO"),
    ("example-python-machine", "example-python-documents", "example-python-documents-installation", "EXAMPLE_PYTHON"),
    ("example-java-machine", "example-java-tickets", "example-java-tickets-installation", "EXAMPLE_JAVA"),
)


class APIError(RuntimeError):
    def __init__(self, method: str, path: str, status: int, code: str):
        super().__init__(f"{method} {path} failed: HTTP {status} {code}")
        self.status = status
        self.code = code


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        # Never forward a password or browser-session cookie to another host.
        return None


class BrowserAPI:
    def __init__(self, base_url: str):
        parsed = urllib.parse.urlsplit(base_url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            raise ValueError("base URL must be an origin such as http://127.0.0.1:8080")
        if parsed.scheme != "https" and host not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("HTTP is allowed only for a loopback development server")
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(CookieJar()), RejectRedirects(),
            *([urllib.request.ProxyHandler({})] if host in {"localhost", "127.0.0.1", "::1"} else []),
        )

    def call(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers = {"Origin": self.origin, "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.origin + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(1 << 20)
                if len(raw) >= 1 << 20:
                    raise RuntimeError("API response exceeded the size limit")
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            try:
                payload = json.loads(error.read(64 << 10))
                detail = payload.get("error", {}) if isinstance(payload, dict) else {}
                code = detail.get("code", payload.get("code", "API_ERROR")) if isinstance(detail, dict) else "API_ERROR"
                if not isinstance(code, str) or not code.isascii() or not code.replace("_", "").isalnum():
                    code = "API_ERROR"
            except Exception:
                code = "API_ERROR"
            raise APIError(method, path.split("?", 1)[0], error.code, code) from None

    def login(self, username: str, password: str) -> None:
        self.call("POST", "/auth/login", {"username": username, "password": password})

    def select_workspace(self, scope: dict[str, str]) -> None:
        result = self.call("POST", "/auth/workspace", scope)
        if not isinstance(result, dict) or any(result.get(key) != value for key, value in scope.items()):
            raise RuntimeError("administrator could not enter the requested active workspace")


def verify_login_identity(identity: Any, username: str, scope: dict[str, str]) -> None:
    """Fail closed unless /auth/me proves both principal and selected workspace."""
    if not isinstance(identity, dict) or identity.get("username") != username:
        raise RuntimeError(f"independent login identity check failed for {username}")
    if any(identity.get(key) != value for key, value in scope.items()):
        raise RuntimeError(f"independent login workspace check failed for {username}")


def management_scope(scope: dict[str, str]) -> dict[str, str]:
    return {"scope_type": "application", **scope}


def api_path(path: str) -> str:
    return "/api/modules/identity" + path


def items(response: Any, label: str) -> list[dict[str, Any]]:
    if isinstance(response, list):
        values = response
    elif isinstance(response, dict) and isinstance(response.get("items"), list):
        values = response["items"]
    else:
        raise RuntimeError(f"{label} response is invalid")
    if any(not isinstance(value, dict) for value in values):
        raise RuntimeError(f"{label} response contains an invalid item")
    return values


def confirm(phrase: str) -> bool:
    return input(f"Type {phrase!r} to submit this exact change (anything else cancels): ") == phrase


def application_scope_query(scope: dict[str, str]) -> str:
    return urllib.parse.urlencode(scope)


def ensure_organization(api: BrowserAPI) -> None:
    department_query = urllib.parse.urlencode({"tenant_id": "tenant-demo", "department_id": "dept-demo", "status": "active"})
    departments = items(api.call("GET", api_path("/departments?" + department_query)), "department list")
    matching_department = [value for value in departments if value.get("id") == "dept-demo"]
    department_body = {
        "id": "dept-demo", "tenant_id": "tenant-demo", "code": "examples",
        "name": "SDK示例", "status": "active", "revision": 1,
    }
    if matching_department:
        if len(matching_department) != 1 or any(matching_department[0].get(key) != value for key, value in department_body.items()):
            raise RuntimeError("dept-demo exists with a different owner or status; stop and review it")
    else:
        print(json.dumps({"operation": "create_department", "id": "dept-demo", "scope": "tenant-demo"}, ensure_ascii=False))
        if not confirm("dept-demo"):
            raise RuntimeError("organization creation cancelled")
        api.call("POST", api_path("/departments"), department_body)

    app_query = urllib.parse.urlencode({**BUSINESS_SCOPE, "status": "active"})
    applications = items(api.call("GET", api_path("/applications?" + app_query)), "application list")
    matching_app = [value for value in applications if value.get("id") == "app-demo"]
    app_body = {
        "id": "app-demo", "tenant_id": "tenant-demo", "department_id": "dept-demo",
        "code": "sdk-examples", "name": "SDK业务示例", "status": "active", "revision": 1,
    }
    if matching_app:
        if len(matching_app) != 1 or any(matching_app[0].get(key) != value for key, value in app_body.items()):
            raise RuntimeError("app-demo exists with a different owner or status; stop and review it")
    else:
        print(json.dumps({"operation": "create_application", "id": "app-demo", "scope": "tenant-demo/dept-demo"}, ensure_ascii=False))
        if not confirm("app-demo"):
            raise RuntimeError("organization creation cancelled")
        api.call("POST", api_path("/applications"), app_body)


def profile(api: BrowserAPI, subject_id: str, kind: str = "user") -> dict[str, Any]:
    query = urllib.parse.urlencode({"principal_type": kind})
    path = api_path("/principals/" + urllib.parse.quote(subject_id, safe="") + "/access-profile?" + query)
    result = api.call("GET", path)
    if not isinstance(result, dict) or not isinstance(result.get("principal"), dict):
        raise RuntimeError(f"identity access profile for {subject_id} is invalid")
    # PermissionSnapshot intentionally omits an empty task_assignments field
    # (json:"task_assignments,omitempty"). Normalize only that documented
    # optional collection; malformed or absent permission facts still fail closed.
    if "task_assignments" not in result:
        result["task_assignments"] = []
    elif not isinstance(result["task_assignments"], list):
        raise RuntimeError(f"identity task-assignment profile for {subject_id} is invalid")
    return result


def strict_empty_access(profile_value: dict[str, Any], subject_id: str, kind: str) -> None:
    principal = profile_value["principal"]
    if principal.get("id") != subject_id or principal.get("type") != kind or principal.get("is_active") is not True:
        raise RuntimeError(f"{subject_id} is not the expected active {kind}")
    if principal.get("roles", []) or profile_value.get("role_bindings", []) or profile_value.get("resource_grants", []):
        raise RuntimeError(f"{subject_id} already has roles or resource grants; review rather than overwrite")


def first_admin_ids(tenant_id: str = "tenant-demo", principal_id: str = "system.admin",
                    approval_reference: str = FIRST_ADMIN_APPROVAL_REFERENCE) -> tuple[str, str]:
    if not tenant_id or not principal_id or not approval_reference:
        raise ValueError("first-administrator identity coordinates must be explicit")
    digest = hashlib.sha256((tenant_id + "\x00" + principal_id + "\x00" + approval_reference).encode("utf-8")).hexdigest()
    return "first-super-" + digest, "first-member-" + digest


def verify_initial_admin_access(profile_value: dict[str, Any], allow_business_membership: bool | None = False) -> dict[str, Any]:
    """Accept only the immutable first-admin management binding, never business access."""
    principal = profile_value.get("principal")
    if (not isinstance(principal, dict) or principal.get("id") != "system.admin"
            or principal.get("type") != "user" or principal.get("tenant_id") != "tenant-demo"
            or principal.get("is_active") is not True or not isinstance(principal.get("revision"), int)
            or principal.get("revision", 0) < 1
            or principal.get("roles") not in (None, []) or principal.get("groups") not in (None, [])):
        raise RuntimeError("system.admin is not the expected untouched first-administrator identity")
    binding_id, first_membership_id = first_admin_ids(principal["tenant_id"], principal["id"])
    bindings = profile_value.get("role_bindings")
    if not isinstance(bindings, list) or len(bindings) != 1:
        raise RuntimeError("system.admin must retain exactly its original first-administrator binding")
    expected_binding = {
        "id": binding_id, "subject_id": "system.admin", "role_code": "super_admin", "role_version": 1,
        "scope": {"scope_type": "global"}, "status": "active", "revision": 1,
        "source_id": "bootstrap:" + FIRST_ADMIN_APPROVAL_REFERENCE,
    }
    if bindings[0] != expected_binding:
        raise RuntimeError("system.admin first-administrator binding differs from the exact global bootstrap binding")
    if profile_value.get("resource_grants") != []:
        raise RuntimeError("system.admin must have no business resource grants")
    for key in ("task_assignments", "delegations"):
        if profile_value.get(key) not in (None, []):
            raise RuntimeError(f"system.admin must have no {key.replace('_', ' ')}")
    memberships = profile_value.get("memberships")
    if not isinstance(memberships, list):
        raise RuntimeError("system.admin membership profile is invalid")
    initial = [member for member in memberships if isinstance(member, dict) and member.get("id") == first_membership_id]
    if len(initial) != 1 or any(initial[0].get(key) != value for key, value in {
        "subject_id": "system.admin", "scope": management_scope(ADMIN_SCOPE), "status": "active", "revision": 1,
    }.items()):
        raise RuntimeError("system.admin original first-administrator membership is missing or changed")
    business = [member for member in memberships if isinstance(member, dict) and member.get("scope") == management_scope(BUSINESS_SCOPE)]
    allowed_counts = {0, 1} if allow_business_membership is None else {1 if allow_business_membership else 0}
    if len(business) not in allowed_counts or len(memberships) != 1 + len(business):
        raise RuntimeError("system.admin has an unexpected workspace membership")
    if business and any(business[0].get(key) != value for key, value in {
        "id": "public-demo-workspace-v1-system-admin", "subject_id": "system.admin",
        "scope": management_scope(BUSINESS_SCOPE), "status": "active",
    }.items()):
        raise RuntimeError("system.admin app-demo membership differs from the exact public identity change")
    return bindings[0]


def verify_public_human_access(profile_value: dict[str, Any], username: str, allow_business_membership: bool | None = False) -> None:
    if username == "system.admin":
        verify_initial_admin_access(profile_value, allow_business_membership)
        return
    strict_empty_access(profile_value, username, "user")
    for key in ("task_assignments", "delegations"):
        if profile_value.get(key) not in (None, []):
            raise RuntimeError(f"{username} must have no {key.replace('_', ' ')}")
    memberships = profile_value.get("memberships")
    if not isinstance(memberships, list):
        raise RuntimeError(f"{username} membership profile is invalid")
    admin = [member for member in memberships if isinstance(member, dict) and member.get("scope") == management_scope(ADMIN_SCOPE)]
    business = [member for member in memberships if isinstance(member, dict) and member.get("scope") == management_scope(BUSINESS_SCOPE)]
    allowed_counts = {0, 1} if allow_business_membership is None else {1 if allow_business_membership else 0}
    if len(admin) != 1 or admin[0].get("subject_id") != username or admin[0].get("status") != "active":
        raise RuntimeError(f"{username} lacks the exact active initial-administrator workspace membership")
    if len(business) not in allowed_counts or len(memberships) != 1 + len(business):
        raise RuntimeError(f"{username} has an unexpected workspace membership")
    if business and any(business[0].get(key) != value for key, value in {
        "id": "public-demo-workspace-v1-" + username.replace(".", "-"), "subject_id": username,
        "scope": management_scope(BUSINESS_SCOPE), "status": "active",
    }.items()):
        raise RuntimeError(f"{username} app-demo membership differs from the exact public identity change")


def profile_missing(api: BrowserAPI, subject_id: str, kind: str = "user") -> bool:
    query = urllib.parse.urlencode({"principal_type": kind})
    path = api_path("/principals/" + urllib.parse.quote(subject_id, safe="") + "/access-profile?" + query)
    try:
        api.call("GET", path)
        return False
    except APIError as error:
        if error.status == 404:
            return True
        raise


def create_accounts(api: BrowserAPI) -> None:
    for username, display_name in ACCOUNTS:
        password = getpass.getpass(f"Set or verify the independent local password for {username}: ")
        if len(password) < 10 or len(password) > 128:
            raise ValueError(f"password for {username} must contain 10..128 characters")

        # Existing credentials are never reset. A valid login means this account
        # is already provisioned; an existing identity with a failed login stops.
        if not profile_missing(api, username):
            existing = profile(api, username)
            strict_empty_access(existing, username, "user")
            test = BrowserAPI(api.origin)
            try:
                test.login(username, password)
            except APIError:
                raise RuntimeError(f"{username} already exists but this password did not authenticate; no credential was changed") from None
            identity = test.call("GET", "/auth/me")
            verify_login_identity(identity, username, ADMIN_SCOPE)
            test.call("POST", "/auth/logout", {})
            print(json.dumps({"account": username, "result": "existing_login_verified"}, ensure_ascii=False))
            continue

        confirmation_password = getpass.getpass(f"Repeat the password for {username}: ")
        if password != confirmation_password:
            raise ValueError(f"password confirmation did not match for {username}")
        command = {
            "username": username,
            "display_name": display_name,
            "password": password,
            "scope": management_scope(ADMIN_SCOPE),
            "idempotency_key": "public-example-account-v1:" + username,
            "reason": "Create an independently authenticated public example account",
        }
        plan = api.call("POST", api_path("/principals:preview"), command)
        validate_account_plan(plan, username)
        print(json.dumps({"account": username, "plan_digest": plan.get("plan_digest"), "business_roles": [], "resource_grants": []}, ensure_ascii=False))
        if not confirm("create " + username):
            raise RuntimeError(f"account creation cancelled for {username}")
        submit = dict(command)
        submit["plan_digest"] = plan["plan_digest"]
        submit["plan_expires_at"] = plan["plan_expires_at"]
        api.call("POST", api_path("/principals:create"), submit)
        strict_empty_access(profile(api, username), username, "user")
        independent = BrowserAPI(api.origin)
        independent.login(username, password)
        identity = independent.call("GET", "/auth/me")
        verify_login_identity(identity, username, ADMIN_SCOPE)
        independent.call("POST", "/auth/logout", {})
        print(json.dumps({"account": username, "result": "created_and_independent_login_verified"}, ensure_ascii=False))


def validate_account_plan(plan: Any, username: str) -> None:
    if not isinstance(plan, dict) or plan.get("subject_id") != username or not isinstance(plan.get("change"), dict):
        raise RuntimeError("principal creation preview response is invalid")
    change = plan["change"]
    memberships = plan.get("expanded_memberships")
    wanted_scope = management_scope(ADMIN_SCOPE)
    if not isinstance(memberships, list) or len(memberships) != 1:
        raise RuntimeError("principal creation preview did not contain exactly its admin-workspace membership")
    member = memberships[0]
    if member.get("subject_id") != username or member.get("status") != "active" or member.get("scope") != wanted_scope:
        raise RuntimeError("principal creation preview differs from the expected workspace membership")
    if any(plan.get(key) for key in ("expanded_role_bindings", "expanded_resource_grants", "expanded_task_assignments", "automatic_revoke_binding_ids", "automatic_revoke_grant_ids", "automatic_revoke_assignment_ids")):
        raise RuntimeError("principal creation preview contains an unexpected role, grant, assignment or revocation")
    if not isinstance(plan.get("plan_digest"), str) or not plan["plan_digest"] or not plan.get("plan_expires_at"):
        raise RuntimeError("principal creation preview is missing its digest or expiration")
    if change.get("subject_id") != username or change.get("preset"):
        raise RuntimeError("principal creation preview unexpectedly applies a preset")


def active_membership(profile_value: dict[str, Any], username: str, scope: dict[str, str]) -> bool:
    now = datetime.now(timezone.utc)
    for member in profile_value.get("memberships", []):
        if not isinstance(member, dict) or member.get("subject_id") != username or member.get("status") != "active" or member.get("scope") != management_scope(scope):
            continue
        try:
            starts = member.get("starts_at")
            expires = member.get("expires_at")
            starts_at = datetime.fromisoformat(starts.replace("Z", "+00:00")) if starts else None
            expires_at = datetime.fromisoformat(expires.replace("Z", "+00:00")) if expires else None
            if (starts_at is None or starts_at <= now) and (expires_at is None or now < expires_at):
                return True
        except (AttributeError, ValueError):
            raise RuntimeError(f"membership validity for {username} could not be verified") from None
    return False


def add_membership(api: BrowserAPI, username: str, *, preserve_initial_admin: bool = False) -> None:
    if preserve_initial_admin and username != "system.admin":
        raise ValueError("first-administrator preservation applies only to system.admin")
    current = profile(api, username)
    principal = current["principal"]
    verify_public_human_access(current, username, allow_business_membership=None)
    initial_admin_binding = verify_initial_admin_access(current, allow_business_membership=None) if preserve_initial_admin else None
    if active_membership(current, username, BUSINESS_SCOPE):
        verify_public_human_access(current, username, allow_business_membership=True)
        print(json.dumps({"subject_id": username, "workspace": "app-demo", "result": "already_member"}, ensure_ascii=False))
        return
    expected_revision = principal.get("revision")
    if not isinstance(expected_revision, int) or expected_revision < 1:
        raise RuntimeError(f"{username} has no usable current principal revision")
    command = {
        "subject_type": "user",
        "subject_id": username,
        "expected_revision": expected_revision,
        "idempotency_key": "public-demo-workspace-v1:" + username,
        "reason": "Add the public example application workspace without business roles or resource grants",
        "memberships": [{
            "id": "public-demo-workspace-v1-" + username.replace(".", "-"),
            "scope": management_scope(BUSINESS_SCOPE),
            "expected_revision": 0,
            "status": "active",
        }],
    }
    plan = api.call("POST", api_path("/authorization-changes:preview"), command)
    validate_membership_plan(plan, username)
    print(json.dumps({"subject_id": username, "workspace": "app-demo", "plan_digest": plan.get("plan_digest"), "business_roles": [], "resource_grants": []}, ensure_ascii=False))
    phrase = "{}@app-demo".format(username)
    if not confirm(phrase):
        raise RuntimeError(f"workspace membership cancelled for {username}")
    submit = dict(plan["change"])
    submit["plan_digest"] = plan["plan_digest"]
    submit["plan_expires_at"] = plan["plan_expires_at"]
    api.call("POST", api_path("/authorization-changes"), submit)
    verified = profile(api, username)
    verify_public_human_access(verified, username, allow_business_membership=True)
    if preserve_initial_admin and verify_initial_admin_access(verified, allow_business_membership=True) != initial_admin_binding:
        raise RuntimeError("system.admin first-administrator management binding changed during the membership-only update")
    if not active_membership(verified, username, BUSINESS_SCOPE):
        raise RuntimeError(f"{username} workspace membership was not visible after submit")


def validate_membership_plan(plan: Any, username: str) -> None:
    if not isinstance(plan, dict) or plan.get("subject_id") != username or not isinstance(plan.get("change"), dict):
        raise RuntimeError("workspace membership preview response is invalid")
    expanded = plan.get("expanded_memberships")
    wanted_scope = management_scope(BUSINESS_SCOPE)
    if not isinstance(expanded, list) or len(expanded) != 1 or expanded[0].get("subject_id") != username or expanded[0].get("scope") != wanted_scope or expanded[0].get("status") != "active":
        raise RuntimeError("workspace membership preview differs from the exact app-demo membership")
    if any(plan.get(key) for key in ("expanded_role_bindings", "expanded_resource_grants", "expanded_task_assignments", "automatic_revoke_binding_ids", "automatic_revoke_grant_ids", "automatic_revoke_assignment_ids")):
        raise RuntimeError("workspace membership preview contains an unexpected role, grant, assignment or revocation")
    command = plan["change"]
    if command.get("subject_id") != username or command.get("preset") or len(command.get("memberships", [])) != 1:
        raise RuntimeError("workspace membership preview changed fields outside the one membership")
    if not plan.get("plan_digest") or not plan.get("plan_expires_at"):
        raise RuntimeError("workspace membership preview is missing its digest or expiration")


def load_or_create_machine_env(path: Path) -> dict[str, str]:
    path = path.expanduser()
    validate_machine_env_path(path)
    if path.is_symlink():
        raise ValueError("machine environment output may not be a symlink")
    ensure_private_directory(path.parent)
    names = {prefix + suffix for _, _, _, prefix in MACHINES for suffix in ("_CLIENT_ID", "_CLIENT_SECRET")}
    if path.exists():
        verify_private_file(path)
        values: dict[str, str] = {}
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            if not separator or key not in names or key in values or not value:
                raise ValueError("existing machine environment has unsupported fields")
            values[key] = value
        if set(values) != names:
            raise ValueError("existing machine environment must contain the exact six example credential fields")
        for machine_id, _, _, prefix in MACHINES:
            if values[prefix + "_CLIENT_ID"] != machine_id or len(values[prefix + "_CLIENT_SECRET"]) < 32:
                raise ValueError("existing machine environment does not match the reviewed machine mapping")
        return values

    values = {}
    for machine_id, _, _, prefix in MACHINES:
        values[prefix + "_CLIENT_ID"] = machine_id
        values[prefix + "_CLIENT_SECRET"] = secrets.token_urlsafe(48)
    content = "# Owner-private workload credentials. Do not commit or share.\n" + "".join(f"{key}={value}\n" for key, value in values.items())
    write_new_private_file(path, content)
    return values


def secure_windows_file(path: Path) -> None:
    """For a newly created file, remove inherited ACLs and grant only user/SYSTEM."""
    try:
        current_user, sid = windows_user_identity()
        subprocess.run(["icacls", str(path), "/reset"], check=True, capture_output=True, text=True, encoding="mbcs")
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:(F)", "*S-1-5-18:(F)"],
            check=True, capture_output=True, text=True, encoding="mbcs",
        )
        if windows_acl_entries(path) != {current_user.casefold(), "nt authority\\system"}:
            raise ValueError
    except (OSError, subprocess.CalledProcessError, ValueError, StopIteration):
        raise RuntimeError("could not apply owner-only Windows ACL to the private file") from None


def windows_user_identity() -> tuple[str, str]:
    who = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], check=True, capture_output=True, text=True)
    row = next(csv.reader([who.stdout.strip()]))
    current_user = row[0].lstrip("\ufeff \t\r\n") if row else ""
    sid = row[-1].lstrip("\ufeff \t\r\n") if row else ""
    if not current_user or not sid.startswith("S-") or not all(char.isdigit() or char == "-" for char in sid[2:]):
        raise ValueError
    return current_user, sid


def windows_acl_entries(path: Path) -> set[str]:
    audit = subprocess.run(["icacls", str(path)], check=True, capture_output=True, text=True, encoding="mbcs")
    entries = set()
    for line in audit.stdout.splitlines():
        if ":(" not in line:
            continue
        line = line.strip()
        if line.startswith(str(path)):
            line = line[len(str(path)):].strip()
        entries.add(line.split(":(", 1)[0].strip().casefold())
    if not entries:
        raise ValueError
    return entries


def secure_windows_directory(path: Path) -> None:
    """Secure a newly created private directory and allow safe child inheritance."""
    try:
        current_user, sid = windows_user_identity()
        subprocess.run(["icacls", str(path), "/reset"], check=True, capture_output=True, text=True, encoding="mbcs")
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)(F)", "*S-1-5-18:(OI)(CI)(F)"],
            check=True, capture_output=True, text=True, encoding="mbcs",
        )
        if windows_acl_entries(path) != {current_user.casefold(), "nt authority\\system"}:
            raise ValueError
    except (OSError, subprocess.CalledProcessError, ValueError, StopIteration):
        raise RuntimeError("could not create an owner-private Windows directory") from None


def verify_windows_private_file(path: Path) -> None:
    """Check an existing credential ACL without changing any existing ACL."""
    try:
        current_user, _ = windows_user_identity()
        if windows_acl_entries(path) != {current_user.casefold(), "nt authority\\system"}:
            raise ValueError
    except (OSError, subprocess.CalledProcessError, ValueError, StopIteration):
        raise ValueError("existing machine environment ACL is not owner-only; no ACL was changed") from None


def verify_private_file(path: Path) -> None:
    if is_reparse_point(path) or not path.is_file():
        raise ValueError("existing private file must be a regular non-reparse file")
    if os.name == "nt":
        verify_windows_private_file(path)
    elif path.stat().st_mode & 0o077:
        raise ValueError("existing private file permissions are not owner-only; no permissions were changed")


def ensure_private_directory(path: Path) -> None:
    """Create private child directories or reject existing directories with broad access."""
    root = ROOT / ".local-secrets"
    validate_machine_env_path(path / "_private_directory_probe")
    relative = path.absolute().relative_to(root.absolute())
    if not root.exists():
        root.mkdir(mode=0o700)
        if os.name == "nt":
            secure_windows_directory(root)
    elif not root.is_dir() or is_reparse_point(root):
        raise ValueError(".local-secrets must be a regular directory")
    if not relative.parts:
        if os.name == "nt":
            try:
                current_user, _ = windows_user_identity()
                if windows_acl_entries(root) != {current_user.casefold(), "nt authority\\system"}:
                    raise ValueError("existing .local-secrets ACL is not owner-only; no ACL was changed")
            except (OSError, subprocess.CalledProcessError, ValueError, StopIteration):
                raise ValueError("existing .local-secrets ACL is not owner-only; no ACL was changed") from None
        elif root.stat().st_mode & 0o077:
            raise ValueError("existing .local-secrets permissions are not owner-only; no permissions were changed")
    current = root
    for part in relative.parts:
        current = current / part
        if not current.exists():
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
            else:
                if os.name == "nt":
                    secure_windows_directory(current)
                continue
        if not current.is_dir() or is_reparse_point(current):
            raise ValueError("private directory path is not a regular directory")
        if os.name == "nt":
            try:
                current_user, _ = windows_user_identity()
                if windows_acl_entries(current) != {current_user.casefold(), "nt authority\\system"}:
                    raise ValueError("existing private directory ACL is not owner-only; no ACL was changed")
            except (OSError, subprocess.CalledProcessError, ValueError, StopIteration):
                raise ValueError("existing private directory ACL is not owner-only; no ACL was changed") from None
        elif current.stat().st_mode & 0o077:
            raise ValueError("existing private directory permissions are not owner-only; no permissions were changed")


def write_new_private_file(path: Path, content: str) -> None:
    """Create once with restrictive parent permissions, secure before writing data."""
    validate_machine_env_path(path)
    ensure_private_directory(path.parent)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        if os.name == "nt":
            secure_windows_file(path)
        else:
            path.chmod(0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            descriptor = -1
            output.write(content)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def validate_machine_env_path(path: Path) -> None:
    root = ROOT / ".local-secrets"
    if is_reparse_point(root):
        raise ValueError("machine environment secret directory may not be a symlink")
    candidate = path if path.is_absolute() else ROOT / path
    try:
        relative = candidate.absolute().relative_to(root.absolute())
    except ValueError:
        raise ValueError("machine credentials must be stored under the ignored .local-secrets directory") from None
    if not relative.parts or any(part in {".", ".."} for part in relative.parts):
        raise ValueError("machine credential path may not contain dot or parent traversal components")
    resolved_root = root.resolve()
    resolved_candidate = candidate.resolve(strict=False)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError:
        raise ValueError("machine credential path resolves outside the ignored .local-secrets directory") from None
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        if is_reparse_point(current):
            raise ValueError("machine credential parent directory may not contain a symlink, junction, or reparse point")
    if is_reparse_point(candidate):
        raise ValueError("machine credential path may not be a symlink, junction, or reparse point")


def is_reparse_point(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT
    except FileNotFoundError:
        return False


def prepare_machine_env(path: Path) -> None:
    values = load_or_create_machine_env(path)
    print(json.dumps({
        "result": "machine_credentials_prepared_offline",
        "path": str(path.expanduser().resolve()),
        "principals": [machine_id for machine_id, _, _, _ in MACHINES],
        "fields": sorted(values),
        "secrets_printed": False,
        "identity_api_called": False,
    }, ensure_ascii=False, indent=2))


def parse_agent_cidrs(raw_values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in raw_values:
        machine_id, separator, cidr = raw.partition("=")
        if not separator or machine_id not in {value[0] for value in MACHINES} or machine_id in result:
            raise ValueError("--agent-cidr must use each exact machine ID once: ID=CIDR")
        network = ipaddress.ip_network(cidr, strict=False)
        if str(network) != cidr:
            raise ValueError(f"CIDR for {machine_id} must already be canonical: {network}")
        result[machine_id] = cidr
    if set(result) != {value[0] for value in MACHINES}:
        raise ValueError("--create-machines requires one exact --agent-cidr ID=CIDR for each of the three machines")
    return result


def installation(api: BrowserAPI, machine: tuple[str, str, str, str]) -> dict[str, Any]:
    machine_id, agent_id, installation_id, _ = machine
    path = "/api/modules/catalog/installations/" + urllib.parse.quote(installation_id, safe="")
    value = api.call("GET", path)
    if not isinstance(value, dict) or any(value.get(key) != expected for key, expected in {
        "id": installation_id, **BUSINESS_SCOPE, "agent_id": agent_id, "status": "active",
    }.items()):
        raise RuntimeError(f"installation for {machine_id} must be the matching active installation before machine binding")
    return value


def active_bindings(api: BrowserAPI) -> list[dict[str, Any]]:
    path = api_path("/workload-bindings?" + application_scope_query(BUSINESS_SCOPE))
    return items(api.call("GET", path), "workload binding list")


def verify_policy_snapshot_for_installation(api: BrowserAPI, machine: tuple[str, str, str, str]) -> dict[str, Any]:
    machine_id, agent_id, installation_id, _prefix = machine
    installed = installation(api, machine)
    version_id = installed.get("version_id")
    if not isinstance(version_id, str) or not version_id:
        raise RuntimeError(f"{installation_id} has no active Catalog Version for PolicyAsset verification")
    scope = {"tenant_id": BUSINESS_SCOPE["tenant_id"], "department_id": BUSINESS_SCOPE["department_id"],
             "application_id": BUSINESS_SCOPE["application_id"], "agent_id": agent_id,
             "agent_version_id": version_id}
    path = "/api/modules/policyasset/snapshots/current?" + urllib.parse.urlencode(scope)
    snapshot = api.call("GET", path)
    if not isinstance(snapshot, dict):
        raise RuntimeError(f"{installation_id} current PolicyAsset snapshot response is invalid")
    def value(name: str):
        snake = ""
        for index, char in enumerate(name):
            if char.isupper() and index:
                snake += "_"
            snake += char.lower()
        return snapshot.get(name, snapshot.get(snake))
    revision = value("Revision")
    digest = value("Hash")
    refs = [value(key) for key in ("ModelProfileID", "PromptVersionID", "ToolPolicyID",
                                    "MemoryPolicyID", "KnowledgePolicyID", "RuntimePolicyID")]
    if (type(revision) is not int or revision < 1 or not isinstance(digest, str)
            or not re.fullmatch(r"[a-f0-9]{64}", digest)
            or any(not isinstance(item, str) or not item or any(char.isspace() for char in item) for item in refs)):
        raise RuntimeError(f"{installation_id} requires a published snapshot with all six exact PolicyAsset references")
    return {"installation_id": installation_id, "agent_id": agent_id, "agent_version_id": version_id,
            "snapshot_revision": revision, "snapshot_hash": digest}


def verify_policy_snapshots_for_machines(api: BrowserAPI) -> list[dict[str, Any]]:
    return [verify_policy_snapshot_for_installation(api, machine) for machine in MACHINES]


def private_binding_journal_path(env_path: Path) -> Path:
    path = env_path.with_name("machine-bindings.json")
    validate_machine_env_path(path)
    return path


def load_machine_binding_journal(path: Path) -> dict[str, Any]:
    validate_machine_env_path(path)
    if not path.exists():
        return {"schema": "public-workload-binding-journal/v1", "scope": dict(BUSINESS_SCOPE), "bindings": {}}
    verify_private_file(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise RuntimeError("owner-private machine binding journal is unreadable; no API write was attempted") from None
    if (not isinstance(value, dict) or set(value) != {"schema", "scope", "bindings"}
            or value.get("schema") != "public-workload-binding-journal/v1"
            or value.get("scope") != BUSINESS_SCOPE or not isinstance(value.get("bindings"), dict)
            or not set(value["bindings"]).issubset({machine[0] for machine in MACHINES})):
        raise RuntimeError("owner-private machine binding journal has an unknown schema or scope")
    return value


def save_machine_binding_journal(path: Path, journal: dict[str, Any]) -> None:
    validate_machine_env_path(path)
    content = json.dumps(journal, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if not path.exists():
        write_new_private_file(path, content)
        return
    verify_private_file(path)
    temporary = path.with_name(path.name + ".next-" + secrets.token_hex(8))
    try:
        write_new_private_file(temporary, content)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def bind_machines_with_private_journal(api: BrowserAPI, env_path: Path) -> dict[str, Any]:
    """Bind through the normal API with durable intent and exact readback receipts."""
    journal_path = private_binding_journal_path(env_path)
    journal = load_machine_binding_journal(journal_path)

    def persist() -> None:
        save_machine_binding_journal(journal_path, journal)

    def before(machine_id: str, binding: dict[str, Any], command: dict[str, Any]) -> None:
        if machine_id in journal["bindings"]:
            raise RuntimeError(f"{machine_id} has an unresolved prior binding intent; read live state before another POST")
        encoded = json.dumps(command, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        journal["bindings"][machine_id] = {"status": "intent", "binding": binding,
                                           "request_sha256": hashlib.sha256(encoded).hexdigest(),
                                           "idempotency_key": command["idempotency_key"]}
        persist()

    def response(machine_id: str, binding: dict[str, Any], command: dict[str, Any], value: Any) -> None:
        record = journal["bindings"].get(machine_id)
        if not isinstance(record, dict) or record.get("status") != "intent" or record.get("binding") != binding:
            raise RuntimeError("machine binding response has no matching durable intent")
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        record.update({"status": "api_response_received", "response_sha256": hashlib.sha256(encoded).hexdigest()})
        persist()

    def verified(machine_id: str, binding: dict[str, Any], actual: dict[str, Any]) -> None:
        record = journal["bindings"].get(machine_id)
        if record is None:
            record = {"request_sha256": None, "idempotency_key": None}
            journal["bindings"][machine_id] = record
        if not isinstance(record, dict) or record.get("binding", binding) != binding:
            raise RuntimeError("workload binding readback differs from the exact owner-local installation")
        record.update({"status": "verified", "binding": binding, "readback": actual})
        persist()

    create_workload_bindings(api, before, response, verified)
    return journal


def create_workload_principals(api: BrowserAPI, env_path: Path, cidrs: dict[str, str]) -> list[dict[str, Any]]:
    """Create or verify only the three unprivileged machine identities.

    Workload installation bindings are a separate stage because the platform
    resolves them against the currently published PolicyAsset snapshot. This
    split lets operators publish and read back policy before binding a machine.
    """
    credentials = load_or_create_machine_env(env_path)
    verified: list[dict[str, Any]] = []
    for machine in MACHINES:
        machine_id, agent_id, installation_id, prefix = machine
        installation(api, machine)
        current_profile: dict[str, Any] | None = None
        if not profile_missing(api, machine_id, "service_principal"):
            current_profile = profile(api, machine_id, "service_principal")
            strict_empty_access(current_profile, machine_id, "service_principal")
        secret = credentials[prefix + "_CLIENT_SECRET"]
        command = {
            "principal_id": machine_id,
            "scope": management_scope(BUSINESS_SCOPE),
            "network_cidrs": [cidrs[machine_id]],
            "idempotency_key": "public-example-workload-v1:" + machine_id,
            "reason": "Create one unprivileged workload principal for its matching example installation",
            "client_secret": secret,
        }
        if current_profile is None:
            print(json.dumps({"operation": "create_workload_principal", "machine_id": machine_id, "network_cidr": cidrs[machine_id], "roles": [], "resource_grants": []}, ensure_ascii=False))
            if not confirm(machine_id):
                raise RuntimeError(f"workload creation cancelled for {machine_id}")
            api.call("POST", api_path("/workload-principals"), command)
            current_profile = profile(api, machine_id, "service_principal")
            strict_empty_access(current_profile, machine_id, "service_principal")
        principal = current_profile.get("principal") if isinstance(current_profile, dict) else None
        if (not isinstance(principal, dict) or principal.get("tenant_id") != BUSINESS_SCOPE["tenant_id"]
                or type(principal.get("revision")) is not int or principal["revision"] < 1):
            raise RuntimeError(f"{machine_id} workload principal differs from its active owner tenant or has no revision")
        verified.append({"principal_id": principal["id"], "agent_id": agent_id,
                         "installation_id": installation_id, "principal_revision": principal["revision"],
                         "type": principal["type"], "is_active": principal["is_active"],
                         "binding_created": False, "roles": [], "resource_grants": []})
        print(json.dumps({"machine_id": machine_id, "agent_id": agent_id,
                          "result": "workload_principal_verified", "roles": [], "resource_grants": []}, ensure_ascii=False))
    return verified


def create_workload_bindings(api: BrowserAPI, before_binding=None, after_binding=None,
                             after_binding_verified=None) -> None:
    """Bind existing machine identities only after matching policies publish."""
    bindings = active_bindings(api)
    for machine in MACHINES:
        machine_id, agent_id, installation_id, _prefix = machine
        installed = installation(api, machine)
        if profile_missing(api, machine_id, "service_principal"):
            raise RuntimeError(f"{machine_id} workload principal must exist before installation binding")
        current_profile = profile(api, machine_id, "service_principal")
        strict_empty_access(current_profile, machine_id, "service_principal")
        active_for_machine = [value for value in bindings if value.get("principal_id") == machine_id and value.get("status") == "active"]
        if len(active_for_machine) > 1:
            raise RuntimeError(f"{machine_id} has multiple active installations; stop and review bindings")
        expected_binding = {
            **BUSINESS_SCOPE, "installation_id": installation_id, "agent_id": agent_id,
            "agent_version_id": installed.get("version_id"), "principal_id": machine_id,
        }
        active_for_installation = [value for value in bindings if value.get("installation_id") == installation_id and value.get("status") == "active"]
        if len(active_for_installation) > 1 or active_for_installation and active_for_installation[0].get("principal_id") != machine_id:
            raise RuntimeError(f"{installation_id} is already bound to a different workload principal")
        if active_for_machine and any(active_for_machine[0].get(key) != value for key, value in expected_binding.items()):
            raise RuntimeError(f"{machine_id} is already bound differently; do not rebind it in bootstrap")

        if not active_for_machine:
            binding_command = {
                "binding": expected_binding,
                "expected_revision": 0,
                "idempotency_key": "public-example-binding-v1:" + machine_id,
                "reason": "Bind the workload principal only to its matching active example installation",
                "revoke": False,
            }
            print(json.dumps({"operation": "bind_workload", "machine_id": machine_id, "installation_id": installation_id, "agent_version_id": installed.get("version_id"), "business_grants": []}, ensure_ascii=False))
            if not confirm(installation_id):
                raise RuntimeError(f"workload binding cancelled for {machine_id}")
            if before_binding is not None:
                before_binding(machine_id, expected_binding, binding_command)
            response = api.call("POST", api_path("/workload-bindings"), binding_command)
            if after_binding is not None:
                after_binding(machine_id, expected_binding, binding_command, response)

        verified = profile(api, machine_id, "service_principal")
        strict_empty_access(verified, machine_id, "service_principal")
        after = active_bindings(api)
        exact = [value for value in after if value.get("principal_id") == machine_id and value.get("status") == "active"]
        if len(exact) != 1 or any(exact[0].get(key) != value for key, value in expected_binding.items()):
            raise RuntimeError(f"{machine_id} binding did not verify as its single matching active installation")
        if after_binding_verified is not None:
            after_binding_verified(machine_id, expected_binding, exact[0])
        print(json.dumps({"machine_id": machine_id, "installation_id": installation_id, "agent_version_id": installed.get("version_id"), "result": "identity_and_binding_verified"}, ensure_ascii=False))


def create_machines(api: BrowserAPI, env_path: Path, cidrs: dict[str, str]) -> None:
    """Create and bind machines only after each matching PolicyAsset snapshot publishes."""
    verify_policy_snapshots_for_machines(api)
    create_workload_principals(api, env_path, cidrs)
    bind_machines_with_private_journal(api, env_path)
    print("Owner-private Compose credentials are saved at " + str(env_path.resolve()))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080", help="browser gateway origin; production must use HTTPS")
    parser.add_argument("--administrator", help="existing authorized administrator username; never created or promoted here")
    parser.add_argument("--prepare-machine-env", action="store_true", help="offline: create/reuse owner-private random Compose credentials without login or API calls")
    parser.add_argument("--create-organization", action="store_true", help="create only missing dept-demo/app-demo through Identity APIs")
    parser.add_argument("--create-accounts", action="store_true", help="preview/create permission.admin and three independent local demo users without roles or grants")
    parser.add_argument("--grant-demo-workspaces", action="store_true", help="explicitly preview app-demo membership for system.admin and the three demo users; membership grants no business action")
    parser.add_argument("--create-machines", action="store_true", help="create and bind unprivileged machines after all matching policies publish")
    parser.add_argument("--create-machine-principals", action="store_true", help="create only unprivileged workload identities; no installation binding")
    parser.add_argument("--bind-machines", action="store_true", help="bind existing machine identities after all six-asset policies publish")
    parser.add_argument("--agent-cidr", action="append", default=[], help="machine source CIDR as MACHINE_ID=NETWORK; repeat once per machine-creation operation")
    parser.add_argument("--machine-env-file", type=Path, default=ROOT / ".local-secrets/public-examples/machines.env", help="owner-private Compose credentials file; secrets are never printed")
    args = parser.parse_args()
    machine_operations = (args.create_machines, args.create_machine_principals, args.bind_machines)
    if sum(machine_operations) > 1:
        parser.error("choose one machine operation: create-and-bind, create-principals-only, or bind-existing")
    operations = (args.create_organization, args.create_accounts, args.grant_demo_workspaces, *machine_operations)
    if args.prepare_machine_env and (any(operations) or args.agent_cidr):
        parser.error("--prepare-machine-env is an offline-only stage and cannot be combined with API operations or CIDRs")
    if not args.prepare_machine_env and not any(operations):
        parser.error("select at least one explicit operation flag")
    if not args.prepare_machine_env and not args.administrator:
        parser.error("--administrator is required for API operations")
    if args.prepare_machine_env:
        try:
            prepare_machine_env(args.machine_env_file)
            return 0
        except (OSError, ValueError, RuntimeError) as error:
            print("Machine credential preparation stopped: " + str(error), file=sys.stderr)
            return 1
    if args.create_machines or args.create_machine_principals:
        try:
            cidrs = parse_agent_cidrs(args.agent_cidr)
        except ValueError as error:
            parser.error(str(error))
    elif args.agent_cidr:
        parser.error("--agent-cidr is valid only with --create-machines or --create-machine-principals")
    else:
        cidrs = {}
    try:
        api = BrowserAPI(args.base_url)
        password = getpass.getpass("Administrator password: ")
        if not password:
            raise ValueError("administrator password is required")
        api.login(args.administrator, password)
        api.select_workspace(ADMIN_SCOPE)
        if args.create_organization:
            ensure_organization(api)
        if args.create_accounts:
            create_accounts(api)
        if args.grant_demo_workspaces:
            for username in ("system.admin", *DEMO_USERS):
                add_membership(api, username, preserve_initial_admin=username == "system.admin")
        if args.create_machine_principals:
            api.select_workspace(BUSINESS_SCOPE)
            receipts = create_workload_principals(api, args.machine_env_file, cidrs)
            print(json.dumps({"result": "workload_principals_verified_without_bindings", "principals": receipts,
                              "business_grants": []}, ensure_ascii=False))
        if args.bind_machines:
            api.select_workspace(BUSINESS_SCOPE)
            snapshots = verify_policy_snapshots_for_machines(api)
            bindings = bind_machines_with_private_journal(api, args.machine_env_file)
            print(json.dumps({"result": "machine_bindings_verified_after_policy_publish", "policy_snapshots": snapshots,
                              "bindings": bindings, "business_grants": []}, ensure_ascii=False))
        if args.create_machines:
            api.select_workspace(BUSINESS_SCOPE)
            create_machines(api, args.machine_env_file, cidrs)
        print("Requested Identity operations finished; no business role, Agent run, capability grant, Skill, policy or approval was created.")
        return 0
    except (OSError, ValueError, RuntimeError, urllib.error.URLError) as error:
        print("Public example bootstrap stopped: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
