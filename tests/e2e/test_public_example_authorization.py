"""Offline rejection and exact-preview tests; no Docker, API or credentials."""
import copy
from datetime import datetime, timedelta, timezone
import unittest

import public_example_authorization as auth

PROJECT = "agentplug-test-public-012345abcdef"
SCOPE = {"tenant_id": "tenant-demo", "department_id": "dept-demo", "application_id": "app-demo"}


def plan():
    resource = {"resource_type": "agent_installation", "resource_id": "example-go-operations-installation", "action": "run"}
    grant = {"id": "test-go-run", **SCOPE, "agent_instance_id": resource["resource_id"],
             "subject_id": "demo.go.user", "subject_type": "user", **resource,
             "effect": "allow", "status": "active", "revision": 1,
             "source_id": "explicit-tutorial", "data_scope": {"type": "owner"}}
    change = {"subject_id": "demo.go.user", "subject_type": "user", "scope": SCOPE,
              "reason": "Explicit owner-only teaching run", "resource_grants": [grant]}
    return {"schema": "public-example-authorization/v1", "owner": PROJECT,
            "allowed_resources": {resource["resource_id"]: [resource]}, "changes": [change]}


def preview(command):
    return {"actor_id": "system.admin", "subject_id": command["subject_id"], "baseline_revision": command["expected_revision"],
            "plan_digest": "a" * 64, "plan_expires_at": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            "change": copy.deepcopy(command), "expanded_resource_grants": copy.deepcopy(command["resource_grants"])}


class GrantPlanTests(unittest.TestCase):
    def test_explicit_plan_is_valid_and_not_mutated(self):
        value = plan()
        result = auth.validate_plan(value, PROJECT, SCOPE)
        self.assertEqual(result, value)
        self.assertIsNot(result, value)

    def test_production_owner_and_administrator_grant_rejected(self):
        with self.assertRaises(ValueError):
            auth.validate_plan(plan(), "agentplug", SCOPE)
        value = plan()
        value["changes"][0]["subject_id"] = "system.admin"
        with self.assertRaises(ValueError):
            auth.validate_plan(value, PROJECT, SCOPE)

    def test_role_preset_and_revoke_inputs_rejected(self):
        for key in ("role_bindings", "preset", "memberships", "revoke_grant_ids"):
            value = plan()
            value["changes"][0][key] = []
            with self.subTest(key=key), self.assertRaises(ValueError):
                auth.validate_plan(value, PROJECT, SCOPE)

    def test_foreign_installation_and_wildcard_rejected(self):
        for key, value in (("agent_instance_id", "example-java-tickets-installation"), ("resource_id", "*")):
            source = plan()
            source["changes"][0]["resource_grants"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                auth.validate_plan(source, PROJECT, SCOPE)

    def test_unreviewed_action_and_organization_history_rejected(self):
        value = plan()
        value["changes"][0]["resource_grants"][0]["action"] = "history.export"
        with self.assertRaises(ValueError):
            auth.validate_plan(value, PROJECT, SCOPE)
        value = plan()
        value["changes"][0]["resource_grants"][0]["data_scope"] = {"type": "approved_organization"}
        with self.assertRaises(ValueError):
            auth.validate_plan(value, PROJECT, SCOPE)

    def test_preview_extra_effects_or_changed_grants_rejected(self):
        command = {"subject_type": "user", "subject_id": "demo.go.user", "expected_revision": 1,
                   "reason": "Explicit grant", "idempotency_key": "one", "resource_grants": plan()["changes"][0]["resource_grants"]}
        auth.assert_preview(preview(command), command, "system.admin")
        for key in auth.EMPTY_PREVIEW_FIELDS:
            value = preview(command)
            value[key] = [{"id": "unexpected"}]
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                auth.assert_preview(value, command, "system.admin")
        value = preview(command)
        value["expanded_resource_grants"][0]["data_scope"] = {"type": "approved_organization"}
        with self.assertRaises(RuntimeError):
            auth.assert_preview(value, command, "system.admin")

    def test_no_confirmation_means_no_commit(self):
        calls = []
        class API:
            def call(self, method, path, body=None):
                calls.append((method, path))
                if "/catalog/installations/" in path:
                    return {"id": "example-go-operations-installation", "agent_id": "example-go-operations", "version_id": "v1", "status": "active", **SCOPE}
                if method == "GET":
                    return {"principal": {"id": "demo.go.user", "type": "user", "is_active": True, "tenant_id": SCOPE["tenant_id"], "revision": 1}, "resource_grants": []}
                if path.endswith(":preview"):
                    return preview(body)
                raise AssertionError("unconfirmed commit was reached")
        with self.assertRaisesRegex(RuntimeError, "not confirmed"):
            auth.apply_changes(API(), plan(), PROJECT, SCOPE, lambda _: False, lambda _: None)
        self.assertFalse(any(method == "POST" and not path.endswith(":preview") for method, path in calls))

    def test_exact_commit_and_readback_or_cas_drift(self):
        value = plan()
        class API:
            def __init__(self, drift=False):
                self.committed = False
                self.drift = drift
            def call(self, method, path, body=None):
                if "/catalog/installations/" in path:
                    return {"id": "example-go-operations-installation", "agent_id": "example-go-operations", "version_id": "v1", "status": "active", **SCOPE}
                if path.endswith(":preview"):
                    return preview(body)
                if method == "POST":
                    self.committed = True
                    return {"actor_id": "system.admin", "subject_id": "demo.go.user", "revision": 2,
                            "plan_digest": body["plan_digest"], "change_id": "change-1"}
                return {"principal": {"id": "demo.go.user", "type": "user", "is_active": True,
                                      "tenant_id": SCOPE["tenant_id"], "revision": (3 if self.drift else 2) if self.committed else 1},
                        "resource_grants": copy.deepcopy(value["changes"][0]["resource_grants"]) if self.committed else [],
                        "memberships": [], "role_bindings": [], "delegations": [], "task_assignments": []}
        records = []
        receipts = auth.apply_changes(API(), value, PROJECT, SCOPE, lambda _: True, records.append)
        self.assertEqual([row["phase"] for row in records], ["preview", "commit_started", "verified"])
        self.assertEqual(receipts[0]["revision"], 2)
        with self.assertRaisesRegex(RuntimeError, "CAS revision"):
            auth.apply_changes(API(drift=True), value, PROJECT, SCOPE, lambda _: True, lambda _: None)

    def test_machine_binding_version_mismatch_stops_before_preview(self):
        value = plan()
        change = value["changes"][0]
        change["subject_id"], change["subject_type"] = "example-go-machine", "service_principal"
        grant = change["resource_grants"][0]
        grant["subject_id"], grant["subject_type"] = change["subject_id"], change["subject_type"]
        grant["data_scope"] = {"type": "approved_organization"}
        class API:
            def call(self, method, path, body=None):
                if method != "GET":
                    raise AssertionError("mismatched binding reached a write")
                if "/catalog/installations/" in path:
                    return {"id": "example-go-operations-installation", "agent_id": "example-go-operations", "version_id": "v2", "status": "active", **SCOPE}
                if "/workload-bindings?" in path:
                    return {"items": [{"principal_id": "example-go-machine", "installation_id": "example-go-operations-installation",
                                       "agent_version_id": "v1", "status": "active", **SCOPE}]}
                raise AssertionError("mismatched binding reached principal preview preparation")
        with self.assertRaisesRegex(RuntimeError, "exact active installed version"):
            auth.apply_changes(API(), value, PROJECT, SCOPE, lambda _: True, lambda _: None)

    def test_inventory_reader_cannot_submit_identity_changes(self):
        class Inventory:
            def call(self, method, path, body=None):
                self.assert_get(method)
                if "/catalog/installations/" not in path:
                    raise AssertionError("inventory client used for a non-inventory operation")
                return {"id": "example-go-operations-installation", "agent_id": "example-go-operations", "version_id": "v1", "status": "active", **SCOPE}
            @staticmethod
            def assert_get(method):
                if method != "GET":
                    raise AssertionError("resource manager must never submit IAM changes")
        class Authorizer:
            def call(self, method, path, body=None):
                if "/catalog/" in path:
                    raise AssertionError("delegated authorizer should not require catalog.manage")
                if method == "GET":
                    return {"principal": {"id": "demo.go.user", "type": "user", "is_active": True, "tenant_id": SCOPE["tenant_id"], "revision": 1}, "resource_grants": []}
                if path.endswith(":preview"):
                    value = preview(body)
                    value["actor_id"] = "permission.admin"
                    for grants in (value["change"]["resource_grants"], value["expanded_resource_grants"]):
                        grants[0]["delegation_id"] = "approved-delegation"
                    return value
                raise AssertionError("unconfirmed IAM commit")
        with self.assertRaisesRegex(RuntimeError, "not confirmed"):
            auth.apply_changes(Authorizer(), plan(), PROJECT, SCOPE, lambda _: False, lambda _: None,
                               actor="permission.admin", resource_api=Inventory(), delegation_ids={"test-go-run": "approved-delegation"})

    def test_delegated_changes_use_manager_only_for_readonly_principal_profiles(self):
        value = plan()
        events = []
        state = {"committed": False}
        grant = value["changes"][0]["resource_grants"][0]

        class Inventory:
            def call(self, method, path, body=None):
                events.append(("manager", method, path))
                if method != "GET":
                    raise AssertionError("resource manager must remain read-only")
                if "/catalog/installations/" in path:
                    return {"id": "example-go-operations-installation", "agent_id": "example-go-operations",
                            "version_id": "v1", "status": "active", **SCOPE}
                raise AssertionError("unexpected inventory read")

        class ProfileReader:
            def call(self, method, path, body=None):
                events.append(("manager-profile", method, path))
                if method != "GET" or not path.endswith("access-profile?principal_type=user"):
                    raise AssertionError("only the manager may perform exact readonly principal-profile GETs")
                return {"principal": {"id": "demo.go.user", "type": "user", "is_active": True,
                                      "tenant_id": SCOPE["tenant_id"], "revision": 2 if state["committed"] else 1},
                        "resource_grants": [dict(grant, delegation_id="approved-delegation")] if state["committed"] else [],
                        "memberships": [], "role_bindings": [], "delegations": [], "task_assignments": []}

        class Authorizer:
            def call(self, method, path, body=None):
                events.append(("permission.admin", method, path))
                if method == "GET":
                    raise AssertionError("delegated authorizer lacks principal.read; it must not read principal profiles")
                if path.endswith(":preview"):
                    value_preview = preview(body)
                    value_preview["actor_id"] = "permission.admin"
                    for grants in (value_preview["change"]["resource_grants"],
                                   value_preview["expanded_resource_grants"]):
                        grants[0]["delegation_id"] = "approved-delegation"
                    return value_preview
                if path.endswith("authorization-changes"):
                    state["committed"] = True
                    return {"actor_id": "permission.admin", "subject_id": "demo.go.user", "revision": 2,
                            "plan_digest": body["plan_digest"], "change_id": "change-delegated"}
                raise AssertionError("unexpected authorizer path")

        receipts = auth.apply_changes(
            Authorizer(), value, PROJECT, SCOPE, lambda _: True, lambda _: None,
            actor="permission.admin", resource_api=Inventory(),
            delegation_ids={"test-go-run": "approved-delegation"}, profile_api=ProfileReader())
        self.assertEqual(receipts[0]["change_id"], "change-delegated")
        self.assertTrue(any(who == "permission.admin" and path.endswith(":preview") for who, _, path in events))
        self.assertTrue(any(who == "permission.admin" and path.endswith("authorization-changes") for who, _, path in events))
        self.assertTrue(all(who != "permission.admin" or method != "GET" for who, method, _ in events))

    def test_delegated_authorizer_without_exact_provenance_stops_before_api(self):
        class API:
            def call(self, *args):
                raise AssertionError("invalid provenance reached API")
        for mapping in ({}, {"foreign-grant": "delegate"}, {"test-go-run": "*"}):
            with self.subTest(mapping=mapping), self.assertRaises(ValueError):
                auth.apply_changes(API(), plan(), PROJECT, SCOPE, lambda _: True, lambda _: None,
                                   actor="permission.admin", delegation_ids=mapping)

    def test_preview_cannot_substitute_another_delegation(self):
        command = {"subject_type": "user", "subject_id": "demo.go.user", "expected_revision": 1,
                   "reason": "Explicit grant", "idempotency_key": "one", "resource_grants": plan()["changes"][0]["resource_grants"]}
        expected = [dict(command["resource_grants"][0], delegation_id="approved-delegation")]
        value = preview(command)
        value["actor_id"] = "permission.admin"
        for grants in (value["change"]["resource_grants"], value["expanded_resource_grants"]):
            grants[0]["delegation_id"] = "other-delegation"
        with self.assertRaisesRegex(RuntimeError, "explicit plan"):
            auth.assert_preview(value, command, "permission.admin", expected)


if __name__ == "__main__":
    unittest.main()
