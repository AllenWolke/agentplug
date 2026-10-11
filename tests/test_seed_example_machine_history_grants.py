import unittest
from unittest.mock import patch

from scripts.seed_example_machine_history_grants import (
    BrowserAPI,
    apply_one,
    grant_body,
    load_seed,
)


class FakeBrowserAPI:
    def __init__(self, existing_grants=None, extra_plan_field=None, bindings=None):
        self.grants = list(existing_grants or [])
        self.extra_plan_field = extra_plan_field
        self.bindings = bindings
        self.calls = []

    def call(self, method, path, body=None):
        self.calls.append((method, path, body))
        grant = load_seed()["grants"][0]
        scope = load_seed()["scope"]
        installation_id = grant["agent_instance_id"]
        if method == "GET" and "/catalog/installations/" in path:
            return {
                **scope,
                "id": installation_id,
                "agent_id": grant["agent_id"],
                "version_id": "example-version-v1",
                "status": "active",
            }
        if method == "GET" and path.startswith("/api/modules/identity/workload-bindings?"):
            return {"items": self.bindings or [{
                **scope,
                "installation_id": installation_id,
                "agent_id": grant["agent_id"],
                "agent_version_id": "example-version-v1",
                "principal_id": grant["subject_id"],
                "status": "active",
            }]}
        if method == "GET" and "/access-profile?" in path:
            return {
                "policy_mode": "v2",
                "principal": {
                    "type": "service_principal",
                    "id": grant["subject_id"],
                    "tenant_id": scope["tenant_id"],
                    "is_active": True,
                    "roles": [],
                    "revision": 2,
                },
                "resource_grants": self.grants,
            }
        if method == "POST" and path.endswith("authorization-changes:preview"):
            plan = {
                "actor_id": "permission.admin",
                "subject_id": body["subject_id"],
                "change": body,
                "plan_digest": "reviewed-plan-digest",
                "plan_expires_at": "2030-01-01T00:00:00Z",
                "expanded_resource_grants": body["resource_grants"],
                "expanded_role_bindings": [],
                "expanded_assignments": [],
                "expanded_memberships": [],
                "automatic_revoke_grant_ids": [],
                "automatic_revoke_binding_ids": [],
                "automatic_revoke_assignment_ids": [],
            }
            if self.extra_plan_field:
                plan[self.extra_plan_field] = [{"unexpected": True}]
            return plan
        if method == "POST" and path.endswith("authorization-changes"):
            self.grants.append(body["resource_grants"][0])
            return {"change_id": "change-example"}
        raise AssertionError(f"unexpected API call: {method} {path}")


class SeedExampleMachineHistoryGrantTests(unittest.TestCase):
    def test_seed_is_three_exact_machine_installation_grants(self):
        seed = load_seed()
        self.assertEqual(len(seed["grants"]), 3)
        self.assertEqual({item["action"] for item in seed["grants"]}, {"history.read"})
        self.assertEqual({item["subject_type"] for item in seed["grants"]}, {"service_principal"})
        self.assertEqual({item["data_scope"]["type"] for item in seed["grants"]}, {"approved_organization"})
        self.assertEqual(len({item["agent_instance_id"] for item in seed["grants"]}), 3)

    def test_preview_requires_exact_grant_and_commit_confirmation(self):
        seed = load_seed()
        grant = seed["grants"][0]
        api = FakeBrowserAPI()
        with patch("builtins.input", return_value=grant["agent_instance_id"]):
            result = apply_one(api, grant, seed["scope"])
        self.assertEqual(result, "committed:change-example")
        preview_index = next(i for i, call in enumerate(api.calls) if call[1].endswith("authorization-changes:preview"))
        commit_index = next(i for i, call in enumerate(api.calls) if call[1].endswith("authorization-changes"))
        self.assertLess(preview_index, commit_index)
        command = api.calls[preview_index][2]
        self.assertEqual(command["subject_type"], "service_principal")
        self.assertEqual(command["resource_grants"][0]["action"], "history.read")
        self.assertEqual(command["resource_grants"][0]["agent_instance_id"], grant["agent_instance_id"])
        self.assertNotIn("role_bindings", command)

    def test_existing_exact_grant_is_idempotent(self):
        seed = load_seed()
        grant = seed["grants"][0]
        existing = grant_body(grant, seed["scope"])
        existing["id"] = "previously-approved-id"
        existing["revision"] = 2
        api = FakeBrowserAPI([existing])
        self.assertEqual(apply_one(api, grant, seed["scope"]), "already_granted")
        self.assertFalse(any(path.endswith("authorization-changes:preview") for _, path, _ in api.calls))

    def test_only_loopback_http_is_allowed_for_password_login(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            BrowserAPI("http://example.com")

    def test_wrong_confirmation_does_not_commit(self):
        seed = load_seed()
        grant = seed["grants"][0]
        api = FakeBrowserAPI()
        with patch("builtins.input", return_value="wrong-installation"):
            self.assertEqual(apply_one(api, grant, seed["scope"]), "declined")
        self.assertFalse(any(path.endswith("authorization-changes") for _, path, _ in api.calls))

    def test_binding_to_another_installation_stops_before_preview(self):
        seed = load_seed()
        grant = seed["grants"][0]
        scope = seed["scope"]
        api = FakeBrowserAPI(bindings=[{
            **scope,
            "installation_id": "another-installation",
            "agent_id": grant["agent_id"],
            "agent_version_id": "example-version-v1",
            "principal_id": grant["subject_id"],
            "status": "active",
        }])
        with self.assertRaisesRegex(RuntimeError, "not bound only"):
            apply_one(api, grant, scope)
        self.assertFalse(any(path.endswith("authorization-changes:preview") for _, path, _ in api.calls))

    def test_unexpected_preview_change_stops_before_commit(self):
        seed = load_seed()
        grant = seed["grants"][0]
        api = FakeBrowserAPI(extra_plan_field="expanded_role_bindings")
        with patch("builtins.input", side_effect=AssertionError("unexpected confirmation prompt")):
            with self.assertRaisesRegex(RuntimeError, "unexpected role"):
                apply_one(api, grant, seed["scope"])
        self.assertFalse(any(path.endswith("authorization-changes") for _, path, _ in api.calls))


if __name__ == "__main__":
    unittest.main()
