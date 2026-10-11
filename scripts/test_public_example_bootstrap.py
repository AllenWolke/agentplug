import contextlib
import copy
import io
import os
from pathlib import Path
import subprocess
import sys
import secrets
import unittest
from unittest import mock

import bootstrap_public_examples as bootstrap
import publish_public_policy_release as policy_release


SCOPE = {
    "tenant_id": "tenant-demo",
    "department_id": "dept-platform",
    "application_id": "app-platform-admin",
}


class PublicBootstrapTests(unittest.TestCase):
    def test_missing_or_wrong_login_principal_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "identity check"):
            bootstrap.verify_login_identity({"tenant_id": SCOPE["tenant_id"]}, "demo.user", SCOPE)
        with self.assertRaisesRegex(RuntimeError, "identity check"):
            bootstrap.verify_login_identity({"username": "other.user", **SCOPE}, "demo.user", SCOPE)
        bootstrap.verify_login_identity({"username": "demo.user", **SCOPE}, "demo.user", SCOPE)

    def test_remote_http_and_cross_origin_redirect_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            bootstrap.BrowserAPI("http://example.com")
        handler = bootstrap.RejectRedirects()
        request = mock.Mock()
        self.assertIsNone(handler.redirect_request(request, None, 302, "Found", {}, "https://other.example/"))

    def test_empty_operation_selection_never_opens_an_api_session(self):
        with mock.patch.object(sys, "argv", ["bootstrap_public_examples.py", "--administrator", "system.admin"]), \
             mock.patch.object(bootstrap, "BrowserAPI") as api, \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                bootstrap.main()
        self.assertEqual(raised.exception.code, 2)
        api.assert_not_called()

    def test_membership_preview_cannot_contain_a_role_or_resource_grant(self):
        plan = {
            "subject_id": "demo.go.user",
            "change": {"subject_id": "demo.go.user", "memberships": [{"scope": bootstrap.management_scope(bootstrap.BUSINESS_SCOPE)}]},
            "expanded_memberships": [{
                "subject_id": "demo.go.user", "scope": bootstrap.management_scope(bootstrap.BUSINESS_SCOPE), "status": "active",
            }],
            "plan_digest": "digest", "plan_expires_at": "2030-01-01T00:00:00Z",
        }
        bootstrap.validate_membership_plan(plan, "demo.go.user")
        plan["expanded_resource_grants"] = [{"action": "agent.run"}]
        with self.assertRaisesRegex(RuntimeError, "unexpected role, grant"):
            bootstrap.validate_membership_plan(plan, "demo.go.user")

    def first_admin_profile(self):
        binding_id, member_id = bootstrap.first_admin_ids()
        return {
            "principal": {"id": "system.admin", "type": "user", "tenant_id": "tenant-demo",
                          "is_active": True, "revision": 1, "roles": None, "groups": None},
            "memberships": [{"id": member_id, "subject_id": "system.admin",
                             "scope": bootstrap.management_scope(bootstrap.ADMIN_SCOPE),
                             "status": "active", "revision": 1}],
            "role_bindings": [{"id": binding_id, "subject_id": "system.admin", "role_code": "super_admin",
                               "role_version": 1, "scope": {"scope_type": "global"}, "status": "active",
                               "revision": 1, "source_id": "bootstrap:" + bootstrap.FIRST_ADMIN_APPROVAL_REFERENCE}],
            "resource_grants": [], "delegations": [], "task_assignments": [],
        }

    def test_first_admin_accepts_only_exact_existing_global_management_binding(self):
        profile = self.first_admin_profile()
        expected = copy.deepcopy(profile["role_bindings"][0])
        self.assertEqual(bootstrap.verify_initial_admin_access(profile), expected)
        profile["memberships"].append({"id": "public-demo-workspace-v1-system-admin", "subject_id": "system.admin",
                                       "scope": bootstrap.management_scope(bootstrap.BUSINESS_SCOPE), "status": "active", "revision": 1})
        self.assertEqual(bootstrap.verify_initial_admin_access(profile, allow_business_membership=True), expected)
        for mutate in (
            lambda value: value["role_bindings"].append({**value["role_bindings"][0], "id": "extra-role", "role_code": "operator"}),
            lambda value: value.update(resource_grants=[{"action": "agent.run"}]),
            lambda value: value["role_bindings"][0].update(source_id="bootstrap:other"),
            lambda value: value["role_bindings"][0].update(scope={"scope_type": "tenant", "tenant_id": "tenant-demo"}),
            lambda value: value["memberships"].append({"id": "unexpected", "subject_id": "system.admin",
                                                        "scope": bootstrap.management_scope(bootstrap.ADMIN_SCOPE), "status": "active"}),
        ):
            changed = copy.deepcopy(profile)
            mutate(changed)
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                bootstrap.verify_initial_admin_access(changed, allow_business_membership=True)

    def test_membership_update_can_preserve_first_admin_binding_without_business_grants(self):
        before = self.first_admin_profile()

        class IdentityAPI:
            def __init__(self):
                self.current = copy.deepcopy(before)
                self.methods = []

            def call(self, method, path, body=None):
                self.methods.append((method, path))
                if method == "GET" and "/access-profile?" in path:
                    return copy.deepcopy(self.current)
                if method == "POST" and path.endswith("/authorization-changes:preview"):
                    change = copy.deepcopy(body)
                    member = change["memberships"][0]
                    return {"subject_id": "system.admin", "change": change,
                            "expanded_memberships": [{"id": member["id"], "subject_id": "system.admin",
                                                      "scope": member["scope"], "status": "active"}],
                            "expanded_role_bindings": [], "expanded_resource_grants": [],
                            "expanded_task_assignments": [], "automatic_revoke_binding_ids": [],
                            "automatic_revoke_grant_ids": [], "automatic_revoke_assignment_ids": [],
                            "plan_digest": "reviewed-digest", "plan_expires_at": "2030-01-01T00:00:00Z"}
                if method == "POST" and path.endswith("/authorization-changes"):
                    member = body["memberships"][0]
                    self.current["memberships"].append({"id": member["id"], "subject_id": "system.admin",
                                                         "scope": member["scope"], "status": "active", "revision": 1})
                    self.current["principal"]["revision"] += 1
                    return {"change_id": "membership-change"}
                raise AssertionError((method, path))

        api = IdentityAPI()
        with mock.patch.object(bootstrap, "confirm", return_value=True), contextlib.redirect_stdout(io.StringIO()):
            bootstrap.add_membership(api, "system.admin", preserve_initial_admin=True)
        self.assertEqual(api.methods, [
            ("GET", bootstrap.api_path("/principals/system.admin/access-profile?principal_type=user")),
            ("POST", bootstrap.api_path("/authorization-changes:preview")),
            ("POST", bootstrap.api_path("/authorization-changes")),
            ("GET", bootstrap.api_path("/principals/system.admin/access-profile?principal_type=user")),
        ])
        self.assertEqual(api.current["role_bindings"], before["role_bindings"])
        self.assertEqual(api.current["resource_grants"], [])
        bootstrap.verify_initial_admin_access(api.current, allow_business_membership=True)

    def test_profile_normalizes_only_documented_omitted_empty_task_assignments(self):
        class ProfileAPI:
            response = {"principal": {"id": "system.admin", "type": "user", "is_active": True}}

            def call(self, method, path, body=None):
                return copy.deepcopy(self.response)

        api = ProfileAPI()
        self.assertEqual(bootstrap.profile(api, "system.admin")["task_assignments"], [])
        api.response["task_assignments"] = None
        with self.assertRaisesRegex(RuntimeError, "task-assignment profile"):
            bootstrap.profile(api, "system.admin")

    def test_machine_secret_path_must_be_git_ignored_tree(self):
        private_path = bootstrap.ROOT / ".local-secrets" / "public-examples" / "machines.env"
        bootstrap.validate_machine_env_path(private_path)
        with self.assertRaisesRegex(ValueError, "ignored .local-secrets"):
            bootstrap.validate_machine_env_path(bootstrap.ROOT / "machines.env")
        for escaped in (
            bootstrap.ROOT / ".local-secrets" / ".." / "public.env",
            bootstrap.ROOT / ".local-secrets" / "nested" / ".." / ".." / "public.env",
        ):
            with self.subTest(path=str(escaped)), self.assertRaisesRegex(ValueError, "traversal|resolves outside"):
                bootstrap.validate_machine_env_path(escaped)

    def test_machine_secret_path_rejects_a_real_reparse_parent(self):
        secret_root = bootstrap.ROOT / ".local-secrets"
        parent = secret_root / "public-examples"
        parent.mkdir(parents=True, exist_ok=True)
        target = secret_root / "reparse-target-test"
        link = parent / "reparse-link-test"
        target.mkdir(exist_ok=True)
        try:
            try:
                os.symlink(target, link, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                if os.name == "nt":
                    quote = lambda value: "'" + str(value).replace("'", "''") + "'"
                    command = "New-Item -ItemType Junction -Path {} -Target {} -ErrorAction Stop | Out-Null".format(quote(link), quote(target))
                    try:
                        subprocess.run(["powershell.exe", "-NoProfile", "-Command", command], check=True, capture_output=True, text=True)
                    except (OSError, subprocess.CalledProcessError):
                        self.skipTest(f"platform does not allow creating a directory reparse point: {type(error).__name__}")
                else:
                    self.skipTest(f"platform does not allow creating a directory reparse point: {type(error).__name__}")
            with self.assertRaisesRegex(ValueError, "junction, or reparse point"):
                bootstrap.validate_machine_env_path(link / "machines.env")
        finally:
            if bootstrap.is_reparse_point(link):
                link.rmdir()
            if target.exists():
                target.rmdir()

    def test_offline_machine_credentials_are_independent_and_never_printed(self):
        secret_root = bootstrap.ROOT / ".local-secrets"
        directory = secret_root / ("test-machine-env-" + secrets.token_hex(8))
        bootstrap.ensure_private_directory(directory)
        path = directory / "machines.env"
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                bootstrap.prepare_machine_env(path)
            credentials = bootstrap.load_or_create_machine_env(path)
            values = [credentials[machine[3] + "_CLIENT_SECRET"] for machine in bootstrap.MACHINES]
            self.assertEqual(len(set(values)), 3)
            self.assertTrue(all(len(value) >= 32 for value in values))
            self.assertTrue(all(value not in output.getvalue() for value in values))
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        finally:
            if path.exists():
                path.unlink()
            directory.rmdir()

    def test_machine_principal_stage_reuses_existing_go_identity_and_never_binds(self):
        class API:
            def __init__(self):
                self.calls = []

            def call(self, method, path, body=None):
                self.calls.append((method, path, body))
                if method == "POST" and path.endswith("/workload-principals"):
                    return {"created": True}
                raise AssertionError((method, path))

        api = API()
        profiles = {machine[0]: {"principal": {"id": machine[0], "type": "service_principal",
                                                  "is_active": True, "tenant_id": "tenant-demo", "revision": 1},
                                 "role_bindings": [], "resource_grants": []}
                    for machine in bootstrap.MACHINES}
        with mock.patch.object(bootstrap, "load_or_create_machine_env", return_value={
                machine[3] + "_CLIENT_SECRET": "s" * 40 for machine in bootstrap.MACHINES}), \
             mock.patch.object(bootstrap, "installation", return_value={"version_id": "active-v1"}), \
             mock.patch.object(bootstrap, "profile_missing", side_effect=[False, True, True]), \
             mock.patch.object(bootstrap, "profile", side_effect=lambda _api, subject, _kind: copy.deepcopy(profiles[subject])), \
             mock.patch.object(bootstrap, "confirm", return_value=True), \
             contextlib.redirect_stdout(io.StringIO()):
            bootstrap.create_workload_principals(api, Path("private-machines.env"), {
                machine[0]: "172.18.0." + str(index) + "/32"
                for index, machine in enumerate(bootstrap.MACHINES, start=4)})
        posts = [(method, path) for method, path, _body in api.calls if method == "POST"]
        self.assertEqual(len(posts), 2)
        self.assertTrue(all(path.endswith("/workload-principals") for _method, path in posts))
        self.assertFalse(any("workload-bindings" in path for _method, path, _body in api.calls))

    def test_machine_binding_journal_callbacks_bracket_single_posts_and_readback(self):
        class API:
            def __init__(self):
                self.calls = []
                self.bindings = []

            def call(self, method, path, body=None):
                self.calls.append((method, path, body))
                if method == "GET" and path.endswith("/workload-bindings?tenant_id=tenant-demo&department_id=dept-demo&application_id=app-demo"):
                    return {"items": copy.deepcopy(self.bindings)}
                if method == "POST" and path.endswith("/workload-bindings"):
                    self.bindings.append({**body["binding"], "status": "active", "revision": 1})
                    return {"accepted": True}
                raise AssertionError((method, path))

        api = API()
        events = []
        with mock.patch.object(bootstrap, "installation", side_effect=lambda _api, machine: {"version_id": "v1-" + machine[0]}), \
             mock.patch.object(bootstrap, "profile_missing", return_value=False), \
             mock.patch.object(bootstrap, "profile", side_effect=lambda _api, subject, _kind: {
                 "principal": {"id": subject, "type": "service_principal", "is_active": True},
                 "role_bindings": [], "resource_grants": []}), \
             mock.patch.object(bootstrap, "confirm", return_value=True), \
             contextlib.redirect_stdout(io.StringIO()):
            bootstrap.create_workload_bindings(
                api,
                before_binding=lambda machine, binding, command: events.append(("intent", machine, binding, command)),
                after_binding=lambda machine, _binding, _command, _response: events.append(("response", machine)),
                after_binding_verified=lambda machine, _binding, _actual: events.append(("verified", machine)))
        self.assertEqual(len([row for row in api.calls if row[0] == "POST"]), 3)
        for index, machine in enumerate(bootstrap.MACHINES):
            self.assertEqual([row[0] for row in events[index * 3:(index + 1) * 3]], ["intent", "response", "verified"])
            self.assertEqual(events[index * 3][1], machine[0])
        self.assertEqual(len(api.bindings), 3)

    def test_machine_binding_journal_prevents_blind_retry_after_unknown_write(self):
        class API:
            def __init__(self):
                self.posts = 0

            def call(self, method, path, body=None):
                if method == "GET" and path.startswith("/api/modules/identity/workload-bindings?"):
                    return {"items": []}
                if method == "POST" and path.endswith("/workload-bindings"):
                    self.posts += 1
                    raise RuntimeError("simulated HTTP 503 after request start")
                raise AssertionError((method, path))

        directory = bootstrap.ROOT / ".local-secrets" / ("test-binding-journal-" + secrets.token_hex(8))
        bootstrap.ensure_private_directory(directory)
        env_path = directory / "machines.env"
        api = API()
        try:
            with mock.patch.object(bootstrap, "installation", side_effect=lambda _api, machine: {"version_id": "v1-" + machine[0]}), \
                 mock.patch.object(bootstrap, "profile_missing", return_value=False), \
                 mock.patch.object(bootstrap, "profile", side_effect=lambda _api, subject, _kind: {
                     "principal": {"id": subject, "type": "service_principal", "is_active": True},
                     "role_bindings": [], "resource_grants": []}), \
                 mock.patch.object(bootstrap, "confirm", return_value=True), \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, "simulated HTTP 503"):
                    bootstrap.bind_machines_with_private_journal(api, env_path)
                journal_path = bootstrap.private_binding_journal_path(env_path)
                journal = bootstrap.load_machine_binding_journal(journal_path)
                self.assertEqual(journal["bindings"][bootstrap.MACHINES[0][0]]["status"], "intent")
                with self.assertRaisesRegex(RuntimeError, "unresolved prior binding intent"):
                    bootstrap.bind_machines_with_private_journal(api, env_path)
            self.assertEqual(api.posts, 1)
            self.assertEqual(set(journal["bindings"]), {bootstrap.MACHINES[0][0]})
        finally:
            journal_path = directory / "machine-bindings.json"
            if journal_path.exists():
                journal_path.unlink()
            directory.rmdir()

    def test_machine_bind_requires_published_six_asset_snapshot_at_active_version(self):
        machine = bootstrap.MACHINES[0]
        snapshot = {"Revision": 2, "Hash": "a" * 64,
                    "ModelProfileID": "model-v1", "PromptVersionID": "prompt-v1",
                    "ToolPolicyID": "tool-v1", "MemoryPolicyID": "memory-v1",
                    "KnowledgePolicyID": "knowledge-v1", "RuntimePolicyID": "runtime-v1"}

        class API:
            def __init__(self, value):
                self.value = value
                self.calls = []

            def call(self, method, path, body=None):
                self.calls.append((method, path))
                return copy.deepcopy(self.value)

        api = API(snapshot)
        with mock.patch.object(bootstrap, "installation", return_value={"version_id": "example-go-operations-v2"}):
            verified = bootstrap.verify_policy_snapshot_for_installation(api, machine)
        self.assertEqual(verified["snapshot_revision"], 2)
        self.assertEqual(len(api.calls), 1)
        self.assertIn("agent_version_id=example-go-operations-v2", api.calls[0][1])
        api.value["Revision"] = 0
        with mock.patch.object(bootstrap, "installation", return_value={"version_id": "example-go-operations-v2"}), \
             self.assertRaisesRegex(RuntimeError, "published snapshot"):
            bootstrap.verify_policy_snapshot_for_installation(api, machine)

    def test_existing_windows_acl_is_rejected_without_acl_rewrite(self):
        if os.name != "nt":
            self.skipTest("Windows ACL behavior is platform-specific")
        with mock.patch.object(bootstrap, "windows_user_identity", return_value=("test\\user", "S-1-5-21-1")), \
             mock.patch.object(bootstrap, "windows_acl_entries", return_value={"everyone"}) as inspect_acl, \
             mock.patch.object(bootstrap, "secure_windows_file") as rewrite_acl:
            with self.assertRaisesRegex(ValueError, "no ACL was changed"):
                bootstrap.verify_windows_private_file(bootstrap.ROOT / ".local-secrets" / "existing.env")
        inspect_acl.assert_called_once()
        rewrite_acl.assert_not_called()


class PublicPolicyReleaseTests(unittest.TestCase):
    def test_policy_author_must_match_prepared_author(self):
        release = {"author": "alice"}
        api = mock.Mock()
        with self.assertRaisesRegex(RuntimeError, "must match"):
            policy_release.create_drafts(api, release, "bob")
        api.call.assert_not_called()

    def test_zero_run_budget_and_missing_knowledge_binding_block_publish(self):
        release = {"assets": {
            "model": {"create_request_template": {"body": {"content": {
                "provider": "approved", "model": "chat", "model_version_id": "model-v1",
                "embedding_provider": "approved", "embedding_model": "embed", "embedding_model_version_id": "embed-v1",
                "input_micros_per_1k_tokens": 100000, "output_micros_per_1k_tokens": 100000, "budget_cents": 500,
            }}}},
            "runtime": {"create_request_template": {"body": {"content": {"run_budget": {"limit_tokens": 0, "limit_micros": 0}}}}},
            "knowledge": {"create_request_template": {"body": {"content": {"document_bindings": []}}}},
        }}
        with self.assertRaisesRegex(RuntimeError, "positive RunBudget"):
            policy_release.ensure_publishable_policy(release)
        api = mock.Mock()
        with self.assertRaisesRegex(RuntimeError, "positive RunBudget"):
            policy_release.publish_release(api, release, "publisher")
        api.call.assert_not_called()

    def test_placeholder_template_can_be_saved_as_drafts_but_publish_gate_precedes_policy_writes(self):
        scope = {
            "tenant_id": "tenant-demo", "department_id": "dept-demo", "application_id": "app-demo",
            "agent_id": "example-python-documents", "agent_version_id": "example-python-documents-v0.2.2",
        }
        assets = {}
        for asset_type in policy_release.ASSET_TYPES:
            asset_id = "example-" + asset_type + "-v1"
            content = {
                "model": {"model_version_id": "REPLACE_WITH_APPROVED_MODEL_VERSION_ID"},
                "knowledge": {"document_bindings": []},
            }.get(asset_type, {})
            assets[asset_type] = {
                "type": asset_type, "id": asset_id, "content_hash": "a" * 64,
                "create_request_template": {"body": {"id": asset_id, "type": asset_type, "scope": scope, "content": content}},
            }

        class ExistingDraftAPI:
            def __init__(self):
                self.methods = []

            def call(self, method, path, body=None):
                self.methods.append(method)
                asset = next(item for item in assets.values() if item["id"] in path)
                template = asset["create_request_template"]["body"]
                return {
                    "id": asset["id"], "type": asset["type"], "scope": scope,
                    "content_hash": asset["content_hash"], "content": template["content"],
                    "revision": 1, "status": "draft", "created_by": "alice",
                }

        api = ExistingDraftAPI()
        release = {"author": "alice", "scope": scope, "assets": assets}
        with mock.patch.object(policy_release, "ensure_publishable_policy", side_effect=AssertionError("publish-only validation ran during Draft stage")):
            policy_release.create_drafts(api, release, "alice")
        self.assertEqual(api.methods, ["GET"] * len(policy_release.ASSET_TYPES))

        api.methods.clear()
        with self.assertRaisesRegex(RuntimeError, "model_version_id"):
            policy_release.publish_release(api, {"assets": assets}, "bob")
        self.assertEqual(api.methods, [])

    def test_finite_budget_matches_approved_price_and_enforces_caps(self):
        release = {"assets": {
            "model": {"create_request_template": {"body": {"content": {
                "provider": "approved", "model": "chat", "model_version_id": "model-v1",
                "embedding_provider": "approved", "embedding_model": "embed", "embedding_model_version_id": "embed-v1",
                "input_micros_per_1k_tokens": 100000, "output_micros_per_1k_tokens": 100000,
                "budget_cents": 500,
            }}}},
            "runtime": {"create_request_template": {"body": {"content": {"run_budget": {"limit_tokens": 16000, "limit_micros": 1600000}}}}},
            "knowledge": {"create_request_template": {"body": {"content": {"document_bindings": [{"document_id": "doc-v1"}]}}}},
        }}
        policy_release.ensure_publishable_policy(release)
        budget = release["assets"]["runtime"]["create_request_template"]["body"]["content"]["run_budget"]
        model = release["assets"]["model"]["create_request_template"]["body"]["content"]
        model["budget_cents"] = 1000
        policy_release.ensure_publishable_policy(release)
        for rejected_daily in (0, -1, 1001, True):
            model["budget_cents"] = rejected_daily
            with self.assertRaisesRegex(RuntimeError, "explicit finite daily budget"):
                policy_release.ensure_publishable_policy(release)
        model["budget_cents"] = 500
        budget.update(limit_tokens=32000, limit_micros=3200000)
        policy_release.ensure_publishable_policy(release)
        budget["limit_micros"] = 3_200_001
        with self.assertRaisesRegex(RuntimeError, "reviewed 32000-token"):
            policy_release.ensure_publishable_policy(release)
        budget.update(limit_tokens=32001, limit_micros=3200000)
        with self.assertRaisesRegex(RuntimeError, "reviewed 32000-token"):
            policy_release.ensure_publishable_policy(release)

    def test_publish_requires_the_current_effective_governance_price_before_policyasset_reads(self):
        release = self.valid_price_release()
        now = policy_release.datetime(2030, 1, 2, tzinfo=policy_release.timezone.utc)
        price = {
            "id": "price-current", "model_version_id": "model-v1", "currency": "USD",
            "input_micros_per_1k_tokens": 100000, "output_micros_per_1k_tokens": 100000,
            "effective_from": "2030-01-01T00:00:00Z", "effective_until": None, "status": "approved",
        }

        class PriceAPI:
            def __init__(self, rows):
                self.rows = rows
                self.calls = []

            def call(self, method, path, body=None):
                self.calls.append((method, path, body))
                if path.startswith("/api/modules/model-governance/prices?"):
                    return {"items": self.rows}
                raise AssertionError("PolicyAsset API must not be read before live price verification")

        api = PriceAPI([{
            **price, "id": "old-price", "effective_until": "2030-01-02T00:00:00Z",
        }, {**price, "id": "future-price", "effective_from": "2030-01-03T00:00:00Z"}, price])
        self.assertEqual(policy_release.verify_policy_price(api, release, now)["id"], "price-current")
        self.assertEqual(len(api.calls), 1)
        self.assertIn("model_version_id=model-v1", api.calls[0][1])
        self.assertIn("limit=200", api.calls[0][1])

        changed = self.valid_price_release()
        changed["assets"]["model"]["create_request_template"]["body"]["content"]["input_micros_per_1k_tokens"] = 99000
        mismatch = PriceAPI([{**price, "effective_from": "2020-01-01T00:00:00Z"}])
        with self.assertRaisesRegex(RuntimeError, "differ from the current approved"):
            policy_release.publish_release(mismatch, changed, "publisher")
        self.assertEqual(len(mismatch.calls), 1)

    def test_price_read_fails_closed_when_current_version_is_missing_or_ambiguous(self):
        now = policy_release.datetime(2030, 1, 2, tzinfo=policy_release.timezone.utc)
        base = {
            "id": "price", "model_version_id": "model-v1", "currency": "USD",
            "input_micros_per_1k_tokens": 100000, "output_micros_per_1k_tokens": 100000,
            "effective_from": "2030-01-01T00:00:00Z", "effective_until": None, "status": "approved",
        }

        class PriceAPI:
            def __init__(self, rows):
                self.rows = rows

            def call(self, method, path, body=None):
                return {"items": self.rows}

        with self.assertRaisesRegex(RuntimeError, "exactly one currently effective"):
            policy_release.current_effective_price(PriceAPI([]), "model-v1", now)
        with self.assertRaisesRegex(RuntimeError, "exactly one currently effective"):
            policy_release.current_effective_price(PriceAPI([base, {**base, "id": "price-2"}]), "model-v1", now)
        with self.assertRaisesRegex(RuntimeError, "invalid PriceVersion interval"):
            policy_release.current_effective_price(PriceAPI([{**base, "effective_from": "not-a-time"}]), "model-v1", now)

    def test_price_read_fails_closed_when_api_page_may_be_truncated(self):
        class TruncatedPriceAPI:
            def __init__(self):
                self.calls = []

            def call(self, method, path, body=None):
                self.calls.append((method, path))
                return {"items": [{"id": "price-{}".format(index)} for index in range(200)]}

        api = TruncatedPriceAPI()
        with self.assertRaisesRegex(RuntimeError, "full 200-row.*pagination metadata"):
            policy_release.current_effective_price(api, "model-v1")
        self.assertEqual(len(api.calls), 1)

    @staticmethod
    def valid_price_release():
        return {"assets": {
            "model": {"create_request_template": {"body": {"content": {
                "provider": "approved", "model": "chat", "model_version_id": "model-v1",
                "embedding_provider": "approved", "embedding_model": "embed", "embedding_model_version_id": "embed-v1",
                "input_micros_per_1k_tokens": 100000, "output_micros_per_1k_tokens": 100000,
                "budget_cents": 500,
            }}}},
            "runtime": {"create_request_template": {"body": {"content": {"run_budget": {"limit_tokens": 16000, "limit_micros": 1600000}}}}},
            "knowledge": {"create_request_template": {"body": {"content": {"document_bindings": [{"document_id": "doc-v1"}]}}}},
        }}

    def test_snapshot_cas_conflict_is_submitted_once_without_retry(self):
        class ConflictAPI:
            def __init__(self):
                self.calls = 0

            def call(self, method, path, body):
                self.calls += 1
                raise bootstrap.APIError(method, path, 409, "REVISION_CONFLICT")

        api = ConflictAPI()
        with self.assertRaises(bootstrap.APIError):
            policy_release.submit_snapshot_cas(api, {"expected_revision": 7})
        self.assertEqual(api.calls, 1)


if __name__ == "__main__":
    unittest.main()
