from __future__ import annotations

import sys
import ast
import inspect
import json
import hashlib
from pathlib import Path
import unittest
from datetime import datetime, timedelta, timezone
import copy
import tempfile
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import public_examples_replay as replay


class PublicExamplesReplayTests(unittest.TestCase):
    def test_owner_model_reasoning_dialect_is_bound_to_verified_vendor(self):
        self.assertEqual(replay.owner_chat_reasoning_mode('https://api.deepseek.com/v1'), 'disabled')
        for endpoint in ('https://api.deepseek.com.evil.example/v1', 'http://api.deepseek.com', 'https://another.example/v1'):
            self.assertIsNone(replay.owner_chat_reasoning_mode(endpoint))

    def test_knowledge_projection_uses_only_owner_runtime_database(self):
        password = "owned-test-fixture-secret-" + "x" * 32
        self.assertEqual(replay.owner_knowledge_dsn(password),
                         "postgresql://platform_runtime:" + password + "@postgres:5432/agentplug?sslmode=disable")
        for bad in ("short", "x" * 32 + "@other-host", "x" * 32 + "\n", None):
            with self.assertRaises(ValueError):
                replay.owner_knowledge_dsn(bad)

    def test_business_plan_uses_languages_instead_of_machine_ids(self):
        versions = replay.business_versions_by_language({
            "example-go-operations": {"version": {"id": "example-go-operations-v9"}},
            "example-python-documents": {"version": {"id": "example-python-documents-v9"}},
            "example-java-tickets": {"version": {"id": "example-java-tickets-v10"}}})
        plan = replay.public_business.build_plan("agentplug-test-public-012345abcdef", replay.bootstrap.BUSINESS_SCOPE, versions)
        self.assertEqual({row["language"] for row in plan["cases"]}, {"go", "python", "java"})
        for case in plan["cases"]:
            self.assertEqual(case["agent_version_id"], versions[case["language"]])
            self.assertEqual(case["owner"], "demo." + case["language"] + ".user")
        owner = {"business_replay_plan": {"path": "business.json", "plan_sha256": replay.public_business.digest(plan)},
                 "catalog_lifecycle": {row["agent_id"]: {"release": {"version_id": row["agent_version_id"]}}
                                       for row in plan["cases"]}}
        with mock.patch.object(replay, "private_plan_file", return_value=(plan, "business.json")):
            self.assertEqual(replay.load_business_plan("agentplug-test-public-012345abcdef", Path("unused"), owner), (plan, "business.json"))

    def test_owner_subnet_selection_avoids_existing_networks(self):
        subnet = replay.select_owner_network_subnet(["172.29.16.0/24", "192.168.0.0/16", "fd00::/64"])
        self.assertEqual(subnet, "172.29.17.0/28")
        with self.assertRaisesRegex(RuntimeError, "no isolated owner subnet"):
            replay.select_owner_network_subnet(["172.29.0.0/16"])

    def test_owner_network_has_explicit_ipam_for_fixed_sdk_addresses(self):
        replies = [SimpleNamespace(stdout=b"network-id\n"),
                   SimpleNamespace(stdout=json.dumps([{"IPAM": {"Config": [{"Subnet": "172.29.16.0/28"}]}}]).encode())]
        with mock.patch.object(replay.subprocess, "run", side_effect=replies):
            value = replay.owner_network_overlay("agentplug-test-public-012345abcdef")
        self.assertEqual(value["networks"]["default"], {
            "name": "agentplug-test-public-012345abcdef_default",
            "ipam": {"config": [{"subnet": "172.29.17.0/28"}]}})

    def test_runtime_start_preserves_the_existing_platform_artifact(self):
        project = "agentplug-test-public-012345abcdef"
        directory = Path("isolated-owner")
        owner = {"runtime_prepared": True, "runtime_process_started": False}
        calls = []

        def invoke(command, **kwargs):
            calls.append(command)
            output = b"platform-app\ncode-runtime\n" if "ps" in command else b""
            return SimpleNamespace(returncode=0, stdout=output, stderr=b"")

        with mock.patch.object(replay, "read_manifest", return_value=(directory, owner, {})), \
                mock.patch.object(replay.bootstrap, "verify_private_file"), \
                mock.patch.object(replay, "compose_prefix", return_value=["docker", "compose"]), \
                mock.patch.object(replay, "isolated_compose_environment", return_value={}), \
                mock.patch.object(replay.subprocess, "run", side_effect=invoke), \
                mock.patch.object(replay, "write_json_private") as write_owner:
            replay.runtime_start_phase(project, project)

        self.assertEqual([call for call in calls if "build" in call],
                         [["docker", "compose", "build", "code-runtime"]])
        start = next(call for call in calls if "up" in call)
        self.assertIn("--no-build", start)
        self.assertEqual(start[-2:], ["platform-app", "code-runtime"])
        self.assertTrue(owner["runtime_process_started"])
        write_owner.assert_called_once_with(directory / "owner.json", owner)

    def test_model_access_create_readback_allows_database_timestamp_precision_only(self):
        expected = {"principal_id": "demo.go.user", "installation_id": "go-installation",
                    "agent_version_id": "go-v1", "allow_external": True}
        created = {**expected, "id": "policy-1", "status": "draft", "revision": 1,
                   "created_at": "2026-10-05T20:31:14.219564274Z",
                   "updated_at": "2026-10-05T20:31:14.219564274Z"}
        readback = {**expected, "id": "policy-1", "status": "draft", "revision": 1,
                    "created_at": "2026-10-05T20:31:14.219564Z",
                    "updated_at": "2026-10-05T20:31:14.219564Z"}
        self.assertTrue(replay.model_access_policy_create_readback_matches(created, readback, expected))
        readback["allow_external"] = False
        self.assertFalse(replay.model_access_policy_create_readback_matches(created, readback, expected))
        readback["allow_external"] = True
        readback["created_at"] = "2026-10-05T20:31:14.219565Z"
        self.assertFalse(replay.model_access_policy_create_readback_matches(created, readback, expected))

    def test_policy_plan_asset_content_uses_the_public_cli_descriptor_shape(self):
        expected = {"allowed_scopes": ["knowledge-example-go"]}
        release = {"assets": {"knowledge": {
            "create_request_template": {"body": {"content": expected}},
        }}}
        self.assertEqual(replay.policy_plan_asset_content(release, "knowledge"), expected)
        with self.assertRaisesRegex(RuntimeError, "create_request_template.body.content"):
            replay.policy_plan_asset_content({"assets": {"knowledge": {"content": expected}}}, "knowledge")

    def test_offline_policy_input_can_only_resume_from_an_identical_private_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "owner"
            directory.mkdir()
            path = directory / "policy-input-go.json"
            expected = {"schema": "policy-input/v1", "budget": {"tokens": 16000}}

            def write_private(target, content):
                target.write_text(content, encoding="utf-8")

            def verify_private(target):
                if target.is_symlink() or not target.is_file():
                    raise ValueError("not a regular file")

            with mock.patch.object(replay.bootstrap, "ensure_private_directory"), \
                    mock.patch.object(replay.bootstrap, "write_new_private_file", side_effect=write_private), \
                    mock.patch.object(replay.bootstrap, "verify_private_file", side_effect=verify_private):
                self.assertEqual(replay.write_or_reuse_exact_private_json(directory, path, expected), path)
                before = path.read_bytes()
                self.assertEqual(replay.write_or_reuse_exact_private_json(directory, path, expected), path)
                self.assertEqual(path.read_bytes(), before)
                with self.assertRaisesRegex(RuntimeError, "different plan"):
                    replay.write_or_reuse_exact_private_json(directory, path, {**expected, "budget": {"tokens": 1}})
                self.assertEqual(json.loads(path.read_text(encoding="utf-8")), expected)

    def test_catalog_submit_uses_global_admin_for_reads_and_the_author_only_for_posts(self):
        agent_id = "example-go-operations"
        author = "demo.go.user"
        definition_id = agent_id + "-definition"
        version_id = agent_id + "-v1"
        definition = {"id": definition_id, "publisher_id": author, "status": "draft", "revision": 1}
        version = {"id": version_id, "definition_id": definition_id, "status": "draft", "revision": 1,
                   "artifact_digest": "sha256:" + "a" * 64, "manifest": {"agent_id": agent_id}}
        scope = replay.bootstrap.BUSINESS_SCOPE
        requests = [
            {"stage": "submit", "method": "POST", "path": "/api/modules/catalog/definitions?tenant_id=tenant-demo",
             "body": copy.deepcopy(definition)},
            {"stage": "submit", "method": "POST", "path": "/api/modules/catalog/definitions/" + definition_id + "/versions?tenant_id=tenant-demo",
             "body": copy.deepcopy(version)},
        ]
        plan = {"agent_id": agent_id, "definition": definition, "version": version, "requests": requests}
        live = {}
        events = []

        class FakeAPI:
            def __init__(self, principal):
                self.principal = principal

            def call(self, method, path, body=None):
                events.append((self.principal, method, path.split("?", 1)[0]))
                canonical_path = path.split("?", 1)[0]
                if method == "GET":
                    if self.principal != "system.admin":
                        raise AssertionError("scoped Catalog author must not perform global GET")
                    if canonical_path not in live:
                        raise replay.bootstrap.APIError("GET", canonical_path, 404, "RESOURCE_NOT_FOUND")
                    return copy.deepcopy(live[canonical_path])
                if method == "POST" and self.principal == author and isinstance(body, dict):
                    if canonical_path.endswith("/versions"):
                        resource_path = "/api/modules/catalog/versions/" + body["id"]
                    elif canonical_path == "/api/modules/catalog/definitions":
                        resource_path = canonical_path + "/" + body["id"]
                    else:
                        resource_path = canonical_path
                    stored = copy.deepcopy(body)
                    stored["submitted_by"] = author
                    live[resource_path] = stored
                    return copy.deepcopy(stored)
                raise AssertionError("Catalog writes must remain author-bound POSTs")

        apis = {author: FakeAPI(author), "system.admin": FakeAPI("system.admin")}
        with mock.patch.object(replay, "require_temporary_author_role"), \
                mock.patch.object(replay, "owner_human_api", side_effect=lambda _p, _d, user, _s: apis[user]), \
                mock.patch.object(replay, "save_catalog_receipt"):
            replay.catalog_submit_phase("agentplug-test-public-012345abcdef", Path("."), plan, author, version_id)

        self.assertEqual([(principal, method) for principal, method, _path in events], [
            ("system.admin", "GET"), ("system.admin", "GET"),
            (author, "POST"), ("system.admin", "GET"),
            (author, "POST"), ("system.admin", "GET"),
        ])
        self.assertEqual(live["/api/modules/catalog/definitions/" + definition_id]["submitted_by"], author)
        self.assertEqual(live["/api/modules/catalog/versions/" + version_id]["submitted_by"], author)

    def _catalog_author_receipt_fixture(self):
        agent_id = "example-go-operations"
        author = "demo.go.user"
        definition_id, version_id = agent_id + "-definition", agent_id + "-v7"
        installation_id, deployment_id = agent_id + "-installation", agent_id + "-deployment"
        artifact_digest = "sha256:" + "a" * 64
        manifest_hash = "sha256:" + "b" * 64
        skill = {"skill_id": "example.operations.guidance", "version_id": "7.0.0",
                 "bundle_digest": "c" * 64}
        plan = {"agent_id": agent_id,
                "definition": {"id": definition_id, "publisher_id": author},
                "version": {"id": version_id, "definition_id": definition_id,
                            "semantic_version": "0.2.4", "artifact_digest": artifact_digest,
                            "manifest": {"agent_id": agent_id, "version": "0.2.4"}},
                "installation": {"id": installation_id}, "deployment": {"id": deployment_id},
                "bundle": {"manifest_hash": manifest_hash, "skill_publications": [skill]}}
        release_pin = {"agent_id": agent_id, "definition_id": definition_id,
                       "version_id": version_id, "installation_id": installation_id,
                       "deployment_id": deployment_id, "artifact_digest": artifact_digest,
                       "manifest_hash": manifest_hash}
        owner = {"catalog_lifecycle": {agent_id: {
                    "author": author, "evaluator": "system.admin", "approver": "system.admin",
                    "active_installation": "system.admin", "release": release_pin}},
                 "policy_lifecycle": {agent_id: {"published": True, "author": author,
                                                  "publisher": "system.admin", "version_id": version_id,
                                                  "installation_id": installation_id}},
                 "skill_lifecycle": {agent_id: {skill["skill_id"] + "/" + skill["version_id"]: {
                     "author": author, "reviewer": "system.admin", "publisher": "system.admin",
                     "release": {"bundle_digest": skill["bundle_digest"]}}}}}
        live = {
            "/api/modules/catalog/definitions/" + definition_id: {
                "id": definition_id, "publisher_id": author, "submitted_by": author,
                "status": "published", "approved_by": "system.admin", "revision": 3},
            "/api/modules/catalog/versions/" + version_id: {
                **copy.deepcopy(plan["version"]), "submitted_by": author,
                "status": "published", "approved_by": "system.admin", "revision": 4},
        }
        return plan, owner, author, live

    def test_knowledge_index_author_is_verified_from_bundle_owner_receipts_and_live_catalog(self):
        plan, owner, author, live = self._catalog_author_receipt_fixture()
        calls = []

        class FakeAPI:
            def call(self, method, path, body=None):
                calls.append((method, path))
                if method != "GET" or path not in live:
                    raise AssertionError("Catalog author verification must use only exact public GETs")
                return copy.deepcopy(live[path])

        self.assertEqual(replay.verify_catalog_release_author(FakeAPI(), owner, plan, author), author)
        self.assertEqual(calls, [
            ("GET", "/api/modules/catalog/definitions/" + plan["definition"]["id"]),
            ("GET", "/api/modules/catalog/versions/" + plan["version"]["id"]),
        ])

    def test_knowledge_index_author_rejects_owner_or_actual_version_author_mismatch(self):
        for mismatch in ("definition-author", "catalog-receipt", "policy-receipt",
                         "skill-receipt", "live-version-submitter", "live-definition-submitter"):
            with self.subTest(mismatch=mismatch):
                plan, owner, author, live = self._catalog_author_receipt_fixture()
                if mismatch == "definition-author":
                    plan["definition"]["publisher_id"] = "demo.python.user"
                elif mismatch == "catalog-receipt":
                    owner["catalog_lifecycle"][plan["agent_id"]]["author"] = "demo.python.user"
                elif mismatch == "policy-receipt":
                    owner["policy_lifecycle"][plan["agent_id"]]["author"] = "demo.python.user"
                elif mismatch == "skill-receipt":
                    row = next(iter(owner["skill_lifecycle"][plan["agent_id"]].values()))
                    row["author"] = "demo.python.user"
                elif mismatch == "live-version-submitter":
                    live["/api/modules/catalog/versions/" + plan["version"]["id"]]["submitted_by"] = "demo.python.user"
                else:
                    live["/api/modules/catalog/definitions/" + plan["definition"]["id"]]["submitted_by"] = "demo.python.user"

                class FakeAPI:
                    def call(self, method, path, body=None):
                        if method != "GET" or path not in live:
                            raise AssertionError("Catalog author verification must use only exact public GETs")
                        return copy.deepcopy(live[path])

                with self.assertRaises(RuntimeError):
                    replay.verify_catalog_release_author(FakeAPI(), owner, plan, author)

    def test_catalog_deployment_list_accepts_only_explicit_null_as_an_empty_list(self):
        self.assertEqual(replay.catalog_deployment_items({"items": None}), [])
        self.assertEqual(replay.catalog_deployment_items({"items": []}), [])
        for malformed in (None, {}, {"items": ""}, {"items": [None]}, {"items": [{}] * 100}):
            with self.subTest(response=type(malformed).__name__), self.assertRaises(RuntimeError):
                replay.catalog_deployment_items(malformed)

    def test_catalog_deploy_posts_once_after_null_empty_list_and_stops_on_invalid_list_dto(self):
        installation_id = "example-go-operations-installation"
        deployment = {
            "id": "public-go-deployment-test", "tenant_id": "tenant-demo", "department_id": "dept-demo",
            "application_id": "app-demo", "agent_installation_id": installation_id,
            "agent_version_id": "example-go-operations-v1", "artifact_digest": "sha256:" + "a" * 64,
            "endpoint_ref": "http://example-go:8080", "manifest_hash": "b" * 64,
            "desired_revision": 1, "status": "pending",
        }
        plan = {"installation": {"id": installation_id}, "deployment": deployment}

        class FakeAPI:
            def __init__(self, first_response):
                self.first_response = first_response
                self.list_reads = 0
                self.calls = []

            def call(self, method, path, body=None):
                self.calls.append((method, path, body))
                if method == "GET" and path.endswith(installation_id):
                    return {"id": installation_id, "status": "provisioning"}
                if method == "GET" and path.endswith("/deployments?limit=100"):
                    self.list_reads += 1
                    if self.list_reads == 1:
                        return copy.deepcopy(self.first_response)
                    return {"items": [copy.deepcopy(deployment)]}
                if method == "POST" and path.endswith("/deployments"):
                    return copy.deepcopy(body)
                raise AssertionError("unexpected Catalog deployment API request")

        api = FakeAPI({"items": None})
        with mock.patch.object(replay, "verify_example_container_health"), \
                mock.patch.object(replay, "owner_human_api", return_value=api):
            replay.catalog_deploy_phase("agentplug-test-public-012345abcdef", Path("."), plan,
                                        "system.admin", deployment["id"])
        self.assertEqual(sum(method == "POST" for method, _path, _body in api.calls), 1)

        invalid_api = FakeAPI({})
        with mock.patch.object(replay, "verify_example_container_health"), \
                mock.patch.object(replay, "owner_human_api", return_value=invalid_api):
            with self.assertRaisesRegex(RuntimeError, "deployment list response is invalid"):
                replay.catalog_deploy_phase("agentplug-test-public-012345abcdef", Path("."), plan,
                                            "system.admin", deployment["id"])
        self.assertFalse(any(method == "POST" for method, _path, _body in invalid_api.calls))

    def test_owner_human_api_reuses_memory_session_and_verifies_identity_each_time(self):
        project = "agentplug-test-public-012345abcdef"
        scope = dict(replay.bootstrap.BUSINESS_SCOPE)
        owner = {"ports": {"FRONTEND_HOST_PORT": 19080}}
        passwords = {username: "not-a-real-password" for username in replay.HUMANS}

        class FakeAPI:
            def __init__(self, origin):
                self.origin = origin
                self.logins = []
                self.workspaces = []
                self.calls = []
                self.scope = {}

            def login(self, username, password):
                self.logins.append((username, password))

            def select_workspace(self, selected):
                self.workspaces.append(copy.deepcopy(selected))
                self.scope = copy.deepcopy(selected)

            def call(self, method, path, body=None):
                self.calls.append((method, path))
                if (method, path) == ("GET", "/auth/me"):
                    return {"username": replay.bootstrap.DEMO_USERS[0], **self.scope}
                raise AssertionError("unexpected refresh request for a non-expiring session")

        sessions = []
        with mock.patch.object(replay, "read_manifest", return_value=(Path("."), owner, passwords)), \
                mock.patch.object(replay.bootstrap, "BrowserAPI", side_effect=lambda origin: sessions.append(FakeAPI(origin)) or sessions[-1]), \
                mock.patch.object(replay, "owner_session_cookie_expiry", return_value=None):
            first = replay.owner_human_api(project, Path("."), replay.bootstrap.DEMO_USERS[0], scope)
            second = replay.owner_human_api(project, Path("."), replay.bootstrap.DEMO_USERS[0], scope)
            other_scope = {**scope, "application_id": "app-other"}
            third = replay.owner_human_api(project, Path("."), replay.bootstrap.DEMO_USERS[0], other_scope)

        self.assertIs(first, second)
        self.assertIsNot(first, third)
        self.assertEqual(len(sessions), 2)
        self.assertEqual([session.logins[0][0] for session in sessions], [replay.bootstrap.DEMO_USERS[0]] * 2)
        self.assertEqual(len(sessions[0].calls), 2)
        self.assertEqual(len(sessions[0].workspaces), 1)

    def test_owner_human_api_refreshes_only_known_expiry_and_never_relogs_invalid_cache(self):
        project = "agentplug-test-public-012345abcdef"
        username = replay.bootstrap.DEMO_USERS[0]
        scope = dict(replay.bootstrap.BUSINESS_SCOPE)
        owner = {"ports": {"FRONTEND_HOST_PORT": 19081}}
        passwords = {name: "not-a-real-password" for name in replay.HUMANS}

        class FakeAPI:
            def __init__(self, origin):
                self.origin = origin
                self.login_count = 0
                self.refresh_count = 0
                self.identity_denied = False
                self.scope = {}

            def login(self, _username, _password):
                self.login_count += 1

            def select_workspace(self, selected):
                self.scope = copy.deepcopy(selected)

            def call(self, method, path, body=None):
                if (method, path) == ("POST", "/auth/refresh"):
                    self.refresh_count += 1
                elif (method, path) == ("GET", "/auth/me") and self.identity_denied:
                    raise replay.bootstrap.APIError("GET", path, 401, "API_ERROR")
                elif (method, path) != ("GET", "/auth/me"):
                    raise AssertionError("unexpected owner session API request")
                return {"username": username, **self.scope}

        sessions = []
        expiry = iter((900, 2000))
        with mock.patch.object(replay, "read_manifest", return_value=(Path("."), owner, passwords)), \
                mock.patch.object(replay.bootstrap, "BrowserAPI", side_effect=lambda origin: sessions.append(FakeAPI(origin)) or sessions[-1]), \
                mock.patch.object(replay, "owner_session_cookie_expiry", side_effect=lambda _api, _name: next(expiry)), \
                mock.patch.object(replay.time, "time", return_value=1000):
            cached = replay.owner_human_api(project, Path("."), username, scope)
            reused = replay.owner_human_api(project, Path("."), username, scope)
            self.assertIs(cached, reused)
            self.assertEqual(cached.refresh_count, 1)
            self.assertEqual(cached.login_count, 1)
            cached.identity_denied = True
            with self.assertRaisesRegex(RuntimeError, "no password login was retried"):
                replay.owner_human_api(project, Path("."), username, scope)
            with self.assertRaisesRegex(RuntimeError, "cached owner browser session is invalid"):
                replay.owner_human_api(project, Path("."), username, scope)
            self.assertEqual(cached.login_count, 1)

    def test_java_evaluation_builds_repository_sdk_source_and_handles_windows_mvn_cmd(self):
        executable = r"C:\Program Files\Apache Maven\bin\mvn.cmd"
        invocation = replay.java_maven_invocation(executable, ["--batch-mode", "-f", "sdk/java/pom.xml"], windows=True)
        self.assertTrue(invocation[0].lower().endswith("cmd.exe"))
        self.assertEqual(invocation[1:3], ["/d", "/c"])
        self.assertIn('"' + executable + '"', invocation[3])
        self.assertIn("sdk/java/pom.xml", invocation[3])

        completed = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        with mock.patch.object(replay.shutil, "which", side_effect=[executable]), \
                mock.patch.object(replay.subprocess, "run", side_effect=[completed, completed, completed]) as run:
            evidence = replay.run_java_catalog_source_tests("example-java-tickets-v7")
        self.assertEqual(evidence["runner"], "repository-maven-reactor")
        self.assertEqual(run.call_count, 3)
        first_command = run.call_args_list[0].args[0]
        self.assertTrue(first_command[0].lower().endswith("cmd.exe"))
        self.assertEqual(first_command[1:3], ["/d", "/c"])
        self.assertIn("-f", first_command[3])
        self.assertIn("sdk/java/pom.xml", first_command[3])
        self.assertIn("-Dmaven.repo.local=", first_command[3])

    def test_java_evaluation_fallback_requires_full_no_skip_evidence(self):
        suites = [
            {"name": "generated.CapabilityFixtureTest", "tests": 2, "failures": 0, "errors": 0, "skipped": 0},
            {"name": "generated.ExecutionBoundaryTest", "tests": 3, "failures": 0, "errors": 0, "skipped": 0},
            {"name": "generated.VendoredSdkSyncTest", "tests": 1, "failures": 0, "errors": 0, "skipped": 0},
            {"name": "generated.WorkflowTest", "tests": 3, "failures": 0, "errors": 0, "skipped": 0},
            {"name": "generated.CapabilityFixtureTest", "tests": 2, "failures": 0, "errors": 0, "skipped": 0},
            {"name": "generated.ExecutionBoundaryTest", "tests": 3, "failures": 0, "errors": 0, "skipped": 0},
            {"name": "generated.VendoredSdkSyncTest", "tests": 1, "failures": 0, "errors": 0, "skipped": 0},
            {"name": "com.lexagent.sdk.spring.CapabilityVerifierInterceptorTest", "tests": 3, "failures": 0, "errors": 0, "skipped": 0},
            {"name": "com.lexagent.sdk.spring.ExecutionServerAutoConfigurationTest", "tests": 3, "failures": 0, "errors": 0, "skipped": 0},
            {"name": "com.lexagent.sdk.CapabilityClientTest", "tests": 5, "failures": 0, "errors": 0, "skipped": 0},
            {"name": "com.lexagent.sdk.DeclaredManifestTest", "tests": 2, "failures": 0, "errors": 0, "skipped": 0},
            {"name": "com.lexagent.sdk.ExecutionContractFixtureTest", "tests": 4, "failures": 0, "errors": 0, "skipped": 0},
            {"name": "com.lexagent.sdk.ExecutionServerTest", "tests": 12, "failures": 0, "errors": 0, "skipped": 0},
            {"name": "com.lexagent.sdk.ExecutionTrackerTest", "tests": 2, "failures": 0, "errors": 0, "skipped": 0},
            {"name": "com.lexagent.sdk.HarnessRunnerTest", "tests": 13, "failures": 0, "errors": 0, "skipped": 0},
            {"name": "com.lexagent.sdk.MemoryRunStoreTest", "tests": 5, "failures": 0, "errors": 0, "skipped": 0},
            {"name": "com.lexagent.examples.tickets.TicketAssistantTest", "tests": 5, "failures": 0, "errors": 0, "skipped": 0},
            {"name": "com.lexagent.examples.tickets.TicketTransportTest", "tests": 1, "failures": 0, "errors": 0, "skipped": 0},
        ]
        passed = {"owner": "java-ticket-" + "a" * 32, "result": "PASS", "batch_id": "", "full_sdk_reactor": True,
                  "tests_passed": True, "command_exit_codes": [0, 0, 0], "source_workspace_sha256": "b" * 64,
                  "suites": suites, "test_totals": {"tests": 70, "failures": 0, "errors": 0, "skipped": 0},
                  "example_jar_built": True, "runtime_sdk_dependency_present": True,
                  "temporary_workspace_removed": True, "cleanup_errors": [], "external_provider_calls": 0,
                  "development_database_changed": False}

        def verifier_result(command, **_kwargs):
            receipt = dict(passed, batch_id=command[-1])
            return SimpleNamespace(returncode=0, stdout=json.dumps(receipt).encode("utf-8"), stderr=b"")

        with mock.patch.object(replay.shutil, "which", return_value=None), \
                mock.patch.object(replay.subprocess, "run", side_effect=verifier_result) as run:
            evidence = replay.run_java_catalog_source_tests("example-java-tickets-v7")
        self.assertEqual(evidence["test_count"], 70)
        self.assertEqual(evidence["skipped"], 0)
        self.assertEqual(evidence["suite_count"], 18)
        self.assertRegex(evidence["source_workspace_sha256"], r"\A[a-f0-9]{64}\Z")
        command = run.call_args.args[0]
        self.assertTrue(command[1].endswith("verify_java_ticket_example.py"))
        self.assertEqual(command[2:4], ["--full-reactor", "--batch-id"])
        skipped_receipt = dict(passed, test_totals={"tests": 70, "failures": 0, "errors": 0, "skipped": 1})
        with mock.patch.object(replay.shutil, "which", return_value=None), \
                mock.patch.object(replay.subprocess, "run", return_value=SimpleNamespace(
                    returncode=0, stdout=json.dumps(skipped_receipt).encode("utf-8"), stderr=b"")):
            with self.assertRaisesRegex(RuntimeError, "full repository reactor verification failed"):
                replay.run_java_catalog_source_tests("example-java-tickets-v7")
        stale_batch = dict(passed, batch_id="old-batch")
        with mock.patch.object(replay.shutil, "which", return_value=None), \
                mock.patch.object(replay.subprocess, "run", return_value=SimpleNamespace(
                    returncode=0, stdout=json.dumps(stale_batch).encode("utf-8"), stderr=b"")):
            with self.assertRaisesRegex(RuntimeError, "full repository reactor verification failed"):
                replay.run_java_catalog_source_tests("example-java-tickets-v7")

    def test_python_catalog_gate_runs_current_pytest_suite_with_repository_sdk(self):
        completed = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        with mock.patch.object(replay.subprocess, "run", return_value=completed) as run:
            replay.run_example_source_tests("example-python-documents", "example-python-documents-v4")
        command = run.call_args.args[0]
        options = run.call_args.kwargs
        self.assertEqual(command[1:6], ["-m", "pytest", "-p", "no:cacheprovider", "--import-mode=importlib"])
        self.assertNotIn("unittest", command)
        self.assertEqual(options["cwd"], replay.ROOT / "examples" / "python-documents")
        python_path = options["env"]["PYTHONPATH"].split(replay.os.pathsep)
        self.assertEqual(python_path, [str(replay.ROOT / relative) for relative in (
            "sdk/python", ".cache/sdk-postgres", "examples/python-documents")])
        self.assertEqual(options["env"]["PYTHONDONTWRITEBYTECODE"], "1")
        with mock.patch.object(replay.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout=b"", stderr=b"")):
            with self.assertRaisesRegex(RuntimeError, "current public example source tests failed"):
                replay.run_example_source_tests("example-python-documents", "example-python-documents-v4")

    def test_identity_reconcile_is_owner_safe_and_never_restarts_or_recreates_identities(self):
        source = inspect.getsource(replay.identity_reconcile_phase)
        tree = ast.parse(source)
        called = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertFalse(called & {"start_isolated_base", "initialize_first_admin", "create_accounts", "ensure_organization"})
        self.assertIn("reconcile_identity_membership", called)

    def test_identity_membership_cas_preserves_every_existing_access_fact_and_advances_once(self):
        username = "demo.go.user"
        before = {"principal": {"id": username, "type": "user", "tenant_id": "tenant-demo",
                                "is_active": True, "revision": 7, "roles": [], "groups": []},
                  "memberships": [{"id": "initial-membership", "subject_id": username,
                                   "scope": replay.bootstrap.management_scope(replay.bootstrap.ADMIN_SCOPE),
                                   "status": "active", "revision": 1}],
                  "role_bindings": [], "resource_grants": [], "task_assignments": [], "delegations": []}
        baseline = replay.identity_membership_facts(before)
        after = copy.deepcopy(before)
        after["principal"]["revision"] = 8
        after["memberships"].append({"id": "public-demo-workspace-v1-demo-go-user", "subject_id": username,
                                      "scope": replay.bootstrap.management_scope(replay.bootstrap.BUSINESS_SCOPE),
                                      "status": "active", "revision": 1,
                                      "source_id": "membership:public-demo-workspace-v1:demo.go.user"})
        added = replay.verify_identity_membership_delta(baseline, after, username)
        self.assertEqual(added["id"], "public-demo-workspace-v1-demo-go-user")
        changed = copy.deepcopy(after)
        changed["principal"]["revision"] = 9
        with self.assertRaisesRegex(RuntimeError, "advance the principal revision exactly once"):
            replay.verify_identity_membership_delta(baseline, changed, username)
        changed = copy.deepcopy(after)
        changed["memberships"][0]["revision"] = 2
        with self.assertRaisesRegex(RuntimeError, "modified or replaced an existing membership"):
            replay.verify_identity_membership_delta(baseline, changed, username)

    def test_identity_preview_comparison_accepts_only_the_go_zero_time_dto_field(self):
        command = replay.identity_membership_command("system.admin", 1)
        plan = {"actor_id": "system.admin", "subject_id": "system.admin", "baseline_revision": 1,
                "change": {**copy.deepcopy(command), "plan_expires_at": "0001-01-01T00:00:00Z"}}
        replay.verify_identity_membership_preview_change(plan, command, "system.admin", 1)
        changed = copy.deepcopy(plan)
        changed["change"]["plan_expires_at"] = "2030-01-01T00:00:00Z"
        with self.assertRaisesRegex(RuntimeError, "unexpected change expiration"):
            replay.verify_identity_membership_preview_change(changed, command, "system.admin", 1)
        changed = copy.deepcopy(plan)
        changed["change"]["reason"] = "unreviewed permission mutation"
        with self.assertRaisesRegex(RuntimeError, "differs from the exact"):
            replay.verify_identity_membership_preview_change(changed, command, "system.admin", 1)

    def test_minimum_authorization_plan_covers_six_subjects_with_owner_bound_capabilities(self):
        project = "agentplug-test-public-012345abcdef"
        now = datetime.now(timezone.utc).replace(microsecond=0)
        policies = {}
        for _machine, agent_id, installation, _prefix in replay.bootstrap.MACHINES:
            snapshot = {"ModelProfileID": agent_id + "-model", "MemoryPolicyID": agent_id + "-memory"}
            assets = {
                "tool": {"content": {"allowed_tools": ["runtime.inspect"]}},
                "knowledge": {"content": {"allowed_scopes": [agent_id + "-knowledge"],
                                              "document_bindings": [{"knowledge_scope": agent_id + "-knowledge",
                                                                     "provider_document_id": agent_id + "-doc",
                                                                     "document_version": "v1", "status": "active"}]}},
                "runtime": {"content": {"allowed_skills": [agent_id + ".guidance"]}},
            }
            policies[agent_id] = (snapshot, assets, {"installation_id": installation})
        expiry = replay.iso_utc(now + timedelta(hours=2))
        plan = replay.build_minimum_authorization_plan(project, policies, expiry, now)
        reviewed = replay.example_authorization.validate_plan(plan, project, replay.bootstrap.BUSINESS_SCOPE)
        self.assertEqual(len(reviewed["changes"]), 6)
        self.assertEqual(sum(len(row["resource_grants"]) for row in reviewed["changes"]), 57)
        by_subject = {row["subject_id"]: row for row in reviewed["changes"]}
        for user, machine in (("demo.go.user", "example-go-machine"),
                              ("demo.python.user", "example-python-machine"),
                              ("demo.java.user", "example-java-machine")):
            self.assertEqual(len(by_subject[user]["resource_grants"]), 11)
            self.assertEqual(len(by_subject[machine]["resource_grants"]), 8)
            self.assertTrue(all(row["data_scope"] == {"type": "owner"} for row in by_subject[user]["resource_grants"]))
            self.assertTrue(all(row["data_scope"] == {"type": "approved_organization"} for row in by_subject[machine]["resource_grants"]))
            own_run = [row for row in by_subject[machine]["resource_grants"]
                       if row["resource_type"] == "agent_installation"]
            self.assertEqual([(row["resource_id"], row["action"]) for row in own_run],
                             [(replay.example_authorization.SUBJECTS[machine][1], "run")])
        self.assertEqual(by_subject["demo.go.user"]["resource_grants"][0]["starts_at"], replay.iso_utc(now))
        resource_delegations = 0
        binding_delegations = 0
        for ordinal, (subject, grant) in enumerate(
                ((change["subject_id"], grant) for change in plan["changes"] for grant in change["resource_grants"]),
                start=1):
            command = replay.delegation_command(project, ordinal, grant, {"principal": {"revision": ordinal}})
            delegated = command["delegation"]
            self.assertEqual(delegated["actions"], [grant["action"]])
            self.assertEqual(delegated["data_scope_types"], [grant["data_scope"]["type"]])
            self.assertEqual(delegated["management_actions"], ["authorization.change"])
            self.assertEqual(delegated["scope"], {
                "scope_type": "application", **replay.bootstrap.BUSINESS_SCOPE})
            if grant["resource_type"] == "agent_installation":
                resource_delegations += 1
                self.assertEqual(delegated["resources"], [replay.example_authorization.SUBJECTS[subject][1]])
                self.assertNotIn("resource_bindings", delegated)
            else:
                binding_delegations += 1
                self.assertEqual(delegated["resources"], [])
                self.assertEqual(delegated["resource_bindings"], [{
                    "resource_type": grant["resource_type"], "resource_id": grant["resource_id"],
                    "installation_id": grant["agent_instance_id"],
                }])
        self.assertEqual((resource_delegations, binding_delegations), (15, 42))

    def test_supersedable_plan_is_only_known_unapplied_machine_run_omission(self):
        project = "agentplug-test-public-012345abcdef"
        now = datetime.now(timezone.utc).replace(microsecond=0)
        policies = {}
        for _machine, agent_id, _installation, _prefix in replay.bootstrap.MACHINES:
            policies[agent_id] = ({"ModelProfileID": agent_id + "-model", "MemoryPolicyID": agent_id + "-memory"},
                                  {"tool": {"content": {"allowed_tools": ["runtime.inspect"]}},
                                   "knowledge": {"content": {"allowed_scopes": [agent_id + "-knowledge"],
                                                                 "document_bindings": [{"knowledge_scope": agent_id + "-knowledge",
                                                                                        "provider_document_id": agent_id + "-doc",
                                                                                        "document_version": "v1", "status": "active"}]}},
                                   "runtime": {"content": {"allowed_skills": [agent_id + ".guidance"]}}}, {})
        expiry = replay.iso_utc(now + timedelta(hours=1))
        replacement = replay.build_minimum_authorization_plan(project, policies, expiry, now)
        previous = copy.deepcopy(replacement)
        machine_subjects = {name for name, (kind, _installation) in replay.example_authorization.SUBJECTS.items()
                            if kind == "service_principal"}
        for change in previous["changes"]:
            if change["subject_id"] in machine_subjects:
                change["resource_grants"] = [grant for grant in change["resource_grants"]
                                             if grant["resource_type"] != "agent_installation"]
        previous_digest = hashlib.sha256(replay.example_authorization.canonical(previous)).hexdigest()
        pin = {"path": "minimum-authorization.plan.json", "plan_sha256": previous_digest}
        owner = {"authorization_plan": pin, "permission_admin_delegations": []}
        with mock.patch.object(replay, "private_plan_file", return_value=(previous, pin["path"])):
            self.assertEqual(replay.verify_supersedable_minimum_authorization_plan(project, Path("."), owner), pin)
            used = dict(owner, permission_admin_delegations=[{"grant_id": "already-delegated"}])
            with self.assertRaisesRegex(RuntimeError, "already in use"):
                replay.verify_supersedable_minimum_authorization_plan(project, Path("."), used)
            changed_pin = dict(owner, authorization_attempt={"status": "commit_started"})
            with self.assertRaisesRegex(RuntimeError, "already in use"):
                replay.verify_supersedable_minimum_authorization_plan(project, Path("."), changed_pin)
            wrong_revision = copy.deepcopy(previous)
            user_change = next(row for row in wrong_revision["changes"] if row["subject_type"] == "user")
            knowledge_grant = next(row for row in user_change["resource_grants"] if row["resource_type"] == "knowledge")
            knowledge_grant["data_scope"] = {"type": "approved_organization"}
            wrong_digest = hashlib.sha256(replay.example_authorization.canonical(wrong_revision)).hexdigest()
            wrong_pin = {**pin, "plan_sha256": wrong_digest}
            with mock.patch.object(replay, "private_plan_file", return_value=(wrong_revision, pin["path"])):
                with self.assertRaisesRegex(RuntimeError, "known unapplied"):
                    replay.verify_supersedable_minimum_authorization_plan(
                        project, Path("."), {**owner, "authorization_plan": wrong_pin})

    def test_permission_admin_appointment_reconcile_requires_persisted_exact_request_and_profile(self):
        project = "agentplug-test-public-012345abcdef"
        now = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
        idem, key, binding_id = replay.permission_admin_appointment_key(project)
        scope = {"scope_type": "application", **replay.bootstrap.BUSINESS_SCOPE}
        command = {
            "subject_id": "permission.admin", "expected_revision": 3,
            "idempotency_key": idem,
            "reason": "Appoint the isolated permission administrator to issue only separately delegated app-demo grants",
            "role_code": "permission_admin", "scope": scope,
            "expires_at": replay.iso_utc(now + timedelta(days=6)),
        }
        digest = hashlib.sha256(json.dumps(command, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        binding = {"id": binding_id, "subject_id": "permission.admin", "role_code": "permission_admin",
                   "role_version": 1, "scope": scope, "status": "active", "revision": 1,
                   "source_id": "appointment-" + key, "expires_at": command["expires_at"]}
        receipt = {"id": "appointment-" + key, "actor_id": "system.admin", "subject_id": "permission.admin",
                   "action": "administrator.appoint", "revision": 4, "request_digest": digest,
                   "change": command, "role_binding": binding}
        persisted = {"id": receipt["id"], "actor_id": receipt["actor_id"],
                     "subject_id": receipt["subject_id"], "idempotency_hash": key,
                     "request_digest": digest, "receipt": receipt}
        profile = {"principal": {"id": "permission.admin", "type": "user", "is_active": True, "revision": 4},
                   "memberships": [{"subject_id": "permission.admin", "scope": scope, "status": "active"}],
                   "role_bindings": [binding], "resource_grants": [], "delegations": [], "task_assignments": []}
        self.assertEqual(replay.validate_persisted_permission_admin_appointment(project, persisted, profile, now)["binding_id"], binding_id)

        bad = copy.deepcopy(persisted)
        bad["idempotency_hash"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "idempotency receipt"):
            replay.validate_persisted_permission_admin_appointment(project, bad, profile, now)
        bad = copy.deepcopy(persisted)
        bad["request_digest"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "idempotency receipt"):
            replay.validate_persisted_permission_admin_appointment(project, bad, profile, now)
        bad_profile = copy.deepcopy(profile)
        bad_profile["resource_grants"] = [{"id": "unplanned"}]
        with self.assertRaisesRegex(RuntimeError, "idempotency receipt"):
            replay.validate_persisted_permission_admin_appointment(project, persisted, bad_profile, now)

    def test_minimum_authorization_plan_rejects_extra_or_expired_authority(self):
        project = "agentplug-test-public-012345abcdef"
        now = datetime.now(timezone.utc)
        policies = {}
        for _machine, agent_id, _installation, _prefix in replay.bootstrap.MACHINES:
            policies[agent_id] = ({"ModelProfileID": agent_id + "-model", "MemoryPolicyID": agent_id + "-memory"},
                                  {"tool": {"content": {"allowed_tools": ["runtime.inspect"]}},
                                   "knowledge": {"content": {"allowed_scopes": [agent_id + "-knowledge"],
                                                                 "document_bindings": [{"knowledge_scope": agent_id + "-knowledge",
                                                                                        "provider_document_id": agent_id + "-doc",
                                                                                        "document_version": "v1", "status": "active"}]}},
                                   "runtime": {"content": {"allowed_skills": [agent_id + ".guidance"]}}}, {})
        plan = replay.build_minimum_authorization_plan(project, policies, replay.iso_utc(now + timedelta(hours=1)), now)
        pinned_expected = replay.expected_minimum_authorization_plan(
            project, policies, plan, now=now + timedelta(seconds=20))
        self.assertEqual(pinned_expected, plan)
        inconsistent_window = copy.deepcopy(plan)
        inconsistent_window["changes"][0]["resource_grants"][0]["starts_at"] = replay.iso_utc(now + timedelta(seconds=1))
        with self.assertRaisesRegex(RuntimeError, "one shared start and expiry"):
            replay.expected_minimum_authorization_plan(project, policies, inconsistent_window, now=now)
        actual_resources = copy.deepcopy(plan)
        extra = copy.deepcopy(actual_resources["changes"][0]["resource_grants"][0])
        extra["id"] = "unexpected-extra-grant"
        extra["action"] = "history.export"
        actual_resources["changes"][0]["resource_grants"].append(extra)
        with self.assertRaisesRegex(RuntimeError, "minimum Grant"):
            replay.assert_minimum_authorization_plan(actual_resources, plan)
        machine_change = next(row for row in plan["changes"] if row["subject_type"] == "service_principal")
        extra_machine = copy.deepcopy(machine_change["resource_grants"][-1])
        extra_machine["id"] = "unexpected-machine-history"
        extra_machine["resource_type"] = "agent_installation"
        extra_machine["resource_id"] = replay.example_authorization.SUBJECTS[machine_change["subject_id"]][1]
        extra_machine["action"] = "history.read"
        widened = copy.deepcopy(plan)
        next(row for row in widened["changes"] if row["subject_id"] == machine_change["subject_id"])["resource_grants"].append(extra_machine)
        with self.assertRaisesRegex(RuntimeError, "minimum Grant"):
            replay.assert_minimum_authorization_plan(widened, plan)
        with self.assertRaisesRegex(ValueError, "expiry"):
            replay.build_minimum_authorization_plan(project, policies, replay.iso_utc(now - timedelta(seconds=1)), now)

    def test_authorization_preview_denial_is_not_recorded_as_grant_commit(self):
        owner = {
            "authorization_attempt": {"plan_digest": "a" * 64, "status": "commit_started"},
            "authorization_journal": [],
        }
        error = replay.bootstrap.APIError("POST", "/api/modules/identity/authorization-changes:preview",
                                          403, "PERMISSION_DENIED")
        self.assertTrue(replay.mark_authorization_attempt_failure(owner, error))
        attempt = owner["authorization_attempt"]
        self.assertEqual(attempt["status"], "preview_denied")
        self.assertEqual(attempt["status_history"], ["commit_started"])
        self.assertEqual(attempt["last_failure"], {
            "stage": "preview", "method": "POST",
            "path": "/api/modules/identity/authorization-changes:preview",
            "http_status": 403, "api_code": "PERMISSION_DENIED",
            "grant_commit_attempted": False,
        })

        ambiguous = copy.deepcopy(owner)
        self.assertFalse(replay.mark_authorization_attempt_failure(
            ambiguous, replay.bootstrap.APIError("POST", "/api/modules/identity/authorization-changes",
                                                 403, "PERMISSION_DENIED")))
        committed = copy.deepcopy(owner)
        committed["authorization_journal"] = [{"phase": "commit_started", "subject_id": "demo.go.user"}]
        self.assertFalse(replay.mark_authorization_attempt_failure(committed, error))

    def _verified_delegation_prefix_fixture(self, prefix_count=7):
        project = "agentplug-test-public-012345abcdef"
        now = datetime.now(timezone.utc).replace(microsecond=0)
        policies = {}
        for _machine, agent_id, _installation, _prefix in replay.bootstrap.MACHINES:
            policies[agent_id] = (
                {"ModelProfileID": agent_id + "-model", "MemoryPolicyID": agent_id + "-memory"},
                {"tool": {"content": {"allowed_tools": ["runtime.inspect"]}},
                 "knowledge": {"content": {"allowed_scopes": [agent_id + "-knowledge"],
                                               "document_bindings": [{"knowledge_scope": agent_id + "-knowledge",
                                                                      "provider_document_id": agent_id + "-doc",
                                                                      "document_version": "v1", "status": "active"}]}},
                 "runtime": {"content": {"allowed_skills": [agent_id + ".guidance"]}}},
                {},
            )
        plan = replay.build_minimum_authorization_plan(
            project, policies, replay.iso_utc(now + timedelta(hours=1)), now)
        plan_digest = hashlib.sha256(replay.example_authorization.canonical(plan)).hexdigest()
        _idem, key, binding_id = replay.permission_admin_appointment_key(project)
        scope = {"scope_type": "application", **replay.bootstrap.BUSINESS_SCOPE}
        appointment_expiry = replay.iso_utc(now + timedelta(days=6))
        owner = {
            "owner": project,
            "authorization_plan": {"path": "minimum-authorization.plan.json", "plan_sha256": plan_digest},
            "permission_admin_appointment": {"role": "permission_admin", "scope": scope,
                                               "binding_id": binding_id,
                                               "expires_at": appointment_expiry, "revision": 4},
            "permission_admin_delegations": [], "authorization_journal": [],
            "authorization_attempt": None,
            "permission_admin_delegation_replacement_attempt": None,
            "superseded_permission_admin_delegations": [],
        }
        binding = {"id": binding_id, "subject_id": "permission.admin",
                   "role_code": "permission_admin", "status": "active",
                   "scope": scope, "expires_at": appointment_expiry,
                   "source_id": "appointment-" + key}
        profile = {
            "principal": {"id": "permission.admin", "type": "user", "is_active": True,
                          "revision": 4 + prefix_count},
            "memberships": [{"subject_id": "permission.admin", "scope": scope,
                             "status": "active", "starts_at": replay.iso_utc(now - timedelta(minutes=1)),
                             "expires_at": appointment_expiry}],
            "role_bindings": [binding], "resource_grants": [], "task_assignments": [],
            "delegations": [],
        }
        ordered = [(change["subject_id"], grant)
                   for change in plan["changes"] for grant in change["resource_grants"]]
        for ordinal, (subject, grant) in enumerate(ordered[:prefix_count], start=1):
            command = replay.delegation_command(
                project, ordinal, grant,
                {"principal": {"revision": 4 + ordinal - 1}})
            digest = hashlib.sha256(replay.example_authorization.canonical(command)).hexdigest()
            row = {"grant_id": grant["id"], "subject_id": subject,
                   "delegation_id": command["delegation"]["id"], "request_digest": digest,
                   "expected_revision": 4 + ordinal - 1,
                   "expires_at": command["delegation"]["expires_at"],
                   "plan_digest": plan_digest,
                   "grant_digest": hashlib.sha256(replay.example_authorization.canonical(
                       {"subject": subject, "grant": grant})).hexdigest(),
                   "delegation": command["delegation"], "status": "verified",
                   "revision": 4 + ordinal}
            owner["permission_admin_delegations"].append(row)
            profile["delegations"].append(copy.deepcopy(row["delegation"]))
        return project, plan, owner, profile, now

    def _completed_replacement_fixture(self):
        project, plan, owner, _profile, _now = self._verified_delegation_prefix_fixture(57)
        ordered = [(change["subject_id"], grant)
                   for change in plan["changes"] for grant in change["resource_grants"]]
        plan_digest = hashlib.sha256(replay.example_authorization.canonical(plan)).hexdigest()
        superseded = copy.deepcopy(owner["permission_admin_delegations"])
        rows = copy.deepcopy(superseded)
        items = []
        preserved_ids = []
        last_install_ordinal = 0
        for ordinal, (subject, grant) in enumerate(ordered, start=1):
            old_row = superseded[ordinal - 1]
            if grant["resource_type"] != "agent_installation":
                preserved_ids.append(old_row["delegation_id"])
                continue
            last_install_ordinal = ordinal
            binding = {"resource_type": grant["resource_type"], "resource_id": grant["resource_id"],
                       "installation_id": grant["agent_instance_id"]}
            old = old_row["delegation"]
            old["resources"] = []
            old["resource_bindings"] = [binding]
            replacement = replay.expected_replacement_delegation(project, ordinal, grant, old)
            revoke_revision, create_revision = old_row["revision"], old_row["revision"] + 1
            revoke_digest = hashlib.sha256(f"revoke-{ordinal}".encode()).hexdigest()
            create_digest = hashlib.sha256(f"create-{ordinal}".encode()).hexdigest()
            revoke_command = {
                "subject_id": "permission.admin", "expected_revision": revoke_revision,
                "idempotency_key": f"replay-delegation-revoke-{project[-12:]}-{ordinal:03d}",
                "reason": "Revoke only the superseded installation-target encoding before exact replacement",
                "revoke_delegation_id": old_row["delegation_id"],
            }
            create_command = {
                "subject_id": "permission.admin", "expected_revision": create_revision,
                "idempotency_key": f"replay-delegation-rebind-{project[-12:]}-{ordinal:03d}",
                "reason": "Replace the revoked tuple with the same bounded authority and exact own-installation resource",
                "delegation": replacement,
            }
            item = {
                "ordinal": ordinal, "subject_id": subject, "grant_id": grant["id"],
                "old_delegation_id": old_row["delegation_id"], "new_delegation_id": replacement["id"],
                "status": "verified",
                "revoke_intent": {"status": "verified", "expected_revision": revoke_revision,
                                  "request_digest": revoke_digest, "revision": revoke_revision + 1,
                                  "command": revoke_command},
                "create_intent": {"status": "verified", "expected_revision": create_revision,
                                  "request_digest": create_digest, "revision": create_revision + 1,
                                  "command": create_command},
            }
            items.append(item)
            grant_digest = hashlib.sha256(replay.example_authorization.canonical(
                {"subject": subject, "grant": grant})).hexdigest()
            rows[ordinal - 1] = {
                "grant_id": grant["id"], "subject_id": subject,
                "delegation_id": replacement["id"], "request_digest": create_digest,
                "expected_revision": create_revision, "expires_at": replacement["expires_at"],
                "plan_digest": plan_digest, "grant_digest": grant_digest,
                "delegation": replacement, "status": "verified", "revision": create_revision + 1,
                "generation": 2, "supersedes_delegation_id": old_row["delegation_id"],
            }
        owner["permission_admin_delegations"] = rows
        owner["superseded_permission_admin_delegations"] = superseded
        owner["permission_admin_delegation_replacement_attempt"] = {
            "status": "complete", "plan_digest": plan_digest, "replaced_count": 15,
            "preserved_typed_count": 42, "active_delegation_count": 57,
            "revoked_history_count": 15, "last_verified_ordinal": last_install_ordinal,
            "preserved_delegation_ids": preserved_ids, "items": items,
        }
        return project, plan, owner

    def test_delegation_generation_mode_accepts_exact_fresh_57(self):
        project, plan, owner, profile, now = self._verified_delegation_prefix_fixture(57)
        self.assertEqual(replay.delegation_generation_mode(project, plan, owner), 1)
        self.assertEqual(replay.verified_delegation_prefix(project, plan, owner, profile, now)[0], 57)
        bad = copy.deepcopy(owner)
        install_row = next(row for row in bad["permission_admin_delegations"]
                           if row["delegation"].get("resources"))
        install_row["delegation"]["resource_bindings"] = []
        with self.assertRaisesRegex(RuntimeError, "exact own-installation"):
            replay.delegation_generation_mode(project, plan, bad)

    def test_delegation_generation_mode_preserves_strict_completed_replacement_history(self):
        project, plan, owner = self._completed_replacement_fixture()
        self.assertEqual(replay.delegation_generation_mode(project, plan, owner), 2)
        for corrupt in ("missing-item", "scope", "action", "expiry", "extra-delegation"):
            with self.subTest(corrupt=corrupt):
                bad = copy.deepcopy(owner)
                attempt = bad["permission_admin_delegation_replacement_attempt"]
                if corrupt == "missing-item":
                    attempt["items"].pop()
                elif corrupt == "scope":
                    attempt["items"][0]["create_intent"]["command"]["delegation"]["scope"] = {
                        "scope_type": "tenant", "tenant_id": "tenant-demo"}
                elif corrupt == "action":
                    attempt["items"][0]["create_intent"]["command"]["delegation"]["actions"] = ["history.read"]
                elif corrupt == "expiry":
                    attempt["items"][0]["create_intent"]["command"]["delegation"]["expires_at"] = "2099-01-01T00:00:00Z"
                else:
                    attempt["items"].append(copy.deepcopy(attempt["items"][0]))
                with self.assertRaises(RuntimeError):
                    replay.delegation_generation_mode(project, plan, bad)

    def test_delegation_resume_accepts_only_exact_verified_prefix(self):
        project, plan, owner, profile, now = self._verified_delegation_prefix_fixture()
        count, receipts = replay.verified_delegation_prefix(project, plan, owner, profile, now)
        self.assertEqual(count, 7)
        self.assertEqual(len(receipts), 7)
        self.assertEqual(receipts[-1]["revision"], 11)
        self.assertEqual(owner["permission_admin_delegations"][-1]["delegation_id"],
                         "replay-delegation-012345abcdef-007")

    def test_delegation_resume_accepts_only_pristine_missing_or_null_journal_as_empty(self):
        project, plan, owner, profile, now = self._verified_delegation_prefix_fixture()
        owner.pop("permission_admin_delegations")
        profile["principal"]["revision"] = 4
        profile["delegations"] = []
        self.assertEqual(replay.verified_delegation_prefix(project, plan, owner, profile, now), (0, []))

        owner["permission_admin_delegations"] = None
        self.assertEqual(replay.verified_delegation_prefix(project, plan, owner, profile, now), (0, []))

        _project, _plan, owner, profile, now = self._verified_delegation_prefix_fixture()
        owner["permission_admin_delegations"] = None
        with self.assertRaisesRegex(RuntimeError, "appointment-plus-prefix|verified owner prefix"):
            replay.verified_delegation_prefix(project, plan, owner, profile, now)

    def test_delegation_resume_rejects_missing_sequence_or_extra_live_row(self):
        project, plan, owner, profile, now = self._verified_delegation_prefix_fixture()
        owner["permission_admin_delegations"].pop(3)
        with self.assertRaisesRegex(RuntimeError, "profile|prefix"):
            replay.verified_delegation_prefix(project, plan, owner, profile, now)

        project, plan, owner, profile, now = self._verified_delegation_prefix_fixture()
        profile["delegations"].append({"id": "unplanned-delegation", "status": "active"})
        with self.assertRaisesRegex(RuntimeError, "exact appointment-plus-prefix"):
            replay.verified_delegation_prefix(project, plan, owner, profile, now)

    def test_delegation_resume_rejects_tampered_scope_action_or_expiry(self):
        for field, value in (("scope", {"scope_type": "tenant", "tenant_id": "tenant-demo"}),
                             ("actions", ["history.read"]),
                             ("expires_at", "2026-10-06T12:30:00Z")):
            with self.subTest(field=field):
                project, plan, owner, profile, now = self._verified_delegation_prefix_fixture()
                owner["permission_admin_delegations"][0]["delegation"][field] = value
                profile["delegations"][0][field] = copy.deepcopy(value)
                with self.assertRaisesRegex(RuntimeError, "exact contiguous verified prefix"):
                    replay.verified_delegation_prefix(project, plan, owner, profile, now)

    def test_delegation_resume_rejects_unknown_intent_or_changed_plan_pin(self):
        project, plan, owner, profile, now = self._verified_delegation_prefix_fixture()
        owner["authorization_attempt"] = {"status": "commit_started"}
        with self.assertRaisesRegex(RuntimeError, "no other or unresolved IAM write"):
            replay.verified_delegation_prefix(project, plan, owner, profile, now)

        project, plan, owner, profile, now = self._verified_delegation_prefix_fixture()
        owner["authorization_plan"]["plan_sha256"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "same pinned plan"):
            replay.verified_delegation_prefix(project, plan, owner, profile, now)

    def test_delegation_command_matches_identity_installation_scope_semantics(self):
        project = "agentplug-test-public-012345abcdef"
        now = datetime.now(timezone.utc).replace(microsecond=0)
        installation = "example-go-operations-installation"
        actor = {"principal": {"revision": 61}}
        grant = {
            "id": "grant-own-run", "subject_id": "example-go-machine",
            "resource_type": "agent_installation", "resource_id": installation,
            "agent_instance_id": installation, "action": "run",
            "data_scope": {"type": "approved_organization"},
            "starts_at": replay.iso_utc(now), "expires_at": replay.iso_utc(now + timedelta(hours=1)),
        }
        command = replay.delegation_command(project, 1, grant, actor)
        delegation = command["delegation"]
        self.assertEqual(delegation["scope"], {
            "scope_type": "application", **replay.bootstrap.BUSINESS_SCOPE})
        self.assertEqual(delegation["actions"], ["run"])
        self.assertEqual(delegation["resources"], [installation])
        self.assertNotIn("resource_bindings", delegation)
        self.assertEqual(delegation["data_scope_types"], ["approved_organization"])
        self.assertEqual(delegation["management_actions"], ["authorization.change"])

        # Real Go omitempty DTO: absent empty bindings must still match exactly.
        preview = {"request_digest": "a" * 64, "step_up_action": "delegation.manage",
                   "change": copy.deepcopy(command), "delegation": copy.deepcopy(delegation)}
        self.assertEqual(replay.assert_delegation_preview(preview, command), "a" * 64)
        widened = copy.deepcopy(preview)
        widened["delegation"]["actions"].append("history.read")
        with self.assertRaises(RuntimeError):
            replay.assert_delegation_preview(widened, command)
        changed_scope = copy.deepcopy(preview)
        changed_scope["change"]["delegation"]["scope"]["application_id"] = "other-app"
        with self.assertRaises(RuntimeError):
            replay.assert_delegation_preview(changed_scope, command)

        typed = copy.deepcopy(grant)
        typed.update({"id": "grant-model", "resource_type": "model",
                      "resource_id": "example-go-operations-model-v1", "action": "model.generate",
                      "data_scope": {"type": "owner"}})
        typed_command = replay.delegation_command(project, 2, typed, actor)["delegation"]
        self.assertEqual(typed_command["resources"], [])
        self.assertEqual(typed_command["resource_bindings"], [{
            "resource_type": "model", "resource_id": "example-go-operations-model-v1",
            "installation_id": installation,
        }])

    def test_installation_delegation_replacement_preserves_all_other_bounds(self):
        project = "agentplug-test-public-012345abcdef"
        installation = "example-go-operations-installation"
        now = datetime.now(timezone.utc).replace(microsecond=0)
        grant = {"id": "grant-own-run", "subject_id": "example-go-machine",
                 "resource_type": "agent_installation", "resource_id": installation,
                 "agent_instance_id": installation, "action": "run",
                 "data_scope": {"type": "approved_organization"},
                 "expires_at": replay.iso_utc(now + timedelta(hours=1))}
        digest = "a" * 64
        old = {"id": "replay-delegation-012345abcdef-001", "subject_id": "permission.admin",
               "scope": {"scope_type": "application", **replay.bootstrap.BUSINESS_SCOPE},
               "roles": [], "actions": ["run"], "resources": [],
               "resource_bindings": [{"resource_type": "agent_installation", "resource_id": installation,
                                      "installation_id": installation}],
               "data_scope_types": ["approved_organization"], "management_actions": ["authorization.change"],
               "max_duration_seconds": 3600, "allow_permanent": False,
               "starts_at": replay.iso_utc(now), "expires_at": grant["expires_at"],
               "status": "active", "revision": 1}
        row = {"grant_id": grant["id"], "subject_id": grant["subject_id"],
               "delegation_id": old["id"], "plan_digest": digest,
               "grant_digest": hashlib.sha256(replay.example_authorization.canonical(
                   {"subject": grant["subject_id"], "grant": grant})).hexdigest(),
               "delegation": copy.deepcopy(old), "status": "verified"}
        self.assertEqual(replay.validate_previous_installation_delegation(
            project, 1, grant["subject_id"], grant, row, digest), old)
        corrected = replay.expected_replacement_delegation(project, 1, grant, old)
        expected = copy.deepcopy(old)
        expected.update({"id": "replay-delegation-012345abcdef-r2-001",
                         "resources": [installation]})
        expected.pop("resource_bindings")
        self.assertEqual(corrected, expected)
        self.assertEqual(corrected["max_duration_seconds"], old["max_duration_seconds"])
        self.assertEqual(corrected["expires_at"], old["expires_at"])
        bad_old = copy.deepcopy(row)
        bad_old["delegation"]["resources"] = ["another-installation"]
        with self.assertRaisesRegex(RuntimeError, "historical installation delegation"):
            replay.validate_previous_installation_delegation(
                project, 1, grant["subject_id"], grant, bad_old, digest)

    def test_delegation_revoke_preview_is_exact_and_read_only(self):
        command = {"subject_id": "permission.admin", "expected_revision": 61,
                   "idempotency_key": "revoke-one", "reason": "bounded correction",
                   "revoke_delegation_id": "old-install-delegation"}
        current = {"id": "old-install-delegation", "subject_id": "permission.admin",
                   "status": "active", "revision": 1}
        preview = {"request_digest": "b" * 64, "step_up_action": "delegation.manage",
                   "change": copy.deepcopy(command), "delegation": copy.deepcopy(current)}
        self.assertEqual(replay.assert_delegation_revoke_preview(preview, command, current), "b" * 64)
        changed = copy.deepcopy(preview)
        changed["delegation"]["resources"] = ["other-installation"]
        with self.assertRaisesRegex(RuntimeError, "revoke preview"):
            replay.assert_delegation_revoke_preview(changed, command, current)

    def test_authorization_resume_accepts_only_a_verified_ordered_prefix(self):
        plan_digest = "a" * 64
        plan = {"changes": [
            {"subject_id": "demo.go.user", "resource_grants": [{"id": "g1"}]},
            {"subject_id": "example-go-machine", "resource_grants": [{"id": "g2"}]},
        ]}
        owner = {"authorization_journal": [
            {"phase": "preview", "subject_id": "demo.go.user", "plan_digest": "b" * 64,
             "baseline_revision": 5, "grant_count": 1},
            {"phase": "commit_started", "subject_id": "demo.go.user", "plan_digest": "b" * 64},
            {"phase": "verified", "subject_id": "demo.go.user", "plan_digest": "b" * 64,
             "grant_count": 1, "change_id": "change-one", "revision": 6},
        ]}
        completed, receipts = replay.verified_grant_subject_prefix(owner, plan, plan_digest)
        self.assertEqual(completed, ["demo.go.user"])
        self.assertEqual(receipts[0]["change_id"], "change-one")
        owner["authorization_journal"].append(
            {"phase": "commit_started", "subject_id": "example-go-machine", "plan_digest": "c" * 64})
        with self.assertRaisesRegex(RuntimeError, "verified prefix"):
            replay.verified_grant_subject_prefix(owner, plan, plan_digest)

    def test_business_role_preview_rejects_implicit_grants_and_presets(self):
        project = "agentplug-test-public-012345abcdef"
        subject = "demo.go.user"
        bindings = replay.business_role_bindings(project, subject, replay.example_authorization.SUBJECTS[subject][1])
        command = {"subject_type": "user", "subject_id": subject, "expected_revision": 1,
                   "idempotency_key": "roles", "reason": "exact own-installation business roles",
                   "role_bindings": bindings}
        now = datetime.now(timezone.utc)
        preview = {"actor_id": "system.admin", "subject_id": subject, "baseline_revision": 1,
                   "plan_digest": "a" * 64, "plan_expires_at": replay.iso_utc(now + timedelta(minutes=1)),
                   "change": {**copy.deepcopy(command), "plan_expires_at": "0001-01-01T00:00:00Z"},
                   "expanded_role_bindings": copy.deepcopy(bindings),
                   "expanded_resource_grants": [], "expanded_task_assignments": [], "expanded_memberships": [],
                   "automatic_revoke_binding_ids": [], "automatic_revoke_grant_ids": [],
                   "automatic_revoke_assignment_ids": []}
        self.assertEqual(replay.assert_business_role_preview(preview, command, bindings), "a" * 64)
        for mutate in (lambda value: value["change"].update(preset="operator"),
                       lambda value: value["change"].update(plan_expires_at="2030-01-01T00:00:00Z"),
                       lambda value: value.update(expanded_resource_grants=[{"id": "implicit"}])):
            bad = copy.deepcopy(preview)
            mutate(bad)
            with self.assertRaisesRegex(RuntimeError, "role preview|unplanned business"):
                replay.assert_business_role_preview(bad, command, bindings)

    def test_auditor_revoke_preview_requires_exact_owned_binding(self):
        command = {"subject_type": "user", "subject_id": "system.admin", "expected_revision": 7,
                   "idempotency_key": "auditor-revoke", "reason": "completed owned audit",
                   "revoke_binding_ids": ["public-replay-auditor-012345abcdef"]}
        preview = {"actor_id": "system.admin", "subject_id": "system.admin", "baseline_revision": 7,
                   "plan_digest": "b" * 64, "plan_expires_at": replay.iso_utc(datetime.now(timezone.utc) + timedelta(minutes=1)),
                   "change": copy.deepcopy(command), "expanded_role_bindings": None}
        replay.assert_role_preview(preview, command, "system.admin", None)
        for mutate in (lambda value: value["change"].update(revoke_binding_ids=["another-binding"]),
                       lambda value: value["change"].update(role_bindings=[{"id": "addition"}]),
                       lambda value: value.update(automatic_revoke_binding_ids=["implicit-revoke"]),
                       lambda value: value.update(expanded_resource_grants=[{"id": "implicit-grant"}])):
            bad = copy.deepcopy(preview)
            mutate(bad)
            with self.assertRaises(RuntimeError):
                replay.assert_role_preview(bad, command, "system.admin", None)

    def test_model_observation_requires_provider_output_shape_and_exact_observed_revision(self):
        self.assertEqual(replay.validate_provider_probe_response(
            "chat", {"choices": [{"message": {"content": "ready"}}]}),
            {"kind": "chat", "nonempty_message": True})
        with self.assertRaisesRegex(RuntimeError, "wrong-sized"):
            replay.validate_provider_probe_response("embedding", {"data": [{"embedding": [0.1, float("nan")]}]}, 2)

        kind = "chat"
        item = {"endpoint_ref": "service://example-chat"}
        pin = {"deployment_id": "deployment-chat", "version_id": "version-chat"}
        current = {"id": "deployment-chat", "model_version_id": "version-chat",
                   "endpoint_ref": "service://example-chat", **replay.bootstrap.BUSINESS_SCOPE,
                   "status": "ready", "health_status": "ready", "observed_revision": 7, "revision": 8}
        receipt = {"status": "verified", "observation_revision": 7, "revision": 8}
        replay.verify_one_model_deployment(current, kind, item, pin, receipt)
        with self.assertRaisesRegex(RuntimeError, "exact trusted observed revision"):
            replay.verify_one_model_deployment({**current, "observed_revision": 6}, kind, item, pin, receipt)

    def test_release_policy_input_uses_exact_model_knowledge_and_manifest_fragments(self):
        agent = "example-go-operations"
        version = "example-go-operations-v0.2.3-clean"
        installation = "example-go-operations-installation"
        pins = {
            "chat": {"provider_key": "training-chat", "model_key": "chat-model",
                     "version_id": "chat-version"},
            "embedding": {"provider_key": "training-embedding", "model_key": "embed-model",
                           "version_id": "embedding-version"},
        }
        prices = {
            "chat": {"id": "chat-price", "status": "approved", "currency": "USD",
                     "input_micros_per_1k_tokens": 100000, "output_micros_per_1k_tokens": 100000},
            "embedding": {"id": "embedding-price", "status": "approved", "currency": "USD",
                           "input_micros_per_1k_tokens": 90000, "output_micros_per_1k_tokens": 90000},
        }
        pins["chat"]["price_version_id"] = prices["chat"]["id"]
        pins["embedding"]["price_version_id"] = prices["embedding"]["id"]
        knowledge_item = {"language": "go", "knowledge_id": "go-operations",
                          "document_id": "repository-handbook", "owner": "demo.go.user"}
        receipt = {"document_id": "repository-handbook", "document_version": 1,
                   "source_revision": 2, "acl_revision": 3, "content_digest": "a" * 64}
        skill_id = "example.operations.guidance"
        fragments = [{"skill_id": skill_id,
                      "tool_policy_fragment": {"allowed_tools": ["runtime.inspect", "code.python"],
                          "require_confirmation": ["code.python"], "functions": [{"name": "inspect", "tool_name": "runtime.inspect"},
                              {"name": "sandbox_python", "tool_name": "code.python"}]},
                      "runtime_policy_fragment": {"allowed_skills": [skill_id]}}]
        built = replay.build_owner_policy_input(agent, version, installation, pins, prices,
            knowledge_item, receipt, "agentplug-test-public-012345abcdef", fragments, 8000, 800000, True)
        self.assertEqual(built["scope"]["agent_version_id"], version)
        assets = {row["type"]: row["content"] for row in built["assets"]}
        self.assertEqual(assets["model"]["model_version_id"], "chat-version")
        self.assertEqual(assets["model"]["embedding_model_version_id"], "embedding-version")
        self.assertTrue(assets["model"]["allow_external"])
        self.assertEqual(assets["knowledge"]["document_bindings"][0]["ownership_source"],
            "public-knowledge-receipt:agentplug-test-public-012345abcdef:source=2:acl=3:sha256=" + "a" * 64)
        self.assertEqual(assets["runtime"]["run_budget"], {"limit_tokens": 8000, "limit_micros": 800000})
        self.assertIn("code.python", assets["tool"]["allowed_tools"])
        with self.assertRaisesRegex(ValueError, "allow-external-provider"):
            replay.build_owner_policy_input(agent, version, installation, pins, prices,
                knowledge_item, receipt, "agentplug-test-public-012345abcdef", fragments, 8000, 800000, False)

    def test_project_name_must_be_a_fresh_public_replay_owner(self):
        self.assertEqual(replay.project_name("agentplug-test-public-012345abcdef"), "agentplug-test-public-012345abcdef")
        for value in ("agentplug", "agentplug-test-clean-abcdef012345", "agentplug-test-public-../../root"):
            with self.subTest(project=value), self.assertRaises(ValueError):
                replay.project_name(value)

    def test_machine_bindings_require_active_install_and_current_observed_catalog_readiness(self):
        class API:
            def __init__(self):
                self.calls = []
                self.stale = False

            def call(self, method, path, body=None):
                self.calls.append((method, path, body))
                for machine_id, agent_id, installation_id, _prefix in replay.bootstrap.MACHINES:
                    if path == "/api/modules/catalog/installations/" + installation_id:
                        return {
                            "id": installation_id, "tenant_id": "tenant-demo", "department_id": "dept-demo",
                            "application_id": "app-demo", "agent_id": agent_id, "version_id": "version-" + machine_id,
                            "status": "active",
                        }
                    if path == "/api/modules/catalog/installations/" + installation_id + "/deployments?limit=100":
                        revision = 8 if self.stale and machine_id == "example-go-machine" else 7
                        observed = revision - 1 if self.stale and machine_id == "example-go-machine" else revision
                        return {"items": [{
                            "id": "deployment-" + machine_id, "tenant_id": "tenant-demo", "department_id": "dept-demo",
                            "application_id": "app-demo", "agent_installation_id": installation_id,
                            "agent_version_id": "version-" + machine_id,
                            "endpoint_ref": "http://" + {"example-go-machine": "example-go", "example-python-machine": "example-python", "example-java-machine": "example-java"}[machine_id] + ":8080",
                            "status": "ready", "desired_revision": revision, "observed_revision": observed,
                        }]}
                raise AssertionError("unexpected Catalog API path")

        api = API()
        readiness = replay.verify_catalog_installation_readiness(api)
        self.assertEqual(len(readiness), 3)
        self.assertTrue(all(item["status"] == "ready" and item["observed_revision"] == 7 for item in readiness))
        indexed = replay.catalog_installations_by_id(readiness)
        self.assertEqual(set(indexed), {row[2] for row in replay.bootstrap.MACHINES})
        for machine_id, _agent_id, installation_id, _prefix in replay.bootstrap.MACHINES:
            self.assertEqual(indexed[installation_id]["machine_id"], machine_id)
        with self.assertRaisesRegex(RuntimeError, "exactly the three"):
            replay.catalog_installations_by_id(readiness + [readiness[0]])
        api.stale = True
        with self.assertRaisesRegex(RuntimeError, "latest Catalog deployment is not ready"):
            replay.verify_catalog_installation_readiness(api)

    def test_machine_principal_stage_records_identities_without_creating_bindings(self):
        project = "agentplug-test-public-012345abcdef"
        owner = {"ports": {"FRONTEND_HOST_PORT": 19080}, "identity_complete": True,
                 "services_ready": True, "machine_principals_complete": False,
                 "machines_complete": False}
        api = mock.Mock()
        api.call.return_value = {"username": "system.admin", **replay.bootstrap.BUSINESS_SCOPE}
        readiness = [{"machine_id": row[0], "installation_id": row[2],
                      "agent_version_id": "version-" + row[0]} for row in replay.bootstrap.MACHINES]
        cidrs = [row[0] + "=172.18.0." + str(index) + "/32"
                 for index, row in enumerate(replay.bootstrap.MACHINES, start=4)]
        with mock.patch.object(replay, "read_manifest", return_value=(Path("."), owner, {})), \
             mock.patch.object(replay, "verify_owner_frontend"), \
             mock.patch.object(replay, "verify_example_container_health"), \
             mock.patch.object(replay, "owner_human_api", return_value=api), \
             mock.patch.object(replay, "verify_catalog_installation_readiness", return_value=readiness), \
             mock.patch.object(replay.bootstrap, "profile", return_value={"principal": {}}), \
             mock.patch.object(replay.bootstrap, "verify_initial_admin_access"), \
             mock.patch.object(replay.bootstrap, "create_workload_principals", return_value=[
                 {"principal_id": row[0], "agent_id": row[1], "installation_id": row[2],
                  "principal_revision": 1, "type": "service_principal", "is_active": True,
                  "binding_created": False, "roles": [], "resource_grants": []}
                 for row in replay.bootstrap.MACHINES]) as create_principals, \
             mock.patch.object(replay, "write_json_private") as save_owner:
            replay.machine_principals_phase(project, project, "http://127.0.0.1:19080", cidrs)

        create_principals.assert_called_once_with(api, Path(".") / "machines.env", mock.ANY)
        self.assertIs(owner["machine_principals_complete"], True)
        self.assertIs(owner["machines_complete"], False)
        self.assertEqual(len(owner["machine_principal_receipts"]), 3)
        self.assertTrue(all(item["binding_created"] is False and item["resource_grants"] == []
                            for item in owner["machine_principal_receipts"]))
        save_owner.assert_called_once()

    def test_machine_binding_stage_is_blocked_until_all_six_asset_snapshots_publish(self):
        project = "agentplug-test-public-012345abcdef"
        owner = {"ports": {"FRONTEND_HOST_PORT": 19080}, "identity_complete": True,
                 "services_ready": True, "machine_principals_complete": True,
                 "machines_complete": False, "policy_lifecycle": {}}
        with mock.patch.object(replay, "read_manifest", return_value=(Path("."), owner, {})), \
             mock.patch.object(replay, "owner_human_api") as login:
            with self.assertRaisesRegex(RuntimeError, "six-asset PolicyAsset snapshots"):
                replay.machines_phase(project, project, "http://127.0.0.1:19080")
        login.assert_not_called()

    def test_runtime_overlay_uses_the_exact_owner_private_material_and_compose_runtime(self):
        project = "agentplug-test-public-012345abcdef"
        directory = replay.state_dir(project)
        prefix = replay.compose_prefix(project, directory, include_runtime=True)
        self.assertIn(str(replay.COMPOSE_RUNTIME), prefix)
        self.assertIn(str(directory / "runtime-control" / "compose.env"), prefix)
        overlay = replay.build_runtime_owner_overlay(directory, project)
        platform_mounts = overlay["services"]["platform-app"]["volumes"]
        controller_mounts = overlay["services"]["code-runtime"]["volumes"]
        self.assertEqual(len(platform_mounts), 4)
        self.assertEqual(len(controller_mounts), 6)
        self.assertTrue(all((directory / "runtime-control").as_posix() in mount["source"] for mount in platform_mounts + controller_mounts[1:]))
        self.assertEqual(controller_mounts[0]["source"], "/var/run/docker.sock")
        self.assertNotIn(".local-secrets/public-runtime-control", str(overlay))
        self.assertEqual(overlay["services"]["code-runtime"]["image"], "agentplug:test-code-runtime-012345abcdef")

    def test_runtime_configuration_requires_private_subnet_and_immutable_images(self):
        images = {key: "sha256:" + value * 64 for key, value in (("python", "a"), ("javascript", "b"), ("shell", "c"))}
        replay.validate_runtime_material_inputs("172.31.240.0/28", "172.31.240.3", images,
                                                "docker.io/library/docker@sha256:" + "a" * 64, "999")
        with self.assertRaisesRegex(ValueError, "dedicated private IPv4"):
            replay.validate_runtime_material_inputs("10.0.0.0/8", "10.0.0.5", images,
                                                    "docker.io/library/docker@sha256:" + "a" * 64, "999")
        with self.assertRaisesRegex(ValueError, "immutable language image"):
            replay.validate_runtime_material_inputs("172.31.240.0/28", "172.31.240.3", {**images, "python": "latest"},
                                                    "docker.io/library/docker@sha256:" + "a" * 64, "999")

    def test_temporary_role_preview_is_one_exact_short_lived_binding(self):
        project = "agentplug-test-public-012345abcdef"
        agent_id = "example-go-operations"
        subject = "demo.go.user"
        binding_id = replay.role_binding_id(project, agent_id)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        binding = {"id": binding_id, "subject_id": subject, "role_code": "agent_developer", "role_version": 1,
                   "scope": {"scope_type": "application", **replay.bootstrap.BUSINESS_SCOPE},
                   "starts_at": now.isoformat().replace("+00:00", "Z"),
                   "expires_at": (now + timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
                   "status": "active", "revision": 1, "source_id": "public-replay:" + project + ":" + agent_id}
        command = {"subject_type": "user", "subject_id": subject, "expected_revision": 3,
                   "idempotency_key": "grant-author", "reason": "temporary author", "role_bindings": [binding]}
        plan = {"actor_id": "system.admin", "subject_id": subject, "baseline_revision": 3,
                "plan_digest": "a" * 64,
                "plan_expires_at": (now + timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
                "change": copy.deepcopy(command), "expanded_role_bindings": [copy.deepcopy(binding)],
                "expanded_resource_grants": [], "expanded_task_assignments": [], "expanded_memberships": [],
                "automatic_revoke_binding_ids": [], "automatic_revoke_grant_ids": [], "automatic_revoke_assignment_ids": []}
        replay.assert_role_preview(plan, command, "system.admin", binding)
        profile = {"role_bindings": [binding]}
        replay.exact_role_binding(profile, binding_id, subject, project, agent_id)
        plan["expanded_resource_grants"] = [{"id": "unexpected-run-grant"}]
        with self.assertRaisesRegex(RuntimeError, "unplanned grant"):
            replay.assert_role_preview(plan, command, "system.admin", binding)
        with self.assertRaisesRegex(RuntimeError, "differs from the exact temporary author grant"):
            replay.exact_role_binding({"role_bindings": [{**binding, "source_id": "other-owner"}]}, binding_id, subject, project, agent_id)

    def test_temporary_role_revoke_preview_is_only_the_exact_binding_id(self):
        command = {"subject_type": "user", "subject_id": "demo.python.user", "expected_revision": 4,
                   "idempotency_key": "revoke-author", "reason": "finish release", "revoke_binding_ids": ["binding-one"]}
        now = datetime.now(timezone.utc)
        plan = {"actor_id": "system.admin", "subject_id": command["subject_id"], "baseline_revision": 4,
                "plan_digest": "b" * 64, "plan_expires_at": (now + timedelta(minutes=2)).isoformat(),
                "change": copy.deepcopy(command), "expanded_role_bindings": [], "expanded_resource_grants": [],
                "expanded_task_assignments": [], "expanded_memberships": [], "automatic_revoke_binding_ids": [],
                "automatic_revoke_grant_ids": [], "automatic_revoke_assignment_ids": []}
        replay.assert_role_preview(plan, command, "system.admin", None)
        plan["change"]["revoke_grant_ids"] = ["unexpected"]
        with self.assertRaisesRegex(RuntimeError, "outside the exact role binding"):
            replay.assert_role_preview(plan, command, "system.admin", None)

    def test_index_worker_filename_and_rotation_request_bind_exact_installation_and_loopback(self):
        machine_id, _agent_id, installation_id, _prefix = replay.index_workload_machine("go")
        scope = replay.bootstrap.BUSINESS_SCOPE
        encoded = json.dumps([scope["tenant_id"], scope["department_id"], scope["application_id"], installation_id],
                             separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.assertEqual(replay.index_workload_secret_filename(scope, installation_id),
                         hashlib.sha256(encoded).hexdigest() + ".json")
        current = {"client_id": machine_id, "tenant_id": scope["tenant_id"], "status": "active",
                   "revision": 7, "network_cidrs": ["172.26.0.5/32"]}
        request = replay.build_index_machine_rotation(machine_id, installation_id, current, "172.26.0.5")
        self.assertEqual(request, {"expected_revision": 7,
                                   "network_cidrs": ["172.26.0.5/32", "127.0.0.1/32"]})
        for bad_ip, bad_networks in (("172.26.0.6", current["network_cidrs"]),
                                     ("172.26.0.5", ["172.26.0.0/24"])):
            with self.subTest(ip=bad_ip, networks=bad_networks), self.assertRaises(RuntimeError):
                replay.build_index_machine_rotation(machine_id, installation_id,
                    {**current, "network_cidrs": bad_networks}, bad_ip)
        with self.assertRaises(ValueError):
            replay.build_index_machine_rotation(machine_id, installation_id + "-other", current, "172.26.0.5")

    def test_index_worker_inventory_allows_only_receipted_prior_rotations_and_one_unknown_cas(self):
        project = "agentplug-test-public-012345abcdef"
        scope = replay.bootstrap.BUSINESS_SCOPE
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rows = {}
            journal = {"owner": project, "machines": {}}
            for index, (machine_id, _agent, installation_id, _prefix) in enumerate(replay.bootstrap.MACHINES, start=5):
                ip = f"172.26.0.{index}"
                rows[machine_id] = {"client_id": machine_id, "tenant_id": scope["tenant_id"],
                                    "status": "active", "revision": 1,
                                    "network_cidrs": [ip + "/32"]}
            go_id, _agent, go_installation, _prefix = replay.index_workload_machine("go")
            go_ip = "172.26.0.5"
            go_entry = {"machine_id": go_id, "language": "go", "installation_id": go_installation,
                        "status": "environment_updated", "expected_revision": 1,
                        "network_cidrs": [go_ip + "/32", "127.0.0.1/32"], "request_sha256": "a" * 64}
            journal["machines"][go_id] = go_entry
            rows[go_id] = {**rows[go_id], "revision": 2, "network_cidrs": go_entry["network_cidrs"]}
            go_receipt_path = replay.index_rotation_receipt_path(directory, "go")
            go_receipt_path.write_text("receipt", encoding="utf-8")

            py_id, _agent, py_installation, _prefix = replay.index_workload_machine("python")
            py_ip = "172.26.0.6"
            py_entry = {"machine_id": py_id, "language": "python", "installation_id": py_installation,
                        "status": "unknown", "expected_revision": 1, "sdk_ip_before": py_ip,
                        "network_cidrs": [py_ip + "/32", "127.0.0.1/32"], "request_sha256": "b" * 64}
            journal["machines"][py_id] = py_entry
            rows[py_id] = {**rows[py_id], "revision": 2, "network_cidrs": py_entry["network_cidrs"]}

            receipt_response = {"client_id": go_id, "client_secret": "g" * 40, "status": "active",
                                "revision": 2, "network_cidrs": go_entry["network_cidrs"]}
            inventory = list(rows.values())
            with mock.patch.object(replay, "read_index_rotation_receipt", return_value={"response": receipt_response}):
                checked = replay.validate_index_machine_credentials_for_rotation(
                    inventory, journal, directory, unresolved_machine_id=py_id)
                self.assertEqual(set(checked), {row[0] for row in replay.bootstrap.MACHINES})
                bad = copy.deepcopy(inventory)
                bad[next(i for i, row in enumerate(bad) if row["client_id"] == py_id)]["network_cidrs"] = ["172.26.0.0/24"]
                with self.assertRaisesRegex(RuntimeError, "unexpected revision or CIDR"):
                    replay.validate_index_machine_credentials_for_rotation(
                        bad, journal, directory, unresolved_machine_id=py_id)
                bad = copy.deepcopy(inventory)
                bad[next(i for i, row in enumerate(bad) if row["client_id"] == py_id)]["revision"] = 4
                with self.assertRaisesRegex(RuntimeError, "unexpected revision or CIDR"):
                    replay.validate_index_machine_credentials_for_rotation(
                        bad, journal, directory, unresolved_machine_id=py_id)

    def test_unknown_index_credential_post_is_get_only_and_never_retried(self):
        project = "agentplug-test-public-012345abcdef"
        machine_id, agent_id, installation_id, prefix = replay.index_workload_machine("go")
        old_secret = "o" * 40
        sdk_ip = "172.26.0.5"
        requested_cidrs = [sdk_ip + "/32", "127.0.0.1/32"]
        entry = {"language": "go", "machine_id": machine_id, "installation_id": installation_id,
                 "status": "unknown", "expected_revision": 3, "network_cidrs": requested_cidrs,
                 "sdk_ip_before": sdk_ip, "request_sha256": "c" * 64,
                 "old_secret_sha256": hashlib.sha256(old_secret.encode("ascii")).hexdigest()}
        inventory = [{"client_id": row[0], "tenant_id": replay.bootstrap.BUSINESS_SCOPE["tenant_id"],
                      "status": "active", "revision": 4 if row[0] == machine_id else 1,
                      "network_cidrs": requested_cidrs if row[0] == machine_id else [f"172.26.0.{6 + i}/32"]}
                     for i, row in enumerate(replay.bootstrap.MACHINES)]
        owner = {"identity_complete": True, "services_ready": True, "machines_complete": True,
                 "business_roles_complete": True, "authorization_complete": True,
                 "runtime_prepared": True, "runtime_process_started": True,
                 "knowledge_replay_journal": {"languages": {"go": {"source_receipt": {"id": "source-go"}}}},
                 "authorization_plan": {"path": "authorization.json", "plan_sha256": "d" * 64},
                 "index_workload_credentials": {"schema": replay.INDEX_WORKLOAD_ROTATION_SCHEMA,
                     "owner": project, "scope": dict(replay.bootstrap.BUSINESS_SCOPE),
                     "machines": {machine_id: entry}, "deployment": None, "mount_activation": None}}
        api_calls = []

        class API:
            def call(self, method, path, body=None):
                api_calls.append((method, path))
                if method == "GET" and path == "/auth/me":
                    return {"username": "system.admin", **replay.bootstrap.BUSINESS_SCOPE}
                if method == "GET" and path == replay.INDEX_WORKLOAD_ROTATION_PATH:
                    return copy.deepcopy(inventory)
                if method == "POST":
                    raise AssertionError("an unresolved credential rotation must never be retried")
                raise AssertionError("unexpected API operation")

        api = API()
        machine_values = {row[3] + "_CLIENT_ID": row[0] for row in replay.bootstrap.MACHINES}
        machine_values.update({row[3] + "_CLIENT_SECRET": old_secret for row in replay.bootstrap.MACHINES})
        grant_plan = {"changes": [{"subject_id": row[0], "resource_grants": []}
                                  for row in replay.bootstrap.MACHINES]}
        grant_plan["changes"].extend({"subject_id": subject, "resource_grants": []}
                                     for subject in replay.bootstrap.DEMO_USERS)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "empty-secrets").mkdir()
            knowledge_plan = {"items": [{"language": "go", "machine": machine_id,
                            "installation_id": installation_id, "owner": "demo.go.user",
                            "knowledge_id": replay.public_knowledge.EXAMPLES["go"][0]}]}
            with mock.patch.object(replay, "read_manifest", return_value=(directory, owner, {})), \
                    mock.patch.object(replay, "load_knowledge_plan", return_value=knowledge_plan), \
                    mock.patch.object(replay, "machine_environment_credentials", return_value=machine_values), \
                    mock.patch.object(replay, "verify_owner_frontend"), \
                    mock.patch.object(replay, "verify_example_container_health"), \
                    mock.patch.object(replay, "owner_human_api", return_value=api), \
                    mock.patch.object(replay.bootstrap, "verify_initial_admin_access"), \
                    mock.patch.object(replay.bootstrap, "profile", return_value={"principal": {}}), \
                    mock.patch.object(replay, "verify_catalog_installation_readiness", return_value=[]), \
                    mock.patch.object(replay, "load_authorization_plan", return_value=(grant_plan, "authorization.json")), \
                    mock.patch.object(replay, "verify_live_minimum_grants"), \
                    mock.patch.object(replay, "verify_sdk_source_ip", return_value=sdk_ip), \
                    mock.patch.object(replay.bootstrap, "ensure_private_directory"), \
                    mock.patch.object(replay, "persist_index_rotation_state", side_effect=lambda _p, _d, _h, value: owner.update(
                        {"index_workload_credentials": copy.deepcopy(value)}) or owner):
                with self.assertRaisesRegex(RuntimeError, "POST was not repeated"):
                    replay.index_workload_credential_rotation_phase(project, directory, "go",
                                                                     machine_id + "@" + installation_id)
                self.assertFalse(any((directory / "empty-secrets").iterdir()))
        self.assertEqual([method for method, _path in api_calls if method == "POST"], [])
        self.assertIn(("GET", replay.INDEX_WORKLOAD_ROTATION_PATH), api_calls)
        self.assertEqual(owner["index_workload_credentials"]["machines"][machine_id]["status"], "unknown")
        self.assertFalse((directory / "index-workload-rotation-go.json").exists())

    def test_machine_env_reconcile_finishes_only_a_prior_or_rotated_selected_secret(self):
        machine_id, _agent_id, installation_id, prefix = replay.index_workload_machine("go")
        old_secret, new_secret = "o" * 40, "n" * 40
        values = {}
        for row in replay.bootstrap.MACHINES:
            values[row[3] + "_CLIENT_ID"] = row[0]
            values[row[3] + "_CLIENT_SECRET"] = old_secret if row[0] == machine_id else "x" * 40
        machine_values = copy.deepcopy(values)
        machine_values[prefix + "_CLIENT_SECRET"] = new_secret
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            env_path, private_path = directory / "machines.env", directory / "private.env"

            def render(fields):
                return "\n".join(key + "=" + value for key, value in fields.items()) + "\n"

            env_path.write_text(render(machine_values), encoding="utf-8")
            private_path.write_text(render(values), encoding="utf-8")
            writes = []

            def replace(path, content):
                writes.append(path.name)
                path.write_text(content, encoding="utf-8")

            with mock.patch.object(replay.bootstrap, "validate_machine_env_path"), \
                    mock.patch.object(replay.bootstrap, "verify_private_file"), \
                    mock.patch.object(replay, "replace_private_file", side_effect=replace):
                replay.replace_rotated_machine_secret(directory, "go", machine_id, installation_id,
                    hashlib.sha256(old_secret.encode("ascii")).hexdigest(), new_secret)
            self.assertEqual(writes, ["private.env"], "the already-updated file must not be rewritten")
            with mock.patch.object(replay.bootstrap, "validate_machine_env_path"), \
                    mock.patch.object(replay.bootstrap, "verify_private_file"):
                self.assertEqual(replay.parse_machine_env_private(env_path), replay.read_owner_env(directory))
                self.assertEqual(replay.read_owner_env(directory)[prefix + "_CLIENT_SECRET"], new_secret)

            with mock.patch.object(replay.bootstrap, "validate_machine_env_path"), \
                    mock.patch.object(replay.bootstrap, "verify_private_file"), \
                    mock.patch.object(replay, "read_owner_env") as read_env, \
                    mock.patch.object(replay, "replace_private_file") as unsafe_write:
                private_values = copy.deepcopy(machine_values)
                private_values[prefix + "_CLIENT_SECRET"] = "z" * 40
                read_env.return_value = private_values
                with self.assertRaisesRegex(RuntimeError, "outside the exact prior/rotated pair"):
                    replay.replace_rotated_machine_secret(directory, "go", machine_id, installation_id,
                        hashlib.sha256(old_secret.encode("ascii")).hexdigest(), new_secret)
            unsafe_write.assert_not_called()

    def test_sdk_recreate_uses_runtime_overlay_and_preserves_platform_namespace(self):
        project = "agentplug-test-public-012345abcdef"
        directory = Path("owner-state")
        expected_prefix = replay.compose_prefix(project, directory, include_examples=True, include_runtime=True)
        result = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        with mock.patch.object(replay.subprocess, "run", return_value=result) as run, \
                mock.patch.object(replay, "isolated_compose_environment", return_value={"COMPOSE_FILE": "base:examples:runtime"}):
            replay.run_owner_runtime_compose(project, directory,
                ["up", "-d", "--no-deps", "--no-build", "--force-recreate", "--wait", "--wait-timeout", "180",
                 "example-go", "example-python", "example-java"])
        command = run.call_args.args[0]
        self.assertEqual(command[:len(expected_prefix)], expected_prefix)
        self.assertEqual(command[len(expected_prefix):][-3:], ["example-go", "example-python", "example-java"])
        self.assertIn("--force-recreate", command)
        self.assertIn("--no-build", command)
        self.assertNotIn("platform-app", command, "SDK-only recreation must leave platform-app and MCP namespace untouched")

    def test_index_source_overlay_references_existing_owner_network_without_redeclaring_ipam(self):
        project = "agentplug-test-public-012345abcdef"
        target_ips = {row[0]: f"172.26.0.{index}" for index, row in enumerate(replay.bootstrap.MACHINES, start=5)}
        network = {"name": project + "_default", "network_id": "a" * 64,
                   "subnet": "172.26.0.0/16", "gateway": "172.26.0.1"}
        overlay = replay.build_index_sdk_source_overlay(project, network, target_ips)
        self.assertEqual(overlay["networks"]["default"], {"external": True, "name": project + "_default"})
        self.assertNotIn("ipam", overlay["networks"]["default"])
        self.assertEqual(overlay["services"]["example-go"]["networks"]["default"]["ipv4_address"], "172.26.0.5")
        with self.assertRaisesRegex(ValueError, "remain inside the owner private"):
            replay.build_index_sdk_source_overlay(project, {**network, "name": "other_default"}, target_ips)

    def test_sdk_credential_deploy_proves_old_process_then_recreated_process_uses_new_env(self):
        project = "agentplug-test-public-012345abcdef"
        new_values = {}
        old_secrets = {}
        ips = {}
        machines = {}
        for index, (machine_id, _agent_id, installation_id, prefix) in enumerate(replay.bootstrap.MACHINES, start=5):
            old_secret, new_secret = ("o" + str(index)) * 20, ("n" + str(index)) * 20
            old_secrets[machine_id] = old_secret
            new_values[prefix + "_CLIENT_ID"] = machine_id
            new_values[prefix + "_CLIENT_SECRET"] = new_secret
            ip = f"172.26.0.{index}"
            ips[machine_id] = ip
            machines[machine_id] = {"language": {"example-go-machine": "go", "example-python-machine": "python",
                                                   "example-java-machine": "java"}[machine_id],
                                    "machine_id": machine_id, "installation_id": installation_id,
                                    "status": "environment_updated", "sdk_ip_before": ip,
                                    "old_secret_sha256": hashlib.sha256(old_secret.encode("ascii")).hexdigest(),
                                    "network_cidrs": [ip + "/32", "127.0.0.1/32"]}
        journal = {"schema": replay.INDEX_WORKLOAD_ROTATION_SCHEMA, "owner": project,
                   "scope": dict(replay.bootstrap.BUSINESS_SCOPE), "machines": machines,
                   "deployment": None, "mount_activation": None}
        owner = {"authorization_plan": {"plan_sha256": "e" * 64},
                 "index_workload_credentials": copy.deepcopy(journal)}
        process_state = {"credentials": "old"}
        inspected_services = []

        def inspect(_project, _directory, service):
            inspected_services.append(service)
            if service == "platform-app":
                return {"container_id": "platform-container-stable", "ip": "172.26.0.3", "environment": {}}
            machine_id = {"example-go": replay.bootstrap.MACHINES[0][0],
                          "example-python": replay.bootstrap.MACHINES[1][0],
                          "example-java": replay.bootstrap.MACHINES[2][0]}[service]
            row = next(item for item in replay.bootstrap.MACHINES if item[0] == machine_id)
            secret = old_secrets[machine_id] if process_state["credentials"] == "old" else new_values[row[3] + "_CLIENT_SECRET"]
            return {"container_id": service + "-stable", "ip": ips[machine_id],
                    "environment": {"AGENT_CLIENT_ID": machine_id, "AGENT_CLIENT_SECRET": secret}}

        compose_calls = []
        def compose(_project, _directory, args, timeout=240, required=True, include_index_ip_overlay=False):
            compose_calls.append(tuple(args))
            self.assertNotIn("platform-app", args)
            self.assertTrue(include_index_ip_overlay)
            if args[0] == "up":
                self.assertIn("--force-recreate", args)
                self.assertIn("--no-build", args)
                process_state["credentials"] = "new"
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        def persist(_project, _directory, _digest, value):
            owner["index_workload_credentials"] = copy.deepcopy(value)
            return owner

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with mock.patch.object(replay, "read_manifest", return_value=(directory, owner, {})), \
                    mock.patch.object(replay, "machine_environment_credentials", return_value=new_values), \
                    mock.patch.object(replay, "ensure_owner_index_ip_overlay", return_value=(
                        directory / replay.INDEX_IP_OVERLAY_NAME, "f" * 64,
                        {"name": project + "_default", "network_id": "c" * 64,
                         "subnet": "172.26.0.0/16", "gateway": "172.26.0.1"})), \
                    mock.patch.object(replay, "verify_owner_frontend"), \
                    mock.patch.object(replay, "verify_example_container_health"), \
                    mock.patch.object(replay, "inspect_owner_compose_service", side_effect=inspect), \
                    mock.patch.object(replay, "run_owner_runtime_compose", side_effect=compose), \
                    mock.patch.object(replay, "persist_index_rotation_state", side_effect=persist):
                result = replay.index_workload_credential_deploy_phase(project, directory)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["source_ips_before"], ips)
        self.assertEqual(result["source_ips_after"], ips)
        self.assertEqual(result["platform_container_id_before"], "platform-container-stable")
        self.assertEqual(result["platform_container_id_after"], "platform-container-stable")
        self.assertEqual(process_state["credentials"], "new")
        self.assertEqual([call[0] for call in compose_calls], ["stop", "rm", "up"])
        self.assertEqual(inspected_services.count("example-go"), 2)
        self.assertEqual(inspected_services.count("example-python"), 2)
        self.assertEqual(inspected_services.count("example-java"), 2)

    def test_explicit_sdk_ip_correction_recovers_only_verified_drift_and_preserves_failed_receipt(self):
        project = "agentplug-test-public-f4a0b7991fbc"
        target_ips = {"example-go-machine": "172.26.0.7", "example-python-machine": "172.26.0.5",
                      "example-java-machine": "172.26.0.6"}
        drift_ips = {"example-go-machine": "172.26.0.5", "example-python-machine": "172.26.0.7",
                     "example-java-machine": "172.26.0.6"}
        new_values, secrets_by_machine, machine_rows = {}, {}, {}
        for index, (machine_id, _agent, installation_id, prefix) in enumerate(replay.bootstrap.MACHINES, start=1):
            secret = ("r" + str(index)) * 20
            secrets_by_machine[machine_id] = secret
            new_values[prefix + "_CLIENT_ID"] = machine_id
            new_values[prefix + "_CLIENT_SECRET"] = secret
            language = {"example-go-machine": "go", "example-python-machine": "python",
                        "example-java-machine": "java"}[machine_id]
            machine_rows[machine_id] = {"language": language, "machine_id": machine_id,
                "installation_id": installation_id, "status": "environment_updated",
                "sdk_ip_before": target_ips[machine_id], "old_secret_sha256": hashlib.sha256(("o" + str(index) * 39).encode()).hexdigest(),
                "network_cidrs": [target_ips[machine_id] + "/32", "127.0.0.1/32"]}
        failed_deployment = {"status": "unknown", "services": ["example-go", "example-python", "example-java"],
            "source_ips_before": copy.deepcopy(target_ips), "platform_container_id_before": "platform-stable",
            "error_type": "RuntimeError"}
        journal = {"schema": replay.INDEX_WORKLOAD_ROTATION_SCHEMA, "owner": project,
                   "scope": dict(replay.bootstrap.BUSINESS_SCOPE), "machines": machine_rows,
                   "deployment": failed_deployment, "mount_activation": None}
        owner = {"authorization_plan": {"plan_sha256": "a" * 64},
                 "index_workload_credentials": copy.deepcopy(journal)}
        live = {"ips": copy.deepcopy(drift_ips), "container_ids": {
            "example-go-machine": "go-drift-container", "example-python-machine": "py-drift-container",
            "example-java-machine": "java-original-container"}, "platform_id": "platform-stable"}
        compose_calls = []
        service_for_machine = {"example-go-machine": "example-go", "example-python-machine": "example-python",
                               "example-java-machine": "example-java"}
        machine_for_service = {value: key for key, value in service_for_machine.items()}

        def inspect(_project, _directory, service):
            if service == "platform-app":
                return {"container_id": live["platform_id"], "ip": "172.26.0.3", "environment": {}}
            machine_id = machine_for_service[service]
            row = next(item for item in replay.bootstrap.MACHINES if item[0] == machine_id)
            return {"container_id": live["container_ids"][machine_id], "ip": live["ips"][machine_id],
                    "environment": {"AGENT_CLIENT_ID": machine_id,
                                    "AGENT_CLIENT_SECRET": new_values[row[3] + "_CLIENT_SECRET"]}}

        def compose(_project, _directory, args, timeout=240, required=True, include_index_ip_overlay=False):
            compose_calls.append(tuple(args))
            self.assertTrue(include_index_ip_overlay)
            if args[0] == "up":
                live["ips"] = copy.deepcopy(target_ips)
                live["container_ids"] = {machine_id: container + "-fixed"
                                          for machine_id, container in live["container_ids"].items()}
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        def persist(_project, _directory, _digest, value):
            owner["index_workload_credentials"] = copy.deepcopy(value)
            return owner

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with mock.patch.object(replay, "read_manifest", return_value=(directory, owner, {})), \
                    mock.patch.object(replay, "machine_environment_credentials", return_value=new_values), \
                    mock.patch.object(replay, "ensure_owner_index_ip_overlay", return_value=(
                        directory / replay.INDEX_IP_OVERLAY_NAME, "b" * 64,
                        {"name": project + "_default", "network_id": "c" * 64,
                         "subnet": "172.26.0.0/16", "gateway": "172.26.0.1"})), \
                    mock.patch.object(replay, "verify_owner_frontend"), \
                    mock.patch.object(replay, "verify_example_container_health"), \
                    mock.patch.object(replay, "inspect_owner_compose_service", side_effect=inspect), \
                    mock.patch.object(replay, "run_owner_runtime_compose", side_effect=compose), \
                    mock.patch.object(replay, "persist_index_rotation_state", side_effect=persist), \
                    mock.patch.object(replay, "confirm_digest_phrase", side_effect=lambda phrase, _confirm: phrase.startswith(
                        project + " correct-sdk-ips ")) as confirm:
                correction = replay.index_workload_credential_correct_ips_phase(project, directory)
                self.assertEqual(journal["deployment"]["status"], "unknown",
                                 "the correction stage must preserve the original failed deploy status")
                self.assertEqual(correction["status"], "verified")
                self.assertEqual(correction["source_ips_after"], target_ips)
                self.assertEqual(correction["platform_container_id_after"], "platform-stable")
                self.assertEqual([call[0] for call in compose_calls], ["stop", "rm", "up"])
                corrected = replay.index_workload_credential_deploy_phase(project, directory)
                self.assertEqual(corrected["status"], "corrected")
                self.assertEqual(corrected["source_ips_after"], target_ips)
                self.assertEqual(corrected["error_type"], "RuntimeError")
                self.assertEqual(len(compose_calls), 3, "normal deploy reconciliation after correction must be read-only")
                self.assertEqual(owner["index_workload_credentials"]["deployment"]["status"], "corrected")
            confirm.assert_called_once()


if __name__ == "__main__":
    unittest.main()
