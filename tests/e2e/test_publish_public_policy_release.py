from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import publish_public_policy_release as publisher


class PublicPolicyPrepareTests(unittest.TestCase):
    def test_missing_current_snapshot_is_exact_zero_revision(self):
        class MissingSnapshotAPI:
            def call(self, method, path):
                self.request = (method, path)
                raise publisher.APIError(method, path.split("?", 1)[0], 404, "RESOURCE_NOT_FOUND")

        api = MissingSnapshotAPI()
        scope = {"tenant_id": "tenant-demo", "department_id": "dept-demo",
                 "application_id": "app-demo", "agent_id": "example-go-operations",
                 "agent_version_id": "example-go-operations-v1"}
        self.assertEqual(publisher.current_snapshot(api, scope), {"Revision": 0, "Hash": ""})
        self.assertEqual(api.request[0], "GET")
        self.assertIn("agent_version_id=example-go-operations-v1", api.request[1])

    def test_current_snapshot_does_not_hide_authorization_or_other_errors(self):
        class FailedSnapshotAPI:
            def __init__(self, status, code):
                self.status, self.code = status, code

            def call(self, method, path):
                raise publisher.APIError(method, path.split("?", 1)[0], self.status, self.code)

        scope = {"tenant_id": "tenant-demo", "department_id": "dept-demo",
                 "application_id": "app-demo", "agent_id": "example-go-operations",
                 "agent_version_id": "example-go-operations-v1"}
        for status, code in ((403, "FORBIDDEN"), (404, "OTHER_NOT_FOUND"), (503, "STORE_UNAVAILABLE")):
            with self.subTest(status=status, code=code), self.assertRaises(publisher.APIError):
                publisher.current_snapshot(FailedSnapshotAPI(status, code), scope)

    def test_snapshot_reader_matches_go_json_initialism_fields(self):
        snapshot = {
            "revision": 1, "hash": "a" * 64,
            "model_profile_id": "model-v1", "prompt_version_id": "prompt-v1",
            "tool_policy_id": "tool-v1", "memory_policy_id": "memory-v1",
            "knowledge_policy_id": "knowledge-v1", "runtime_policy_id": "runtime-v1",
            "rule_bundle_version": "", "rule_bundle_checksum": "", "rule": {},
        }
        release = {
            "snapshot_template": {"rule": {}},
            "assets": {typ: {"id": value} for typ, value in {
                "model": "model-v1", "prompt": "prompt-v1", "tool": "tool-v1",
                "memory": "memory-v1", "knowledge": "knowledge-v1", "runtime": "runtime-v1",
            }.items()},
        }
        self.assertTrue(publisher.snapshot_already_uses(snapshot, release))

    def test_endpoint_is_explicit_clean_http_or_https(self):
        self.assertEqual(publisher.validate_deployment_endpoint("http://example-python:8080"),
                         "http://example-python:8080")
        self.assertEqual(publisher.validate_deployment_endpoint("https://agents.example.test:8443/runtime"),
                         "https://agents.example.test:8443/runtime")
        for endpoint in ("", "ftp://example.test", "http://user:secret@example.test", "http://example.test?x=1",
                         "http://example.test#fragment", "http://example.test:bad"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                publisher.validate_deployment_endpoint(endpoint)

    def test_generated_catalog_request_must_keep_the_requested_endpoint(self):
        plan = {"requests": [{"stage": "deploy", "method": "POST",
                              "body": {"endpoint_ref": "http://example-python:8080"}}]}
        publisher.verify_bundle_endpoint(plan, "http://example-python:8080")
        with self.assertRaisesRegex(ValueError, "differs from the explicitly requested"):
            publisher.verify_bundle_endpoint(plan, "http://example-java:8080")

    def test_prepare_forwards_endpoint_and_rejects_a_generator_mismatch(self):
        endpoint = "http://example-python:8080"
        scope = {"tenant_id": "tenant-demo", "department_id": "dept-demo",
                 "application_id": "app-demo", "agent_id": "example-python-documents",
                 "agent_version_id": "example-python-documents-v1"}
        types = publisher.ASSET_TYPES
        assets = []
        for asset_type in types:
            asset_id = "example-" + asset_type
            assets.append({"type": asset_type, "id": asset_id, "content_hash": "a" * 64,
                           "create_request_template": {"body": {"id": asset_id, "type": asset_type,
                                                                  "scope": scope, "content": {}}}})
        bundle = {"policy_publication": {
            "schema": "policyasset-preparation/v1", "preparation_only": True,
            "scope": scope, "assets": assets,
            "publish_snapshot_request_template": {"body": {"scope": scope}},
        }, "requests": [{"stage": "deploy", "method": "POST",
                         "body": {"endpoint_ref": endpoint}}]}
        args = SimpleNamespace(example="examples/python-documents", artifact_digest="sha256:" + "b" * 64,
                               publisher="demo.python.user", tenant="tenant-demo", department="dept-demo",
                               application="app-demo", version_id=scope["agent_version_id"],
                               installation_id="example-python-documents-installation",
                               deployment_id="public-python-deployment", endpoint=endpoint,
                               policy_input=Path("policy-input.json"), output=Path("release-plan.json"))

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "release-plan.json"
            args.output = output
            completed = SimpleNamespace(stdout=json.dumps(bundle))
            def save_private(path: Path, content: str) -> None:
                path.write_text(content, encoding="utf-8")

            with mock.patch.object(publisher, "validate_machine_env_path"), \
                    mock.patch.object(publisher, "ensure_private_directory"), \
                    mock.patch.object(publisher, "write_new_private_file", side_effect=save_private), \
                    mock.patch.object(publisher.subprocess, "run", return_value=completed) as run:
                publisher.prepare_plan(args)
                command = run.call_args.args[0]
                endpoint_index = command.index("--endpoint")
                self.assertEqual(command[endpoint_index + 1], endpoint)
                saved = json.loads(output.read_text(encoding="utf-8"))
                publisher.validate_plan(saved)

            mismatched = json.loads(json.dumps(bundle))
            mismatched["requests"][0]["body"]["endpoint_ref"] = "http://example-go:8080"
            with mock.patch.object(publisher, "validate_machine_env_path"), \
                    mock.patch.object(publisher.subprocess, "run", return_value=SimpleNamespace(stdout=json.dumps(mismatched))):
                args.output = Path(temporary) / "rejected.json"
                with self.assertRaisesRegex(ValueError, "differs from the explicitly requested"):
                    publisher.prepare_plan(args)
                self.assertFalse(args.output.exists())


if __name__ == "__main__":
    unittest.main()
