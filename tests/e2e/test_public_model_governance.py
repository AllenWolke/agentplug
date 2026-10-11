"""Offline mutation safety checks. No Docker, credentials or provider calls."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import unittest
from urllib.parse import urlsplit, parse_qs

import public_model_governance as model

PROJECT = "agentplug-test-public-012345abcdef"
SCOPE = {"tenant_id": "tenant-demo", "department_id": "dept-demo", "application_id": "app-demo"}


def plan():
    models = []
    for kind in ("chat", "embedding"):
        models.append({"kind": kind, "provider_key": "test-" + kind, "model_key": "teaching-" + kind,
                       "endpoint_ref": "service://example-" + kind,
                       "secret_ref": "secret://" + ("deepseek.key" if kind == "chat" else "embedding.key"),
                       "capabilities": {"dimensions": 1024} if kind == "embedding" else {"reasoning": "disabled"},
                       "context_limit": 8192, "semantic_version": "0.1.0", "descriptor_sha256": "a" * 64,
                       "price": {"currency": "USD", "input_micros_per_1k_tokens": 100000,
                                 "output_micros_per_1k_tokens": 100000,
                                 "effective_from": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()}})
    return {"schema": "public-model-governance/v1", "owner_project": PROJECT, "scope": SCOPE, "models": models}


class API:
    def __init__(self, provider_scope=None, definition_scope=None, provider_owner="system.admin"):
        self.resources = {}
        self.calls = []
        self.username = "system.admin"
        self.fail_approval = False
        self.provider_scope = provider_scope or {"tenant_id": "", "department_id": "", "application_id": ""}
        self.definition_scope = definition_scope or {"tenant_id": "", "department_id": "", "application_id": ""}
        self.provider_owner = provider_owner

    def call(self, method, path, body=None):
        self.calls.append((method, path, deepcopy(body)))
        if path == "/auth/me":
            return {"username": self.username, **SCOPE}
        parsed = urlsplit(path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if method == "GET":
            if path in self.resources:
                return deepcopy(self.resources[path])
            values = [row for key, row in self.resources.items() if key.rsplit("/", 1)[0] == path]
            for field in ("provider_id", "model_version_id"):
                if field in query:
                    values = [row for row in values if row.get(field) == query[field][0]]
            return {"items": deepcopy(values)}
        if path.endswith("/test"):
            return {"provider_id": path.split("/")[-2], "validated": True}
        if path.endswith("/approve"):
            if self.fail_approval:
                raise RuntimeError("approval response lost")
            resource = self.resources[path.removesuffix("/approve")]
            if resource["revision"] != body["revision"]:
                raise AssertionError("stale CAS")
            resource.update(status="approved", revision=resource["revision"] + 1)
            return deepcopy(resource)
        row = dict(deepcopy(body), id="resource-" + str(len(self.resources) + 1), revision=1, status="draft")
        if path.endswith("/providers"):
            row.update(self.provider_scope)
            row["owner_id"] = self.provider_owner
        if path.endswith("/models"):
            row.update(self.definition_scope)
        if path.endswith("/versions"):
            row["definition_id"] = path.split("/")[-2]
        if path.endswith("/deployments"):
            row.update(status="pending", health_status="unknown", observed_revision=0)
        self.resources[path + "/" + row["id"]] = row
        return deepcopy(row)


class ModelPublicationTests(unittest.TestCase):
    def test_offline_metadata_plan_excludes_urls_and_rejects_credentials(self):
        metadata = {"llm": {"model": "teaching-chat", "base_url": "https://model.example/v1", "key_file": "deepseek.key"},
                    "embedding": {"model": "teaching-embedding", "base_url": "https://embedding.example/v1", "key_file": "embedding.key"}}
        prices = {kind: {"currency": "USD", "input_micros_per_1k_tokens": 100000, "output_micros_per_1k_tokens": 100000} for kind in ("chat", "embedding")}
        result = model.build_plan(PROJECT, SCOPE, metadata, prices, 1024, {"chat": 8192, "embedding": 8192},
                                  (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat())
        self.assertNotIn("https://", str(result))
        for field, value in (("api_key", "not-a-real-secret"), ("base_url", "https://user:password@model.example/v1")):
            bad = deepcopy(metadata)
            bad["llm"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                model.build_plan(PROJECT, SCOPE, bad, prices, 1024, {"chat": 8192, "embedding": 8192}, "2026-01-01T00:00:00Z")

    def test_does_not_claim_provider_connectivity_or_observed_deployment(self):
        api, journal, records = API(), {}, []
        result = model.publish_models(api, plan(), PROJECT, SCOPE, journal, lambda *args: True, records.append)
        self.assertEqual(set(result["models"]), {"chat", "embedding"})
        self.assertFalse(result["model_deployment_readiness_proven"])
        self.assertFalse(result["business_execution_proven"])
        self.assertTrue(all(item["deployment"]["health_status"] == "unknown" for item in result["models"].values()))
        self.assertFalse(any(path.endswith("/health") for _, path, _ in api.calls))
        self.assertTrue(records[0]["steps"]["test-chat:provider-create"]["intent"])
        self.assertNotIn("receipt", records[0]["steps"]["test-chat:provider-create"])

    def test_global_provider_and_definition_dtos_keep_catalog_scope_global(self):
        api, journal = API(), {}
        model.publish_models(api, plan(), PROJECT, SCOPE, journal, lambda *args: True, lambda value: None)
        providers = [row for path, row in api.resources.items() if path.startswith(model.PREFIX + "/providers/")]
        definitions = [row for path, row in api.resources.items() if path.startswith(model.PREFIX + "/models/")
                       and "/versions/" not in path]
        self.assertEqual(len(providers), 2)
        self.assertEqual(len(definitions), 2)
        self.assertTrue(all(row["owner_id"] == "system.admin" for row in providers))
        for row in providers + definitions:
            self.assertEqual({key: row[key] for key in ("tenant_id", "department_id", "application_id")},
                             {"tenant_id": "", "department_id": "", "application_id": ""})

    def test_non_global_or_wrong_owner_provider_is_rejected(self):
        for api in (API(provider_scope=SCOPE), API(provider_owner="demo.java.user")):
            with self.subTest(provider_scope=api.provider_scope, provider_owner=api.provider_owner):
                with self.assertRaisesRegex(RuntimeError, "global Model Governance catalog|owner must be"):
                    model.publish_models(api, plan(), PROJECT, SCOPE, {}, lambda *args: True, lambda value: None)

    def test_non_global_model_definition_is_rejected(self):
        api = API(definition_scope=SCOPE)
        with self.assertRaisesRegex(RuntimeError, "global Model Governance catalog"):
            model.publish_models(api, plan(), PROJECT, SCOPE, {}, lambda *args: True, lambda value: None)

    def test_normal_manager_login_is_required_before_writes(self):
        api = API()
        api.username = "demo.java.user"
        with self.assertRaisesRegex(RuntimeError, "administrator login"):
            model.publish_models(api, plan(), PROJECT, SCOPE, {}, lambda *args: True, lambda value: None)
        self.assertFalse(any(method == "POST" for method, _, _ in api.calls))

    def test_unknown_secret_or_unapproved_endpoint_never_reaches_api(self):
        for field, value in (("secret_ref", "secret://other-user.key"), ("endpoint_ref", "https://example.com"), ("api_key", "not-a-real-secret")):
            document = plan()
            document["models"][0][field] = value
            api = API()
            with self.subTest(field=field), self.assertRaises(ValueError):
                model.publish_models(api, document, PROJECT, SCOPE, {}, lambda *args: True, lambda value: None)
            self.assertEqual(api.calls, [])

    def test_lost_approval_receipt_blocks_automatic_retry(self):
        api, journal, document = API(), {}, plan()
        api.fail_approval = True
        with self.assertRaisesRegex(RuntimeError, "response lost"):
            model.publish_models(api, document, PROJECT, SCOPE, journal, lambda *args: True, lambda value: None)
        api.fail_approval = False
        writes = sum(method == "POST" for method, _, _ in api.calls)
        with self.assertRaisesRegex(RuntimeError, "unreconciled"):
            model.publish_models(api, document, PROJECT, SCOPE, journal, lambda *args: True, lambda value: None)
        self.assertEqual(sum(method == "POST" for method, _, _ in api.calls), writes)

    def test_confirm_rejection_has_no_write_or_intent(self):
        api, journal = API(), {}
        with self.assertRaisesRegex(RuntimeError, "confirmation"):
            model.publish_models(api, plan(), PROJECT, SCOPE, journal, lambda *args: False, lambda value: None)
        self.assertEqual(journal["steps"], {})
        self.assertFalse(any(method == "POST" for method, _, _ in api.calls))

    def test_list_without_pagination_fails_closed_at_limit(self):
        class Truncated:
            def call(self, *args):
                return {"items": [{"id": str(i)} for i in range(200)]}
        with self.assertRaisesRegex(RuntimeError, "truncated"):
            model.rows(Truncated(), model.PREFIX + "/providers")

    def test_reviewed_model_plan_cannot_change_during_resume(self):
        journal = {"owner_project": PROJECT, "plan_sha256": "b" * 64, "steps": {}}
        with self.assertRaisesRegex(RuntimeError, "different project or plan"):
            model.publish_models(API(), plan(), PROJECT, SCOPE, journal, lambda *args: True, lambda value: None)


if __name__ == "__main__":
    unittest.main()
