"""Offline safety checks for public teaching source/index replay."""
from copy import deepcopy
import unittest

import public_knowledge_replay as knowledge

PROJECT = "agentplug-test-public-012345abcdef"
SCOPE = {"tenant_id": "tenant-demo", "department_id": "dept-demo", "application_id": "app-demo"}


class API:
    def __init__(self, username="system.admin"):
        self.username = username
        self.snapshot = {"schema_version": "knowledge-source-snapshot/v1", "revision": 0, "documents": []}
        self.calls = []
        self.detail = {"schema_version": "knowledge-index-task-detail/v1", "run_id": "index-run", "knowledge_id": "python-documents",
                       "mode": "full", "status": "accepted", "revision": 1}
        self.lose_response = False

    def call(self, method, path, body=None):
        self.calls.append((method, path))
        if path == "/auth/me":
            return {"username": self.username, **SCOPE}
        if method == "GET" and "/sources/" in path:
            return deepcopy(self.snapshot)
        if method == "PUT":
            if self.lose_response:
                raise RuntimeError("source receipt lost")
            receipt = {"actor_principal_id": self.username, "document_id": "repository-handbook", "document_version": 1,
                       "source_revision": 1, "acl_revision": 1, "deleted": False, "content_digest": "a" * 64}
            self.snapshot.update(revision=1, documents=[{"id": "repository-handbook", "version": 1, "source_revision": 1,
                                                        "acl_revision": 1, "content_digest": "a" * 64,
                                                        **{key: deepcopy(body[key]) for key in ("body", "metadata", "acl", "deleted")}}])
            return receipt
        if "/catalog/installations/" in path:
            return {**SCOPE, "id": "example-python-documents-installation", "agent_id": "example-python-documents", "version_id": "version-4", "status": "active"}
        if method == "POST":
            return {"schema_version": "knowledge-index-task/v1", "run_id": "index-run", "status": "accepted", "replayed": False}
        return deepcopy(self.detail)


class KnowledgeReplayTests(unittest.TestCase):
    def setUp(self):
        self.plan = knowledge.build_plan(PROJECT, SCOPE, 1024)
        self.journal = {}
        self.admin = API()
        self.owner = API("demo.python.user")

    def source(self):
        return knowledge.publish_source(self.admin, self.plan, PROJECT, SCOPE, "python", self.journal, lambda *args: True, lambda value: None)

    def test_source_has_explicit_owner_acl_and_exact_body_readback(self):
        records = []
        knowledge.publish_source(self.admin, self.plan, PROJECT, SCOPE, "python", self.journal, lambda *args: True, records.append)
        self.assertEqual(self.admin.snapshot["documents"][0]["acl"], {"owner_principal_id": "demo.python.user", "application_visible": False, "readers": ["example-python-machine"]})
        self.assertNotIn("source_receipt", records[0]["languages"]["python"])
        self.assertEqual(self.admin.calls[-1][0], "GET")

    def test_plan_acl_or_repository_body_tampering_never_reaches_api(self):
        for key, value in (("acl", {"owner_principal_id": "system.admin", "application_visible": True}), ("body", "unreviewed content")):
            bad = deepcopy(self.plan)
            bad["items"][1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                knowledge.publish_source(self.admin, bad, PROJECT, SCOPE, "python", self.journal, lambda *args: True, lambda value: None)
        self.assertEqual(self.admin.calls, [])

    def test_existing_source_is_not_overwritten(self):
        self.admin.snapshot.update(revision=1, documents=[{"id": "existing-business-document"}])
        with self.assertRaisesRegex(RuntimeError, "not be overwritten"):
            self.source()
        self.assertFalse(any(method == "PUT" for method, _ in self.admin.calls))

    def test_ambiguous_source_write_is_not_retried(self):
        self.admin.lose_response = True
        with self.assertRaisesRegex(RuntimeError, "receipt lost"):
            self.source()
        self.admin.lose_response = False
        with self.assertRaisesRegex(RuntimeError, "ambiguous"):
            self.source()
        self.assertEqual(sum(method == "PUT" for method, _ in self.admin.calls), 1)

    def test_nonterminal_index_is_observed_without_replacement_submission(self):
        self.source()
        knowledge.submit_index(self.owner, self.admin, self.plan, PROJECT, SCOPE, "python", self.journal, lambda *args: True, lambda value: None)
        for _ in range(2):
            result = knowledge.observe_index(self.owner, self.admin, self.plan, PROJECT, SCOPE, "python", self.journal, lambda value: None)
            self.assertEqual(result["run_id"], "index-run")
            self.assertFalse(result["index_publication_verified"])
        self.assertEqual(sum(method == "POST" for method, _ in self.owner.calls), 1)

    def test_foreign_owner_cannot_submit_managed_task(self):
        self.source()
        self.owner.username = "demo.go.user"
        with self.assertRaisesRegex(RuntimeError, "identity"):
            knowledge.submit_index(self.owner, self.admin, self.plan, PROJECT, SCOPE, "python", self.journal, lambda *args: True, lambda value: None)
        self.assertFalse(any(method == "POST" for method, _ in self.owner.calls))

    def test_success_requires_exact_frozen_source_generation_and_checkpoint(self):
        self.source()
        knowledge.submit_index(self.owner, self.admin, self.plan, PROJECT, SCOPE, "python", self.journal, lambda *args: True, lambda value: None)
        self.owner.detail.update(status="succeeded", revision=4, result={"schema_version": "knowledge-index-result/v1", "knowledge_id": "python-documents", "generation_id": "generation-1", "source_revision": 1, "index_revision": 1, "checkpoint_revision": 1, "embedded_chunks": 3, "reused_chunks": 0})
        result = knowledge.observe_index(self.owner, self.admin, self.plan, PROJECT, SCOPE, "python", self.journal, lambda value: None)
        self.assertTrue(result["index_publication_verified"])
        self.assertFalse(result["business_retrieval_proven"])
        self.owner.detail["result"]["source_revision"] = 2
        with self.assertRaisesRegex(RuntimeError, "frozen source"):
            knowledge.observe_index(self.owner, self.admin, self.plan, PROJECT, SCOPE, "python", self.journal, lambda value: None)


if __name__ == "__main__":
    unittest.main()
