"""Offline checks for the owner-bound stage confirmation gate."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import public_owner_stage_runner as runner


class OwnerConfirmationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.writes = []

        def persist(path, value):
            self.writes.append((path, json.loads(json.dumps(value))))

        self.persist_patch = patch.object(runner.replay, "write_json_private", side_effect=persist)
        self.persist_patch.start()
        self.addCleanup(self.persist_patch.stop)
        self.confirm = runner.OwnerConfirmations(runner.PROJECT, Path(self.temp.name))

    def test_model_confirmation_binds_fixed_owner_resource_stage_and_digest(self):
        digest = "a" * 64
        self.assertTrue(self.confirm.model_governance(runner.PROJECT, "public-example-chat", "provider-create", digest))
        row = self.confirm.journal["confirmations"][0]
        self.assertEqual(row["digest"], digest)
        self.assertEqual(row["confirmation"], f"{runner.PROJECT} model public-example-chat provider-create {digest}")
        self.assertFalse(self.confirm.model_governance(runner.PROJECT, "other-provider", "provider-create", digest))
        self.assertFalse(self.confirm.model_governance(runner.PROJECT, "public-example-chat", "provider-disable", digest))

    def test_phrase_confirmation_allows_only_provider_health_source_and_exact_access_subjects(self):
        digest = "b" * 64
        accepted = (
            f"{runner.PROJECT} provider-probe chat deployment-1 {digest}",
            f"{runner.PROJECT} apply model-health deployment-1 revision:2 {digest}",
            f"{runner.PROJECT} knowledge go source-create {digest}",
            f"{runner.PROJECT} Model AccessPolicy demo.go.user create {digest}",
            f"{runner.PROJECT} grant demo.go.user {runner.replay.role_binding_id(runner.PROJECT, 'example-go-operations')} {digest}",
        )
        for phrase in accepted:
            with self.subTest(phrase=phrase):
                self.assertTrue(self.confirm.phrase(phrase))
        self.assertFalse(self.confirm.phrase(f"other-owner provider-probe chat deployment-1 {digest}"))
        self.assertFalse(self.confirm.phrase(f"{runner.PROJECT} knowledge go source-delete {digest}"))
        self.assertFalse(self.confirm.phrase(f"{runner.PROJECT} Model AccessPolicy unknown-user create {digest}"))

    def test_policy_confirmation_is_bound_to_exact_release_target(self):
        plan = {"version": {"id": "example-go-v0-2-3-owner"}}
        allow = runner.confirm_for_policy(self.confirm, runner.PROJECT, "example-go-operations", plan)
        self.assertTrue(allow("create drafts example-go-operations@example-go-v0-2-3-owner"))
        self.assertTrue(allow("publish six policies example-go-operations@example-go-v0-2-3-owner"))
        self.assertTrue(allow("publish snapshot example-go-operations@example-go-v0-2-3-owner rev3"))
        self.assertTrue(allow("publish snapshot example-go-operations@example-go-v0-2-3-owner rev0"))
        self.assertFalse(allow("create drafts example-java-tickets@wrong-version"))
        self.assertFalse(allow("publish snapshot example-java-tickets@wrong-version rev0"))

    def test_existing_runner_receipt_stops_automatic_replay(self):
        self.confirm.journal["phases"]["catalog-submit:example-go-operations"] = {"status": "failed"}
        with self.assertRaisesRegex(RuntimeError, "already has a runner receipt"):
            self.confirm.start_phase("catalog-submit:example-go-operations")


if __name__ == "__main__":
    unittest.main()
