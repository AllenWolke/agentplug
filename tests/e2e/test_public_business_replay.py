"""Offline checks of submission ambiguity, isolation and billing replay windows."""
from copy import deepcopy
import unittest
from urllib.parse import urlsplit, parse_qs

import public_business_replay as business

PROJECT = "agentplug-test-public-012345abcdef"
SCOPE = {"tenant_id": "tenant-demo", "department_id": "dept-demo", "application_id": "app-demo"}
VERSIONS = {"go": "go-v6", "python": "python-v4", "java": "java-v6"}


class HTTPError(RuntimeError):
    def __init__(self, status):
        self.status = status


class API:
    def __init__(self, username, item, scope=SCOPE):
        self.username = username
        self.item = item
        self.scope = dict(scope)
        self.calls = []
        self.session = None
        self.run = None
        self.lost = False
        self.extra_usage = False
        self.replayed = False
        self.usage_end_times = []
        self.usage_count = 1
        self.usage_scope_override = {}
        self.malformed_usage = False
        self.message_reply = None
        self.cancel_reply = None

    def call(self, method, path, body=None):
        self.calls.append((method, path))
        if path == "/auth/me":
            return {"username": self.username, **self.scope}
        if "/catalog/installations/" in path:
            return {**self.scope, "id": self.item["installation_id"], "agent_id": self.item["agent_id"], "version_id": self.item["agent_version_id"], "status": "active"}
        if "/usage/runs/" in path:
            query = parse_qs(urlsplit(path).query)
            self.usage_end_times.append(query["to"][0])
            count = self.usage_count + int(self.extra_usage and self.replayed)
            all_rows = [{"index": index, "event_id": "usage-" + str(index), "step_id": "step-" + str(index),
                         "occurred_at": query["from"][0], "provider": "example-provider", "model": "teaching-model",
                         "input_tokens": 100, "output_tokens": 20, "cost_micros": 1000}
                        for index in range(1, count + 1)]
            page = int(query["page"][0])
            page_size = int(query["page_size"][0])
            rows = all_rows[(page - 1) * page_size:page * page_size]
            if self.malformed_usage and rows:
                rows[0].pop("model")
            usage_scope = {**self.scope, **{key: self.item[key] for key in ("run_id", "agent_id", "agent_version_id")}, **self.usage_scope_override}
            return {"scope": usage_scope, "from": query["from"][0], "to": query["to"][0], "items": rows,
                    "total": count, "page": page, "page_size": page_size}
        if method == "GET" and path.endswith("/messages?page_size=100"):
            if self.message_reply is not None:
                return deepcopy(self.message_reply)
            return {"items": [{"id": "answer-1", "role": "assistant", "content": "Teaching answer", "metadata": {"schema": self.item["output_schema"], "context_checks": {"checked": True}, "knowledge": [{"document_id": "repository-handbook"}]}}],
                    "total": 1, "page": 1, "page_size": 100}
        if method == "GET" and path.startswith(business.RUNS):
            if self.run is None:
                raise HTTPError(404)
            return deepcopy(self.run)
        if method == "GET" and path.startswith(business.PREFIX):
            if self.session is None:
                raise HTTPError(404)
            return deepcopy(self.session)
        if method == "POST" and path == business.PREFIX:
            if self.lost:
                raise RuntimeError("session response lost")
            self.session = {**self.scope, **body, "owner_id": self.username, "installation_id": self.item["installation_id"]}
            return deepcopy(self.session)
        if path.endswith("/cancel"):
            if self.cancel_reply is not None:
                return deepcopy(self.cancel_reply)
            self.run["status"] = "cancelling"
            self.run["revision"] += 1
            return deepcopy(self.run)
        if method == "POST" and path.endswith("/runs"):
            if self.run:
                self.replayed = True
            else:
                self.run = {"run_id": self.item["run_id"], "agent_version_id": self.item["agent_version_id"], "revision": 1, "status": "accepted",
                            "scope": {**self.scope, "principal_type": "user", "principal_id": self.username,
                                      "agent_instance_id": self.item["installation_id"],
                                      **{key: self.item[key] for key in ("agent_id", "agent_version_id", "installation_id", "session_id", "run_id")}}}
            return {"run_id": self.item["run_id"]}
        raise AssertionError("unexpected API call")


class BusinessReplayTests(unittest.TestCase):
    def test_new_bounded_scenario_preserves_old_plan_and_uses_fresh_handles(self):
        old = business.build_plan(PROJECT, SCOPE, VERSIONS)
        new = business.build_plan(PROJECT, SCOPE, VERSIONS, "bounded-20261007-02")
        self.assertEqual(business.validate_plan(old, PROJECT, SCOPE), old)
        self.assertEqual(business.validate_plan(new, PROJECT, SCOPE), new)
        self.assertTrue({r['run_id'] for r in old['cases']}.isdisjoint(r['run_id'] for r in new['cases']))
        bad = deepcopy(new)
        bad['cases'][0]['request']['symptom'] = 'different unreviewed query'
        with self.assertRaises(ValueError):
            business.validate_plan(bad, PROJECT, SCOPE)
        with self.assertRaises(ValueError):
            business.build_plan(PROJECT, SCOPE, VERSIONS, '../unsafe')

    def setUp(self):
        self.plan = business.build_plan(PROJECT, SCOPE, VERSIONS)
        self.item = business.selected(self.plan, "go", "baseline")
        self.owner = API(self.item["owner"], self.item)
        self.admin = API("system.admin", self.item)
        self.journal = {}

    def submit(self):
        return business.submit(self.owner, self.admin, self.plan, PROJECT, SCOPE, "go", "baseline", self.journal, lambda *args: True, lambda value: None)

    def test_business_plan_cannot_inject_policy_or_choose_another_owner(self):
        for key, value in (("owner", "system.admin"), ("request", {"service": "api", "policy_snapshot": {"runtime": {"unlimited": True}}})):
            bad = deepcopy(self.plan)
            bad["cases"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                business.validate_plan(bad, PROJECT, SCOPE)

    def test_ambiguous_session_create_cannot_be_resubmitted(self):
        self.owner.lost = True
        with self.assertRaisesRegex(RuntimeError, "response lost"):
            self.submit()
        self.owner.lost = False
        with self.assertRaisesRegex(RuntimeError, "never resubmit"):
            self.submit()
        self.assertEqual(sum(method == "POST" for method, _ in self.owner.calls), 1)

    def test_original_run_observation_does_not_submit_replacements(self):
        self.submit()
        before = sum(method == "POST" for method, _ in self.owner.calls)
        for _ in range(2):
            result = business.observe(self.owner, self.plan, PROJECT, SCOPE, "go", "baseline", self.journal, lambda value: None)
            self.assertEqual(result["status"], "accepted")
            self.assertFalse(result["replacement_run_created"])
        self.assertEqual(sum(method == "POST" for method, _ in self.owner.calls), before)

    def test_success_replay_preserves_run_output_and_entire_usage(self):
        self.submit()
        self.owner.run.update(status="succeeded", revision=4)
        result = business.verify_success_and_replay(self.owner, self.admin, self.plan, PROJECT, SCOPE, "go", self.journal, lambda *args: True, lambda value: None)
        self.assertTrue(result["replay_verified"])
        self.assertEqual(result["usage_events"], 1)
        self.assertNotEqual(self.admin.usage_end_times[0], self.admin.usage_end_times[1])

    def test_billed_replay_is_detected_by_extended_usage_window(self):
        self.submit()
        self.owner.run.update(status="succeeded", revision=4)
        self.admin.extra_usage = True
        original_call = self.owner.call
        def owner_call(method, path, body=None):
            result = original_call(method, path, body)
            if self.owner.replayed:
                self.admin.replayed = True
            return result
        self.owner.call = owner_call
        with self.assertRaisesRegex(RuntimeError, "actual cumulative Usage"):
            business.verify_success_and_replay(self.owner, self.admin, self.plan, PROJECT, SCOPE, "go", self.journal, lambda *args: True, lambda value: None)

    def test_cancellation_receipt_does_not_claim_provider_stop(self):
        item = business.selected(self.plan, "go", "cancel")
        owner = API(item["owner"], item)
        admin = API("system.admin", item)
        business.submit(owner, admin, self.plan, PROJECT, SCOPE, "go", "cancel", self.journal, lambda *args: True, lambda value: None)
        result = business.request_cancel(owner, self.plan, PROJECT, SCOPE, "go", self.journal, lambda *args: True, lambda value: None)
        self.assertTrue(result["cancellation_requested"])
        self.assertFalse(result["provider_stop_proven"])
        self.assertFalse(result["billing_settlement_proven"])
        with self.assertRaisesRegex(RuntimeError, "single cancellation"):
            business.request_cancel(owner, self.plan, PROJECT, SCOPE, "go", self.journal, lambda *args: True, lambda value: None)

    def test_foreign_scope_is_not_accepted_as_own_run(self):
        self.submit()
        self.owner.run["scope"]["principal_id"] = "demo.java.user"
        with self.assertRaisesRegex(RuntimeError, "trusted scope"):
            business.observe(self.owner, self.plan, PROJECT, SCOPE, "go", "baseline", self.journal, lambda value: None)

    def test_run_instance_must_match_exact_catalog_installation(self):
        self.submit()
        self.owner.run["scope"]["agent_instance_id"] = "different-installation"
        with self.assertRaisesRegex(RuntimeError, "trusted scope"):
            business.observe(self.owner, self.plan, PROJECT, SCOPE, "go", "baseline", self.journal, lambda value: None)

    def test_message_page_must_be_complete_before_replay(self):
        self.submit()
        self.owner.run.update(status="succeeded", revision=4)
        self.owner.message_reply = {"items": [{"id": "answer-1", "role": "assistant", "content": "Teaching answer",
                                                "metadata": {"schema": self.item["output_schema"], "context_checks": {"checked": True}, "knowledge": [{"document_id": "repository-handbook"}]}}],
                                    "total": 2, "page": 1, "page_size": 100}
        with self.assertRaisesRegex(RuntimeError, "message history page"):
            business.verify_success_and_replay(self.owner, self.admin, self.plan, PROJECT, SCOPE, "go", self.journal, lambda *args: True, lambda value: None)
        self.assertEqual(sum(method == "POST" and path.endswith("/runs") for method, path in self.owner.calls), 1)

    def test_usage_requires_exact_org_scope_and_real_step_fields(self):
        for malformed_scope in (True, False):
            with self.subTest(malformed_scope=malformed_scope):
                plan = business.build_plan(PROJECT, SCOPE, VERSIONS)
                item = business.selected(plan, "go", "baseline")
                owner, admin, journal = API(item["owner"], item), API("system.admin", item), {}
                business.submit(owner, admin, plan, PROJECT, SCOPE, "go", "baseline", journal, lambda *args: True, lambda value: None)
                owner.run.update(status="succeeded", revision=4)
                if malformed_scope:
                    admin.usage_scope_override["application_id"] = "another-application"
                    expected_error = "Usage page does not match"
                else:
                    admin.malformed_usage = True
                    expected_error = "complete Usage DTO"
                with self.assertRaisesRegex(RuntimeError, expected_error):
                    business.verify_success_and_replay(owner, admin, plan, PROJECT, SCOPE, "go", journal, lambda *args: True, lambda value: None)
                self.assertEqual(sum(method == "POST" and path.endswith("/runs") for method, path in owner.calls), 1)

    def test_usage_full_page_walk_validates_all_steps(self):
        self.submit()
        self.owner.run.update(status="succeeded", revision=4)
        self.admin.usage_count = 101
        result = business.verify_success_and_replay(self.owner, self.admin, self.plan, PROJECT, SCOPE, "go", self.journal, lambda *args: True, lambda value: None)
        self.assertEqual(result["usage_events"], 101)
        usage_calls = [path for method, path in self.admin.calls if method == "GET" and "/usage/runs/" in path]
        self.assertEqual(len(usage_calls), 4)  # Two complete 100-row scans, each across both pages.

    def test_cancellation_receipt_must_match_run_and_confirm_pending_state(self):
        for change, expected_error in (({"run_id": "another-run"}, "Run handle"), ({"status": "accepted"}, "cancellation state")):
            with self.subTest(change=change):
                plan = business.build_plan(PROJECT, SCOPE, VERSIONS)
                item = business.selected(plan, "go", "cancel")
                owner, journal = API(item["owner"], item), {}
                business.submit(owner, API("system.admin", item), plan, PROJECT, SCOPE, "go", "cancel", journal, lambda *args: True, lambda value: None)
                receipt = deepcopy(owner.run)
                receipt.update(status="cancelling", revision=2)
                receipt.update(change)
                owner.cancel_reply = receipt
                with self.assertRaisesRegex(RuntimeError, expected_error):
                    business.request_cancel(owner, plan, PROJECT, SCOPE, "go", journal, lambda *args: True, lambda value: None)
                self.assertTrue(journal["cases"][item["run_id"]]["cancel_intent"])
                self.assertNotIn("cancel_receipt", journal["cases"][item["run_id"]])

    def test_authentication_failure_is_not_counted_as_authorization_denial(self):
        self.submit()
        self.owner.run.update(status="succeeded", revision=4)
        business.verify_success_and_replay(self.owner, self.admin, self.plan, PROJECT, SCOPE, "go", self.journal, lambda *args: True, lambda value: None)
        class Foreign:
            def call(self, method, path, body=None):
                if path == "/auth/me":
                    return {"username": "demo.python.user", **SCOPE}
                raise HTTPError(401)
        with self.assertRaisesRegex(RuntimeError, "authorization boundary"):
            business.verify_denials(Foreign(), self.admin, self.plan, PROJECT, SCOPE, "go", self.journal, lambda value: None)


if __name__ == "__main__":
    unittest.main()
