#!/usr/bin/env python3
"""Exercise real reviewed CodeQL flows plus fail-closed negative controls."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import filter_codeql_false_positives as policy


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/codeql/reviewed-go.sarif"


class ReviewedFalsePositiveTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="agentplug-codeql-fp-")
        self.addCleanup(self.work.cleanup)
        self.repo = Path(self.work.name) / "repo"
        self.repo.mkdir()
        self.sarif = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.manifest = json.loads(policy.MANIFEST.read_text(encoding="utf-8"))
        # Controlled source fixtures test policy invalidation independently of
        # future production edits. The real-source integration is run separately.
        for entry in self.manifest["exceptions"]:
            for relative in entry["source_sha256"]:
                target = self.repo / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                data = ("// Controlled guard fixture: " + relative + "\n").encode()
                target.write_bytes(data)
                entry["source_sha256"][relative] = hashlib.sha256(data).hexdigest()

    def apply(self):
        return policy.filter_sarif(self.sarif, self.manifest, self.repo)

    def add_changed_finding(self, change, index=0):
        finding = copy.deepcopy(self.sarif["runs"][0]["results"][index])
        change(finding)
        self.sarif["runs"][0]["results"].append(finding)
        result, receipt = self.apply()
        self.assertEqual(result["runs"][0]["results"], [finding])
        self.assertEqual(receipt["excluded_results"], 5)
        self.assertEqual(receipt["retained_results"], 1)

    def test_the_five_real_reviewed_data_flows_match(self):
        output, receipt = self.apply()
        self.assertEqual(receipt["excluded_results"], 5)
        self.assertEqual(receipt["retained_results"], 0)
        self.assertEqual(output["runs"][0]["results"], [])
        self.assertEqual(len(self.sarif["runs"][0]["results"]), 5)

    def test_new_security_rule_is_retained(self):
        self.add_changed_finding(lambda item: item.update(ruleId="go/sql-injection"))

    def test_same_rule_at_another_line_is_retained(self):
        self.add_changed_finding(lambda item: item["locations"][0]["physicalLocation"]["region"].update(startLine=117))

    def test_same_rule_at_another_column_is_retained(self):
        self.add_changed_finding(lambda item: item["locations"][0]["physicalLocation"]["region"].update(startColumn=24))

    def test_same_sink_with_a_new_untrusted_source_is_retained(self):
        def change(item):
            source = item["codeFlows"][0]["threadFlows"][0]["locations"][0]["location"]
            source["physicalLocation"]["artifactLocation"]["uri"] = "workers/metric-runner/cmd/new-handler/main.go"
        self.add_changed_finding(change)

    def test_same_sink_with_a_changed_flow_step_is_retained(self):
        def change(item):
            item["codeFlows"][0]["threadFlows"][0]["locations"][1]["location"]["message"]["text"] = "unguarded path"
        self.add_changed_finding(change)

    def test_changed_data_flow_role_is_retained(self):
        def change(item):
            item["codeFlows"][0]["threadFlows"][0]["locations"][0]["taxa"][0]["properties"]["CodeQL/DataflowRole"] = "sink"
        self.add_changed_finding(change)

    def test_missing_flow_is_not_assumed_safe(self):
        self.add_changed_finding(lambda item: item.pop("codeFlows"))

    def test_new_related_source_is_retained(self):
        self.add_changed_finding(lambda item: item["relatedLocations"][0]["physicalLocation"]["region"].update(startLine=103))

    def test_changed_result_severity_is_retained(self):
        self.add_changed_finding(lambda item: item.update(level="error"))

    def test_changed_result_message_is_retained(self):
        self.add_changed_finding(lambda item: item["message"].update(text="A different path traversal finding."))

    def test_all_reviewed_guard_dependencies_invalidate_on_change(self):
        paths = {path for entry in self.manifest["exceptions"] for path in entry["source_sha256"]}
        original = self.sarif["runs"][0]["results"]
        for path in sorted(paths):
            with self.subTest(guard=path):
                target = self.repo / path
                before = target.read_bytes()
                target.write_bytes(before + b"// removed authorization check\n")
                try:
                    output, receipt = self.apply()
                    expected = [original[i] for i, entry in enumerate(self.manifest["exceptions"])
                                if path in entry["source_sha256"]]
                    self.assertEqual(output["runs"][0]["results"], expected)
                    self.assertTrue(all(state["status"] == "invalidated" for state in receipt["exceptions"]
                                        if path in state["changed_sources"]))
                finally:
                    target.write_bytes(before)

    def test_missing_guard_is_retained(self):
        entry = self.manifest["exceptions"][4]
        (self.repo / "platform/cmd/platform/coordinated_ancestry_guard.go").unlink()
        output, receipt = self.apply()
        self.assertEqual(output["runs"][0]["results"], [self.sarif["runs"][0]["results"][4]])
        self.assertEqual(receipt["exceptions"][4]["status"], "invalidated")
        self.assertIn(entry["path"], entry["source_sha256"])

    def test_incomplete_flow_dependency_review_is_retained(self):
        del self.manifest["exceptions"][0]["source_sha256"]["workers/metric-runner/internal/engine/engine.go"]
        output, _ = self.apply()
        self.assertEqual(output["runs"][0]["results"], [self.sarif["runs"][0]["results"][0]])

    def test_duplicate_matching_findings_are_all_retained(self):
        finding = copy.deepcopy(self.sarif["runs"][0]["results"][0])
        self.sarif["runs"][0]["results"].append(finding)
        output, receipt = self.apply()
        self.assertEqual(output["runs"][0]["results"], [finding, finding])
        self.assertEqual(receipt["exceptions"][0]["status"], "ambiguous_retained")

    def test_duplicates_across_runs_are_not_discarded(self):
        self.sarif["runs"].append(copy.deepcopy(self.sarif["runs"][0]))
        output, receipt = self.apply()
        self.assertEqual(output, self.sarif)
        self.assertEqual(receipt["excluded_results"], 0)

    def test_non_codeql_results_are_preserved(self):
        other = copy.deepcopy(self.sarif["runs"][0])
        other["tool"]["driver"]["name"] = "Another security scanner"
        self.sarif["runs"].append(other)
        output, _ = self.apply()
        self.assertEqual(output["runs"][1], other)

    def test_other_language_results_are_preserved(self):
        self.add_changed_finding(lambda item: item.update(ruleId="js/path-injection"))

    def test_analysis_diagnostics_rules_and_coverage_are_preserved(self):
        run = self.sarif["runs"][0]
        run["invocations"] = [{"executionSuccessful": False, "toolExecutionNotifications": [{"level": "error", "message": {"text": "extraction failed"}}]}]
        run["properties"] = {"metricResults": [{"value": 726, "ruleId": "go/summary/lines-of-code"}]}
        before = copy.deepcopy(self.sarif)
        output, _ = self.apply()
        self.assertEqual(self.sarif, before)
        output["runs"][0]["results"] = before["runs"][0]["results"]
        self.assertEqual(output, before)

    def test_transport_artifact_indices_do_not_change_the_review(self):
        def annotate(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "artifactLocation":
                        item.update(index=1234, uriBaseId="%SRCROOT%")
                    else:
                        annotate(item)
            elif isinstance(value, list):
                for item in value:
                    annotate(item)
        annotate(self.sarif)
        self.assertEqual(self.apply()[1]["excluded_results"], 5)

    def test_taxonomy_renumbering_preserves_semantic_flow_roles(self):
        for result in self.sarif["runs"][0]["results"]:
            for flow in result.get("codeFlows", []):
                for thread in flow["threadFlows"]:
                    for location in thread["locations"]:
                        for taxon in location.get("taxa", []):
                            taxon.update(index=4321, toolComponent={"index": 9876})
        self.assertEqual(self.apply()[1]["excluded_results"], 5)

    def test_missing_uri_resolves_through_artifact_table(self):
        run = self.sarif["runs"][0]
        location = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        run["artifacts"] = [{"location": {"uri": location["uri"]}}]
        location.clear()
        location["index"] = 0
        self.assertEqual(self.apply()[1]["excluded_results"], 5)

    def test_unknown_root_in_an_indexed_artifact_is_retained(self):
        run = self.sarif["runs"][0]
        location = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        run["artifacts"] = [{"location": {"uri": location["uri"], "uriBaseId": "%OTHERROOT%"}}]
        location.clear()
        location["index"] = 0
        output, _ = self.apply()
        self.assertEqual(output["runs"][0]["results"], [run["results"][0]])

    def test_absolute_uri_unknown_base_and_traversal_are_retained(self):
        for uri, base in (("file:///private/protocol.go", None), ("../protocol.go", None),
                          ("%2E%2E/protocol.go", None), ("workers/metric-runner/internal/protocol/protocol.go", "%OTHERROOT%")):
            with self.subTest(uri=uri, base=base):
                finding = copy.deepcopy(self.sarif["runs"][0]["results"][0])
                location = finding["locations"][0]["physicalLocation"]["artifactLocation"]
                location.update(uri=uri, uriBaseId=base)
                self.sarif["runs"][0]["results"].append(finding)
                output, _ = self.apply()
                self.assertEqual(output["runs"][0]["results"], [finding])
                self.sarif["runs"][0]["results"].pop()

    def test_lf_crlf_and_utf8_bom_checkouts_have_identical_hashes(self):
        for path in self.repo.rglob("*.go"):
            path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes().replace(b"\n", b"\r\n"))
        self.assertEqual(self.apply()[1]["excluded_results"], 5)

    def test_wildcard_paths_and_rules_are_rejected(self):
        for field, value in (("path", "**/protocol.go"), ("path", "../protocol.go"), ("rule_id", "go/*")):
            with self.subTest(field=field):
                manifest = copy.deepcopy(self.manifest)
                manifest["exceptions"][0][field] = value
                with self.assertRaises(ValueError):
                    policy.filter_sarif(self.sarif, manifest, self.repo)

    def test_duplicate_review_targets_are_rejected(self):
        extra = copy.deepcopy(self.manifest["exceptions"][0])
        extra["id"] = "another-name"
        self.manifest["exceptions"].append(extra)
        with self.assertRaises(ValueError):
            self.apply()

    def test_missing_reason_and_regression_evidence_are_rejected(self):
        for field, value in (("reason", ""), ("tests", [])):
            manifest = copy.deepcopy(self.manifest)
            manifest["exceptions"][0][field] = value
            with self.assertRaises(ValueError):
                policy.filter_sarif(self.sarif, manifest, self.repo)

    def test_missing_results_is_not_treated_as_a_successful_empty_scan(self):
        del self.sarif["runs"][0]["results"]
        with self.assertRaises(ValueError):
            self.apply()

    def test_empty_successful_scan_does_not_require_five_findings(self):
        self.sarif["runs"][0]["results"] = []
        self.assertEqual(self.apply()[1]["excluded_results"], 0)

    def cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "scripts/filter_codeql_false_positives.py"), *args],
                              capture_output=True, text=True, encoding="utf-8", check=False)

    def test_cli_preserves_original_and_emits_a_separate_receipt(self):
        work = Path(self.work.name)
        source, manifest, output, summary = [work / name for name in ("raw.sarif", "review.json", "filtered.sarif", "receipt.json")]
        source.write_text(json.dumps(self.sarif), encoding="utf-8")
        manifest.write_text(json.dumps(self.manifest), encoding="utf-8")
        original = source.read_bytes()
        result = self.cli("--input", str(source), "--output", str(output), "--summary", str(summary), "--manifest", str(manifest), "--repo", str(self.repo))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(source.read_bytes(), original)
        receipt = json.loads(summary.read_text(encoding="utf-8"))
        self.assertEqual(receipt["excluded_results"], 5)
        self.assertEqual(receipt["original_sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(receipt["upload_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())

    def test_cli_rejects_overwriting_original(self):
        source = Path(self.work.name) / "raw.sarif"
        source.write_text(json.dumps(self.sarif), encoding="utf-8")
        before = source.read_bytes()
        result = self.cli("--input", str(source), "--output", str(source), "--summary", str(source.with_suffix(".json")))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(source.read_bytes(), before)

    def test_cli_missing_or_malformed_input_fails_without_output(self):
        work = Path(self.work.name)
        source, output, summary = [work / name for name in ("raw.sarif", "filtered.sarif", "receipt.json")]
        for malformed in (False, True):
            if malformed:
                source.write_text("{bad json", encoding="utf-8")
            result = self.cli("--input", str(source), "--output", str(output), "--summary", str(summary))
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertFalse(summary.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
