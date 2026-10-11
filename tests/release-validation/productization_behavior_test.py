"""Self-tests for the current modular productization behavior gate."""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import importlib.util


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_productization_behavior.py"
spec = importlib.util.spec_from_file_location("productization_behavior_gate", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def _card(report: dict, task: str) -> dict:
    return next(card for card in report["cards"] if card["task"] == task)


class ProductizationBehaviorGateTest(unittest.TestCase):
    def test_budget_helper_cannot_count_without_the_active_call(self) -> None:
        report = gate.Checker(ROOT, ROOT / "compose.yaml").run()
        original = next(check for check in _card(report, "PF-26")["checks"] if check["name"] == "atomic_price_budget_runtime_chain")
        self.assertEqual(original["status"], "PASS", original["missing"])
        checker = gate.Checker(ROOT, ROOT / "compose.yaml")
        relative = "platform/internal/capability/module.go"
        checker.cache[relative] = checker.read(relative).replace("reserveModelBudgetAdmission(r.Context(), m.modelBudgets, budgetRequest)", "unwiredBudgetAdmission(r.Context(), m.modelBudgets, budgetRequest)")
        changed = checker.run()
        check = next(check for check in _card(changed, "PF-26")["checks"] if check["name"] == "atomic_price_budget_runtime_chain")
        self.assertEqual(check["status"], "FAIL")

    def test_billing_sources_cannot_count_without_required_test_enforcement(self) -> None:
        report = gate.Checker(ROOT, ROOT / "compose.yaml").run()
        original = next(check for check in _card(report, "PF-29")["checks"] if check["name"] == "current_source_model_budget_e2e")
        self.assertEqual(original["status"], "PASS", original["missing"])
        for mutation in ("collector", "acceptance", "test_source"):
            with self.subTest(mutation=mutation):
                checker = gate.Checker(ROOT, ROOT / "compose.yaml")
                relative = "scripts/verify_public_knowledge_postgres.py"
                if mutation == "collector":
                    checker.cache[relative] = checker.read(relative).replace("required_platform_go_test_states(log, GO_GOVERNED_BILLING_REQUIRED_TESTS)", "{}")
                elif mutation == "acceptance":
                    checker.cache[relative] = checker.read(relative).replace("required_go_ok and", "True and")
                else:
                    checker.cache["platform/internal/capability/model_billing_postgres_integration_test.go"] = None
                changed = checker.run()
                check = next(check for check in _card(changed, "PF-29")["checks"] if check["name"] == "current_source_model_budget_e2e")
                self.assertEqual(check["status"], "FAIL")

    def test_repository_report_is_machine_readable(self) -> None:
        # Current source may intentionally report production gaps; JSON and all
        # requested cards must still be present. / 当前源码可以有生产缺口，但输出
        # 必须仍是 JSON，并包含全部核对任务卡。
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--compact"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        report = json.loads(proc.stdout)
        self.assertEqual(report["schema_version"], "productization-behavior/v2")
        self.assertEqual(
            report["scope"],
            [
                "PF-10",
                "PF-12",
                "PF-13",
                "PF-14",
                "PF-15",
                "PF-16",
                "PF-17",
                "PF-18",
                "PF-23",
                "PF-24",
                "PF-25",
                "PF-26",
                "PF-27",
                "PF-28",
                "PF-29",
            ],
        )

    def test_multilanguage_gate_uses_the_current_live_conformance_runner(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--compact"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        report = json.loads(proc.stdout)
        check = next(
            check
            for check in _card(report, "PF-12")["checks"]
            if check["name"] == "adapter_entrypoints_and_multilang_conformance"
        )
        self.assertEqual(check["status"], "PASS", check["missing"])
        self.assertIn("scripts/run_template_conformance.py", check["evidence"])
        self.assertNotIn("tests/e2e/multilang_conformance_test.go", check["evidence"])

    def test_modular_runner_passes_without_legacy_evaluation_worker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="modular-productization-behavior-") as directory:
            fixture = pathlib.Path(directory)
            module = fixture / "platform" / "internal" / "evaluationproduct" / "module.go"
            runner = fixture / "platform" / "internal" / "evaluationproduct" / "runner.go"
            main = fixture / "platform" / "cmd" / "platform" / "main.go"
            module.parent.mkdir(parents=True, exist_ok=True)
            runner.parent.mkdir(parents=True, exist_ok=True)
            main.parent.mkdir(parents=True)
            module.write_text(
                "package evaluationproduct\n"
                "func (m *Module) Start(ctx context.Context) error { return lifecycle.Start(ctx) }\n",
                encoding="utf-8",
            )
            runner.write_text(
                "package evaluationproduct\n"
                "func (r *Runner) Start(ctx context.Context) error { return nil }\n",
                encoding="utf-8",
            )
            main.write_text(
                "package main\n"
                "func wire() { runner, err := evaluationproduct.NewRunner(); _ = runner; _ = err }\n",
                encoding="utf-8",
            )
            compose = fixture / "compose.yaml"
            compose.write_text(
                "services:\n  platform-app:\n    build: ./platform\n",
                encoding="utf-8",
            )

            def run_gate(expected_code: int = 1) -> dict:
                proc = subprocess.run(
                    [sys.executable, str(SCRIPT), "--root", str(fixture), "--compact"],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    check=False,
                )
                self.assertEqual(proc.returncode, expected_code)
                return json.loads(proc.stdout)

            modular_report = run_gate()
            runner_check = next(
                check
                for check in _card(modular_report, "PF-15")["checks"]
                if check["name"] == "single_process_evaluation_runner"
            )
            self.assertEqual(runner_check["status"], "PASS")
            absent_worker = next(
                check
                for check in _card(modular_report, "PF-15")["checks"]
                if check["name"] == "retired_evaluation_worker_not_deployed"
            )
            self.assertEqual(absent_worker["status"], "PASS")

            compose.write_text(
                "services:\n  platform-app:\n    build: ./platform\n"
                "  evaluation-worker:\n    build: ./workers/evaluation-worker\n",
                encoding="utf-8",
            )
            legacy_report = run_gate()
            retired_worker = next(
                check
                for check in _card(legacy_report, "PF-15")["checks"]
                if check["name"] == "retired_evaluation_worker_not_deployed"
            )
            self.assertEqual(retired_worker["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
