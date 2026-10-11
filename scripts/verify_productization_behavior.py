"""Check productization behavior against the current modular-monolith source.

This is an evidence-oriented source gate, not a build or E2E replacement. It
must follow the active Platform composition root and must never pass because a
retired Backend/Harness/Worker implementation happens to remain in the tree.

该检查器只核对当前模块化平台的接线证据，不代替构建或 E2E；退役的旧
Backend/Harness/Worker 源码不得再作为通过依据。
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Iterable, Sequence


ROOT = pathlib.Path(__file__).resolve().parents[1]
TASKS = (
    "PF-10", "PF-12", "PF-13", "PF-14", "PF-15", "PF-16", "PF-17", "PF-18",
    "PF-23", "PF-24", "PF-25", "PF-26", "PF-27", "PF-28", "PF-29",
)


def _without_comments(source: str) -> str:
    """Remove comments before checking source behavior tokens."""
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return re.sub(r"//[^\r\n]*|(^|\s)#.*?$", r"\1", source, flags=re.MULTILINE)


def _has_meaningful_code(source: str) -> bool:
    code = _without_comments(source)
    code = re.sub(r"\bpackage\s+[A-Za-z_][A-Za-z0-9_]*", "", code)
    code = re.sub(r"\bimport\s*(?:\([^)]*\)|\"[^\"]*\")", "", code, flags=re.DOTALL)
    return bool(re.sub(r"[\s{}();,]", "", code))


class Checker:
    """Read current source and emit stable, machine-readable card evidence."""

    def __init__(self, root: pathlib.Path, compose: pathlib.Path):
        self.root = root
        self.compose = compose
        self.cache: dict[str, str | None] = {}
        self.cards: dict[str, dict[str, object]] = {
            task: {"task": task, "status": "PASS", "checks": []} for task in TASKS
        }
        self.gaps: list[dict[str, str]] = []

    def read(self, relative: str) -> str | None:
        if relative not in self.cache:
            path = pathlib.Path(relative)
            if not path.is_absolute():
                path = self.root / path
            try:
                self.cache[relative] = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                self.cache[relative] = None
        return self.cache[relative]

    def add(self, task: str, name: str, ok: bool, evidence: Sequence[str], detail: str,
            missing: Iterable[str] = (), gap: str | None = None) -> None:
        missing_list = list(missing)
        if gap and not ok:
            self.gaps.append({"task": task, "check": name, "reason": gap})
            missing_list.append(gap)
        result = {
            "id": f"{task}:{name}", "name": name,
            "status": "PASS" if ok else "FAIL", "evidence": list(evidence),
            "detail": detail, "missing": missing_list,
        }
        checks = self.cards[task]["checks"]
        assert isinstance(checks, list)
        checks.append(result)
        if not ok:
            self.cards[task]["status"] = "FAIL"

    def behavior(self, task: str, name: str, sources: Sequence[str], patterns: Sequence[str],
                 detail: str, *, any_pattern: bool = False, gap: str | None = None) -> None:
        missing: list[str] = []
        parts: list[str] = []
        for relative in sources:
            source = self.read(relative)
            if source is None:
                missing.append(f"missing or unreadable current source: {relative}")
            elif not _has_meaningful_code(source):
                missing.append(f"current source has no meaningful code: {relative}")
            else:
                parts.append(_without_comments(source))
        combined = "\n".join(parts)
        matches = [bool(re.search(pattern, combined, re.IGNORECASE | re.DOTALL)) for pattern in patterns]
        if not (any(matches) if any_pattern else all(matches)):
            missing.append("missing current behavior token(s): " + ", ".join(patterns))
        self.add(task, name, not missing, sources, detail, missing, gap)

    def compose_check(self, task: str, name: str, *, present: str | None = None,
                      absent: str | None = None, detail: str) -> None:
        relative = self.compose.as_posix()
        source = self.read(relative)
        missing: list[str] = []
        if source is None:
            missing.append(f"missing or unreadable Compose file: {relative}")
        else:
            if present and not re.search(present, source, re.MULTILINE | re.IGNORECASE):
                missing.append(f"Compose missing active service/build wiring: {present}")
            if absent and re.search(absent, source, re.MULTILINE | re.IGNORECASE):
                missing.append(f"retired service/build reference remains active: {absent}")
        self.add(task, name, not missing, [relative], detail, missing)

    def run(self) -> dict[str, object]:
        # PF-10: declarative mappings are validated and executed by Agent Factory.
        self.behavior("PF-10", "current_mapping_validation_and_dry_run",
            ["platform/internal/agentfactory/model.go", "platform/internal/agentfactory/service.go"],
            [r"type\s+Mapping\s+struct", r"func\s+\(s\s+Service\)\s+DryRun\s*\(",
             r"func\s+\(d\s+\*mappingDocument\)\s+Evaluate\s*\("],
            "The active Agent Factory validates and dry-runs declaration mappings.")

        # PF-12: language-neutral adapters remain independently conformant.
        self.behavior("PF-12", "adapter_entrypoints_and_multilang_conformance",
            ["adapters/grpc-mapping/cmd/adapter/main.go", "adapters/process/cmd/adapter/main.go",
             "adapters/sidecar/cmd/adapter/main.go", "scripts/run_template_conformance.py",
             "conformance/runner/run.py"],
            [r"func\s+main\s*\(", r"def\s+main\s*\(", r"agent-execution/v2",
             r"installation_id", r"HTTP Conformance"],
            "Current adapter entrypoints and the live language-template HTTP conformance runner are present.")

        # PF-13: evaluation is an in-process Platform module with an active dispatcher.
        self.behavior("PF-13", "modular_evaluation_module_and_dispatcher",
            ["platform/internal/evaluationproduct/module.go", "platform/internal/evaluationproduct/runner.go",
             "platform/cmd/platform/main.go"],
            [r"evaluationproduct\.NewModule\s*\(", r"modules\.Register\(productModule\)",
             r"evaluationproduct\.NewRunner\s*\(", r"func\s+\(m\s+\*Module\)\s+Start\s*\(",
             r"func\s+\(r\s+\*Runner\)\s+Start\s*\("],
            "Evaluation Product is registered and its dispatcher is started by the Platform composition root.")

        # PF-14: remote metrics have an explicit Product->Metric Runner contract.
        self.behavior("PF-14", "metric_registry_and_remote_evaluator",
            ["platform/internal/evaluationproduct/metric_runner.go", "platform/internal/evaluationproduct/types.go",
             "workers/metric-runner/internal/aggregate/aggregate.go"],
            [r"type\s+RemoteMetricEvaluator\s+struct", r"EvaluateMetric\s*\(",
             r"type\s+MetricOutcome\s+struct", r"package\s+aggregate"],
            "Product metric outcomes are bound to an isolated remote evaluator contract.")

        # PF-15: the Platform runner is not an extra independent business process.
        self.behavior("PF-15", "single_process_evaluation_runner",
            ["platform/internal/evaluationproduct/module.go", "platform/internal/evaluationproduct/runner.go",
             "platform/cmd/platform/main.go"],
            [r"func\s+\(r\s+\*Runner\)\s+Start\s*\(",
             r"evaluationproduct\.NewRunner\s*\(", r"lifecycle\.Start\s*\("],
            "Evaluation run scheduling executes inside the modular Platform process.")
        self.compose_check("PF-15", "retired_evaluation_worker_not_deployed",
            absent=r"(?m)^\s{2}evaluation-worker\s*:",
            detail="The old standalone evaluation worker must not return to the single-instance Compose topology.")

        # PF-16: only untrusted/custom metric execution remains isolated.
        self.behavior("PF-16", "isolated_metric_runner_service",
            ["workers/metric-runner/cmd/metric-service/main.go", "workers/metric-runner/internal/engine/engine.go",
             "workers/metric-runner/internal/sandbox/plugin.go"],
            [r"requireBearer", r"func\s+Handle\s*\(", r"sandbox\.Validate", r"runner\.Execute"],
            "Custom metric execution is isolated behind an authenticated and admission-checked service.")
        self.compose_check("PF-16", "metric_runner_compose_wiring",
            present=r"(?m)^\s{2}metric-runner\s*:",
            detail="The dedicated high-risk metric execution service is present in the modular Compose profile.")

        # PF-17/18: review/Gate and artifacts are part of Evaluation Product.
        self.behavior("PF-17", "review_and_fail_closed_gate",
            ["platform/internal/evaluationproduct/module.go"],
            [r"func\s+\(m\s+\*Module\)\s+reviews\s*\(",
             r"func\s+\(m\s+\*Module\)\s+evaluateGate\s*\(", r"hasApprovedReview", r"GateBlocked"],
            "Human review and fail-closed release Gate are enforced by the active module.")
        self.behavior("PF-18", "scoped_evaluation_artifact_persistence",
            ["platform/internal/evaluationproduct/sql_artifact.go", "platform/internal/evaluationproduct/runner.go",
             "platform/cmd/platform/main.go"],
            [r"PutEvaluationOutput\s*\(", r"ArtifactReference", r"evaluationproduct\.NewRunner\s*\(",
             r"evaluationProductStore"],
            "Evaluation outputs are persisted through the scope-aware artifact store used by the active Runner.")

        # PF-23/24/25: approved Provider metadata, policy and model calls share one path.
        self.behavior("PF-23", "approved_provider_secret_runtime",
            ["platform/internal/modelgateway/http_adapter.go", "platform/internal/modelgovernance/runtime_metadata.go",
             "platform/cmd/platform/main.go"],
            [r"func\s+NewHTTPAdapter\s*\(", r"GetApprovedProvider", r"MountedSecretResolver",
             r"SetGovernedModelInvocation"],
            "The active Platform resolves approved Provider/Model metadata and mounted Secrets before HTTP invocation.")
        self.behavior("PF-24", "model_access_and_policy_runtime_binding",
            ["platform/internal/modelgovernance/access_resolver.go", "platform/internal/capability/module.go",
             "platform/cmd/platform/main.go"],
            [r"func\s+\(r\s+AccessResolver\)\s+ResolveModel\s*\(",
             r"SetGovernedModelInvocation", r"SetModelBilling", r"modelAccess\.ResolveModel"],
            "Model access and billing policy are connected to the active Capability runtime.")
        self.behavior("PF-25", "governed_model_gateway_invocation",
            ["platform/internal/modelgateway/port.go", "platform/internal/capability/module.go",
             "platform/cmd/platform/main.go"],
            [r"type\s+Port\s+interface", r"m\.modelGateway\.Generate\s*\(",
             r"SetGovernedModelInvocation"],
            "Agent model calls enter the Platform-owned governed Model Gateway port.")

        # PF-26: durable pre-reservation, settle, release and reconciliation are wired.
        self.behavior("PF-26", "atomic_price_budget_runtime_chain",
            ["platform/internal/capability/module.go", "platform/internal/capability/model_billing.go",
             "platform/internal/capability/model_budget_admission_wait.go",
             "platform/internal/usagecost/model_budget.go", "platform/cmd/platform/main.go"],
            [r"reserveModelBudgetAdmission\s*\(r\.Context\(\),\s*m\.modelBudgets,\s*budgetRequest\)",
             r"reservation,\s*err\s*:=\s*store\.Reserve\s*\(waitCtx,\s*request\)",
             r"modelBudgets\.Settle\s*\(", r"modelBudgets\.Release\s*\(",
             r"func\s+\(s\s+\*SQLStore\)\s+Reserve\s*\(", r"SetModelBilling"],
            "Approved prices and shared SQL budget ledger are wired around real model calls.")

        # PF-27: do not let the retired Harness lease implementation count as a pass.
        self.behavior("PF-27", "current_model_capacity_governance",
            ["platform/internal/modelgovernance/module.go", "platform/internal/capability/module.go",
             "platform/cmd/platform/main.go"],
            [r"CapacityProvider", r"AcquireCapacity", r"ReleaseCapacity", r"SetModelCapacity"],
            "Local-model capacity is enforced by the current Platform path; retired Harness code is not accepted as evidence.")

        # PF-28/29: current UI and current-source test behavior, not retired APIs.
        self.behavior("PF-28", "modular_governance_console_wiring",
            ["frontend/src/features/model-governance/ModelGovernance.jsx", "frontend/src/api.js",
             "platform/cmd/platform/main.go"],
            [r"modelProviders|model-governance", r"modules\.Register\(modelModule\)", r"evaluation-product"],
            "The console uses current Model Governance APIs and the Platform registers the module.", any_pattern=True)
        self.behavior("PF-29", "current_source_model_governance_e2e",
            ["platform/internal/capability/model_billing_postgres_integration_test.go",
             "scripts/verify_public_knowledge_postgres.py"],
            [r"TestGovernedModelBillingPostgresIntegration", r"ApprovePriceVersion",
             r"NewSQLStore", r"GetSnapshot", r"go_settings\s*=",
             r"PUBLIC_TEST_POSTGRES_MIGRATION_DSN", r"runtime_internal_dsn",
             r"go_json_summary"],
            "Current-source PostgreSQL integration prepares approved governance facts and checks durable model usage. The owned platform-all-go runner executes the integration; this source check does not assert browser approval or live vendor acceptance.")
        self.behavior("PF-29", "current_source_model_budget_e2e",
            ["platform/internal/capability/model_billing_postgres_integration_test.go", "scripts/verify_public_knowledge_postgres.py"],
            [r"TestGovernedModelBillingPostgresIntegration", r"httptest\.NewServer",
             r"ApprovePriceVersion", r"MODEL_BUDGET_EXCEEDED",
             r"providerCalls\.Load\(\)\s*!=\s*1",
             r"actual_micros,reserved_micros",
             r"COUNT\(\*\)\s+FILTER\s*\(WHERE status='released'\)",
             r"command\s*=\s*\[\*container_prefix,\s*'go',\s*'test',\s*'-json'.*?'\./\.\.\.'\]",
             r"GO_GOVERNED_BILLING_REQUIRED_TESTS",
             r"required_platform_go_test_states\(log,\s*GO_GOVERNED_BILLING_REQUIRED_TESTS\)",
             r"set\(required_go_states\)\s*==\s*set\(required_go_names\)",
             r"all\(status\s*==\s*'pass'\s*for status in required_go_states.values\(\)\)",
             r"receipt\['tests_passed'\].*?required_go_ok"],
            "The isolated platform-all-go runner executes real PostgreSQL billing through the guarded HTTP Model Gateway and requires every governed billing integration to pass without skips. Coverage includes approved-price reservation, failure release, actual-usage settlement, replay and pre-call rejection. The upstream is a deterministic OpenAI-compatible endpoint; this is not a real vendor call or a browser-to-Agent run.",
            gap="The owned current-source runner does not require all PostgreSQL governed billing cases to execute successfully.")

        cards = [self.cards[task] for task in TASKS]
        failures = [check for card in cards for check in card["checks"] if check["status"] == "FAIL"]  # type: ignore[index]
        return {"schema_version": "productization-behavior/v2", "ok": not failures,
                "scope": list(TASKS), "root": str(self.root), "compose": str(self.compose),
                "cards": cards, "failures": failures, "gaps": self.gaps}


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check current modular productization wiring and emit JSON.")
    parser.add_argument("--root", type=pathlib.Path, default=ROOT, help="repository root")
    parser.add_argument("--compose", type=pathlib.Path, default=pathlib.Path("compose.yaml"), help="Compose file relative to root")
    parser.add_argument("--compact", action="store_true", help="emit one-line JSON")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    root = args.root.resolve()
    compose = args.compose if args.compose.is_absolute() else root / args.compose
    report = Checker(root, compose).run()
    print(json.dumps(report, ensure_ascii=False, separators=(",", ":") if args.compact else None))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
