package builtin

import (
	"math"
	"testing"

	"github.com/lexagent/metric-runner/contracts"
	"github.com/lexagent/metric-runner/internal/aggregate"
)

// closeTo compares floats with a small tolerance so golden expectations do not
// depend on exact floating-point rounding.
// closeTo 以小幅容差比较浮点数，避免黄金期望值依赖精确的浮点舍入。
func closeTo(got, want float64) bool { return math.Abs(got-want) < 1e-9 }

func mustOK(t *testing.T, r contracts.Result) float64 {
	t.Helper()
	if r.Status != contracts.StatusOK || r.Value == nil {
		t.Fatalf("expected OK with value, got %+v", r)
	}
	return *r.Value
}

// TestStandardIRProducesExpectedMetrics is the golden retrieval dataset: the same
// ranking must yield the documented recall/MRR/nDCG.
// TestStandardIRProducesExpectedMetrics 是黄金检索数据集：同一排名必须得到既定的
// recall/MRR/nDCG。
func TestStandardIRProducesExpectedMetrics(t *testing.T) {
	relevant := []string{"d1", "d2", "d3"}
	ranked := []string{"d4", "d2", "d1", "d3"}

	recall := mustOK(t, RecallAtK(relevant, ranked, 2))
	if !closeTo(recall, 1.0/3.0) {
		t.Fatalf("recall@2 = %v, want %v", recall, 1.0/3.0)
	}
	mrr := mustOK(t, MRRAtK(relevant, ranked, 2))
	if !closeTo(mrr, 0.5) {
		t.Fatalf("mrr@2 = %v, want 0.5", mrr)
	}
	ndcg := mustOK(t, NDCGAtK(relevant, ranked, 2))
	if !closeTo(ndcg, 0.38685280723454160) {
		t.Fatalf("ndcg@2 = %v, want 0.38685280723454160", ndcg)
	}
}

// TestBuiltinRetrievalMatchesAggregate proves the productized built-in metrics do
// not drift from the legacy aggregation the worker already depends on.
// TestBuiltinRetrievalMatchesAggregate 证明产品化后的内置指标没有偏离 Worker 已在依赖的
// 旧聚合实现。
func TestBuiltinRetrievalMatchesAggregate(t *testing.T) {
	relevant := []string{"d1", "d2", "d3"}
	ranked := []string{"d4", "d2", "d1", "d3"}
	legacyRecall, legacyMRR, legacyNDCG := aggregate.Retrieval(relevant, ranked, 4)

	if got := mustOK(t, RecallAtK(relevant, ranked, 4)); !closeTo(got, legacyRecall) {
		t.Fatalf("recall %v != legacy %v", got, legacyRecall)
	}
	if got := mustOK(t, MRRAtK(relevant, ranked, 4)); !closeTo(got, legacyMRR) {
		t.Fatalf("mrr %v != legacy %v", got, legacyMRR)
	}
	if got := mustOK(t, NDCGAtK(relevant, ranked, 4)); !closeTo(got, legacyNDCG) {
		t.Fatalf("ndcg %v != legacy %v", got, legacyNDCG)
	}
}

// TestZeroSamplesMissingCitationsNonFiniteAndInsufficientAreUnknown covers the
// shared fail-closed semantics: no metric may turn "no data" into a number.
// TestZeroSamplesMissingCitationsNonFiniteAndInsufficientAreUnknown 覆盖共享的失败闭合
// 语义：任何指标都不得把"无数据"变成数值。
func TestZeroSamplesMissingCitationsNonFiniteAndInsufficientAreUnknown(t *testing.T) {
	if got := RecallAtK(nil, nil, 5); got.Status != contracts.StatusUnknown {
		t.Fatalf("no relevant ids: got %+v", got)
	}
	if got := RecallAtK([]string{"d1"}, []string{"d1"}, 0); got.Status != contracts.StatusUnknown {
		t.Fatalf("non-positive k: got %+v", got)
	}
	if got := CitationCoverage(0, 0); got.Status != contracts.StatusUnknown {
		t.Fatalf("zero claims: got %+v", got)
	}
	if got := CitationPrecision(0, 0); got.Status != contracts.StatusUnknown {
		t.Fatalf("zero citations: got %+v", got)
	}
	if got := FactAccuracy(10, 11); got.Status != contracts.StatusUnknown {
		t.Fatalf("impossible counts: got %+v", got)
	}
	if got := MeanLatency(nil); got.Status != contracts.StatusUnknown {
		t.Fatalf("zero latency samples: got %+v", got)
	}
	if got := MeanLatency([]float64{math.NaN()}); got.Status != contracts.StatusUnknown {
		t.Fatalf("NaN latency: got %+v", got)
	}
	if got := MeanLatency([]float64{math.Inf(1)}); got.Status != contracts.StatusUnknown {
		t.Fatalf("Inf latency: got %+v", got)
	}
	if got := MeanLatency([]float64{-1}); got.Status != contracts.StatusUnknown {
		t.Fatalf("negative latency: got %+v", got)
	}
	if got := Cost(-1, 5); got.Status != contracts.StatusUnknown {
		t.Fatalf("negative cost: got %+v", got)
	}
	if got := Cost(1, 0); got.Status != contracts.StatusUnknown {
		t.Fatalf("zero cost samples: got %+v", got)
	}
	if got := contracts.Ratio(math.Inf(1), 1); got.Status != contracts.StatusUnknown {
		t.Fatalf("non-finite ratio: got %+v", got)
	}

	ok := contracts.Ratio(3, 4)
	if got := contracts.EnforceMinSamples(ok, 2, 5); got.Status != contracts.StatusUnknown {
		t.Fatalf("insufficient samples: got %+v", got)
	}
	if got := contracts.EnforceMinSamples(ok, 0, 0); got.Status != contracts.StatusUnknown {
		t.Fatalf("zero samples must be unknown: got %+v", got)
	}
	if got := contracts.EnforceMinSamples(ok, 5, 5); got.Status != contracts.StatusOK {
		t.Fatalf("enough samples must stay OK: got %+v", got)
	}
}

// TestCostAndConformanceAreBounded checks the two metrics that were previously
// missing from the runner.
// TestCostAndConformanceAreBounded 校验此前 Runner 缺失的两个指标。
func TestCostAndConformanceAreBounded(t *testing.T) {
	if got := mustOK(t, Cost(1.5, 3)); !closeTo(got, 0.5) {
		t.Fatalf("cost per sample = %v, want 0.5", got)
	}
	if got := mustOK(t, Conformance(8, 6)); !closeTo(got, 0.75) {
		t.Fatalf("conformance = %v, want 0.75", got)
	}
	descriptors := Descriptors()
	if len(descriptors) != 12 {
		t.Fatalf("expected 12 built-in metrics including retrieval precision, got %d", len(descriptors))
	}
	seen := map[string]string{}
	for _, d := range descriptors {
		seen[d.MetricID] = d.Kind
	}
	if seen[MetricLatencyHistogram] != KindLatency {
		t.Fatalf("latency_histogram must be registered as a latency metric: %+v", descriptors)
	}
	if seen[MetricPrecision] != KindRatio {
		t.Fatal("retrieval precision is missing from the platform metric registry", descriptors)
	}
	for i := 1; i < len(descriptors); i++ {
		if descriptors[i-1].MetricID >= descriptors[i].MetricID {
			t.Fatalf("descriptors must be ordered by id: %+v", descriptors)
		}
	}
}

// gateConfig is the frozen gate the golden counterexamples run under.
// gateConfig 是黄金反例运行所依据的冻结闸门。
func gateConfig() contracts.GateConfig {
	return contracts.GateConfig{
		MinEntailment:    1.0,
		RequireAllClaims: true,
		ExpectedRevision: "rev-1",
		FailOnUnknown:    true,
	}
}

func decide(t *testing.T, cfg contracts.GateConfig, citations []contracts.Citation, claims []contracts.Claim) contracts.GroundingGateResult {
	t.Helper()
	verdicts, err := EvaluateClaims(LexicalEntailmentMetric{}, citations, claims)
	if err != nil {
		t.Fatalf("evaluate claims: %v", err)
	}
	return contracts.EvaluateGroundingGate(cfg, citations, claims, verdicts)
}

// TestGroundingGateGoldenCounterexamples is the golden grounding set: only a
// genuinely entailed claim passes; the "citation correct but conclusion wrong",
// "wrong subject", "negation reversal", "omitted condition", "version conflict"
// and "unknown evidence" counterexamples must all block.
// TestGroundingGateGoldenCounterexamples 是黄金接地集：只有真正蕴含的声明通过；
// "引用正确但结论错误""主体错误""否定反转""条件遗漏""版本冲突""引用未知证据"反例一律拦截。
func TestGroundingGateGoldenCounterexamples(t *testing.T) {
	refundEvidence := contracts.Citation{
		ID:       "c1",
		Revision: "rev-1",
		Content:  "The refund window is 30 days from purchase.",
	}
	negationEvidence := contracts.Citation{
		ID:       "c2",
		Revision: "rev-1",
		Content:  "The product is not waterproof.",
	}
	conditionEvidence := contracts.Citation{
		ID:       "c3",
		Revision: "rev-1",
		Content:  "The device may be used outdoors if it is dry.",
	}

	t.Run("genuine entailment passes", func(t *testing.T) {
		claims := []contracts.Claim{{ID: "a1", Text: "The refund window is 30 days from purchase.", CitationIDs: []string{"c1"}}}
		result := decide(t, gateConfig(), []contracts.Citation{refundEvidence}, claims)
		if !result.Passed() {
			t.Fatalf("expected pass, got %+v", result)
		}
		if result.Grounded != 1 {
			t.Fatalf("expected 1 grounded claim, got %+v", result)
		}
	})

	t.Run("citation correct but conclusion wrong", func(t *testing.T) {
		claims := []contracts.Claim{{ID: "a1", Text: "The refund window is 90 days from purchase.", CitationIDs: []string{"c1"}}}
		result := decide(t, gateConfig(), []contracts.Citation{refundEvidence}, claims)
		if result.Passed() || result.Status != contracts.StatusBlocked {
			t.Fatalf("wrong conclusion must block, got %+v", result)
		}
	})

	t.Run("wrong subject", func(t *testing.T) {
		claims := []contracts.Claim{{ID: "a1", Text: "The warranty window is 30 days from purchase.", CitationIDs: []string{"c1"}}}
		result := decide(t, gateConfig(), []contracts.Citation{refundEvidence}, claims)
		if result.Passed() {
			t.Fatalf("wrong subject must block, got %+v", result)
		}
	})

	t.Run("negation reversal", func(t *testing.T) {
		claims := []contracts.Claim{{ID: "a1", Text: "The product is waterproof.", CitationIDs: []string{"c2"}}}
		result := decide(t, gateConfig(), []contracts.Citation{negationEvidence}, claims)
		if result.Passed() {
			t.Fatalf("negation reversal must block, got %+v", result)
		}
	})

	t.Run("omitted condition", func(t *testing.T) {
		claims := []contracts.Claim{{ID: "a1", Text: "The device may be used outdoors.", CitationIDs: []string{"c3"}}}
		result := decide(t, gateConfig(), []contracts.Citation{conditionEvidence}, claims)
		if result.Passed() {
			t.Fatalf("omitted condition must block, got %+v", result)
		}
	})

	t.Run("version conflict", func(t *testing.T) {
		claims := []contracts.Claim{{ID: "a1", Text: "The refund window is 30 days from purchase.", CitationIDs: []string{"c1"}}}
		cfg := gateConfig()
		cfg.ExpectedRevision = "rev-2"
		result := decide(t, cfg, []contracts.Citation{refundEvidence}, claims)
		if result.Passed() || len(result.VersionConflict) != 1 {
			t.Fatalf("version conflict must block, got %+v", result)
		}
	})

	t.Run("claim cites unknown evidence", func(t *testing.T) {
		claims := []contracts.Claim{{ID: "a1", Text: "The refund window is 30 days from purchase.", CitationIDs: []string{"c-missing"}}}
		result := decide(t, gateConfig(), []contracts.Citation{refundEvidence}, claims)
		if result.Passed() || len(result.MissingCitation) != 1 {
			t.Fatalf("unknown evidence must block, got %+v", result)
		}
	})

	t.Run("citation existing is not grounded", func(t *testing.T) {
		claims := []contracts.Claim{{ID: "a1", Text: "Completely unrelated invented fact about penguins.", CitationIDs: []string{"c1"}}}
		result := decide(t, gateConfig(), []contracts.Citation{refundEvidence}, claims)
		if result.Passed() {
			t.Fatalf("a non-empty citation list must never pass on its own, got %+v", result)
		}
	})

	t.Run("no claims blocks", func(t *testing.T) {
		result := decide(t, gateConfig(), []contracts.Citation{refundEvidence}, nil)
		if result.Passed() {
			t.Fatalf("no claims must block, got %+v", result)
		}
	})
}

// TestMetricVersionsAreTraceable proves two versions of the same metric stay
// distinguishable in the emitted outcome.
// TestMetricVersionsAreTraceable 证明同一指标的两个版本在输出封套中保持可区分。
func TestMetricVersionsAreTraceable(t *testing.T) {
	res := contracts.Ratio(3, 4)
	v1 := contracts.NewOutcome("fact_accuracy", "1.0.0", KindRatio, "hash-1", res, nil)
	v2 := contracts.NewOutcome("fact_accuracy", "2.0.0", KindRatio, "hash-2", res, nil)

	if v1.Version == v2.Version || v1.FormulaHash == v2.FormulaHash {
		t.Fatalf("metric versions must be traceable and distinct: %+v %+v", v1, v2)
	}
	if v1.Value == nil || v2.Value == nil || *v1.Value != *v2.Value {
		t.Fatalf("both versions must carry the same computed value: %+v %+v", v1, v2)
	}
}
