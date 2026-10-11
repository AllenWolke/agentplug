package contracts

import (
	"math"
	"testing"
)

// TestOutcomeValidateFailsClosedForInvalidPopulation keeps the runner side of
// the metric trust boundary aligned with the Worker and backend. An OK ratio
// without a positive finite denominator is never publishable.
// TestOutcomeValidateFailsClosedForInvalidPopulation 保持 Runner 与 Worker、Backend
// 的指标信任边界一致：分母非正或非有限的 OK 比例永远不可发布。
func TestOutcomeValidateFailsClosedForInvalidPopulation(t *testing.T) {
	value := 0.75
	base := Outcome{MetricID: "recall", Version: "1", Kind: "ratio", FormulaHash: "hash", Result: Result{Numerator: 3, Denominator: 4, Value: &value, Status: StatusOK}}
	if !base.Validate("recall", "1", "hash") {
		t.Fatal("valid outcome rejected")
	}
	for _, denominator := range []float64{0, -1, math.Inf(1), math.NaN()} {
		row := base
		row.Denominator = denominator
		if row.Validate("recall", "1", "hash") {
			t.Fatalf("invalid denominator %v accepted", denominator)
		}
	}
}
