package builtin

import (
	"github.com/lexagent/metric-runner/contracts"
	"testing"
)

func TestPrecisionAtKUsesRequestedRanksAndNoDuplicateCredit(t *testing.T) {
	for _, test := range []struct {
		name   string
		ranked []string
		k      int
		want   float64
	}{
		{"golden", []string{"x", "a", "b"}, 2, .5},
		{"short-result", []string{"a"}, 3, 1.0 / 3},
		{"duplicate", []string{"a", "a"}, 2, .5},
		{"empty", nil, 2, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := mustOK(t, PrecisionAtK([]string{"a", "b"}, test.ranked, test.k)); !closeTo(got, test.want) {
				t.Fatal(got, test.want)
			}
		})
	}
	for _, result := range []contracts.Result{PrecisionAtK(nil, []string{"a"}, 1), PrecisionAtK([]string{"a"}, []string{"a"}, 0)} {
		if result.Status != contracts.StatusUnknown || result.Value != nil {
			t.Fatal("missing labels or invalid K produced quality score", result)
		}
	}
}
