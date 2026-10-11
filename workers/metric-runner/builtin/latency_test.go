package builtin

import (
	"testing"

	"github.com/lexagent/metric-runner/contracts"
	"github.com/lexagent/metric-runner/internal/aggregate"
)

func TestLatencyHistogramIsMergeableAndKeepsItsCounts(t *testing.T) {
	samples := []float64{2, 8, 40, 400, 3000}

	t.Run("empty samples stay unknown without a distribution", func(t *testing.T) {
		result, details := LatencyHistogram(nil)
		if result.Status != contracts.StatusUnknown || details != nil {
			t.Fatalf("empty samples must be UNKNOWN with no details: %+v %+v", result, details)
		}
	})

	t.Run("a negative sample fails closed", func(t *testing.T) {
		result, details := LatencyHistogram([]float64{1, -1})
		if result.Status != contracts.StatusUnknown || details != nil {
			t.Fatalf("negative sample must be UNKNOWN with no details: %+v %+v", result, details)
		}
	})

	t.Run("summary keeps sum over count", func(t *testing.T) {
		result, details := LatencyHistogram(samples)
		if result.Status != contracts.StatusOK {
			t.Fatalf("status = %q, want OK (%+v)", result.Status, result)
		}
		if result.Numerator != 3450 || result.Denominator != 5 {
			t.Fatalf("summary must keep the exact sum and count: %+v", result)
		}
		if result.Value == nil || !closeTo(*result.Value, 690) {
			t.Fatalf("value = %v, want the mean", result.Value)
		}
		histogram, ok := details["latency_histogram"].(aggregate.Histogram)
		if !ok {
			t.Fatalf("details must carry a mergeable histogram: %+v", details)
		}
		if histogram.Count != 5 || histogram.Sum != 3450 {
			t.Fatalf("histogram lost observations: %+v", histogram)
		}
		labels, ok := details["bucket_labels"].(map[string]uint64)
		if !ok {
			t.Fatalf("details must carry explicit bucket labels: %+v", details)
		}
		if labels["+Inf"] != 5 || labels["le_10000"] != 5 {
			t.Fatalf("every observation must be accounted for: %+v", labels)
		}
	})

	t.Run("two partial runs merge into one pass", func(t *testing.T) {
		firstHistogram := aggregate.NewHistogram()
		secondHistogram := aggregate.NewHistogram()
		whole := aggregate.NewHistogram()
		for i, sample := range samples {
			whole.Observe(sample)
			if i%2 == 0 {
				firstHistogram.Observe(sample)
			} else {
				secondHistogram.Observe(sample)
			}
		}
		merged, err := firstHistogram.Merge(secondHistogram)
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		if merged.Count != whole.Count || merged.Sum != whole.Sum {
			t.Fatalf("merged %+v != one pass %+v", merged, whole)
		}
	})
}
