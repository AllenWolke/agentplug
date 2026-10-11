package aggregate

import (
	"errors"
	"strings"
	"testing"
)

func TestHistogramObserveIsCumulativeAndComplete(t *testing.T) {
	histogram := NewHistogram()
	for _, sample := range []float64{3, 7, 12, 120, 9000, 20000} {
		histogram.Observe(sample)
	}
	if histogram.Count != 6 {
		t.Fatalf("count = %d, want 6", histogram.Count)
	}
	if histogram.Sum != 3+7+12+120+9000+20000 {
		t.Fatalf("sum = %v", histogram.Sum)
	}
	// Cumulative buckets: 3 and 7 are <= 10, plus 12 <= 25, plus 120 <= 250 and
	// the 9000/20000 observations only ever reach the last finite bound.
	wantCumulative := map[string]uint64{"le_5": 1, "le_10": 2, "le_25": 3, "le_100": 3, "le_250": 4, "le_500": 4, "le_1000": 4, "le_2500": 4, "le_5000": 4, "le_10000": 5}
	buckets := histogram.Buckets()
	for label, want := range wantCumulative {
		if buckets[label] != want {
			t.Fatalf("bucket %s = %d, want %d", label, buckets[label], want)
		}
	}
	if buckets["+Inf"] != 6 {
		t.Fatalf("+Inf bucket = %d, want every observation counted (%d)", buckets["+Inf"], 6)
	}
	for label := range buckets {
		if strings.Contains(label, "case") || strings.ContainsAny(label, "/:") {
			t.Fatalf("histogram labels must stay case-agnostic: %q", label)
		}
	}
}

func TestHistogramMergeEqualsOnePass(t *testing.T) {
	whole := NewHistogram()
	first := NewHistogram()
	second := NewHistogram()
	samples := []float64{1, 9, 30, 240, 700, 4000, 12000}
	for i, sample := range samples {
		whole.Observe(sample)
		if i%2 == 0 {
			first.Observe(sample)
		} else {
			second.Observe(sample)
		}
	}
	merged, err := first.Merge(second)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if merged.Count != whole.Count || merged.Sum != whole.Sum {
		t.Fatalf("merged summary %+v != one pass %+v", merged, whole)
	}
	for i := range merged.Counts {
		if merged.Counts[i] != whole.Counts[i] {
			t.Fatalf("bucket %d: merged %d != one pass %d", i, merged.Counts[i], whole.Counts[i])
		}
	}
}

func TestHistogramMergeRefusesForeignBounds(t *testing.T) {
	first := NewHistogram()
	foreign := Histogram{BoundsMs: []float64{1, 2, 3}, Counts: []uint64{1, 2, 3}, Count: 3, Sum: 6}
	if _, err := first.Merge(foreign); !errors.Is(err, ErrIncompatibleHistogram) {
		t.Fatalf("foreign bounds must be refused, got %v", err)
	}
}

func TestHistogramWithoutObservationsHasNoMean(t *testing.T) {
	empty := NewHistogram()
	if _, ok := empty.Mean(); ok {
		t.Fatal("an empty histogram must not report a mean")
	}
	empty.Observe(4)
	mean, ok := empty.Mean()
	if !ok || mean != 4 {
		t.Fatalf("mean = %v ok = %v, want 4 true", mean, ok)
	}
}
