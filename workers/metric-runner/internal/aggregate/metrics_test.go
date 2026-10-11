package aggregate

import (
	"math"
	"testing"
)

func TestRetrievalAndGroundingMetrics(t *testing.T) {
	recall, mrr, ndcg := Retrieval([]string{"a", "b"}, []string{"x", "b", "a"}, 2)
	if recall != .5 || mrr != .5 || ndcg <= 0 {
		t.Fatalf("%v %v %v", recall, mrr, ndcg)
	}
	if CitationCoverage(0, 0).Status != "UNKNOWN" {
		t.Fatal("zero claims must be unknown")
	}
}
func TestMeanLatencyRejectsNonFinite(t *testing.T) {
	if MeanLatency([]float64{1, math.NaN()}).Status != "UNKNOWN" {
		t.Fatal("NaN accepted")
	}
}
