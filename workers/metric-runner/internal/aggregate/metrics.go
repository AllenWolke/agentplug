package aggregate

import "math"

// Retrieval calculates standard ranking measures from immutable IDs. It is
// intentionally model/provider independent. / 检索指标不依赖模型供应商。
func Retrieval(relevant, ranked []string, k int) (recall, mrr, ndcg float64) {
	if k <= 0 || len(relevant) == 0 {
		return 0, 0, 0
	}
	want := map[string]bool{}
	for _, id := range relevant {
		if id != "" {
			want[id] = true
		}
	}
	if len(want) == 0 {
		return 0, 0, 0
	}
	limit := k
	if limit > len(ranked) {
		limit = len(ranked)
	}
	hits := 0
	first := 0
	for i, id := range ranked[:limit] {
		if want[id] {
			hits++
			if first == 0 {
				first = i + 1
			}
		}
	}
	recall = float64(hits) / float64(len(want))
	if first > 0 {
		mrr = 1 / float64(first)
	}
	var dcg, ideal float64
	for i, id := range ranked[:limit] {
		if want[id] {
			dcg += 1 / math.Log2(float64(i+2))
		}
	}
	for i := 0; i < limit && i < len(want); i++ {
		ideal += 1 / math.Log2(float64(i+2))
	}
	if ideal > 0 {
		ndcg = dcg / ideal
	}
	return
}

// CitationCoverage measures the fraction of answer claims with at least one
// supporting citation. / 引用覆盖率统计有支持引用的事实声明比例。
func CitationCoverage(totalClaims, supportedClaims int) Result {
	if totalClaims <= 0 || supportedClaims < 0 || supportedClaims > totalClaims {
		return Result{Status: "UNKNOWN"}
	}
	return Result{Numerator: float64(supportedClaims), Denominator: float64(totalClaims), Value: float64(supportedClaims) / float64(totalClaims), Status: "OK"}
}
func RefusalAccuracy(total, correct int) Result { return boundedRatio(total, correct) }
func FactAccuracy(total, correct int) Result    { return boundedRatio(total, correct) }
func boundedRatio(total, correct int) Result {
	if total <= 0 || correct < 0 || correct > total {
		return Result{Status: "UNKNOWN"}
	}
	return Result{Numerator: float64(correct), Denominator: float64(total), Value: float64(correct) / float64(total), Status: "OK"}
}
func MeanLatency(samples []float64) Result {
	if len(samples) == 0 {
		return Result{Status: "UNKNOWN"}
	}
	var total float64
	for _, v := range samples {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return Result{Status: "UNKNOWN"}
		}
		total += v
	}
	return Result{Numerator: total, Denominator: float64(len(samples)), Value: total / float64(len(samples)), Status: "OK"}
}
