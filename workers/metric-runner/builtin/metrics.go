// Package builtin implements the platform's deterministic built-in metrics on top
// of the shared contracts. Every metric returns a fail-closed contracts.Result so
// zero samples, missing citations, non-finite values and insufficient samples
// surface as UNKNOWN rather than as a number.
// Package builtin 在共享 contracts 之上实现平台确定性的内置指标。每个指标都返回失败闭合的
// contracts.Result，使零样本、缺引用、非有限值与样本不足一律以 UNKNOWN 呈现而非数值。
package builtin

import (
	"math"
	"sort"

	"github.com/lexagent/metric-runner/contracts"
	"github.com/lexagent/metric-runner/internal/aggregate"
)

// Built-in metric ids. Every id resolves to a platform-owned kind so a caller
// cannot invent a metric name.
// 内置指标 id。每个 id 都解析到平台自有类型，调用方无法自创指标名。
const (
	MetricRecall            = "recall"
	MetricPrecision         = "precision"
	MetricMRR               = "mrr"
	MetricNDCG              = "ndcg"
	MetricCitationCoverage  = "citation_coverage"
	MetricCitationPrecision = "citation_precision"
	MetricFactAccuracy      = "fact_accuracy"
	MetricRefusalAccuracy   = "refusal_accuracy"
	MetricMeanLatency       = "mean_latency"
	MetricLatencyHistogram  = "latency_histogram"
	MetricCost              = "cost"
	MetricConformance       = "conformance"
)

// Platform-owned metric kinds.
// 平台自有指标类型。
const (
	KindRatio       = "ratio"
	KindLatency     = "latency"
	KindCost        = "cost"
	KindConformance = "conformance"
)

// Descriptor names one built-in metric and its platform-owned kind.
// Descriptor 描述一个内置指标及其平台自有类型。
type Descriptor struct {
	MetricID string `json:"metric_id"`
	Kind     string `json:"kind"`
}

// Descriptors returns the built-in metrics ordered by id for stable reporting.
// Descriptors 按 id 排序返回内置指标，便于稳定上报。
func Descriptors() []Descriptor {
	out := []Descriptor{
		{MetricID: MetricRecall, Kind: KindRatio},
		{MetricID: MetricPrecision, Kind: KindRatio},
		{MetricID: MetricMRR, Kind: KindRatio},
		{MetricID: MetricNDCG, Kind: KindRatio},
		{MetricID: MetricCitationCoverage, Kind: KindRatio},
		{MetricID: MetricCitationPrecision, Kind: KindRatio},
		{MetricID: MetricFactAccuracy, Kind: KindRatio},
		{MetricID: MetricRefusalAccuracy, Kind: KindRatio},
		{MetricID: MetricMeanLatency, Kind: KindLatency},
		{MetricID: MetricLatencyHistogram, Kind: KindLatency},
		{MetricID: MetricCost, Kind: KindCost},
		{MetricID: MetricConformance, Kind: KindConformance},
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MetricID < out[j].MetricID })
	return out
}

// RecallAtK is the fraction of relevant ids retrieved within the top k ranks.
// RecallAtK 是前 k 个结果中命中的相关 id 占比。
func RecallAtK(relevant, ranked []string, k int) contracts.Result {
	if k <= 0 {
		return contracts.Unknown("k must be positive")
	}
	want := wantSet(relevant)
	if len(want) == 0 {
		return contracts.Unknown("no relevant ids")
	}
	hits := 0
	for _, id := range head(ranked, k) {
		if want[id] {
			hits++
		}
	}
	return contracts.Ratio(float64(hits), float64(len(want)))
}

// PrecisionAtK uses k as its denominator: unfilled ranks count as misses.
// Unlabelled corpora are UNKNOWN, never evidence of perfect quality.
func PrecisionAtK(relevant, ranked []string, k int) contracts.Result {
	if k <= 0 {
		return contracts.Unknown("k must be positive")
	}
	want := wantSet(relevant)
	if len(want) == 0 {
		return contracts.Unknown("no relevant ids")
	}
	seen := map[string]bool{}
	hits := 0
	for _, id := range head(ranked, k) {
		if want[id] && !seen[id] {
			hits++
		}
		seen[id] = true
	}
	return contracts.Ratio(float64(hits), float64(k))
}

// MRRAtK is the reciprocal rank of the first relevant id within the top k ranks;
// a run that retrieves none is a legitimate 0, not an UNKNOWN.
// MRRAtK 是前 k 个结果中首个相关 id 的倒数排名；一个都没检索到是合法的 0，而非 UNKNOWN。
func MRRAtK(relevant, ranked []string, k int) contracts.Result {
	if k <= 0 {
		return contracts.Unknown("k must be positive")
	}
	want := wantSet(relevant)
	if len(want) == 0 {
		return contracts.Unknown("no relevant ids")
	}
	for i, id := range head(ranked, k) {
		if want[id] {
			return contracts.Ratio(1, float64(i+1))
		}
	}
	return contracts.Ratio(0, 1)
}

// NDCGAtK is DCG at k normalized by the ideal DCG at k, so it is the only
// retrieval measure here that rewards putting the relevant ids first.
// NDCGAtK 是前 k 的 DCG 除以前 k 的理想 DCG，是本组检索指标中唯一奖励"把相关项排前面"的。
func NDCGAtK(relevant, ranked []string, k int) contracts.Result {
	if k <= 0 {
		return contracts.Unknown("k must be positive")
	}
	want := wantSet(relevant)
	if len(want) == 0 {
		return contracts.Unknown("no relevant ids")
	}
	limit := head(ranked, k)
	var dcg float64
	for i, id := range limit {
		if want[id] {
			dcg += 1 / math.Log2(float64(i+2))
		}
	}
	var ideal float64
	for i := 0; i < len(limit) && i < len(want); i++ {
		ideal += 1 / math.Log2(float64(i+2))
	}
	if ideal <= 0 {
		return contracts.Unknown("ideal dcg is zero")
	}
	return contracts.Ratio(dcg, ideal)
}

// CitationCoverage is the fraction of answer claims that carry at least one
// citation. A non-empty citation list is NOT groundedness -- see the grounding
// gate; this metric only measures reference coverage.
// CitationCoverage 是携带至少一个引用的回答声明占比。引用列表非空并不等于接地——见接地
// 闸门；本指标只度量引用覆盖度。
func CitationCoverage(totalClaims, supportedClaims int) contracts.Result {
	return bounded(totalClaims, supportedClaims)
}

// CitationPrecision is the fraction of supplied citations that actually support
// the claim they are attached to.
// CitationPrecision 是所提供引用中真正支持其所属声明的占比。
func CitationPrecision(totalCitations, groundedCitations int) contracts.Result {
	return bounded(totalCitations, groundedCitations)
}

// FactAccuracy is the fraction of checked facts answered correctly.
// FactAccuracy 是校验事实中回答正确的占比。
func FactAccuracy(total, correct int) contracts.Result {
	return bounded(total, correct)
}

// RefusalAccuracy is the fraction of out-of-scope prompts that were correctly
// refused.
// RefusalAccuracy 是越界提问中被正确拒答的占比。
func RefusalAccuracy(total, correct int) contracts.Result {
	return bounded(total, correct)
}

// Conformance is the fraction of frozen conformance checks that passed.
// Conformance 是冻结的一致性检查中通过的占比。
func Conformance(total, passed int) contracts.Result {
	return bounded(total, passed)
}

// MeanLatency is the arithmetic mean of the latency samples; an empty sample set,
// a negative sample or a non-finite sample is UNKNOWN, never a fabricated 0.
// MeanLatency 是延迟样本的算术平均；空样本、负样本或非有限样本均为 UNKNOWN，
// 绝不伪造为 0。
func MeanLatency(samples []float64) contracts.Result {
	if len(samples) == 0 {
		return contracts.Unknown("no samples")
	}
	var total float64
	for _, v := range samples {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return contracts.Unknown("non-finite or negative latency sample")
		}
		total += v
	}
	return contracts.Ratio(total, float64(len(samples)))
}

// LatencyHistogram builds a mergeable, fixed-bucket latency distribution and a
// fail-closed summary value. Unlike a bare mean, the returned histogram can be
// added to another histogram produced anywhere else with the same frozen
// bounds, so a suite scored shard-by-shard yields exactly the distribution it
// would have yielded in one pass. The summary keeps the sum and the count as
// numerator and denominator, so no precision is lost on the way out.
// LatencyHistogram 构建可合并的固定桶延迟分布与失败闭合的汇总值。与裸均值不同，返回的直方图
// 可以与任何其他使用同一冻结边界产生的直方图相加，因此分片评分的 Suite 得到与一次性评分完全
// 相同的分布。汇总值把和与计数分别保留为分子与分母，因此输出路径上不丢精度。
func LatencyHistogram(samples []float64) (contracts.Result, map[string]any) {
	if len(samples) == 0 {
		return contracts.Unknown("no samples"), nil
	}
	histogram := aggregate.NewHistogram()
	for _, v := range samples {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return contracts.Unknown("non-finite or negative latency sample"), nil
		}
		histogram.Observe(v)
	}
	if _, ok := histogram.Mean(); !ok {
		return contracts.Unknown("no samples"), nil
	}
	return contracts.Ratio(histogram.Sum, float64(histogram.Count)), map[string]any{
		"latency_histogram": histogram,
		"bucket_labels":     histogram.Buckets(),
	}
}

// Cost is the mean cost per sample, expressed in the caller's declared unit; a
// negative or non-finite total, or zero samples, is UNKNOWN.
// Cost 是每个样本的平均成本，单位由调用方声明；总成本为负、非有限或样本为零均为 UNKNOWN。
func Cost(totalCost float64, samples int) contracts.Result {
	if samples <= 0 {
		return contracts.Unknown("no samples")
	}
	if math.IsNaN(totalCost) || math.IsInf(totalCost, 0) || totalCost < 0 {
		return contracts.Unknown("non-finite or negative cost")
	}
	return contracts.Ratio(totalCost, float64(samples))
}

// bounded builds a ratio from counts, failing closed when there is no sample or
// the good count falls outside [0, total].
// bounded 由计数构建比例：无样本或良品计数落在 [0, total] 之外时失败闭合。
func bounded(total, good int) contracts.Result {
	if total <= 0 {
		return contracts.Unknown("no samples")
	}
	if good < 0 || good > total {
		return contracts.Unknown("invalid counts")
	}
	return contracts.Ratio(float64(good), float64(total))
}

// wantSet collects the non-empty relevant ids into a lookup set.
// wantSet 把非空相关 id 收集为查找集合。
func wantSet(relevant []string) map[string]bool {
	want := make(map[string]bool, len(relevant))
	for _, id := range relevant {
		if id != "" {
			want[id] = true
		}
	}
	return want
}

// head returns the first k ranked ids (or the whole slice when it is shorter).
// head 返回排名前 k 的 id（切片更短时返回全部）。
func head(ranked []string, k int) []string {
	if k < len(ranked) {
		return ranked[:k]
	}
	return ranked
}
