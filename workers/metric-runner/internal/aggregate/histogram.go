// Package aggregate holds the mergeable aggregation primitives the metric runner
// uses to combine per-sample results. Ratios keep their numerator and
// denominator so a ratio can be re-aggregated exactly, and latencies use a
// fixed-bucket histogram so two partial results merge into the same bucket
// counts they would have had if computed together.
// Package aggregate 持有指标 Runner 合并逐样本结果所用的可合并聚合原语。比例保留分子与分母，
// 因此可以被精确再聚合；延迟使用固定桶直方图，使两份部分结果合并后的桶计数与一次性计算完全一致。
package aggregate

import (
	"errors"
	"strconv"
)

// ErrIncompatibleHistogram is returned when two histograms do not share the same
// frozen bucket bounds; adding incompatible buckets would silently produce a
// distribution that matches neither input.
// ErrIncompatibleHistogram 在两份直方图不共享同一冻结桶边界时返回；把不兼容的桶相加会静默
// 产生一个与任一份输入都不相符的分布。
var ErrIncompatibleHistogram = errors.New("latency histograms have incompatible bounds")

// BoundsMs is the frozen, platform-owned bucket layout for latency. It is
// deliberately fixed rather than adaptive: an adaptive layout cannot be merged
// across workers or runs, and a merge that changes the buckets is a merge that
// changes the answer.
// BoundsMs 是平台自有、冻结的延迟桶布局。它刻意固定而非自适应：自适应布局无法跨 Worker 或
// 跨运行合并，而改变桶的合并就是改变答案的合并。
var BoundsMs = []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

// Histogram is a mergeable cumulative-count latency distribution. Each element
// of Counts is the number of observations less than or equal to the matching
// element of BoundsMs. Count and Sum are tracked over every observation
// regardless of magnitude, so an observation above the last bound is never
// dropped -- it simply has no finite bucket of its own.
// Histogram 是可合并的累计计数延迟分布。Counts 的每个元素是小于等于对应 BoundsMs 的观测数。
// Count 与 Sum 覆盖每个观测，与量级无关，因此超过最后一个边界的观测永不丢失——它只是没有属于
// 自己的有限桶。
type Histogram struct {
	BoundsMs []float64 `json:"bounds_ms"`
	Counts   []uint64  `json:"counts"`
	Count    uint64    `json:"count"`
	Sum      float64   `json:"sum"`
}

// NewHistogram returns an empty histogram pinned to the frozen bucket layout.
// NewHistogram 返回绑定到冻结桶布局的空直方图。
func NewHistogram() Histogram {
	return Histogram{BoundsMs: append([]float64(nil), BoundsMs...), Counts: make([]uint64, len(BoundsMs))}
}

// Observe records one latency sample. A negative or non-finite sample is
// refused by the caller before it reaches here; this method is deliberately
// total over its input so the histogram itself cannot be the source of an
// UNKNOWN.
// Observe 记录一个延迟样本。负样本或非有限样本在到达此处之前由调用方拒绝；本方法刻意对输入
// 全域定义，使直方图本身不会成为 UNKNOWN 的来源。
func (h *Histogram) Observe(ms float64) {
	if len(h.BoundsMs) != len(BoundsMs) || len(h.Counts) != len(BoundsMs) {
		*h = NewHistogram()
	}
	for i, bound := range h.BoundsMs {
		if ms <= bound {
			h.Counts[i]++
		}
	}
	h.Count++
	h.Sum += ms
}

// Merge adds another histogram with identical bounds and returns the combined
// distribution. Identical bounds are required because cumulative counts from
// different layouts are not addable.
// Merge 相加另一份边界相同的直方图并返回合并分布。要求边界相同，因为不同布局的累计计数不可相加。
func (h Histogram) Merge(other Histogram) (Histogram, error) {
	if !sameBounds(h.BoundsMs, other.BoundsMs) {
		return Histogram{}, ErrIncompatibleHistogram
	}
	merged := Histogram{BoundsMs: append([]float64(nil), h.BoundsMs...), Counts: make([]uint64, len(h.Counts)), Count: h.Count + other.Count, Sum: h.Sum + other.Sum}
	for i := range merged.Counts {
		merged.Counts[i] = h.Counts[i] + other.Counts[i]
	}
	return merged, nil
}

// Mean returns the arithmetic mean and whether it is defined. A histogram with
// no observations has no mean, which is reported as false rather than as zero.
// Mean 返回算术平均及其是否有定义。没有任何观测的直方图没有均值，以 false 报告而非零。
func (h Histogram) Mean() (float64, bool) {
	if h.Count == 0 {
		return 0, false
	}
	return h.Sum / float64(h.Count), true
}

// Buckets renders the cumulative counts with explicit "le_<bound>" labels plus
// the conventional "+Inf" bucket, so a downstream exporter cannot accidentally
// re-bucket them and no observation is silently unaccounted for. Each entry is
// a cumulative bucket, matching the Prometheus histogram convention; the "+Inf"
// entry always equals Count.
// Buckets 以显式的 "le_<bound>" 标签加上约定的 "+Inf" 桶渲染累计计数，使下游导出器不会意外
// 重新分桶，也不会让任何观测被静默漏计。每项都是累计桶，与 Prometheus 直方图约定一致；
// "+Inf" 项恒等于 Count。
func (h Histogram) Buckets() map[string]uint64 {
	out := make(map[string]uint64, len(h.BoundsMs)+1)
	for i, bound := range h.BoundsMs {
		out["le_"+strconv.FormatFloat(bound, 'f', -1, 64)] = h.Counts[i]
	}
	out["+Inf"] = h.Count
	return out
}

func sameBounds(a, b []float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
