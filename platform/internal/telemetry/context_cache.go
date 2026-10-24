package telemetry

import (
	"fmt"
	"io"
	"sync/atomic"
)

var contextCacheKnown, contextCacheUnreported, contextCacheInvalid atomic.Uint64
var contextCachedTokens, contextUncachedTokens atomic.Uint64

// Counts actual HTTP receipts once; invocation replay never reaches here.
// Labels deliberately exclude actors, prompts, partitions and Provider URLs.
func RecordModelContextCache(cached, uncached int, known bool) {
	if !known {
		contextCacheUnreported.Add(1)
		return
	}
	if cached < 0 || uncached < 0 {
		RecordModelContextCacheInvalid()
		return
	}
	contextCacheKnown.Add(1)
	contextCachedTokens.Add(uint64(cached))
	contextUncachedTokens.Add(uint64(uncached))
}

func RecordModelContextCacheInvalid() { contextCacheInvalid.Add(1) }

func writeContextCacheMetrics(out io.Writer) {
	fmt.Fprintln(out, "# HELP agent_model_context_cache_receipts_total Actual provider cache usage receipts; unreported is unknown.")
	fmt.Fprintln(out, "# TYPE agent_model_context_cache_receipts_total counter")
	fmt.Fprintf(out, "agent_model_context_cache_receipts_total{status=\"known\"} %d\n", contextCacheKnown.Load())
	fmt.Fprintf(out, "agent_model_context_cache_receipts_total{status=\"unreported\"} %d\n", contextCacheUnreported.Load())
	fmt.Fprintf(out, "agent_model_context_cache_receipts_total{status=\"invalid\"} %d\n", contextCacheInvalid.Load())
	fmt.Fprintln(out, "# HELP agent_model_context_cache_input_tokens_total Measured input token split, not additional input tokens.")
	fmt.Fprintln(out, "# TYPE agent_model_context_cache_input_tokens_total counter")
	fmt.Fprintf(out, "agent_model_context_cache_input_tokens_total{kind=\"cached\"} %d\n", contextCachedTokens.Load())
	fmt.Fprintf(out, "agent_model_context_cache_input_tokens_total{kind=\"uncached\"} %d\n", contextUncachedTokens.Load())
}
