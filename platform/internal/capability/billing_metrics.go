package capability

import (
	"crypto/hmac"
	"fmt"
	"log"
	"net/http"
)

// Service-only fixed-cardinality counters: no Scope, prompt, receipt or secret labels.
// 仅服务身份读取低基数计数器，不以 Scope、提示词、回执或密钥作为标签。
func (m *Module) billingMetrics(w http.ResponseWriter, r *http.Request) {
	if m.internalToken == "" || !hmac.Equal([]byte(m.internalToken), []byte(r.Header.Get("X-Internal-Token"))) {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	if r.Header.Get("X-Browser-Module") == "1" {
		http.Error(w, "service identity required", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	counters := []struct {
		name, help string
		value      uint64
	}{
		{"platform_model_billing_worker_runs_total", "Billing recovery passes", m.billingStats.Runs.Load()},
		{"platform_model_billing_worker_completed_total", "Recovery work items completed; not generated answers", m.billingStats.Completed.Load()},
		{"platform_model_billing_worker_failed_total", "Recovery read or write failures", m.billingStats.Failed.Load()},
		{"platform_tool_recovery_worker_runs_total", "Tool recovery passes", m.toolStats.Runs.Load()},
		{"platform_tool_recovery_worker_completed_total", "Tool recovery work items completed", m.toolStats.Completed.Load()},
		{"platform_tool_recovery_worker_pending_total", "Tool recovery failures or unknown results retained", m.toolStats.Failed.Load()},
	}
	for _, counter := range counters {
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", counter.name, counter.help, counter.name, counter.name, counter.value); err != nil {
			log.Print("billing metrics write failed code=BILLING_METRICS_WRITE_FAILED")
			return
		}
	}
}
