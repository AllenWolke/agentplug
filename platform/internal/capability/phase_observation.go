package capability

// Optional per-request phase timing. This is diagnostic metadata, not a billing
// receipt or authorization cache. Request bodies, keys, JWTs and SQL are absent.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type capabilityPhaseKey struct{}
type capabilityPhaseValue struct {
	Count  int     `json:"count"`
	WorkMS float64 `json:"work_ms"`
	MaxMS  float64 `json:"max_ms"`
}
type capabilityPhaseTrace struct {
	mu        sync.Mutex
	RunRef    string                          `json:"run_ref"`
	Path      string                          `json:"path"`
	Namespace string                          `json:"namespace"`
	Operation string                          `json:"operation"`
	TotalMS   float64                         `json:"total_ms"`
	Phases    map[string]capabilityPhaseValue `json:"phases"`
}

var capabilityPhaseNames = map[string]bool{
	"authorize.total": true, "authority.context": true, "authority.policy": true,
	"authority.live_entry": true, "authority.live_recheck": true, "authority.skills": true,
	"state.total": true, "state.encode": true, "state.quota": true, "state.quota_reuse": true,
	"state.begin_tx": true, "state.initial_guard": true, "state.head_lock": true, "state.guarded_check": true,
	"state.current_quota": true, "state.idempotency": true, "state.cas_and_write": true,
	"state.audit": true, "state.commit": true, "knowledge.total": true,
}

func capabilityPhaseContext(ctx context.Context, path string, enabled bool, emit func([]byte)) (context.Context, func()) {
	if !enabled {
		return ctx, func() {}
	}
	known := map[string]bool{"/internal/state/checkpoint": true, "/internal/model/generate": true,
		"/internal/model/embed": true, "/internal/tool/invoke": true, "/internal/tool/receipt": true,
		"/internal/knowledge/search": true, "/internal/knowledge/references/authorize": true,
		"/internal/runtime/harness-policy": true, "/internal/context/renew": true, "/internal/prompt/resolve": true}
	if !known[path] {
		path = "other"
	}
	value := &capabilityPhaseTrace{Path: path, Namespace: "other", Operation: "other", Phases: map[string]capabilityPhaseValue{}}
	started := time.Now()
	return context.WithValue(ctx, capabilityPhaseKey{}, value), func() {
		// Diagnostics cannot change a completed response, including if a supplied
		// sink fails. This does not suppress any business or authorization error.
		defer func() { _ = recover() }()
		value.mu.Lock()
		if value.RunRef == "" {
			value.mu.Unlock()
			return
		}
		value.TotalMS = float64(time.Since(started)) / float64(time.Millisecond)
		encoded, err := json.Marshal(value)
		value.mu.Unlock()
		if err == nil {
			emit(encoded)
		}
	}
}

func capabilityPhaseHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("PLATFORM_CAPABILITY_PHASE_TIMING") != "1" {
			next.ServeHTTP(w, r)
			return
		}
		ctx, finish := capabilityPhaseContext(r.Context(), r.URL.Path, true,
			func(value []byte) { log.Printf("capability_phase_observation %s", value) })
		defer finish()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func capabilityPhase(ctx context.Context, name string) func() {
	value, _ := ctx.Value(capabilityPhaseKey{}).(*capabilityPhaseTrace)
	if value == nil || !capabilityPhaseNames[name] {
		return func() {}
	}
	started := time.Now()
	var once sync.Once
	return func() {
		once.Do(func() {
			elapsed := float64(time.Since(started)) / float64(time.Millisecond)
			value.mu.Lock()
			defer value.mu.Unlock()
			prior := value.Phases[name]
			prior.Count++
			prior.WorkMS += elapsed
			if elapsed > prior.MaxMS {
				prior.MaxMS = elapsed
			}
			value.Phases[name] = prior
		})
	}
}

func capabilityPhaseRoot(ctx context.Context, id string) {
	value, _ := ctx.Value(capabilityPhaseKey{}).(*capabilityPhaseTrace)
	if value == nil || id == "" {
		return
	}
	hash := sha256.Sum256([]byte(id))
	value.mu.Lock()
	value.RunRef = hex.EncodeToString(hash[:])[:16]
	value.mu.Unlock()
}

func capabilityPhaseState(ctx context.Context, namespace, operation string) {
	value, _ := ctx.Value(capabilityPhaseKey{}).(*capabilityPhaseTrace)
	if value == nil {
		return
	}
	if namespace != "harness" && namespace != "harness-v2" && namespace != "step-workflow" && namespace != "knowledge" && namespace != "graph-runtime" && namespace != "checkpoint-cursor" {
		namespace = "other"
	}
	if operation != "load" && operation != "save" {
		operation = "other"
	}
	value.mu.Lock()
	value.Namespace = namespace
	value.Operation = operation
	value.mu.Unlock()
}
