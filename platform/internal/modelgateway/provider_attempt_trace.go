package modelgateway

import (
	"context"
	"sync"
	"time"
)

// ProviderAttemptObservation describes one HTTP connection attempt, not a
// billable generation. A received response can still fail body validation.
type ProviderAttemptObservation struct {
	Attempt         int    `json:"attempt"`
	DurationMS      int64  `json:"duration_ms"`
	HTTPStatus      int    `json:"http_status,omitempty"`
	ErrorKind       string `json:"error_kind,omitempty"`
	TransportStage  string `json:"transport_stage"`
	NetworkCause    string `json:"network_cause"`
	ConnectionState string `json:"connection_state"`
	RetryPlanned    bool   `json:"retry_planned"`
}

type ProviderAttemptTrace struct {
	mu    sync.Mutex
	items []ProviderAttemptObservation
}
type providerAttemptTraceKey struct{}

// WithProviderAttemptTrace is request-scoped and holds at most three bounded,
// redacted observations. It neither persists credentials nor changes retries.
func WithProviderAttemptTrace(ctx context.Context) (context.Context, *ProviderAttemptTrace) {
	trace := &ProviderAttemptTrace{}
	return context.WithValue(ctx, providerAttemptTraceKey{}, trace), trace
}

func (t *ProviderAttemptTrace) Snapshot() []ProviderAttemptObservation {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]ProviderAttemptObservation(nil), t.items...)
}

func observeProviderAttempt(ctx context.Context, attempt int, started time.Time, status int, failure error, progress *providerTransportProgress, retry bool) {
	trace, ok := ctx.Value(providerAttemptTraceKey{}).(*ProviderAttemptTrace)
	if !ok {
		return
	}
	stage, cause, connection := SafeProviderTransportDetail(failure)
	if failure == nil && progress.started.Load() && progress.connected.Load() {
		stage, cause, connection = "response", "none", "acquired"
	}
	item := ProviderAttemptObservation{Attempt: attempt + 1, DurationMS: time.Since(started).Milliseconds(),
		HTTPStatus: status, ErrorKind: SafeProviderFailureKind(failure), TransportStage: stage,
		NetworkCause: cause, ConnectionState: connection, RetryPlanned: retry}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if len(trace.items) < 3 {
		trace.items = append(trace.items, item)
	}
}
