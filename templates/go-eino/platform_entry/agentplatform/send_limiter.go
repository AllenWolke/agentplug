package agentplatform

import (
	"context"
	"sync"
)

// CapabilitySendLimiter shares only physical I/O capacity across executions.
// Authentication, signed bodies and permission checks remain request-local.
type CapabilitySendLimiter struct{ slots chan struct{} }

func NewCapabilitySendLimiter(maximum int) (*CapabilitySendLimiter, error) {
	if maximum < 1 || maximum > 1024 {
		return nil, publicError("CAPABILITY_LIMITER_INVALID")
	}
	return &CapabilitySendLimiter{make(chan struct{}, maximum)}, nil
}
func (l *CapabilitySendLimiter) Acquire(ctx context.Context) (func(), error) {
	select {
	case l.slots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-l.slots }) }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func SafeCapabilityPath(path string) string {
	for _, allowed := range []string{"/internal/context/renew", "/internal/model/generate", "/internal/model/embed", "/internal/model/receipt", "/internal/knowledge/search", "/internal/knowledge/search/recovery", "/internal/knowledge/answer", "/internal/knowledge/answer/recovery", "/internal/knowledge/references/authorize", "/internal/state/checkpoint", "/internal/runtime/harness-policy", "/internal/prompt/resolve", "/internal/tool/invoke", "/internal/tool/receipt", "/internal/memory/access"} {
		if path == allowed {
			return path
		}
	}
	return "other"
}
