package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type batchDeadlineProvider struct {
	observationFixtureProvider
	remaining time.Duration
	bounded   bool
}

func (p *batchDeadlineProvider) Invoke(ctx context.Context, command ToolCommand) (map[string]any, error) {
	deadline, ok := ctx.Deadline()
	p.bounded, p.remaining = ok, time.Until(deadline)
	return p.observationFixtureProvider.Invoke(ctx, command)
}

func TestToolInvocationSeparatesPublishedBatchWindowFromCallAndLeaseBounds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		window  int
		batch   *policyasset.BatchPolicy
		lease   int
		allowed bool
		callMax time.Duration
	}{
		{"hundred", 300, &policyasset.BatchPolicy{MaxItems: 100, ItemTimeoutSeconds: 30, ElapsedSeconds: 300}, 30, true, 3 * time.Second},
		{"thousand", 1800, &policyasset.BatchPolicy{MaxItems: 1000, ItemTimeoutSeconds: 30, ElapsedSeconds: 1800}, 30, true, 3 * time.Second},
		{"maximum-batch", 3600, &policyasset.BatchPolicy{MaxItems: 10000, ItemTimeoutSeconds: 30, ElapsedSeconds: 3600}, 600, true, 3 * time.Second},
		{"ordinary-tight-deadline", 1, nil, 30, true, time.Second},
		{"ordinary-window-boundary", 569, nil, 30, true, 3 * time.Second},
		{"legacy-requires-explicit-batch", 570, nil, 30, false, 0},
		{"long-window-without-batch", 1800, nil, 30, false, 0},
		{"batch-window-mismatch", 1800, &policyasset.BatchPolicy{MaxItems: 1000, ItemTimeoutSeconds: 30, ElapsedSeconds: 300}, 30, false, 0},
		{"batch-window-over-limit", 3601, &policyasset.BatchPolicy{MaxItems: 1000, ItemTimeoutSeconds: 30, ElapsedSeconds: 3601}, 30, false, 0},
		{"lease-over-limit", 1800, &policyasset.BatchPolicy{MaxItems: 1000, ItemTimeoutSeconds: 30, ElapsedSeconds: 1800}, 601, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			policy := governedInvocationResolver()
			policy.snapshot.Hash = strings.Repeat("b", 64)
			policy.snapshot.Tool.AllowedTools = []string{"fixture.read"}
			policy.snapshot.Runtime.TaskTimeoutSeconds = tc.window
			policy.snapshot.Runtime.Batch = tc.batch
			policy.snapshot.Runtime.LeaseSeconds = tc.lease
			m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, policy)
			m.SetLiveExecutionAuthority(contextPreparationAuthority{
				testLiveAuthorityFunc: func(context.Context, sharedkernel.Scope, string, string, string) error { return nil },
				resource:              func(CapabilityResourceAccess) error { return nil },
			})
			provider := &batchDeadlineProvider{observationFixtureProvider: observationFixtureProvider{output: map[string]any{"ok": true}}}
			m.SetToolProvider(provider)
			c := capabilityContext()
			c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
			response := capabilityRequest(t, m, "/internal/tool/invoke", c,
				map[string]any{"name": "fixture.read", "call_id": "batch-boundary", "payload": map[string]any{}})
			if !tc.allowed {
				if response.Code == http.StatusOK || provider.calls != 0 {
					t.Fatalf("unsupported policy reached provider: status=%d calls=%d", response.Code, provider.calls)
				}
				return
			}
			if response.Code != http.StatusOK || provider.calls != 1 {
				t.Fatalf("published batch rejected: status=%d calls=%d body=%s", response.Code, provider.calls, response.Body.String())
			}
			if !provider.bounded || provider.remaining <= 0 || provider.remaining > tc.callMax {
				t.Fatalf("Run window expanded or removed tool deadline: bounded=%v remaining=%s", provider.bounded, provider.remaining)
			}
		})
	}
}
