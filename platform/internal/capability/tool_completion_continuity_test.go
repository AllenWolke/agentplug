package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type returnedToolAuthority struct {
	resourceAuthorityFixture
	problem error
}

func (a *returnedToolAuthority) AuthorizeCapability(context.Context, sharedkernel.Scope, string, string, string) error {
	return a.problem
}

type returnedToolFixture struct {
	calls int
	after func(context.Context)
}

func (*returnedToolFixture) Supports(name string) bool { return name == "fixture.read" }
func (p *returnedToolFixture) DescribeTool(name string) (RuntimeToolDescriptor, bool) {
	return RuntimeToolDescriptor{ExecutionType: "tool", Risk: "read_only", TimeoutSeconds: 1}, p.Supports(name)
}
func (p *returnedToolFixture) Invoke(ctx context.Context, _ ToolCommand) (map[string]any, error) {
	p.calls++
	if p.after != nil {
		p.after(ctx)
	}
	return map[string]any{"value": "private-known-tool-result"}, nil
}

func TestKnownToolResultSurvivesResponseAuthorityFailureWithoutReexecution(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cause  error
		status int
	}{
		{"revoked", errors.New("revoked after actual tool result"), 403},
		{"read-wait", &pgconn.PgError{Code: "55P03"}, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			m := newTestModule("internal-token", "signing-secret", public, "platform", "agent-runtime")
			authority := &returnedToolAuthority{}
			m.SetLiveExecutionAuthority(authority)
			store := newMemoryToolInvocationStore()
			m.toolStore = store
			port := &returnedToolFixture{after: func(context.Context) { authority.problem = tc.cause }}
			m.SetToolProvider(port)
			c := capabilityContext()
			c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
			input := map[string]any{"name": "fixture.read", "call_id": "known-result", "payload": map[string]any{}}
			first := capabilityRequest(t, m, "/internal/tool/invoke", c, input)
			if first.Code != tc.status || strings.Contains(first.Body.String(), "private-known-tool-result") || port.calls != 1 {
				t.Fatal("disclosure guard or exactly-once command lost", first.Code, first.Body.String(), port.calls)
			}
			record, found, err := store.LookupToolInvocation(context.Background(), toolScopeHash(c), "known-result")
			if err != nil || !found || record.Status != "completed" || record.Result == nil {
				t.Fatal("known response was discarded as unknown", record, err)
			}
			authority.problem = nil
			second := capabilityRequest(t, m, "/internal/tool/invoke", c, input)
			if second.Code != http.StatusOK || !strings.Contains(second.Body.String(), "private-known-tool-result") || port.calls != 1 {
				t.Fatal("receipt recovery repeated actual tool", second.Code, port.calls)
			}
		})
	}
}

func TestLateKnownToolResultIsRetainedButDoesNotPassDeadline(t *testing.T) {
	m := newTestModule("internal-token", "signing-secret", nil, "platform", "agent-runtime")
	store := newMemoryToolInvocationStore()
	m.toolStore = store
	port := &returnedToolFixture{after: func(ctx context.Context) { <-ctx.Done() }}
	m.SetToolProvider(port)
	c := capabilityContext()
	input := map[string]any{"name": "fixture.read", "call_id": "late-known-result", "payload": map[string]any{}}
	first := capabilityRequest(t, m, "/internal/tool/invoke", c, input)
	if first.Code != 504 || !strings.Contains(first.Body.String(), "TOOL_EXECUTION_TIMEOUT") || strings.Contains(first.Body.String(), "private-known-tool-result") {
		t.Fatal("late result passed deadline or leaked output", first.Code, first.Body.String())
	}
	stored, found, err := store.LookupToolInvocation(context.Background(), toolScopeHash(c), "late-known-result")
	if err != nil || !found || stored.Status != "completed" {
		t.Fatal("late acknowledged work falsely became unknown", stored, err)
	}
	second := capabilityRequest(t, m, "/internal/tool/invoke", c, input)
	if second.Code != 200 || port.calls != 1 {
		t.Fatal("late result recovery reexecuted provider", second.Code, port.calls)
	}
}

type renewalScript struct {
	delegate ToolLeaseRenewalStore
	calls    int
	run      func(context.Context, ToolExecutionLease, time.Duration, int) (ToolExecutionLease, error)
}

func (s *renewalScript) RenewTool(ctx context.Context, l ToolExecutionLease, ttl time.Duration) (ToolExecutionLease, error) {
	s.calls++
	return s.run(ctx, l, ttl, s.calls)
}

func TestToolRenewalRetriesOnlyInsideAcknowledgedLease(t *testing.T) {
	store := newMemoryToolInvocationStore()
	ctx := context.Background()
	entry, _, err := store.AcquireTool(ctx, "scope", "renew-script", "fp", "owner", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BeginTool(ctx, entry.Lease); err != nil {
		t.Fatal(err)
	}
	script := &renewalScript{}
	script.run = func(ctx context.Context, l ToolExecutionLease, ttl time.Duration, attempt int) (ToolExecutionLease, error) {
		if attempt == 1 {
			// Conditional renewal committed but its response was lost. The
			// retry must keep the exact owner and never invent acknowledged TTL.
			if _, err := store.RenewTool(ctx, l, ttl); err != nil {
				return ToolExecutionLease{}, err
			}
			return ToolExecutionLease{}, &pgconn.PgError{Code: "08006"}
		}
		if l != entry.Lease {
			t.Fatal("unknown renewal changed acknowledged identity/deadline")
		}
		return store.RenewTool(ctx, l, ttl)
	}
	renewed, _, err := (&Module{}).renewToolLeaseWithinFence(ctx, entry.Lease, time.Second, envelope{}, script)
	if err != nil || script.calls != 2 || !renewed.Until.After(entry.Lease.Until) {
		t.Fatal("safe renewal did not recover", script.calls, renewed, err)
	}
	stale := renewed
	stale.Until = time.Now().Add(-time.Millisecond)
	if _, _, err = (&Module{}).renewToolLeaseWithinFence(ctx, stale, time.Second, envelope{}, script); !errors.Is(err, ErrToolInvocationConflict) || script.calls != 2 {
		t.Fatal("expired acknowledged lease was retried", script.calls, err)
	}
	denied := &renewalScript{run: func(context.Context, ToolExecutionLease, time.Duration, int) (ToolExecutionLease, error) {
		return ToolExecutionLease{}, ErrToolInvocationConflict
	}}
	if _, _, err = (&Module{}).renewToolLeaseWithinFence(ctx, renewed, time.Second, envelope{}, denied); !errors.Is(err, ErrToolInvocationConflict) || denied.calls != 1 {
		t.Fatal("stale owner retried", denied.calls, err)
	}
}

func TestToolWatchFailureRetainsCauseAndLocalScope(t *testing.T) {
	for _, tc := range []struct {
		stage  string
		err    error
		status int
		code   string
	}{
		{"current_authority", &pgconn.PgError{Code: "55P03"}, 503, "CAPABILITY_UNAVAILABLE"},
		{"current_authority", errors.New("revoked"), 403, "CAPABILITY_DENIED"},
		{"lease_renewal", ErrToolInvocationConflict, 409, "TOOL_RESULT_UNKNOWN"},
	} {
		done := make(chan struct{})
		close(done)
		w := &toolLeaseWatch{stop: func() {}, done: done, failure: tc.err, stage: tc.stage}
		status, code := w.failureStatus()
		if w.finish() || status != tc.status || code != tc.code {
			t.Fatal("watcher discarded actual failure scope", status, code)
		}
	}
}
