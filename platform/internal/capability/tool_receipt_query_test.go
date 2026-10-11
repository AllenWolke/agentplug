package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestRuntimeObservationReadOnlyReceiptDoesNotExecute(t *testing.T) {
	m := newTestModule("internal-token", "signing-secret", nil, "platform", "agent-runtime")
	p := &observationFixtureProvider{output: map[string]any{"answer": "saved"}}
	m.SetToolProvider(p)
	store := m.toolStore.(*memoryToolInvocationStore)
	c := capabilityContext()
	in := map[string]any{"name": "fixture.read", "call_id": "read-only-receipt", "payload": map[string]any{}}
	missing := capabilityRequest(t, m, "/internal/tool/receipt", c, in)
	if missing.Code != 200 || !strings.Contains(missing.Body.String(), `"status":"not_found"`) || len(store.records) != 0 || p.calls != 0 {
		t.Fatal("query created or executed a missing invocation")
	}
	first := capabilityRequest(t, m, "/internal/tool/invoke", c, in)
	if first.Code != 200 {
		t.Fatal("fixture invoke failed")
	}
	read := capabilityRequest(t, m, "/internal/tool/receipt", c, in)
	if read.Code != 200 || !strings.Contains(read.Body.String(), `"status":"completed"`) || !strings.Contains(read.Body.String(), `runtime-observation/v1`) || p.calls != 1 {
		t.Fatal("query executed or lost completed receipt")
	}
	in["payload"] = map[string]any{"changed": true}
	if result := capabilityRequest(t, m, "/internal/tool/receipt", c, in); result.Code != 409 || strings.Contains(result.Body.String(), "saved") || p.calls != 1 {
		t.Fatal("query ignored fingerprint or disclosed result")
	}
}

func TestRuntimeObservationSignedReceiptRechecksPermissionBeforeReturn(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	policy := governedInvocationResolver()
	policy.snapshot.Hash = strings.Repeat("b", 64)
	policy.snapshot.Tool.AllowedTools = []string{"fixture.read"}
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, policy)
	p := &observationFixtureProvider{output: map[string]any{"answer": "protected-query-body"}}
	m.SetToolProvider(p)
	checks, denyAt := 0, 0
	m.SetLiveExecutionAuthority(contextPreparationAuthority{testLiveAuthorityFunc: func(context.Context, sharedkernel.Scope, string, string, string) error { return nil }, resource: func(access CapabilityResourceAccess) error {
		if access.Action != "tool.invoke" || access.ResourceID != "fixture.read" {
			t.Fatal("query bypassed resource permission")
		}
		checks++
		if checks == denyAt {
			return errors.New("revoked")
		}
		return nil
	}})
	c := capabilityContext()
	c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
	in := map[string]any{"name": "fixture.read", "call_id": "signed-read", "payload": map[string]any{}}
	if result := capabilityRequest(t, m, "/internal/tool/invoke", c, in); result.Code != 200 {
		t.Fatal("invoke failed")
	}
	if result := capabilityRequest(t, m, "/internal/tool/receipt", c, in); result.Code != 200 || p.calls != 1 {
		t.Fatal("signed read failed")
	}
	denyAt = checks + 2
	if result := capabilityRequest(t, m, "/internal/tool/receipt", c, in); result.Code != 403 || strings.Contains(result.Body.String(), "protected-query-body") || p.calls != 1 {
		t.Fatal("query disclosed revoked output or repeated effect")
	}
}
