package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type runtimeDispatchFixture struct {
	descriptor RuntimeToolDescriptor
	name       string
	calls      int
	wait       bool
	received   map[string]any
}

func (p *runtimeDispatchFixture) Supports(name string) bool { return name == p.name }
func (p *runtimeDispatchFixture) RegisteredTools() []string { return []string{p.name} }
func (p *runtimeDispatchFixture) DescribeTool(name string) (RuntimeToolDescriptor, bool) {
	return p.descriptor, p.Supports(name)
}
func (p *runtimeDispatchFixture) Invoke(ctx context.Context, c ToolCommand) (map[string]any, error) {
	p.calls++
	p.received = c.Payload
	if p.wait {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return map[string]any{"answer": "approved-write-result"}, nil
}

func TestRuntimeObservationDispatcherFreezesRegistrationAndRejectsUnsafeExecutors(t *testing.T) {
	p := &runtimeDispatchFixture{name: "fixture.read", descriptor: RuntimeToolDescriptor{ExecutionType: "api", Risk: "write", TimeoutSeconds: 5}}
	d, err := NewExecutionDispatcher(builtinToolProvider{}, p)
	if err != nil {
		t.Fatal(err)
	}
	p.descriptor.Risk = "read_only"
	got, found := d.DescribeTool("fixture.read")
	if !found || got.Risk != "write" || got.ExecutionType != "api" {
		t.Fatal("caller changed frozen risk")
	}
	if _, err = d.WithExecutor(p); err == nil {
		t.Fatal("duplicate replaced executor")
	}
	if !d.Supports("clock.now") || d.Supports("unregistered") {
		t.Fatal("registry mismatch")
	}
	for _, descriptor := range []RuntimeToolDescriptor{
		{ExecutionType: "host", Risk: "read_only", TimeoutSeconds: 1},
		{ExecutionType: "tool", Risk: "read_only", TimeoutSeconds: 4},
		{ExecutionType: "api", Risk: "write", TimeoutSeconds: 6},
		{ExecutionType: "tool", Risk: "unknown", TimeoutSeconds: 1},
		{ExecutionType: "code", Risk: "high", TimeoutSeconds: 30},
	} {
		p.descriptor = descriptor
		if _, err := NewExecutionDispatcher(p); err == nil {
			t.Fatal("unsafe or unsandboxed registration accepted", descriptor)
		}
	}
	if p.calls != 0 {
		t.Fatal("registration executed provider")
	}
}

func TestRuntimeObservationDispatcherCompositionPreservesAllProviders(t *testing.T) {
	api, err := NewAPIToolProvider([]APIBinding{apiTestBinding("https://example.com")}, nil, false, modelgateway.NewGuardedEndpointClient)
	if err != nil {
		t.Fatal(err)
	}
	mcp, err := NewMCPToolProvider([]MCPBinding{{ToolName: "mcp.inspect", RemoteName: "inspect", Endpoint: "https://example.com/mcp", InputSchema: json.RawMessage(`{"type":"object"}`)}}, nil, false, modelgateway.NewGuardedEndpointClient)
	if err != nil {
		t.Fatal(err)
	}
	for _, reverse := range []bool{false, true} {
		m := NewModule("token", "secret", nil, "platform", "agent-runtime")
		if reverse {
			err = m.SetAPIToolProvider(api)
			if err == nil {
				err = m.SetMCPToolProvider(mcp)
			}
		} else {
			err = m.SetMCPToolProvider(mcp)
			if err == nil {
				err = m.SetAPIToolProvider(api)
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"clock.now", "api.read.inspect", "mcp.inspect"} {
			if !m.HasRegisteredTool(name) {
				t.Fatal("installation lost registered provider", name)
			}
		}
		if !m.runtimeConfirmationRequired(nil, "mcp.inspect") || m.runtimeConfirmationRequired(nil, "api.read.inspect") {
			t.Fatal("MCP unknown risk was downgraded")
		}
		if m.SetMCPToolProvider(mcp) == nil || m.SetAPIToolProvider(api) == nil {
			t.Fatal("duplicate installation accepted")
		}
	}
}

func TestRuntimeObservationDispatcherBoundsTimeAndRejectsInvalidScope(t *testing.T) {
	p := &runtimeDispatchFixture{name: "fixture.read", descriptor: RuntimeToolDescriptor{ExecutionType: "tool", Risk: "read_only", TimeoutSeconds: 1}, wait: true}
	d, err := NewExecutionDispatcher(p)
	if err != nil {
		t.Fatal(err)
	}
	c := ToolCommand{Scope: scopeFromHarness(capabilityContext()), Name: p.name, CallID: "bounded", Payload: map[string]any{}}
	started := time.Now()
	if _, err := d.Invoke(context.Background(), c); !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 2*time.Second {
		t.Fatal("timeout not propagated", err)
	}
	c.Scope.AuthorizationEpoch = 0
	if _, err := d.Invoke(context.Background(), c); !errors.Is(err, ErrToolNotSubmitted) {
		t.Fatal("untrusted scope executed")
	}
	c.Scope = scopeFromHarness(capabilityContext())
	c.Name = "unregistered"
	if _, err := d.Invoke(context.Background(), c); !errors.Is(err, ErrToolNotSubmitted) || p.calls != 1 {
		t.Fatal("unregistered executor ran")
	}
}

func TestRuntimeObservationWriteRiskRequiresApprovalEvenWhenPolicyOmitsIt(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := governedInvocationResolver()
	policy.snapshot.Hash = strings.Repeat("b", 64)
	policy.snapshot.Tool.AllowedTools = []string{"fixture.read"}
	policy.snapshot.Tool.RequireConfirmation = nil
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, policy)
	p := &runtimeDispatchFixture{name: "fixture.read", descriptor: RuntimeToolDescriptor{ExecutionType: "api", Risk: "write", TimeoutSeconds: 5}}
	d, err := NewExecutionDispatcher(p)
	if err != nil {
		t.Fatal(err)
	}
	m.SetToolProvider(d)
	denied := false
	m.SetLiveExecutionAuthority(contextPreparationAuthority{testLiveAuthorityFunc: func(context.Context, sharedkernel.Scope, string, string, string) error { return nil }, resource: func(access CapabilityResourceAccess) error {
		if access.Action != "tool.invoke" || access.ResourceID != p.name {
			t.Fatal("missing tool permission")
		}
		if denied {
			return errors.New("revoked")
		}
		return nil
	}})
	c := capabilityContext()
	c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
	input := map[string]any{"name": p.name, "payload": map[string]any{"sequence": json.Number("9007199254740993")}, "confirmed": true}
	if result := capabilityRequest(t, m, "/internal/tool/invoke", c, input); result.Code != 400 || !strings.Contains(result.Body.String(), "RUNTIME_IDEMPOTENCY_REQUIRED") || p.calls != 0 {
		t.Fatal("write accepted generated call id")
	}
	input["call_id"] = "risk-bound-call"
	result := capabilityRequest(t, m, "/internal/tool/invoke", c, input)
	if result.Code != http.StatusForbidden || !strings.Contains(result.Body.String(), "TOOL_CONFIRMATION_REQUIRED") || p.calls != 0 || len(m.toolStore.(*memoryToolInvocationStore).records) != 0 {
		t.Fatal("policy omission bypassed write approval")
	}
	approvalPublic, approvalPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := NewToolConfirmationVerifier(approvalPublic)
	m.SetToolConfirmationVerifier(verifier)
	m.SetToolConfirmationAuthority(confirmationAuthorityFixture{check: func(ToolConfirmationClaims) error { return nil }})
	fp, _ := ToolCommandFingerprint(p.name, input["payload"].(map[string]any))
	input["confirmation_token"] = confirmationTestToken(t, approvalPrivate, confirmationTestClaims(scopeFromHarness(c), policy.snapshot.Hash, p.name, "risk-bound-call", fp, time.Now()))
	if result := capabilityRequest(t, m, "/internal/tool/invoke", c, input); result.Code != 200 || p.calls != 1 {
		t.Fatal("approved write failed")
	}
	if p.received["sequence"] != json.Number("9007199254740993") {
		t.Fatal("runtime changed large integer and approval fingerprint")
	}
	if result := capabilityRequest(t, m, "/internal/tool/invoke", c, input); result.Code != 200 || p.calls != 1 {
		t.Fatal("replay repeated write")
	}
	delete(input, "confirmed")
	if result := capabilityRequest(t, m, "/internal/tool/receipt", c, input); result.Code != 200 || p.calls != 1 {
		t.Fatal("approved read-only receipt failed")
	}
	delete(input, "confirmation_token")
	if result := capabilityRequest(t, m, "/internal/tool/receipt", c, input); result.Code != 403 || strings.Contains(result.Body.String(), "approved-write-result") {
		t.Fatal("receipt bypassed risk approval")
	}
	denied = true
	if result := capabilityRequest(t, m, "/internal/tool/invoke", c, input); result.Code != 403 || p.calls != 1 {
		t.Fatal("revoked permission overrode risk guard")
	}
}
