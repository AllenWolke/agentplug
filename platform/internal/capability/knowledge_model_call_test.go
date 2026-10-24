package capability

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestKnowledgeInternalModelCallRequiresIndependentCurrentResourceGrant(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver := governedModelResolver("local", false, 0)
	resolver.snapshot.Hash = strings.Repeat("b", 64)
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, resolver)
	authority := &resourceAuthorityFixture{}
	m.SetLiveExecutionAuthority(authority)
	accessCalls := 0
	m.SetGovernedModelInvocation(modelAccessResolverFunc(func(context.Context, sharedkernel.Scope, string) (modelgateway.Selection, error) {
		accessCalls++
		return modelgateway.Selection{}, nil
	}), &captureModelGateway{})
	m.knowledge = knowledgeProviderFunc(func(ctx context.Context, _ harnessContext, q knowledgeQuery) (map[string]any, error) {
		// Knowledge access was allowed. Revoke independent model access before
		// the nested stage; it must fail before resolving model/price or sending.
		authority.denied = true
		return q.ModelCall(ctx, "generate", map[string]any{"messages": []map[string]string{{"role": "user", "content": "rewrite"}}})
	})
	c := capabilityContext()
	c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
	response := capabilityRequest(t, m, "/internal/knowledge/search", c, map[string]any{"query": "question", "knowledge_scope": "platform-knowledge"})
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "CAPABILITY_DENIED") || accessCalls != 0 || authority.access.Action != "model.generate" || authority.access.ResourceID != "model-a" {
		t.Fatalf("knowledge resource granted model effect: status=%d access_calls=%d action=%s", response.Code, accessCalls, authority.access.Action)
	}
}

func TestKnowledgeModelDiagnosticsExcludePrivateOrMalformedCodes(t *testing.T) {
	for _, code := range []string{"", "private prompt body", "MODEL_DENIED\nAuthorization: secret", "KEY-secret", strings.Repeat("A", 97), "秘密"} {
		if got := knowledgeModelDiagnosticCode(code); got != "INTERNAL_CODE_REDACTED" {
			t.Fatalf("private diagnostic emitted: %q", got)
		}
	}
	for _, code := range []string{"CAPABILITY_DENIED", "MODEL_INPUT_LIMIT", "MODEL_CONTEXT_LIMIT_2"} {
		if got := knowledgeModelDiagnosticCode(code); got != code {
			t.Fatalf("safe fixed diagnostic lost: %q", got)
		}
	}
}

// factRecheckAuthorityFixture mirrors the composition-root optimized fence:
// the entry check captures request-scoped admission facts, and every later
// stage rechecks the retained workload credential before disclosing a result.
type factRecheckAuthorityFixture struct {
	resourceAuthorityFixture
	rechecks      int
	workloadCalls int
}

func (f *factRecheckAuthorityFixture) AuthorizeCapabilityAndResource(ctx context.Context, scope sharedkernel.Scope, _, _, _ string, access CapabilityResourceAccess) (string, error) {
	if err := f.resourceAuthorityFixture.AuthorizeCapabilityResource(ctx, scope, access); err != nil {
		return "RESOURCE_AUTHORITY", err
	}
	caller := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{ID: scope.PrincipalID, Type: identity.PrincipalType(scope.PrincipalType), TenantID: scope.TenantID}}
	executor := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{ID: "machine-" + scope.RunID, Type: identity.PrincipalServicePrincipal, TenantID: scope.TenantID}}
	binding := identity.WorkloadBinding{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
		InstallationID: scope.InstallationID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID,
		PrincipalID: executor.Principal.ID, Status: "active", Revision: 1}
	credential := identity.MachineCredential{TenantID: scope.TenantID, PrincipalID: executor.Principal.ID, Status: "active", Revision: 1}
	facts := NewCapabilityAdmissionFacts(scope, scope.AuthorizationEpoch, caller, executor, binding, credential)
	if facts == nil || !CaptureCapabilityAdmissionFacts(ctx, facts) {
		return "RUN_AUTHORITY", errors.New("admission facts unavailable")
	}
	return "", nil
}

func (f *factRecheckAuthorityFixture) RecheckCapabilityAndResource(ctx context.Context, scope sharedkernel.Scope, _, _, _ string, access CapabilityResourceAccess, facts *CapabilityAdmissionFacts) error {
	f.rechecks++
	if facts == nil {
		return errors.New("admission facts lost")
	}
	return f.resourceAuthorityFixture.AuthorizeCapabilityResource(ctx, scope, access)
}

func (f *factRecheckAuthorityFixture) AuthenticateWorkload(context.Context, sharedkernel.Scope, string, string, string) error {
	f.workloadCalls++
	return nil
}

func TestTaskEmbeddingSessionNestedStageRetainsWorkloadProof(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver := governedInvocationResolver()
	resolver.snapshot.Hash = strings.Repeat("b", 64)
	resolver.snapshot.Model.EmbeddingModelVersionID = "embedding-version"
	resolver.snapshot.Model.EmbeddingProvider = "embedding-provider"
	resolver.snapshot.Model.EmbeddingModel = "embedding-model"
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, resolver)
	authority := &factRecheckAuthorityFixture{}
	m.SetLiveExecutionAuthority(authority)
	m.SetGovernedModelInvocation(modelAccessResolverFunc(func(context.Context, sharedkernel.Scope, string) (modelgateway.Selection, error) {
		return modelgateway.Selection{ModelVersionID: "embedding-version", ProviderID: "embedding-provider-id", ProviderKey: "embedding-provider",
			ModelID: "embedding-model-id", ModelKey: "embedding-model", TrustZone: modelgovernance.TrustLocal}, nil
	}), &cacheCheckUsageGateway{})
	c := capabilityContext()
	c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-10, time.Now().Unix()+120)
	body, err := json.Marshal(envelope{Context: c, Input: json.RawMessage(`{"task_binding":"immutable-index-job"}`)})
	if err != nil {
		t.Fatal(err)
	}
	path := "/internal/model/embed"
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	r.Header.Set("X-Internal-Token", m.internalToken)
	r.Header.Set("X-Platform-Context", "Bearer "+c.PlatformContextToken)
	mac := hmac.New(sha256.New, []byte(m.signingSecret))
	mac.Write(requestSignaturePayload(http.MethodPost, path, body))
	r.Header.Set("X-Context-Signature", fmt.Sprintf("sha256=%x", mac.Sum(nil)))
	r.Header.Set("X-Agent-Client-ID", "index-worker")
	r.Header.Set("X-Agent-Client-Secret", "fixture-workload-secret-value-12345678")
	r.RemoteAddr = "127.0.0.1:0"
	expected := sharedkernel.Scope{TenantID: c.TenantID, DepartmentID: c.DepartmentID, ApplicationID: c.ApplicationID, AgentID: c.AgentID,
		AgentInstanceID: c.AgentInstanceID, InstallationID: c.InstallationID, AgentVersionID: c.AgentVersionID, PrincipalID: c.ActorID,
		PrincipalType: c.PrincipalType, SessionID: c.SessionID, RunID: c.TaskID, TraceID: c.TraceID, AuthorizationEpoch: c.AuthorizationEpoch}
	session, err := m.OpenTaskEmbeddingSession(context.Background(), r, expected)
	if err != nil {
		t.Fatalf("nested stage rejected retained workload proof: %v", err)
	}
	defer session.Close()
	if authority.rechecks < 1 || authority.workloadCalls < 2 {
		t.Fatalf("nested stage skipped workload revalidation: rechecks=%d workload=%d", authority.rechecks, authority.workloadCalls)
	}
	if err := session.Check(context.Background(), "embed"); err != nil {
		t.Fatal(err)
	}
	if authority.rechecks < 2 || authority.workloadCalls < 3 {
		t.Fatalf("later stage skipped workload revalidation: rechecks=%d workload=%d", authority.rechecks, authority.workloadCalls)
	}
}

type cacheCheckUsageGateway struct{ captureModelGateway }

func (g *cacheCheckUsageGateway) EmbedWithUsage(context.Context, sharedkernel.Scope, policyasset.Snapshot, []string) (modelgateway.EmbeddingResult, error) {
	g.calls++
	return modelgateway.EmbeddingResult{}, modelgateway.ErrProviderUnavailable
}

func TestKnowledgeCacheCheckSelectsPublishedEmbeddingTarget(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver := governedInvocationResolver()
	resolver.snapshot.Hash = strings.Repeat("b", 64)
	resolver.snapshot.Model.EmbeddingModelVersionID = "embedding-version"
	resolver.snapshot.Model.EmbeddingProvider = "embedding-provider"
	resolver.snapshot.Model.EmbeddingModel = "embedding-model"
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, resolver)
	authority := &resourceAuthorityFixture{}
	m.SetLiveExecutionAuthority(authority)
	resolved := 0
	gateway := &cacheCheckUsageGateway{}
	m.SetGovernedModelInvocation(modelAccessResolverFunc(func(_ context.Context, scope sharedkernel.Scope, version string) (modelgateway.Selection, error) {
		resolved++
		if scope.PrincipalID != "user-a" || version != "embedding-version" {
			t.Fatal("cached embedding checked primary model instead of published embedding target")
		}
		return modelgateway.Selection{ModelVersionID: version, ProviderID: "embedding-provider-id", ProviderKey: "embedding-provider", ModelID: "embedding-model-id", ModelKey: "embedding-model", TrustZone: modelgovernance.TrustLocal}, nil
	}), gateway)
	m.knowledge = knowledgeProviderFunc(func(ctx context.Context, _ harnessContext, q knowledgeQuery) (map[string]any, error) {
		if err := q.ModelCheck(ctx, "embed"); err != nil {
			return nil, err
		}
		if authority.access.Action != "model.embed" || authority.access.ResourceID != "model-a" {
			t.Fatal("embedding cache check did not enforce model resource grant", authority.access)
		}
		return map[string]any{"references": []map[string]any{}}, nil
	})
	c := capabilityContext()
	c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
	response := capabilityRequest(t, m, "/internal/knowledge/search", c, map[string]any{"query": "question", "knowledge_scope": "platform-knowledge"})
	if response.Code != http.StatusOK || resolved != 1 || gateway.calls != 0 {
		t.Fatal("cached embedding target check", response.Code, resolved, gateway.calls, authority.access)
	}
}

func TestKnowledgeCacheCheckRequiresCurrentSignedModelAuthority(t *testing.T) {
	for _, mode := range []string{"allowed", "resource-denied", "approval-revoked", "selection-mismatch", "resource-revoked-during-resolution", "retained-after-request"} {
		t.Run(mode, func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			resolver := governedInvocationResolver()
			resolver.snapshot.Hash = strings.Repeat("b", 64)
			m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, resolver)
			authority := &resourceAuthorityFixture{}
			m.SetLiveExecutionAuthority(authority)
			accessCalls := 0
			gateway := &captureModelGateway{}
			m.SetGovernedModelInvocation(modelAccessResolverFunc(func(_ context.Context, scope sharedkernel.Scope, version string) (modelgateway.Selection, error) {
				accessCalls++
				if scope.PrincipalID != "user-a" || version != "version-a" {
					t.Fatal("cache check used untrusted identity or model")
				}
				if mode == "approval-revoked" {
					return modelgateway.Selection{}, modelgovernance.ErrModelAccessDenied
				}
				if mode == "resource-revoked-during-resolution" {
					authority.denied = true
				}
				selection := modelgateway.Selection{ModelVersionID: "version-a", ProviderID: "provider-id", ProviderKey: "provider-a", ModelID: "model-id", ModelKey: "chat-model-a", TrustZone: modelgovernance.TrustLocal}
				if mode == "selection-mismatch" {
					selection.ModelKey = "other"
				}
				return selection, nil
			}), gateway)
			var retained KnowledgeModelCheck
			m.knowledge = knowledgeProviderFunc(func(ctx context.Context, _ harnessContext, q knowledgeQuery) (map[string]any, error) {
				retained = q.ModelCheck
				if mode == "resource-denied" {
					authority.denied = true
				}
				if err := q.ModelCheck(ctx, "generate"); err != nil {
					return nil, err
				}
				return map[string]any{"references": []map[string]any{}}, nil
			})
			c := capabilityContext()
			c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
			response := capabilityRequest(t, m, "/internal/knowledge/search", c, map[string]any{"query": "question", "knowledge_scope": "platform-knowledge"})
			expected := http.StatusForbidden
			if mode == "allowed" || mode == "retained-after-request" {
				expected = http.StatusOK
			}
			if response.Code != expected || gateway.calls != 0 {
				t.Fatal("cache check status/provider invocation", response.Code, gateway.calls)
			}
			if mode == "resource-denied" && accessCalls != 0 {
				t.Fatal("denied resource reached model resolver")
			}
			if mode == "retained-after-request" {
				before := accessCalls
				if err := retained(context.Background(), "generate"); err == nil || accessCalls != before {
					t.Fatal("retained callback escaped request lifetime")
				}
			}
		})
	}
}
