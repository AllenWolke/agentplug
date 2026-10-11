package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"net/http"
	"testing"
	"time"
)

type resourceAuthorityFixture struct {
	access CapabilityResourceAccess
	calls  int
	denied bool
}

// These pre-existing resource-boundary fixtures explicitly exercise legacy
// knowledge behavior; v2 document authorization has separate end-to-end cases.
func (f *resourceAuthorityFixture) FilterKnowledgeDocuments(context.Context, sharedkernel.Scope, string, []policyasset.KnowledgeDocumentBinding) (KnowledgeDocumentPlan, error) {
	return KnowledgeDocumentPlan{Legacy: true}, nil
}

func (f *resourceAuthorityFixture) AuthorizeCapability(context.Context, sharedkernel.Scope, string, string, string) error {
	return nil
}
func (f *resourceAuthorityFixture) AuthorizeCapabilityResource(_ context.Context, scope sharedkernel.Scope, access CapabilityResourceAccess) error {
	f.access = access
	f.calls++
	if scope.PrincipalID != "user-a" || scope.InstallationID != "install-a" {
		return errors.New("incorrect signed scope")
	}
	if f.denied {
		return errors.New("resource revoked")
	}
	return nil
}

type runOnlyAuthorityFixture struct{}

func (runOnlyAuthorityFixture) AuthorizeCapability(context.Context, sharedkernel.Scope, string, string, string) error {
	return nil
}

func TestCapabilityResourceActionsAreDerivedFromActualRouteAndInput(t *testing.T) {
	c := capabilityContext()
	c.KnowledgeScope = "context-scope"
	for _, tc := range []struct {
		path            string
		input           string
		action, typ, id string
	}{
		{"/internal/model/generate", `{}`, "model.generate", "model", "model-a"},
		{"/internal/model/embed", `{}`, "model.embed", "model", "model-a"},
		{"/internal/tool/invoke", `{"name":"actual-tool"}`, "tool.invoke", "tool", "actual-tool"},
		{"/internal/knowledge/search", `{"knowledge_scope":"actual-knowledge"}`, "knowledge.search", "knowledge", "actual-knowledge"},
		{"/internal/knowledge/answer", `{"knowledge_scope":"actual-knowledge"}`, "knowledge.search", "knowledge", "actual-knowledge"},
		{"/internal/knowledge/replay", `{"request_id":"original"}`, "knowledge.search", "knowledge", "context-scope"},
		{"/internal/memory/access", `{"operation":" LOAD "}`, "memory.read", "memory", "memory-a"},
		{"/internal/memory/access", `{"operation":"save"}`, "memory.write", "memory", "memory-a"},
	} {
		got, err := resourceAccessForRoute(tc.path, envelope{Context: c, Input: json.RawMessage(tc.input)})
		if err != nil || got != (CapabilityResourceAccess{tc.action, tc.typ, tc.id}) {
			t.Fatal(tc.path, got, err)
		}
	}
	for _, input := range []string{`{"operation":"delete"}`, `{`} {
		if _, err := resourceAccessForRoute("/internal/memory/access", envelope{Context: c, Input: json.RawMessage(input)}); err == nil {
			t.Fatal("invalid operation accepted")
		}
	}
}

func TestSignedCapabilityRequiresCurrentResourceGrantBeforeEffect(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := newTestModule("internal-token", "signing-secret", public, "platform", "agent-runtime")
	c := capabilityContext()
	c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
	m.SetLiveExecutionAuthority(runOnlyAuthorityFixture{})
	request := map[string]any{"texts": []string{"hello"}}
	if got := capabilityRequest(t, m, "/internal/model/embed", c, request); got.Code != http.StatusForbidden {
		t.Fatal("missing resource authority allowed", got.Code)
	}
	f := &resourceAuthorityFixture{}
	m.SetLiveExecutionAuthority(f)
	if got := capabilityRequest(t, m, "/internal/model/embed", c, request); got.Code != http.StatusOK || f.calls != 2 || f.access.Action != "model.embed" {
		t.Fatal(got.Code, f)
	}
	f.denied = true
	if got := capabilityRequest(t, m, "/internal/model/embed", c, request); got.Code != http.StatusForbidden || f.calls != 3 {
		t.Fatal("revocation bypassed", got.Code, f)
	}
}

func (f *resourceAuthorityFixture) AuthenticateWorkload(context.Context, sharedkernel.Scope, string, string, string) error {
	return nil
}
