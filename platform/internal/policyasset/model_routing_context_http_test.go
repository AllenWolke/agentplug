package policyasset

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRoutingContextUsesSnapshotAuthorizationWithoutDisclosingPrompt(t *testing.T) {
	scope := Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", AgentID: "agent-a", AgentVersionID: "v1"}
	store := newMemoryControlStore()
	snapshot := Snapshot{Revision: 7, Hash: strings.Repeat("a", 64), Prompt: PromptPolicy{Template: "PRIVATE-QUALIFICATION-PROMPT", TemplateHash: strings.Repeat("b", 64)}}
	store.snapshot[scope] = snapshot
	auth := &testAuthorizer{}
	handler := NewModule(store, auth, "module-secret").Handler()
	const query = "/snapshots/routing-context?tenant_id=tenant-a&department_id=dept-a&application_id=app-a&agent_id=agent-a&agent_version_id=v1"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, browserRequest(http.MethodGet, query, ""))
	var receipt struct {
		Version  string `json:"version"`
		Scope    Scope  `json:"scope"`
		Hash     string `json:"snapshot_hash"`
		Revision uint64 `json:"snapshot_revision"`
		Context  string `json:"execution_context_sha256"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &receipt) != nil || receipt.Version != "model-routing-context-receipt/v1" || receipt.Scope != scope || receipt.Hash != snapshot.Hash || receipt.Revision != 7 || receipt.Context != RoutingExecutionContextSHA256(snapshot) {
		t.Fatal("context was not derived from the exact authorized snapshot")
	}
	if strings.Contains(response.Body.String(), "PRIVATE-QUALIFICATION-PROMPT") || len(auth.calls) != 1 || auth.calls[0].action != ActionRead || auth.calls[0].scope != scope {
		t.Fatal("context leaked data or bypassed snapshot access")
	}
	profileResponse := httptest.NewRecorder()
	handler.ServeHTTP(profileResponse, browserRequest(http.MethodGet, query+"&include_qualification_profile=true", ""))
	var profile struct {
		Version string `json:"version"`
		Profile string `json:"qualification_profile_sha256"`
		Context string `json:"execution_context_sha256"`
	}
	if profileResponse.Code != 200 || json.Unmarshal(profileResponse.Body.Bytes(), &profile) != nil || profile.Version != "model-routing-context-receipt/v2" || profile.Profile != RoutingQualificationProfileSHA256(snapshot) || profile.Context != receipt.Context || strings.Contains(profileResponse.Body.String(), snapshot.Prompt.Template) {
		t.Fatal("profile opt-in lost provenance or leaked content")
	}
	auth.err = ErrForbidden
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, browserRequest(http.MethodGet, query, ""))
	if denied.Code != 403 || strings.Contains(denied.Body.String(), receipt.Context) {
		t.Fatal("revoked access disclosed qualification context")
	}
	wrongMethod := httptest.NewRecorder()
	handler.ServeHTTP(wrongMethod, browserRequest(http.MethodPost, query, "{}"))
	if wrongMethod.Code != 405 || store.snapshot[scope].Revision != 7 {
		t.Fatal("read-only context endpoint changed policy")
	}
}
