package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/bootstrap"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestToolApprovalHTTPGatewaySessionAndInternalIsolation(t *testing.T) {
	module := newTestModule("internal-token", "signing-secret", nil, "platform", "agent-runtime")
	scope := scopeFromHarness(capabilityContext())
	resolutions := 0
	module.SetToolApprovalControl(&ToolApprovalControl{Store: &SQLToolApprovalStore{}, Resolve: func(r *http.Request, op ToolApprovalOperation) (sharedkernel.Scope, string, error) {
		resolutions++
		if op.RunID != scope.RunID {
			return sharedkernel.Scope{}, "", errors.New("wrong run")
		}
		return scope, strings.Repeat("b", 64), nil
	}})
	gateway := strings.Repeat("g", 32)
	activeSession := true
	public := bootstrap.BrowserBoundary(bootstrap.BrowserSessionBoundary(http.StripPrefix("/modules/capability", module.Handler()), func(context.Context, *http.Request) (bool, error) { return activeSession, nil }), gateway, module.internalToken)
	server := httptest.NewServer(public)
	defer server.Close()
	operation := ToolApprovalOperation{RunID: scope.RunID, Name: "fixture.read", CallID: "approved-call", Payload: map[string]any{"password": "private-payload-marker", "value": "approved"}}
	request := func(token, principal string, input any) (int, []byte) {
		t.Helper()
		body, _ := json.Marshal(input)
		r, _ := http.NewRequest(http.MethodPost, server.URL+"/modules/capability/tool-approvals/preview", bytes.NewReader(body))
		r.Header.Set("X-Internal-Token", token)
		r.Header.Set("X-Browser-Module", "1")
		r.Header.Set("X-Principal-Type", "user")
		r.Header.Set("X-Principal-ID", principal)
		r.Header.Set("X-Tenant-ID", scope.TenantID)
		r.Header.Set("X-Department-ID", scope.DepartmentID)
		r.Header.Set("X-Application-ID", scope.ApplicationID)
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, _ := io.ReadAll(response.Body)
		return response.StatusCode, raw
	}
	input := map[string]any{"operation": operation}
	status, raw := request(module.internalToken, scope.PrincipalID, input)
	if status != 403 || resolutions != 0 {
		t.Fatal("runtime credential forged browser identity")
	}
	activeSession = false
	status, _ = request(gateway, scope.PrincipalID, input)
	if status != 401 || resolutions != 0 {
		t.Fatal("inactive session reached approval")
	}
	activeSession = true
	status, _ = request(gateway, "foreign-user", input)
	if status != 403 {
		t.Fatal("foreign caller approved operation")
	}
	status, raw = request(gateway, scope.PrincipalID, input)
	if status != 200 || strings.Contains(string(raw), "private-payload-marker") || !strings.Contains(string(raw), "REDACTED") {
		t.Fatalf("preview status=%d or sensitive preview escaped", status)
	}
	var response struct {
		Data struct {
			Claims ToolConfirmationClaims `json:"claims"`
			Digest string                 `json:"request_digest"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &response) != nil || response.Data.Claims.ScopeHash != ToolReceiptScopeHash(scope) || response.Data.Claims.CallID != operation.CallID || response.Data.Digest != ToolApprovalDigest(response.Data.Claims) {
		t.Fatal("preview not bound to operation")
	}
	r := httptest.NewRequest(http.MethodPost, "/tool-approvals/preview", bytes.NewReader(raw))
	r.Header.Set("X-Internal-Token", module.internalToken)
	r.Header.Set("X-Browser-Module", "1")
	r.Header.Set("X-Principal-Type", "user")
	internal := httptest.NewRecorder()
	module.InternalHandler().ServeHTTP(internal, r)
	if internal.Code != 403 || !strings.Contains(internal.Body.String(), "HUMAN_CONTROL_PLANE_ONLY") {
		t.Fatal("internal Agent listener exposed human control")
	}
}
