package catalog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/bootstrap"
)

func TestPolicyTargetProjectionDoesNotRequireOrConferCatalogManagement(t *testing.T) {
	runtimeToken := strings.Repeat("r", 40)
	gatewayToken := strings.Repeat("g", 40)
	store := &memoryStore{installations: []Installation{{ID: "i", TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "agent", VersionID: "v1", RetentionPolicyID: "PRIVATE-RETENTION", DrainPolicy: "PRIVATE-DRAIN"}}}
	module := NewModule(store, runtimeToken)
	module.SetControlAuthorizer(controlAuthorizerFunc(func(_ context.Context, actor ControlActor, action ControlAction, scope ControlScope) error {
		if actor.PrincipalID != "alice" || action != ControlPromptTargets || scope != (ControlScope{TenantID: "t", DepartmentID: "d", ApplicationID: "a"}) {
			return ErrCatalogForbidden
		}
		return nil
	}))
	handler := bootstrap.BrowserBoundary(http.StripPrefix("/modules/catalog", module.Handler()), gatewayToken, runtimeToken)
	for _, item := range []struct {
		query, token string
		status       int
	}{
		{"view=policy-assets&asset_type=prompt", gatewayToken, 200},
		{"view=policy-assets&asset_type=tool", gatewayToken, 403},
		{"view=policy-assets&asset_type=unknown", gatewayToken, 400},
		{"view=policy-assets&asset_type=prompt", runtimeToken, 403},
		{"", gatewayToken, 403},
	} {
		request := httptest.NewRequest(http.MethodGet, "/modules/catalog/installations?tenant_id=t&department_id=d&application_id=a&"+item.query, nil)
		for key, value := range map[string]string{"X-Internal-Token": item.token, "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": "alice", "X-Tenant-ID": "t", "X-Department-ID": "d", "X-Application-ID": "a"} {
			request.Header.Set(key, value)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != item.status {
			t.Fatalf("%s: %d %s", item.query, response.Code, response.Body.String())
		}
		if item.status == 200 && (!strings.Contains(response.Body.String(), `"version_id":"v1"`) || strings.Contains(response.Body.String(), "PRIVATE")) {
			t.Fatal("target projection exposed non-target data", response.Body.String())
		}
	}
}
