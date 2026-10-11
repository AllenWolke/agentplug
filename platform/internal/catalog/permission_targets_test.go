package catalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPermissionTargetsExposeOnlyScopedInstallationMetadata(t *testing.T) {
	store := &memoryStore{installations: []Installation{{ID: "i", TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "agent", VersionID: "v", DisplayName: "Agent", Status: InstallationProvisioning, Revision: 4, DeploymentMode: "managed", DrainPolicy: "wait", RetentionPolicyID: "private-retention"}}}
	m := NewModule(store, "catalog-token")
	m.SetControlAuthorizer(controlAuthorizerFunc(func(_ context.Context, actor ControlActor, action ControlAction, scope ControlScope) error {
		if actor.PrincipalID == "manager" && scope == (ControlScope{TenantID: "t", DepartmentID: "d", ApplicationID: "a"}) && (action == ControlAuthorizationTargets || action == ControlWorkloadTargets || action == ControlDelegationTargets) {
			return nil
		}
		return ErrCatalogForbidden
	}))
	request := func(query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/installations?"+query, nil)
		for k, v := range map[string]string{"Authorization": "Bearer catalog-token", "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": "manager", "X-Tenant-ID": "t", "X-Department-ID": "d", "X-Application-ID": "a"} {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		m.Handler().ServeHTTP(w, r)
		return w
	}
	for _, purpose := range []string{"authorization", "workload", "delegation"} {
		w := request("tenant_id=t&department_id=d&application_id=a&view=permission-targets&purpose=" + purpose)
		if w.Code != http.StatusOK {
			t.Fatal(w.Code)
		}
		var result struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || len(result.Items) != 1 {
			t.Fatal("metadata unavailable", err)
		}
		item := result.Items[0]
		if len(item) != 8 || item["id"] != "i" || item["version_id"] != "v" || item["status"] != "provisioning" {
			t.Fatal("unexpected projection", item)
		}
	}
	for query, status := range map[string]int{
		"tenant_id=t&department_id=d&application_id=a":                                                                http.StatusForbidden,
		"tenant_id=t&department_id=d&application_id=other&view=permission-targets&purpose=workload":                   http.StatusForbidden,
		"tenant_id=t&view=permission-targets&purpose=workload":                                                        http.StatusBadRequest,
		"tenant_id=t&department_id=d&application_id=a&view=permission-targets&purpose=invalid":                        http.StatusBadRequest,
		"tenant_id=t&department_id=d&application_id=a&view=permission-targets&purpose=workload&purpose=authorization": http.StatusBadRequest,
	} {
		if w := request(query); w.Code != status {
			t.Fatalf("%s: %d", query, w.Code)
		}
	}
}
