package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
)

func TestPermissionTargetsExposeOnlyScopedInstallationMetadata(t *testing.T) {
	store := &memoryStore{installations: []Installation{{ID: "i", TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "agent", VersionID: "v", DisplayName: "Agent", Status: InstallationProvisioning, Revision: 4, DeploymentMode: "managed", DrainPolicy: "wait", RetentionPolicyID: "private-retention"}}}
	m := NewModule(store, "catalog-token")
	m.SetControlAuthorizer(controlAuthorizerFunc(func(_ context.Context, actor ControlActor, action ControlAction, scope ControlScope) error {
		if actor.PrincipalID == "manager" && scope == (ControlScope{TenantID: "t", DepartmentID: "d", ApplicationID: "a"}) && (action == ControlAuthorizationTargets || action == ControlWorkloadTargets || action == ControlDelegationTargets || action == ControlDepartmentAgentTargets) {
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
	for _, purpose := range []string{"authorization", "workload", "delegation", "department-access"} {
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

func (m *memoryStore) PagePermissionTargets(ctx context.Context, tenant, department, application, after string, limit int) ([]Installation, string, error) {
	items, err := m.ListInstallations(ctx, tenant, department, application, len(m.installations)+1)
	if err != nil {
		return nil, "", err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	filtered := []Installation{}
	for _, item := range items {
		if item.ID > after {
			filtered = append(filtered, item)
		}
	}
	next := ""
	if len(filtered) > limit {
		filtered = filtered[:limit]
		next = filtered[len(filtered)-1].ID
	}
	return filtered, next, nil
}

func TestDepartmentPermissionTargetsPageBeyondHundredWithinExactAuthorizedScope(t *testing.T) {
	store := &memoryStore{}
	for i := 0; i < 205; i++ {
		store.installations = append(store.installations, Installation{ID: fmt.Sprintf("agent-%03d", i), TenantID: "t", DepartmentID: "d", ApplicationID: "a", Status: InstallationActive, RetentionPolicyID: "secret"})
	}
	store.installations = append(store.installations, Installation{ID: "outside", TenantID: "t", DepartmentID: "other", ApplicationID: "a", Status: InstallationActive})
	m := NewModule(store, "token")
	m.SetControlAuthorizer(controlAuthorizerFunc(func(_ context.Context, actor ControlActor, action ControlAction, scope ControlScope) error {
		if actor.PrincipalID == "manager" && action == ControlDepartmentAgentTargets && scope == (ControlScope{TenantID: "t", DepartmentID: "d", ApplicationID: "a"}) {
			return nil
		}
		return ErrCatalogForbidden
	}))
	request := func(query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/installations?tenant_id=t&department_id=d&application_id=a&view=permission-targets&purpose=department-access&limit=100"+query, nil)
		for key, value := range map[string]string{"Authorization": "Bearer token", "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": "manager", "X-Tenant-ID": "t", "X-Department-ID": "d", "X-Application-ID": "a"} {
			r.Header.Set(key, value)
		}
		w := httptest.NewRecorder()
		m.Handler().ServeHTTP(w, r)
		return w
	}
	count, cursor := 0, ""
	for page := 0; page < 3; page++ {
		w := request("&cursor=" + cursor)
		if w.Code != http.StatusOK {
			t.Fatal(w.Code, w.Body.String())
		}
		var result struct {
			Items []map[string]string `json:"items"`
			Next  string              `json:"next_cursor"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		for _, item := range result.Items {
			if len(item) != 8 || item["id"] == "outside" {
				t.Fatal("out of scope or secret metadata", item)
			}
		}
		count += len(result.Items)
		cursor = result.Next
	}
	if count != 205 || cursor != "" {
		t.Fatal("incomplete directory", count, cursor)
	}
	for _, query := range []string{"&cursor=one&cursor=two", "&cursor=%00", "&cursor=%20after"} {
		if w := request(query); w.Code != http.StatusBadRequest {
			t.Fatal("invalid cursor accepted", w.Code)
		}
	}
}
