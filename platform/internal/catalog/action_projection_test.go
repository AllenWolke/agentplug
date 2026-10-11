package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type projectedAgentAccess struct {
	actor       ControlActor
	ids         []string
	permissions map[string]map[string]bool
	err         error
}

func (p *projectedAgentAccess) CanDiscoverAgent(context.Context, string, string, string, string, string, string) (bool, error) {
	panic("batch projection must not fall back to individual discovery")
}

func (p *projectedAgentAccess) ProjectAgentActions(_ context.Context, actor ControlActor, ids []string) (map[string]map[string]bool, error) {
	p.actor, p.ids = actor, ids
	return p.permissions, p.err
}

func TestAvailableAgentsProjectIndependentActionsAndFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name        string
		permissions map[string]map[string]bool
		err         error
		status      int
	}{
		{"read-only discovery", map[string]map[string]bool{"install": {"discover": true, "run": false, "history.read": true}}, nil, 200},
		{"missing installation", map[string]map[string]bool{}, nil, 200},
		{"missing projection", nil, nil, 503},
		{"identity unavailable", nil, errors.New("database unavailable"), 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &memoryStore{availableAgents: []AvailableAgent{{AgentID: "agent", InstallationID: "install"}}}
			projection := &projectedAgentAccess{permissions: tc.permissions, err: tc.err}
			module := NewModule(store, "catalog-token")
			module.SetAgentAccessChecker(projection)
			module.SetControlAuthorizer(controlAuthorizerFunc(func(context.Context, ControlActor, ControlAction, ControlScope) error { return nil }))
			r := httptest.NewRequest("GET", "/available?tenant_id=forged&principal_id=forged", nil)
			for key, value := range map[string]string{"X-Internal-Token": "catalog-token", "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": "alice", "X-Tenant-ID": "t", "X-Department-ID": "d", "X-Application-ID": "a"} {
				r.Header.Set(key, value)
			}
			w := httptest.NewRecorder()
			module.Handler().ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.status, w.Body)
			}
			if projection.actor != (ControlActor{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "alice"}) || len(projection.ids) != 1 || projection.ids[0] != "install" {
				t.Fatal("projection accepted forged scope", projection.actor, projection.ids)
			}
			if tc.status == http.StatusOK {
				var page struct {
					Items []availableAgentResponse `json:"items"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Items) != 1 {
					t.Fatal("missing catalog page", w.Body)
				}
				item := page.Items[0]
				if tc.name == "read-only discovery" && (item.AccessStatus != "granted" || item.Permissions["run"] || !item.Permissions["history.read"]) {
					t.Fatal("discovery expanded into run", w.Body)
				}
				if tc.name == "missing installation" && item.AccessStatus != "restricted" {
					t.Fatal("missing entry granted", w.Body)
				}
			}
		})
	}
}
