package catalog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestEvaluationHealthProbeNeverFollowsRedirect(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer origin.Close()
	health, _ := probeEvaluationHealth(context.Background(), Deployment{Transport: "http", EndpointRef: origin.URL}, "/health")
	if health == "online" || calls.Load() != 0 {
		t.Fatal("redirect treated as healthy/followed")
	}
}
func TestEvaluationHealthProbeRejectsForgedManifestPathsAndCredentialURL(t *testing.T) {
	for _, path := range []string{"//other/health", "/health?credential=x", "/health#fragment", "/health\\redirect"} {
		if health, _ := probeEvaluationHealth(context.Background(), Deployment{Transport: "http", EndpointRef: "http://agent:80"}, path); health != "unknown" {
			t.Fatalf("accepted %s", path)
		}
	}
	if health, _ := probeEvaluationHealth(context.Background(), Deployment{Transport: "http", EndpointRef: "http://user:secret@agent:80"}, "/health"); health != "unknown" {
		t.Fatal("accepted URL credential")
	}
}
func TestEvaluationTargetUsesExplicitInstanceAmongMultipleInstallations(t *testing.T) {
	m, s := evaluationCatalogFixture(t)
	s.installation = s.installations[0]
	second := s.installations[0]
	second.ID = "second-installation"
	s.installations = append(s.installations, second)
	scope := sharedkernel.Scope{TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a", PrincipalID: "alice", InstallationID: "eval-installation"}
	target, e := m.ResolveEvaluationAgentTarget(context.Background(), scope, "eval-agent", "eval-version-1")
	if e != nil || target.InstallationID != "eval-installation" {
		t.Fatalf("exact installation %v", e)
	}
	scope.ApplicationID = "another-app"
	if _, e = m.ResolveEvaluationAgentTarget(context.Background(), scope, "eval-agent", "eval-version-1"); e == nil {
		t.Fatal("cross workspace explicit instance accepted")
	}
}
