package identity

import (
	"context"
	"errors"
	"github.com/lexagent/platform/internal/sharedkernel"
	"testing"
	"time"
)

type capabilityFixtureResolver struct {
	failure  error
	mismatch string
}

func (r capabilityFixtureResolver) ResolvePermissionResource(_ context.Context, s sharedkernel.Scope, typ, id string) (PermissionResource, error) {
	if r.failure != nil {
		return PermissionResource{}, r.failure
	}
	if id != typ+"-fixture" {
		return PermissionResource{}, ErrInvalidResource
	}
	result := PermissionResource{Type: typ, ID: id, TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, InstallationID: s.InstallationID}
	switch r.mismatch {
	case "type":
		result.Type = "other"
	case "id":
		result.ID = "other"
	case "tenant":
		result.TenantID = "other"
	case "department":
		result.DepartmentID = "other"
	case "application":
		result.ApplicationID = "other"
	case "installation":
		result.InstallationID = "other"
	}
	return result, nil
}

func TestCapabilityResourceOwnershipAndRequestNormalization(t *testing.T) {
	s := &SQLStore{permissionResourceResolver: enrollmentFixtureResolver{}, capabilityResourceResolver: capabilityFixtureResolver{}}
	scope := ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	for _, tc := range []struct{ typ, action string }{{"model", "model.generate"}, {"tool", "tool.invoke"}, {"knowledge", "knowledge.search"}, {"memory", "memory.read"}} {
		item := PermissionRequestItem{Kind: "resource", Scope: scope, ResourceType: tc.typ, ResourceID: tc.typ + "-fixture", InstallationID: "fixture-installation", Action: tc.action, DataScope: DataScope{Type: "owner"}}
		g, err := permissionRequestResourceGrant(item, "u")
		if err != nil || g.ResourceType != tc.typ || g.AgentInstanceID != item.InstallationID {
			t.Fatal(g, err)
		}
		if err := s.validateGrantResource(context.Background(), g); err != nil {
			t.Fatal(err)
		}
		bad := item
		bad.InstallationID = ""
		if _, err := permissionRequestResourceGrant(bad, "u"); err == nil {
			t.Fatal("missing installation accepted")
		}
		bad = item
		bad.ResourceType = "agent_installation"
		if _, err := permissionRequestResourceGrant(bad, "u"); err == nil {
			t.Fatal("incorrect type accepted")
		}
		for _, mismatch := range []string{"type", "id", "tenant", "department", "application", "installation"} {
			s.capabilityResourceResolver = capabilityFixtureResolver{mismatch: mismatch}
			if s.validateGrantResource(context.Background(), g) == nil {
				t.Fatal("ownership mismatch accepted", mismatch)
			}
		}
		failure := errors.New("provider unavailable")
		s.capabilityResourceResolver = capabilityFixtureResolver{failure: failure}
		if !errors.Is(s.validateGrantResource(context.Background(), g), failure) {
			t.Fatal("provider failure swallowed")
		}
		s.capabilityResourceResolver = nil
		if s.validateGrantResource(context.Background(), g) == nil {
			t.Fatal("unwired capability accepted")
		}
		s.capabilityResourceResolver = capabilityFixtureResolver{}
	}
	legacy := PermissionRequestItem{Action: "run", ResourceID: "fixture-installation", Scope: scope}
	g, err := permissionRequestResourceGrant(legacy, "u")
	if err != nil || g.ResourceType != "agent_installation" || g.AgentInstanceID != legacy.ResourceID {
		t.Fatal("legacy request changed", g, err)
	}
}

func TestCapabilityGrantCannotCrossInstallation(t *testing.T) {
	s, q := permissionFixture()
	q.Action = "knowledge.search"
	q.ResourceType = "knowledge"
	q.ResourceID = "knowledge-fixture"
	q.Scope.Type = "agent_installation"
	q.Scope.ResourceID = "i"
	s.Grants[0].Action = q.Action
	s.Grants[0].ResourceType = q.ResourceType
	s.Grants[0].ResourceID = q.ResourceID
	decision, err := EvaluatePermission(s, q)
	if err != nil || !decision.Allowed {
		t.Fatal(decision, err)
	}
	q.Scope.ResourceID = "other"
	decision, err = EvaluatePermission(s, q)
	if err != nil || decision.Allowed {
		t.Fatal("cross-installation grant accepted", decision, err)
	}
	q.Scope.ResourceID = "i"
	s.Bindings = nil
	decision, err = EvaluatePermission(s, q)
	if err != nil || decision.Allowed {
		t.Fatal("grant replaces human role", decision, err)
	}
}

func TestPermissionQueryCannotOmitOrForgeInstallationBoundary(t *testing.T) {
	s, q := permissionFixture()
	q.Scope.Type = "agent_installation"
	q.Scope.ResourceID = "other"
	d, err := EvaluatePermission(s, q)
	if err != nil || d.Allowed || d.Reason != "INSTALLATION_SCOPE_MISMATCH" {
		t.Fatal("forged installation scope accepted", d, err)
	}
	q.Action, q.ResourceType, q.ResourceID = "knowledge.search", "knowledge", "knowledge-fixture"
	s.Grants[0].Action, s.Grants[0].ResourceType, s.Grants[0].ResourceID = q.Action, q.ResourceType, q.ResourceID
	q.Scope.Type, q.Scope.ResourceID = "application", ""
	d, err = EvaluatePermission(s, q)
	if err != nil || d.Allowed || d.Reason != "INSTALLATION_SCOPE_REQUIRED" {
		t.Fatal("capability installation omitted", d, err)
	}
}

func TestExplanationUsesAuthoritativeResourceOwnershipPorts(t *testing.T) {
	s := &SQLStore{permissionResourceResolver: enrollmentFixtureResolver{}, capabilityResourceResolver: capabilityFixtureResolver{}}
	p := Principal{ID: "u", Type: PrincipalUser, TenantID: "t", IsActive: true}
	q := PermissionQuery{Action: "knowledge.search", Scope: ManagementScope{Type: "agent_installation", TenantID: "t", DepartmentID: "d", ApplicationID: "a", ResourceID: "fixture-installation"}, ResourceType: "knowledge", ResourceID: "knowledge-fixture"}
	if err := s.validateExplanationResource(context.Background(), p, q); err != nil {
		t.Fatal(err)
	}
	for _, dimension := range []string{"type", "id", "tenant", "department", "application", "installation"} {
		s.capabilityResourceResolver = capabilityFixtureResolver{mismatch: dimension}
		if err := s.validateExplanationResource(context.Background(), p, q); err == nil {
			t.Fatal("foreign resource accepted", dimension)
		}
	}
	s.capabilityResourceResolver = nil
	if err := s.validateExplanationResource(context.Background(), p, q); !errors.Is(err, ErrPermissionResourceResolverUnavailable) {
		t.Fatal("missing provider was not an authority outage", err)
	}
}

func TestCapabilityDelegationRequiresTypedInstallationBoundary(t *testing.T) {
	now := time.Now().UTC()
	target := ManagementScope{Type: "agent_installation", TenantID: "t", DepartmentID: "d", ApplicationID: "a", ResourceID: "i"}
	d := Delegation{SubjectID: "admin", Scope: ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}, Actions: []string{"knowledge.search", "run"}, Resources: []string{"knowledge-fixture", "i"}, DataScopeTypes: []string{"owner"}, ManagementActions: []string{"authorization.change"}, AllowPermanent: true, Status: "active"}
	data := DataScope{Type: "owner"}
	if d.Covers("admin", "authorization.change", "", "knowledge.search", "knowledge-fixture", target, data, Validity{}, now) {
		t.Fatal("flat resource ID grants capability delegation")
	}
	d.ResourceBindings = []DelegatedResource{{ResourceType: "knowledge", ResourceID: "knowledge-fixture", InstallationID: "i"}}
	if !d.Covers("admin", "authorization.change", "", "knowledge.search", "knowledge-fixture", target, data, Validity{}, now) {
		t.Fatal("typed delegation denied")
	}
	target.ResourceID = "j"
	if d.Covers("admin", "authorization.change", "", "knowledge.search", "knowledge-fixture", target, data, Validity{}, now) {
		t.Fatal("typed delegation crosses installation")
	}
	target.ResourceID = "i"
	if !d.Covers("admin", "authorization.change", "", "run", "i", target, data, Validity{}, now) {
		t.Fatal("legacy installation delegation changed")
	}
	target.Type = "application"
	target.ResourceID = ""
	if d.Covers("admin", "authorization.change", "", "knowledge.search", "knowledge-fixture", target, data, Validity{}, now) {
		t.Fatal("missing installation boundary accepted")
	}
}
