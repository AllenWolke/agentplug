package identity

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type explanationAvailabilityFixture struct {
	capabilityFixtureResolver
	reason      string
	failure     error
	beforeEpoch func() error
}

func (r explanationAvailabilityFixture) ResolvePermissionResource(ctx context.Context, scope sharedkernel.Scope, typ, id string) (PermissionResource, error) {
	if r.beforeEpoch != nil {
		if err := r.beforeEpoch(); err != nil {
			return PermissionResource{}, err
		}
	}
	if typ == "agent_installation" && id == "installation-test" {
		return PermissionResource{Type: typ, ID: id, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
			InstallationID: id, AgentID: "explanation-agent", AgentVersionID: "explanation-version"}, r.failure
	}
	return r.capabilityFixtureResolver.ResolvePermissionResource(ctx, scope, typ, id)
}

func (r explanationAvailabilityFixture) ResolvePermissionRunAvailability(context.Context, sharedkernel.Scope) (string, error) {
	return r.reason, r.failure
}

func TestSQLPermissionExplanationSelfAdministratorScopeAndOutage(t *testing.T) {
	f := newAdministratorFixture(t)
	f.store.SetPermissionResourceResolver(permissionTestResourceResolver{})
	f.store.SetCapabilityResourceResolver(explanationAvailabilityFixture{})
	actor := f.actors[2]
	scope := ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	q := PermissionQuery{Action: "run", Scope: scope, ResourceType: "agent_installation", ResourceID: "installation-test"}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = insertRoleBinding(f.ctx, tx, RoleBinding{ID: "explain-operator", SubjectID: actor.PrincipalID, RoleCode: "operator", RoleVersion: 1, Scope: scope, Status: "active", Revision: 1, SourceID: "explanation-fixture", PresetCode: "operator", PresetVersion: 1}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"explain-allow-a", "explain-allow-b"} {
		if err = insertPermissionGrant(f.ctx, tx, Grant{ID: id, SubjectType: PrincipalUser, SubjectID: actor.PrincipalID, TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, AgentInstanceID: q.ResourceID, ResourceType: q.ResourceType, ResourceID: q.ResourceID, Action: "run", Effect: "allow", Status: "active", Revision: 1, SourceID: id, DataScope: DataScope{Type: "owner"}}, f.now); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	self, err := f.store.ExplainPermission(f.ctx, actor, PrincipalUser, actor.PrincipalID, q)
	if err != nil || !self.Allowed || len(self.Grants) != 2 || len(self.Bindings) != 1 || self.SubjectRevision != 1 || self.Bindings[0].PresetVersion != 1 || !self.ComputedAt.Equal(f.now) {
		t.Fatal("actual SQL self explanation", self, err)
	}
	actualScope := actor
	actualScope.InstallationID, actualScope.AgentInstanceID = q.ResourceID, q.ResourceID
	actualScope.AgentID, actualScope.AgentVersionID = self.AgentID, self.AgentVersionID
	epoch, err := f.store.CurrentAuthorizationEpoch(f.ctx, actualScope, "run")
	if err != nil || self.AuthorizationEpoch == nil || *self.AuthorizationEpoch != epoch || epoch != 1 {
		t.Fatal("explanation and execution did not use the same persisted epoch", self, epoch, err)
	}
	if _, err = f.store.currentAuthorizationEpoch(f.ctx, actualScope, "run", "stale-diagnostic-snapshot"); !errors.Is(err, ErrPermissionExplanationStale) {
		t.Fatal("mismatching diagnostic snapshot accepted", err)
	}
	admin, err := f.store.ExplainPermission(f.ctx, f.actors[0], PrincipalUser, actor.PrincipalID, q)
	if err != nil || admin.EffectiveVersion != self.EffectiveVersion {
		t.Fatal("administrator did not explain the same snapshot", admin, err)
	}
	if _, err = f.store.ExplainPermission(f.ctx, actor, PrincipalUser, f.actors[0].PrincipalID, q); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("ordinary user explained another account", err)
	}
	// The authenticated HTTP endpoint accepts a scoped administrator target,
	// preserves flat allowed/reason fields and emits actual versioned metadata.
	principal, err := f.store.GetPrincipal(f.ctx, PrincipalUser, f.actors[0].PrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(map[string]any{"subject_id": actor.PrincipalID, "subject_type": "user", "action": "run", "scope": scope, "resource_type": q.ResourceType, "resource_id": q.ResourceID})
	r := httptest.NewRequest(http.MethodPost, "/permissions:explain", strings.NewReader(string(encoded)))
	setBrowserIdentityHeaders(r, principal, actor.DepartmentID, actor.ApplicationID)
	r.Header.Set("Authorization", "Bearer fixture-internal")
	w := httptest.NewRecorder()
	NewModule(f.store, "fixture-internal").Handler().ServeHTTP(w, r)
	var body PermissionExplanation
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil || !body.Allowed || body.SubjectID != actor.PrincipalID || body.EffectiveVersion != self.EffectiveVersion {
		t.Fatal("actual SQL-backed HTTP explanation", w.Code)
	}
	tx, err = f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = insertRoleBinding(f.ctx, tx, RoleBinding{ID: "explain-scoped-admin", SubjectID: actor.PrincipalID, RoleCode: "permission_admin", RoleVersion: 1, Scope: scope, Status: "active", Revision: 1, SourceID: "fixture-scoped"}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	management := q
	management.Action = "principal.read"
	management.ResourceType = ""
	management.ResourceID = ""
	bounded, err := f.store.ExplainPermission(f.ctx, actor, PrincipalUser, f.actors[0].PrincipalID, management)
	if err != nil || !bounded.Allowed || len(bounded.Bindings) != 0 || len(bounded.BindingIDs) != 0 {
		t.Fatal("scoped administrator saw global source facts", bounded, err)
	}
	if bounded.AuthorizationEpoch != nil {
		t.Fatal("management explanation fabricated an execution epoch")
	}
	outside := management
	outside.Scope.ApplicationID = "nonexistent-or-outside"
	if _, err = f.store.ExplainPermission(f.ctx, actor, PrincipalUser, f.actors[0].PrincipalID, outside); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("outside scope existence exposed", err)
	}
	forged := q
	forged.Scope.Type = "agent_installation"
	forged.Scope.ResourceID = "other-installation"
	if _, err = f.store.ExplainPermission(f.ctx, actor, PrincipalUser, actor.PrincipalID, forged); !errors.Is(err, ErrInvalidResource) {
		t.Fatal("public explanation accepted inconsistent installation coordinates", err)
	}
	f.store.SetPermissionResourceResolver(nil)
	if _, err = f.store.ExplainPermission(f.ctx, actor, PrincipalUser, actor.PrincipalID, q); !errors.Is(err, ErrPermissionResourceResolverUnavailable) {
		t.Fatal("missing ownership authority returned stored allow", err)
	}
	f.store.SetPermissionResourceResolver(permissionTestResourceResolver{})
	for _, reason := range []string{"RESOURCE_NOT_PUBLISHED", "RESOURCE_UNAVAILABLE"} {
		f.store.SetCapabilityResourceResolver(explanationAvailabilityFixture{reason: reason})
		blocked, e := f.store.ExplainPermission(f.ctx, actor, PrincipalUser, actor.PrincipalID, q)
		if e != nil || blocked.Allowed || blocked.Reason != reason || len(blocked.Grants) != 2 || blocked.AuthorizationEpoch != nil {
			t.Fatal("Catalog block was not explained separately from IAM sources", blocked, e)
		}
	}
	failure := errors.New("Catalog unavailable")
	f.store.SetCapabilityResourceResolver(explanationAvailabilityFixture{failure: failure})
	if _, err = f.store.ExplainPermission(f.ctx, actor, PrincipalUser, actor.PrincipalID, q); !errors.Is(err, failure) {
		t.Fatal("Catalog outage returned stored IAM allow", err)
	}
	f.store.SetCapabilityResourceResolver(nil)
	if _, err = f.store.ExplainPermission(f.ctx, actor, PrincipalUser, actor.PrincipalID, q); !errors.Is(err, ErrPermissionResourceResolverUnavailable) {
		t.Fatal("missing Catalog state port returned stored IAM allow", err)
	}
	f.store.SetCapabilityResourceResolver(explanationAvailabilityFixture{})
	// Change the actual principal after the diagnostic snapshot commits, just
	// before the runtime epoch query. The response must fail, not mix generations.
	f.store.SetCapabilityResourceResolver(explanationAvailabilityFixture{beforeEpoch: func() error {
		_, e := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET revision=revision+1 WHERE principal_type='user' AND id=?`), actor.PrincipalID)
		return e
	}})
	r = httptest.NewRequest(http.MethodPost, "/permissions:explain", strings.NewReader(string(encoded)))
	setBrowserIdentityHeaders(r, principal, actor.DepartmentID, actor.ApplicationID)
	r.Header.Set("Authorization", "Bearer fixture-internal")
	w = httptest.NewRecorder()
	NewModule(f.store, "fixture-internal").Handler().ServeHTTP(w, r)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "PERMISSION_EXPLANATION_STALE") || strings.Contains(w.Body.String(), `"allowed":true`) {
		t.Fatal("old HTTP explanation paired with new runtime epoch", w.Code)
	}
	f.store.SetCapabilityResourceResolver(explanationAvailabilityFixture{})
	fresh, err := f.store.ExplainPermission(f.ctx, actor, PrincipalUser, actor.PrincipalID, q)
	if err != nil || fresh.AuthorizationEpoch == nil || *fresh.AuthorizationEpoch <= epoch || fresh.SubjectRevision != 2 {
		t.Fatal("fresh explanation did not advance to the actual execution generation", fresh, err)
	}
	if err = f.db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.ExplainPermission(f.ctx, actor, PrincipalUser, actor.PrincipalID, q); err == nil {
		t.Fatal("authority outage returned a cached explanation")
	}
}
