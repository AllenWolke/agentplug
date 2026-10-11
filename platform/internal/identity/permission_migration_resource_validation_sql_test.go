package identity

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type migrationMutatingResourceResolver struct{ callback func() error }

func (r migrationMutatingResourceResolver) ResolvePermissionResource(ctx context.Context, scope sharedkernel.Scope, typ, id string) (PermissionResource, error) {
	if err := r.callback(); err != nil {
		return PermissionResource{}, err
	}
	return (capabilityFixtureResolver{}).ResolvePermissionResource(ctx, scope, typ, id)
}

func TestSQLMigrationResourcesValidateOwnershipAndRejectConcurrentSourceChange(t *testing.T) {
	f := newAdministratorFixture(t)
	a := f.actors[2]
	batch, err := f.store.InspectMigrationSources(f.ctx, a.TenantID, []MigrationSubject{{Type: PrincipalUser, ID: a.PrincipalID}})
	if err != nil {
		t.Fatal(err)
	}
	source := batch.Sources[0]
	var target PermissionSnapshot
	raw, _ := json.Marshal(source.Snapshot)
	if err := json.Unmarshal(raw, &target); err != nil {
		t.Fatal(err)
	}
	app := ManagementScope{Type: "application", TenantID: a.TenantID, DepartmentID: a.DepartmentID, ApplicationID: a.ApplicationID}
	target.Bindings = []RoleBinding{{ID: "operator", SubjectID: a.PrincipalID, RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active", Revision: 1}}
	target.Grants = []Grant{{ID: "model", TenantID: a.TenantID, DepartmentID: a.DepartmentID, ApplicationID: a.ApplicationID, AgentInstanceID: "fixture-installation", SubjectType: PrincipalUser, SubjectID: a.PrincipalID, Action: "model.generate", Effect: "allow", Status: "active", Revision: 1, ResourceType: "model", ResourceID: "model-fixture", DataScope: DataScope{Type: "owner"}}}
	makePlan := func() MigrationMappingPreview {
		t.Helper()
		p, err := PreviewMigrationMapping(source, MigrationMapping{ExpectedSourceDigest: source.SourceDigest, Basis: "verified fixture", Target: target}, nil, f.now)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := makePlan()
	if _, err := f.store.ValidateMigrationMappingResources(f.ctx, p); err == nil {
		t.Fatal("missing resource ports marked verified")
	}
	f.store.SetPermissionResourceResolver(enrollmentFixtureResolver{})
	f.store.SetCapabilityResourceResolver(capabilityFixtureResolver{})
	verified, err := f.store.ValidateMigrationMappingResources(f.ctx, p)
	if err != nil || !verified.ResourceOwnershipVerified || !verified.PreviewOnly || verified.Digest == p.Digest {
		t.Fatal(verified, err)
	}
	for _, axis := range []string{"type", "id", "tenant", "department", "application", "installation"} {
		f.store.SetCapabilityResourceResolver(capabilityFixtureResolver{mismatch: axis})
		if _, err := f.store.ValidateMigrationMappingResources(f.ctx, p); err == nil {
			t.Fatal("mismatched resource accepted", axis)
		}
	}
	f.store.SetCapabilityResourceResolver(capabilityFixtureResolver{})
	target.Bindings[0].Scope.ApplicationID = "missing-app"
	if _, err := f.store.ValidateMigrationMappingResources(f.ctx, makePlan()); !errors.Is(err, ErrScopeMismatch) {
		t.Fatal("unregistered organization accepted", err)
	}
	target.Bindings[0].Scope = app
	tampered := p
	tampered.Basis = "altered after preview"
	if _, err := f.store.ValidateMigrationMappingResources(f.ctx, tampered); !errors.Is(err, ErrPermissionPlanStale) {
		t.Fatal("tampered preview accepted", err)
	}
	target.Bindings = append(target.Bindings, RoleBinding{ID: "new-admin", SubjectID: a.PrincipalID, RoleCode: "super_admin", RoleVersion: 1, Scope: ManagementScope{Type: "global"}, Status: "active", Revision: 1})
	concealed := makePlan()
	if len(concealed.Issues) == 0 {
		t.Fatal("administrator review issue missing")
	}
	concealed.Issues = []MigrationMappingIssue{}
	concealed.Digest = ""
	raw, _ = json.Marshal(concealed)
	concealed.Digest = permissionHash(raw)
	if _, err := f.store.ValidateMigrationMappingResources(f.ctx, concealed); !errors.Is(err, ErrPermissionPlanStale) {
		t.Fatal("recomputed checksum hid administrator review", err)
	}
	f.store.SetCapabilityResourceResolver(migrationMutatingResourceResolver{callback: func() error {
		_, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE WHERE id=?`), a.PrincipalID)
		return err
	}})
	if _, err := f.store.ValidateMigrationMappingResources(f.ctx, p); !errors.Is(err, ErrPermissionPlanStale) {
		t.Fatal("source change during resource resolution accepted", err)
	}
}
