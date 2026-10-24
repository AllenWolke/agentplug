package identity

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type workloadVersionFixture struct {
	primary string
	deny    bool
}

func (f workloadVersionFixture) ResolvePermissionResource(_ context.Context, s sharedkernel.Scope, typ, id string) (PermissionResource, error) {
	return PermissionResource{Type: typ, ID: id, TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, InstallationID: s.InstallationID, AgentID: "fixture-agent", AgentVersionID: f.primary}, nil
}

func (f workloadVersionFixture) ValidateWorkloadBindingVersions(_ context.Context, s sharedkernel.Scope, versions []string) error {
	if f.deny || s.AgentID != "fixture-agent" || s.AgentVersionID != f.primary {
		return ErrInvalidResource
	}
	for _, v := range versions {
		if v != "fixture-version" && v != "fixture-version-new" {
			return ErrInvalidResource
		}
	}
	return nil
}

func TestSQLWorkloadBindingRetainsPinnedVersionWithoutCapabilityGrant(t *testing.T) {
	f := newAdministratorFixture(t)
	a := f.actors[0]
	const subject = "version-retaining-executor"
	if err := f.store.CreatePrincipal(f.ctx, Principal{Type: PrincipalServicePrincipal, ID: subject, TenantID: a.TenantID, IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('service_principal',?,'v2',1,1)`), subject); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateMachineCredential(f.ctx, MachineCredential{TenantID: a.TenantID, PrincipalID: subject, SecretHash: strings.Repeat("a", 64), NetworkCIDRs: []string{"127.0.0.1/32"}, Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	f.store.SetCapabilityResourceResolver(workloadVersionFixture{primary: "fixture-version"})
	c := WorkloadBindingCommand{Binding: WorkloadBinding{TenantID: a.TenantID, DepartmentID: a.DepartmentID, ApplicationID: a.ApplicationID, InstallationID: "fixture-installation", AgentID: "fixture-agent", AgentVersionID: "fixture-version", PrincipalID: subject}, IdempotencyKey: "legacy-bind", Reason: "create original execution binding"}
	if _, err := f.store.ChangeWorkloadBinding(f.ctx, a, c); err != nil {
		t.Fatal(err)
	}
	scope := a
	scope.InstallationID, scope.AgentInstanceID = c.Binding.InstallationID, c.Binding.InstallationID
	scope.AgentID, scope.AgentVersionID, scope.AuthorizationEpoch = c.Binding.AgentID, c.Binding.AgentVersionID, 1
	scope.SessionID, scope.RunID, scope.TraceID = "original-session", "original-run", "original-trace"
	f.store.SetCapabilityResourceResolver(workloadVersionFixture{primary: "fixture-version-new"})
	c.ExpectedRevision, c.IdempotencyKey = 1, "retain-version"
	c.Binding.SchemaVersion, c.Binding.AgentVersionID = WorkloadBindingSchemaV2, "fixture-version-new"
	c.Binding.AllowedAgentVersionIDs = []string{"fixture-version-new", "fixture-version"}
	denied := c
	denied.Binding.AllowedAgentVersionIDs = []string{"fixture-version-new", "unpublished"}
	if _, err := f.store.ChangeWorkloadBinding(f.ctx, a, denied); !errors.Is(err, ErrInvalidResource) {
		t.Fatal("unpublished version retained", err)
	}
	f.store.SetCapabilityResourceResolver(workloadTargetFixture{})
	unsupported := c
	unsupported.Binding.AgentVersionID = "fixture-version"
	if _, err := f.store.ChangeWorkloadBinding(f.ctx, a, unsupported); !errors.Is(err, ErrInvalidResource) {
		t.Fatal("missing publication validator accepted", err)
	}
	f.store.SetCapabilityResourceResolver(workloadVersionFixture{primary: "fixture-version-new"})
	receipt, err := f.store.ChangeWorkloadBinding(f.ctx, a, c)
	if err != nil || receipt.Binding.Revision != 2 {
		t.Fatal(receipt, err)
	}
	retry, err := f.store.ChangeWorkloadBinding(f.ctx, a, c)
	if err != nil || !reflect.DeepEqual(retry, receipt) {
		t.Fatal("retry changed version set or epoch", retry, err)
	}
	stale := c
	stale.IdempotencyKey = "stale-retain"
	if _, err := f.store.ChangeWorkloadBinding(f.ctx, a, stale); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("stale update accepted", err)
	}
	for _, version := range []string{"fixture-version", "fixture-version-new"} {
		scope.AgentVersionID = version
		b, err := f.store.ResolveWorkloadIdentity(f.ctx, scope)
		if err != nil || b.AgentVersionID != version || b.PrincipalID != subject || b.Revision != 2 {
			t.Fatal("pinned execution version lost", b, err)
		}
	}
	for _, mutate := range []func(*sharedkernel.Scope){
		func(s *sharedkernel.Scope) { s.AgentVersionID = "undeclared" },
		func(s *sharedkernel.Scope) { s.AgentID = "other-agent" },
		func(s *sharedkernel.Scope) { s.ApplicationID = "other-application" },
		func(s *sharedkernel.Scope) { s.AuthorizationEpoch = 0 },
	} {
		foreign := scope
		mutate(&foreign)
		if _, err := f.store.ResolveWorkloadIdentity(f.ctx, foreign); err == nil {
			t.Fatal("foreign or untrusted run acquired identity", foreign)
		}
	}
	machine, err := f.store.PermissionSnapshot(f.ctx, PrincipalServicePrincipal, subject)
	if err != nil || len(machine.Grants) != 0 || machine.Principal.Revision != 3 {
		t.Fatal("version set granted capability or duplicated mutation", machine, err)
	}
	revoke := c
	revoke.Binding.SchemaVersion, revoke.Binding.AllowedAgentVersionIDs = "", nil
	revoke.ExpectedRevision, revoke.IdempotencyKey, revoke.Revoke = 2, "revoke-all-versions", true
	closed, err := f.store.ChangeWorkloadBinding(f.ctx, a, revoke)
	if err != nil || closed.Binding.SchemaVersion != WorkloadBindingSchemaV2 || len(closed.Binding.AllowedAgentVersionIDs) != 2 || closed.Binding.Status != "revoked" {
		t.Fatal("revocation lost retained versions", closed, err)
	}
	for _, v := range []string{"fixture-version", "fixture-version-new"} {
		scope.AgentVersionID = v
		if _, err := f.store.ResolveWorkloadIdentity(f.ctx, scope); !errors.Is(err, sql.ErrNoRows) {
			t.Fatal("retained version escaped revocation", v, err)
		}
	}
}
