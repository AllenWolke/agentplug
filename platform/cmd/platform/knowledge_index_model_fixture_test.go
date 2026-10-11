package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// Owned disposable SQL fixture: production grants still use preview/CAS/audit.
func seedIndexModelResources(t *testing.T, db *sql.DB, actor sharedkernel.Scope) capability.TaskWorkloadCredential {
	t.Helper()
	ctx := context.Background()
	store := identity.NewSQLStore(db)
	machine := actor.PrincipalID + "-machine"
	secret := "isolated-index-workload-secret-value-12345678"
	if err := store.CreatePrincipal(ctx, identity.Principal{ID: machine, Type: identity.PrincipalServicePrincipal, TenantID: actor.TenantID, IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('service_principal',$1,'v2',1,1)`, machine); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(secret))
	if err := store.CreateMachineCredential(ctx, identity.MachineCredential{TenantID: actor.TenantID, PrincipalID: machine, SecretHash: hex.EncodeToString(digest[:]), NetworkCIDRs: []string{"127.0.0.1/32"}, Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	app := identity.ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	member := identity.Membership{ID: actor.PrincipalID + "-member", SubjectID: actor.PrincipalID, Scope: app, Status: "active", Revision: 1}
	raw, _ := json.Marshal(member)
	if _, err := db.Exec(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES($1,$2,$3,$4,$5,'active',1,$6,$1)`, member.ID, actor.PrincipalID, actor.TenantID, actor.DepartmentID, actor.ApplicationID, string(raw)); err != nil {
		t.Fatal(err)
	}
	role := identity.RoleBinding{ID: actor.PrincipalID + "-operator", SubjectID: actor.PrincipalID, RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active", Revision: 1, SourceID: "isolated-index-model-fixture"}
	raw, _ = json.Marshal(role)
	if _, err := db.Exec(`INSERT INTO platform_identity_role_binding(id,subject_id,role_code,role_version,tenant_id,department_id,application_id,status,revision,payload,source_hash) VALUES($1,$2,'operator',1,$3,$4,$5,'active',1,$6,$1)`, role.ID, actor.PrincipalID, actor.TenantID, actor.DepartmentID, actor.ApplicationID, string(raw)); err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{actor.PrincipalID, machine} {
		kind := identity.PrincipalUser
		if subject == machine {
			kind = identity.PrincipalServicePrincipal
		}
		grant := identity.Grant{ID: subject + "-embed", SubjectID: subject, SubjectType: kind, TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, AgentInstanceID: actor.InstallationID, ResourceType: "model", ResourceID: "model", Action: "model.embed", Effect: "allow", Status: "active", Revision: 1, SourceID: "isolated-fixture", DataScope: identity.DataScope{Type: "approved_organization"}}
		if err := store.CreateGrant(ctx, grant); err != nil {
			t.Fatal(err)
		}
		raw, _ = json.Marshal(grant)
		if _, err := db.Exec(`UPDATE platform_identity_grant SET permission_json=$1 WHERE id=$2`, string(raw), grant.ID); err != nil {
			t.Fatal(err)
		}
	}
	binding := identity.WorkloadBinding{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, InstallationID: actor.InstallationID, AgentID: actor.AgentID, AgentVersionID: actor.AgentVersionID, PrincipalID: machine, Status: "active", Revision: 1}
	raw, _ = json.Marshal(binding)
	key, _ := json.Marshal([]string{actor.TenantID, actor.DepartmentID, actor.ApplicationID, actor.InstallationID})
	hash := sha256.Sum256(key)
	if _, err := db.Exec(`INSERT INTO platform_identity_workload_binding(scope_hash,tenant_id,department_id,application_id,installation_id,principal_id,status,revision,payload) VALUES($1,$2,$3,$4,$5,$6,'active',1,$7)`, hex.EncodeToString(hash[:]), actor.TenantID, actor.DepartmentID, actor.ApplicationID, actor.InstallationID, machine, string(raw)); err != nil {
		t.Fatal(err)
	}
	return capability.TaskWorkloadCredential{ClientID: machine, Secret: secret}
}

type indexModelSelectionFixture struct{}

func (indexModelSelectionFixture) ResolveModel(context.Context, sharedkernel.Scope, string) (modelgateway.Selection, error) {
	return modelgateway.Selection{ModelVersionID: "embedding", ProviderID: "vectors-id", ProviderKey: "vectors", ModelID: "vectors-model", ModelKey: "vectors", TrustZone: modelgovernance.TrustLocal}, nil
}

type indexNoSendGateway struct{ calls int }

func (g *indexNoSendGateway) Generate(context.Context, sharedkernel.Scope, policyasset.Snapshot, modelgateway.GenerateRequest) (modelgateway.GenerateResult, error) {
	g.calls++
	return modelgateway.GenerateResult{}, modelgateway.ErrModelUnavailable
}
func (g *indexNoSendGateway) Embed(context.Context, sharedkernel.Scope, policyasset.Snapshot, []string) ([][]float32, error) {
	g.calls++
	return nil, modelgateway.ErrModelUnavailable
}
func (g *indexNoSendGateway) EmbedWithUsage(context.Context, sharedkernel.Scope, policyasset.Snapshot, []string) (modelgateway.EmbeddingResult, error) {
	g.calls++
	return modelgateway.EmbeddingResult{}, modelgateway.ErrModelUnavailable
}
