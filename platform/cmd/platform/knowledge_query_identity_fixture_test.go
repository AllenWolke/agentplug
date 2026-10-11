package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"testing"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// Truth seeding only in the owned disposable fixture. Production authorization
// changes retain their transactional preview/CAS/audit APIs.
func seedKnowledgeQuerySQLIdentity(t *testing.T, db *sql.DB, scope sharedkernel.Scope, caller, machine identity.PermissionSnapshot, binding identity.WorkloadBinding) *identity.SQLStore {
	t.Helper()
	ctx := context.Background()
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Hostname() != "127.0.0.1" || parsed.Path != "/knowledge_test" {
		t.Fatal("owned IAM fixture required")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	adminStore := identity.NewSQLStore(admin)
	if err := adminStore.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	store := identity.NewSQLStore(db)
	for _, err := range []error{
		store.CreateTenant(ctx, identity.Tenant{ID: scope.TenantID, Code: scope.TenantID, Name: "fixture", Status: "active", Revision: 1}),
		store.CreateDepartment(ctx, identity.Department{ID: scope.DepartmentID, TenantID: scope.TenantID, Code: scope.DepartmentID, Name: "fixture", Status: "active", Revision: 1}),
		store.CreateApplication(ctx, identity.Application{ID: scope.ApplicationID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, Code: scope.ApplicationID, Name: "fixture", Status: "active", Revision: 1}),
		store.CreatePrincipal(ctx, caller.Principal), store.CreatePrincipal(ctx, machine.Principal),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, principal := range []identity.Principal{caller.Principal, machine.Principal} {
		if _, err := db.Exec(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES($1,$2,'v2',1,1)`, principal.Type, principal.ID); err != nil {
			t.Fatal(err)
		}
	}
	hash := func(raw []byte) string { value := sha256.Sum256(raw); return hex.EncodeToString(value[:]) }
	if _, err := db.Exec(`INSERT INTO platform_identity_machine_credential(tenant_id,principal_id,secret_hash,network_cidrs_json,status,revision,created_at,updated_at) VALUES($1,$2,$3,'["127.0.0.1/32"]','active',1,clock_timestamp(),clock_timestamp())`, scope.TenantID, binding.PrincipalID, hash([]byte("isolated-query-machine-secret"))); err != nil {
		t.Fatal(err)
	}
	member := caller.Memberships[0]
	member.ID = scope.TenantID + "-member"
	member.Revision = 1
	raw, _ := json.Marshal(member)
	if _, err := db.Exec(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES($1,$2,$3,$4,$5,'active',1,$6,$7)`, member.ID, member.SubjectID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, string(raw), hash(raw)); err != nil {
		t.Fatal(err)
	}
	role := caller.Bindings[0]
	role.ID = scope.TenantID + "-role"
	role.Revision = 1
	role.SourceID = "owned-fixture"
	raw, _ = json.Marshal(role)
	if _, err := db.Exec(`INSERT INTO platform_identity_role_binding(id,subject_id,role_code,role_version,tenant_id,department_id,application_id,status,revision,payload,source_hash) VALUES($1,$2,'operator',1,$3,$4,$5,'active',1,$6,$7)`, role.ID, role.SubjectID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, string(raw), hash(raw)); err != nil {
		t.Fatal(err)
	}
	run := caller.Grants[0]
	run.ID = scope.TenantID + "-run"
	run.Action = "run"
	run.ResourceType = "agent_installation"
	run.ResourceID = scope.InstallationID
	grants := append(append(append([]identity.Grant(nil), caller.Grants...), machine.Grants...), run)
	for _, grant := range grants {
		grant.Revision = 1
		grant.SourceID = "owned-fixture"
		if err := store.CreateGrant(ctx, grant); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(grant)
		if _, err := db.Exec(`UPDATE platform_identity_grant SET permission_json=$1 WHERE id=$2`, string(raw), grant.ID); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ = json.Marshal(binding)
	key, _ := json.Marshal([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.InstallationID})
	if _, err := db.Exec(`INSERT INTO platform_identity_workload_binding(scope_hash,tenant_id,department_id,application_id,installation_id,principal_id,status,revision,payload) VALUES($1,$2,$3,$4,$5,$6,'active',1,$7)`, hash(key), scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.InstallationID, binding.PrincipalID, string(raw)); err != nil {
		t.Fatal(err)
	}
	return store
}
