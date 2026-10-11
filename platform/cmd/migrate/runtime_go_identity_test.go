package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func seedRuntimeGoIdentity(t *testing.T, ctx context.Context, db *sql.DB, s sharedkernel.Scope, manager string) (string, string, string) {
	return seedRuntimeGoIdentityForMachine(t, ctx, db, s, manager, "go-process-machine")
}

func seedRuntimeGoIdentityForMachine(t *testing.T, ctx context.Context, db *sql.DB, s sharedkernel.Scope, manager, machine string) (string, string, string) {
	t.Helper()
	store := identity.NewSQLStore(db)
	secret := "go-process-machine-secret-01234567890123"
	for _, principal := range []identity.Principal{{ID: s.PrincipalID, Type: identity.PrincipalUser, TenantID: s.TenantID, IsActive: true}, {ID: machine, Type: identity.PrincipalServicePrincipal, TenantID: s.TenantID, IsActive: true}} {
		if err := store.CreatePrincipal(ctx, principal); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES($1,$2,'v2',1,1)`, principal.Type, principal.ID); err != nil {
			t.Fatal(err)
		}
	}
	app := identity.ManagementScope{Type: "application", TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID}
	knowledgeScope := "go-operations"
	if s.AgentID == "example-python-documents" {
		knowledgeScope = "python-documents"
	}
	member := identity.Membership{ID: s.PrincipalID + "-member", SubjectID: s.PrincipalID, Scope: app, Status: "active", Revision: 1}
	raw, _ := json.Marshal(member)
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES($1,$2,$3,$4,$5,'active',1,$6,$1)`, member.ID, s.PrincipalID, s.TenantID, s.DepartmentID, s.ApplicationID, string(raw)); err != nil {
		t.Fatal(err)
	}
	role := identity.RoleBinding{ID: s.PrincipalID + "-operator", SubjectID: s.PrincipalID, RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active", Revision: 1, SourceID: "owned-go-process"}
	raw, _ = json.Marshal(role)
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_role_binding(id,subject_id,role_code,role_version,tenant_id,department_id,application_id,status,revision,payload,source_hash) VALUES($1,$2,'operator',1,$3,$4,$5,'active',1,$6,$1)`, role.ID, s.PrincipalID, s.TenantID, s.DepartmentID, s.ApplicationID, string(raw)); err != nil {
		t.Fatal(err)
	}
	// skill.load is a distinct public capability role. An operator binding and
	// a resource grant alone do not authorize disclosure of a Skill bundle.
	skillRole := identity.RoleBinding{ID: s.PrincipalID + "-skill-user", SubjectID: s.PrincipalID, RoleCode: "skill_user", RoleVersion: 2, Scope: app, Status: "active", Revision: 1, SourceID: "owned-go-process-skill"}
	raw, _ = json.Marshal(skillRole)
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_role_binding(id,subject_id,role_code,role_version,tenant_id,department_id,application_id,status,revision,payload,source_hash) VALUES($1,$2,'skill_user',2,$3,$4,$5,'active',1,$6,$1)`, skillRole.ID, s.PrincipalID, s.TenantID, s.DepartmentID, s.ApplicationID, string(raw)); err != nil {
		t.Fatal(err)
	}
	add := func(subject string, kind identity.PrincipalType, action, resourceType, resource string) {
		t.Helper()
		grant := identity.Grant{ID: subject + "-go-" + action, SubjectID: subject, SubjectType: kind, TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, AgentInstanceID: s.InstallationID, ResourceType: resourceType, ResourceID: resource, Action: action, Effect: "allow", Status: "active", Revision: 1, SourceID: "owned-go-process", DataScope: identity.DataScope{Type: "owner"}}
		if kind == identity.PrincipalServicePrincipal || action == "knowledge.search" || subject == manager {
			grant.DataScope.Type = "approved_organization"
		}
		if err := store.CreateGrant(ctx, grant); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(grant)
		if _, err := db.ExecContext(ctx, `UPDATE platform_identity_grant SET permission_json=$1 WHERE id=$2`, string(raw), grant.ID); err != nil {
			t.Fatal(err)
		}
	}
	for _, subject := range []struct {
		id   string
		kind identity.PrincipalType
	}{{s.PrincipalID, identity.PrincipalUser}, {machine, identity.PrincipalServicePrincipal}} {
		skillID := "example.operations.guidance"
		if s.AgentID == "example-python-documents" {
			skillID = "example.documents.guidance"
		}
		for _, resource := range []struct{ action, kind, id string }{{"model.generate", "model", "go-process-models"}, {"model.embed", "model", "go-process-models"}, {"tool.invoke", "tool", "runtime.inspect"}, {"knowledge.search", "knowledge", knowledgeScope}, {"memory.read", "memory", "go-process-memory"}, {"memory.write", "memory", "go-process-memory"}, {"skill.load", "skill", skillID}} {
			add(subject.id, subject.kind, resource.action, resource.kind, resource.id)
		}
	}
	for _, action := range []string{"run", "history.read", "history.continue", "cancel"} {
		add(s.PrincipalID, identity.PrincipalUser, action, "agent_installation", s.InstallationID)
	}
	// Root-run authority is pinned to both the initiating user and the exact
	// workload principal bound to this installation. The machine receives only
	// its own installation/run capability here; it does not inherit browser
	// history, continuation, cancellation, or another installation's authority.
	add(machine, identity.PrincipalServicePrincipal, "run", "agent_installation", s.InstallationID)
	add(manager, identity.PrincipalUser, "model.embed", "model", "go-process-models")
	digest := sha256.Sum256([]byte(secret))
	if err := store.CreateMachineCredential(ctx, identity.MachineCredential{TenantID: s.TenantID, PrincipalID: machine, SecretHash: hex.EncodeToString(digest[:]), NetworkCIDRs: []string{"127.0.0.1/32"}, Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	binding := identity.WorkloadBinding{TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, InstallationID: s.InstallationID, AgentID: s.AgentID, AgentVersionID: s.AgentVersionID, PrincipalID: machine, Status: "active", Revision: 1}
	raw, _ = json.Marshal(binding)
	key, _ := json.Marshal([]string{s.TenantID, s.DepartmentID, s.ApplicationID, s.InstallationID})
	hash := sha256.Sum256(key)
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_workload_binding(scope_hash,tenant_id,department_id,application_id,installation_id,principal_id,status,revision,payload) VALUES($1,$2,$3,$4,$5,$6,'active',1,$7)`, hex.EncodeToString(hash[:]), s.TenantID, s.DepartmentID, s.ApplicationID, s.InstallationID, machine, string(raw)); err != nil {
		t.Fatal(err)
	}
	machineScope := s
	machineScope.PrincipalType = string(identity.PrincipalServicePrincipal)
	machineScope.PrincipalID = machine
	permission, err := identity.CheckPrincipalAccess(ctx, store, machineScope, identity.PrincipalServicePrincipal, machine, "run")
	if err != nil || !permission.Allowed {
		t.Fatalf("owned workload fixture lacks its installation-scoped root-run authority: allowed=%t reason=%s err=%v", permission.Allowed, permission.Reason, err)
	}
	foreignScope := machineScope
	foreignScope.InstallationID = "unrelated-installation"
	foreignScope.AgentInstanceID = foreignScope.InstallationID
	foreign, err := identity.CheckPrincipalAccess(ctx, store, foreignScope, identity.PrincipalServicePrincipal, machine, "run")
	if err != nil || foreign.Allowed {
		t.Fatalf("workload fixture machine permission escaped its exact installation scope: allowed=%t reason=%s err=%v", foreign.Allowed, foreign.Reason, err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_local_credential(principal_id,tenant_id,department_id,application_id,display_name,password_hash,auth_revision,active,created_at,updated_at) VALUES($1,$2,$3,$4,'Go user','unusable-go-process-fixture',1,TRUE,clock_timestamp(),clock_timestamp())`, s.PrincipalID, s.TenantID, s.DepartmentID, s.ApplicationID); err != nil {
		t.Fatal(err)
	}
	store.SetRefreshSessionRecorder(func(context.Context, *sql.Tx, identity.RefreshSessionEvent) error { return nil })
	session, err := store.CreateRefreshSession(ctx, s.PrincipalID, identity.EnrollmentScope{TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID}, 1)
	if err != nil {
		t.Fatal(err)
	}
	return machine, secret, session.SessionID
}
