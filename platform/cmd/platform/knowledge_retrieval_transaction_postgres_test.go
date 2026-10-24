package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// This uses the production IAM store, not a mock that merely promises a fence.
// A pool of one detects a nested connection wait within the protected read.
func TestPostgresKnowledgeDocumentAuthoritySingleConnection(t *testing.T) {
	dsn := os.Getenv("KNOWLEDGE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL fixture required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	other, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id := fmt.Sprintf("doc-read-%d", time.Now().UnixNano())
	scope := sharedkernel.Scope{TenantID: id, DepartmentID: id, ApplicationID: id, PrincipalID: id + "-user", PrincipalType: "user", AgentInstanceID: "i", InstallationID: "i", AgentID: "agent", AgentVersionID: "v", SessionID: "s", RunID: "r", TraceID: "trace", AuthorizationEpoch: 1}
	app := identity.ManagementScope{Type: "application", TenantID: id, DepartmentID: id, ApplicationID: id}
	grant := identity.Grant{ID: id + "-caller", SubjectID: scope.PrincipalID, SubjectType: identity.PrincipalUser, TenantID: id, DepartmentID: id, ApplicationID: id, AgentInstanceID: "i", ResourceType: "knowledge", ResourceID: "docs", Action: "knowledge.search", Status: "active", Effect: "allow", DataScope: identity.DataScope{Type: "owner"}}
	caller := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalUser, ID: scope.PrincipalID, TenantID: id, IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{SubjectID: scope.PrincipalID, Scope: app, Status: "active"}}, Bindings: []identity.RoleBinding{{SubjectID: scope.PrincipalID, RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active"}}, Grants: []identity.Grant{grant}}
	machineID := id + "-executor"
	grant.ID, grant.SubjectID, grant.SubjectType, grant.DataScope = id+"-machine", machineID, identity.PrincipalServicePrincipal, identity.DataScope{Type: "approved_organization"}
	machine := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalServicePrincipal, ID: machineID, TenantID: id, IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Grants: []identity.Grant{grant}}
	binding := identity.WorkloadBinding{TenantID: id, DepartmentID: id, ApplicationID: id, InstallationID: "i", AgentID: "agent", AgentVersionID: "v", PrincipalID: machineID, Status: "active", Revision: 1}
	iam := seedKnowledgeQuerySQLIdentity(t, db, scope, caller, machine, binding)
	scope.AuthorizationEpoch, err = iam.CurrentAuthorizationEpoch(ctx, scope, "run")
	if err != nil {
		t.Fatal(err)
	}
	source := knowledge.PostgresSource{DB: db, RecordChange: func(context.Context, *sql.Tx, knowledge.ProjectionScope, knowledge.SourceReceipt) error { return nil }}
	ps := knowledge.ProjectionScope{TenantID: id, DepartmentID: id, ApplicationID: id, KnowledgeID: "docs"}
	if _, err := source.Change(ctx, ps, knowledge.SourceChange{DocumentID: "doc", ActorPrincipalID: scope.PrincipalID, IdempotencyKey: "create", Body: "owned evidence", ACL: knowledge.DocumentACL{OwnerPrincipalID: scope.PrincipalID, Readers: []string{machineID}}}); err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	waits := db.Stats().WaitCount
	reads := 0
	var retained context.Context
	assertLocked := func(query string, args ...any) {
		t.Helper()
		tx, err := other.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		_, err = tx.ExecContext(ctx, query, args...)
		var state interface{ SQLState() string }
		if !errors.As(err, &state) || state.SQLState() != "55P03" {
			t.Fatal("concurrent mutation was not fenced", err)
		}
	}
	selected := selectedSourceFixture(func(readCtx context.Context, actual knowledge.ProjectionScope, ids []string) (knowledge.SourceSnapshot, error) {
		reads++
		retained = readCtx
		if _, joined, err := sqlutil.ContinuityTransaction(readCtx, db); !joined || err != nil {
			t.Fatal("source read did not join owner", joined, err)
		}
		result, err := source.SnapshotDocuments(readCtx, actual, ids)
		if err != nil {
			return result, err
		}
		assertLocked(`SELECT revision FROM platform_identity_continuity_guard WHERE id=1 FOR UPDATE NOWAIT`)
		assertLocked(`SELECT source_revision FROM platform_knowledge_source_head WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 FOR UPDATE NOWAIT`, id, id, id, "docs")
		return result, nil
	})
	reader := sourceKnowledgeAuthority{source: selected, iam: capabilityExecutionAuthority{identity: iam}, scope: scope, knowledgeID: "docs", documents: []policyasset.KnowledgeDocumentBinding{{KnowledgeScope: "docs", ProviderID: "platform-knowledge", KnowledgeBaseID: "docs", ProviderDocumentID: "doc", OwnerID: scope.PrincipalID, OwnershipSource: "source:docs/doc", DocumentVersion: "1", Status: "active"}}}
	facts, err := reader.ResolveCurrentDocuments(ctx, scope, "docs")
	if err != nil || len(facts) != 1 || reads != 1 || db.Stats().WaitCount != waits {
		t.Fatal("single connection read incomplete or nested", facts, reads, db.Stats().WaitCount-waits, err)
	}
	if _, err := source.SnapshotDocuments(retained, ps, []string{"doc"}); !errors.Is(err, sql.ErrTxDone) {
		t.Fatal("closed transaction fell back to a new source read", err)
	}
	// The real mutation fence is released at the end of one boundary. The
	// next boundary must see a revoked machine, never an earlier snapshot.
	tx, err := other.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT revision FROM platform_identity_continuity_guard WHERE id=1 FOR UPDATE NOWAIT`); err != nil {
		t.Fatal("read fence outlived callback", err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE platform_identity_grant SET status='revoked',revision=revision+1 WHERE id=$1`, grant.ID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if facts, err = reader.ResolveCurrentDocuments(ctx, scope, "docs"); err == nil || len(facts) != 0 || reads != 1 {
		t.Fatal("revoked executor reached source", facts, reads, err)
	}
}
