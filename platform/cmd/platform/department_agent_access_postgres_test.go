package main

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/cmd/internal/permissionresources"
	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type departmentAgentOutboxFault struct {
	inner         notification.TxEnqueuer
	fail          bool
	onlyEventType string
}

func (f *departmentAgentOutboxFault) EnqueueTx(ctx context.Context, tx *sql.Tx, event notification.Event) (notification.Event, error) {
	created, err := f.inner.EnqueueTx(ctx, tx, event)
	if err == nil && f.fail && (f.onlyEventType == "" || f.onlyEventType == event.EventType) {
		return notification.Event{}, errors.New("owned failure after the actual department audit outbox insert")
	}
	return created, err
}

// All fixture authority is seeded explicitly in an owned disposable database.
// Changes below use the same SQL Catalog, published policy resolver, IAM,
// authenticated proof and audit/outbox composition as the platform. This does
// not claim a real browser session or an external Agent was forcibly stopped.
func TestSQLDepartmentAgentCeilingActualCatalogAuditOutboxAndRuntime(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL fixture required")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Hostname() != "127.0.0.1" || parsed.Path != "/knowledge_test" || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("dedicated loopback database required")
	}
	control, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("department_agent_composed_fixture_%d", time.Now().UnixNano())
	if _, err := control.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		control.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := control.Exec(`DROP DATABASE "` + name + `"`); err != nil {
			t.Error("drop owned department fixture", err)
		}
		control.Close()
	})
	parsed.Path = "/" + name
	db, err := sqlutil.OpenPostgres(context.Background(), parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	iam := identity.NewSQLStore(db)
	cat := catalog.NewSQLStore(db, "pgx")
	policies := policyasset.NewSQLResolver(db)
	outbox := notification.NewSQLStore(db)
	outboxFault := &departmentAgentOutboxFault{inner: outbox}
	auditor := audit.NewSQLStoreWithOutbox(db, outboxFault)
	for _, ensure := range []func(context.Context) error{iam.EnsureSchema, cat.EnsureSchema, policies.EnsureSchema, outbox.EnsureSchema, auditor.EnsureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	auditFault := &releaseAuditFault{recorder: auditor}
	iam.SetAdministrativeRecorder(recordVersionedAdministration(auditFault, outbox, iam))
	iam.SetAuthorizationChangeRecorder(recordVersionedAuthorizationChange(auditor, outbox))
	iam.SetPermissionResourceResolver(permissionresources.NewVerifiedInstallationResolver(cat, cat))
	iam.SetCapabilityResourceResolver(publishedPermissionResourceResolver{catalog: cat, policies: policies})
	company := sharedkernel.Scope{TenantID: "company", DepartmentID: "department", ApplicationID: "application", PrincipalType: "user", PrincipalID: "company-admin", TraceID: "owned-department-agent-trace"}
	department := company
	department.PrincipalID = "department-admin"
	member := company
	member.PrincipalID, member.InstallationID, member.AgentInstanceID = "department-member", "installed-agent", "installed-agent"
	member.AgentID, member.AgentVersionID = "example", "example-v1"
	for _, err := range []error{
		iam.CreateTenant(ctx, identity.Tenant{ID: company.TenantID, Code: "company", Name: "Owned company", Status: "active", Revision: 1}),
		iam.CreateDepartment(ctx, identity.Department{ID: company.DepartmentID, TenantID: company.TenantID, Code: "department", Name: "Owned department", Status: "active", Revision: 1}),
		iam.CreateApplication(ctx, identity.Application{ID: company.ApplicationID, TenantID: company.TenantID, DepartmentID: company.DepartmentID, Code: "application", Name: "Owned Agent group", Status: "active", Revision: 1}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, actor := range []sharedkernel.Scope{company, department, member} {
		if err := iam.CreatePrincipal(ctx, identity.Principal{Type: identity.PrincipalUser, ID: actor.PrincipalID, TenantID: actor.TenantID, IsActive: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('user',$1,'v2',1,1)`, actor.PrincipalID); err != nil {
			t.Fatal(err)
		}
	}
	seedRole := func(subject, code string, version uint64, scope identity.ManagementScope) {
		t.Helper()
		binding := identity.RoleBinding{ID: subject + "-role", SubjectID: subject, RoleCode: code, RoleVersion: version, Scope: scope, Status: "active", Revision: 1, SourceID: "owned-initial-facts"}
		raw, _ := json.Marshal(binding)
		source, _ := json.Marshal([]any{binding.SubjectID, binding.RoleCode, binding.RoleVersion, binding.Scope, binding.SourceID})
		if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_role_binding(id,subject_id,role_code,role_version,tenant_id,department_id,application_id,status,revision,payload,source_hash) VALUES($1,$2,$3,$4,$5,$6,$7,'active',1,$8,$9)`, binding.ID, subject, code, version, scope.TenantID, scope.DepartmentID, scope.ApplicationID, string(raw), fmt.Sprintf("%x", sha256.Sum256(source))); err != nil {
			t.Fatal(err)
		}
	}
	seedRole(company.PrincipalID, "tenant_admin", 2, identity.ManagementScope{Type: "tenant", TenantID: company.TenantID})
	seedRole(department.PrincipalID, "department_admin", 2, identity.ManagementScope{Type: "department", TenantID: company.TenantID, DepartmentID: company.DepartmentID})
	managerMember := identity.Membership{ID: "department-admin-member", SubjectID: department.PrincipalID, Scope: identity.ManagementScope{Type: "department", TenantID: company.TenantID, DepartmentID: company.DepartmentID}, Status: "active", Revision: 1}
	managerRaw, _ := json.Marshal(managerMember)
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES($1,$2,$3,$4,'','active',1,$5,$6)`, managerMember.ID, managerMember.SubjectID, company.TenantID, company.DepartmentID, string(managerRaw), fmt.Sprintf("%x", sha256.Sum256(managerRaw))); err != nil {
		t.Fatal(err)
	}
	password := "owned-department-composition-password"
	salt := []byte("owned-department-composition-salt")
	derived, err := pbkdf2.Key(sha256.New, password, salt, 600000, 32)
	if err != nil {
		t.Fatal(err)
	}
	passwordHash := "$pbkdf2-sha256$600000$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(derived)
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_local_credential(principal_id,tenant_id,department_id,application_id,display_name,password_hash,auth_revision,active,created_at,updated_at) VALUES($1,$2,$3,$4,'Owned company administrator',$5,1,TRUE,clock_timestamp(),clock_timestamp())`, company.PrincipalID, company.TenantID, company.DepartmentID, company.ApplicationID, passwordHash); err != nil {
		t.Fatal(err)
	}
	definition := catalog.Definition{ID: "example-definition", PublisherID: "owned", AgentKey: "example", DisplayName: "Owned example", Description: "Owned composed permission fixture", Status: catalog.DefinitionDraft, Revision: 1}
	manifest := json.RawMessage(`{"manifest_version":"agent-manifest/v1","agent_id":"example","version":"1.0.0","execution_protocols":["agent-execution/v2"],"capabilities":["invoke"],"schemas":{"input":"schema://example/input/v1","output":"schema://example/output/v1","event":"schema://example/event/v1","checkpoint":"schema://example/checkpoint/v1"},"runtime":{"transport":"http","isolation":"container","health_path":"/health/ready"}}`)
	schema := json.RawMessage(`{"type":"object"}`)
	hash, err := catalog.VersionContentHash(manifest, schema, schema)
	if err != nil {
		t.Fatal(err)
	}
	version := catalog.Version{ID: member.AgentVersionID, DefinitionID: definition.ID, SemanticVersion: "1.0.0", ManifestHash: hash, Manifest: manifest, ArtifactDigest: "sha256:" + strings.Repeat("a", 64), InputSchema: schema, OutputSchema: schema, Status: catalog.DefinitionDraft, Revision: 1}
	if err := cat.CreateDefinition(ctx, definition); err != nil {
		t.Fatal(err)
	}
	if err := cat.CreateVersion(ctx, version); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{`UPDATE platform_catalog_definition SET status='published' WHERE id='example-definition'`, `UPDATE platform_catalog_version SET status='published' WHERE id='example-v1'`, `INSERT INTO platform_catalog_installation(id,tenant_id,department_id,application_id,agent_id,version_id,status,revision,created_at,updated_at) VALUES('installed-agent','company','department','application','example','example-v1','active',1,clock_timestamp(),clock_timestamp())`, `INSERT INTO platform_catalog_installation_options(installation_id,display_name,deployment_mode,drain_policy,retention_policy_id,created_at) VALUES('installed-agent','Owned example','managed','wait','owned-retention',clock_timestamp())`} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	policy := policyasset.Snapshot{ModelProfileID: "model", PromptVersionID: "prompt", ToolPolicyID: "tools", MemoryPolicyID: "memory", KnowledgePolicyID: "knowledge", RuntimePolicyID: "runtime", Revision: 1, Hash: strings.Repeat("b", 64), Model: policyasset.ModelPolicy{Provider: "owned", Model: "owned", MaxTokens: 64}, Prompt: policyasset.PromptPolicy{TemplateHash: "owned-prompt", Template: "approved"}, Tool: policyasset.ToolPolicy{AllowedTools: []string{"clock.now"}}, Memory: policyasset.MemoryPolicy{MaxEntries: 10}, Knowledge: policyasset.KnowledgePolicy{AllowedScopes: []string{"docs"}}, Runtime: policyasset.RuntimePolicy{MaxAttempts: 1, TaskTimeoutSeconds: 60, LeaseSeconds: 30}}
	if err := policies.Upsert(ctx, member, policy); err != nil {
		t.Fatal(err)
	}
	command := identity.DepartmentAgentChangeCommand{TenantID: company.TenantID, DepartmentID: company.DepartmentID, MigrateExisting: true, IdempotencyKey: "owned-migrate-ceiling", Reason: "Reviewed department Agent migration", Entries: []identity.DepartmentAgentPolicyEntry{{ApplicationID: company.ApplicationID, InstallationID: member.InstallationID, Actions: []string{"discover", "run", "cancel", "history.read", "history.continue", "model.generate", "model.embed", "tool.invoke", "knowledge.search", "memory.read", "memory.write"}}}}
	// Actual Catalog ownership and publication are checked during preview.
	invalid := command
	invalid.Entries = []identity.DepartmentAgentPolicyEntry{{ApplicationID: company.ApplicationID, InstallationID: "unpublished-or-foreign-agent", Actions: []string{"run"}}}
	if _, err := iam.PreviewDepartmentAgentChange(ctx, company, invalid); err == nil {
		t.Fatal("actual Catalog admitted an unknown installation")
	}
	plan, err := iam.PreviewDepartmentAgentChange(ctx, company, command)
	if err != nil {
		t.Fatal("preview with actual Catalog", err)
	}
	proof, err := iam.CreateLocalStepUp(ctx, company, identity.StepUpRequest{CurrentPassword: password, Action: plan.StepUpAction, RequestDigest: plan.Digest})
	if err != nil {
		t.Fatal("actual company password proof", err)
	}
	command = plan.Command
	command.StepUpToken = proof.Token
	assertRollback := func() {
		t.Helper()
		var heads, audits, events int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_identity_department_agent_policy`).Scan(&heads); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_audit_event WHERE action='department.agent_policy.change'`).Scan(&audits); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_notification_outbox WHERE event_type='audit.department.agent_policy.change'`).Scan(&events); err != nil {
			t.Fatal(err)
		}
		if heads != 0 || audits != 0 || events != 0 {
			t.Fatalf("failed change persisted heads=%d audit=%d outbox=%d", heads, audits, events)
		}
	}
	auditFault.fail = true
	if _, err := iam.CommitDepartmentAgentChange(ctx, company, command); err == nil {
		t.Fatal("actual audit fault did not reject change")
	}
	assertRollback()
	auditFault.fail, outboxFault.fail = false, true
	if _, err := iam.CommitDepartmentAgentChange(ctx, company, command); err == nil {
		t.Fatal("actual outbox fault did not reject change")
	}
	assertRollback()
	outboxFault.fail = false
	receipt, err := iam.CommitDepartmentAgentChange(ctx, company, command)
	if err != nil || receipt.Policy.Revision != 1 {
		t.Fatal("same proof did not survive complete rollback", err)
	}
	var audits, events int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_audit_event WHERE event_id=$1`, receipt.ID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_notification_outbox WHERE event_id=$1`, "audit-"+receipt.ID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if audits != 1 || events != 1 {
		t.Fatalf("successful ceiling change audit=%d outbox=%d", audits, events)
	}
	command.StepUpToken = ""
	if replay, err := iam.CommitDepartmentAgentChange(ctx, company, command); err != nil || replay.ID != receipt.ID {
		t.Fatal("original receipt not replayed without new mutation", err)
	}
	appScope := identity.ManagementScope{Type: "application", TenantID: member.TenantID, DepartmentID: member.DepartmentID, ApplicationID: member.ApplicationID}
	allocation := identity.AuthorizationChangeCommand{SubjectType: identity.PrincipalUser, SubjectID: member.PrincipalID, ExpectedRevision: 1, IdempotencyKey: "owned-member-agent", Reason: "Department member may use approved Agent", Memberships: []identity.MembershipMutation{{ID: "member-department", Scope: identity.ManagementScope{Type: "department", TenantID: member.TenantID, DepartmentID: member.DepartmentID}, Status: "active"}}, Bindings: []identity.RoleBinding{{ID: "member-operator", SubjectID: member.PrincipalID, RoleCode: "operator", RoleVersion: 1, Scope: appScope, Status: "active", Revision: 1}}}
	for _, action := range []string{"run", "cancel"} {
		allocation.Grants = append(allocation.Grants, identity.Grant{ID: "member-" + action, SubjectType: identity.PrincipalUser, SubjectID: member.PrincipalID, TenantID: member.TenantID, DepartmentID: member.DepartmentID, ApplicationID: member.ApplicationID, AgentInstanceID: member.InstallationID, ResourceType: "agent_installation", ResourceID: member.InstallationID, Action: action, Effect: "allow", Status: "active", Revision: 1, DataScope: identity.DataScope{Type: "owner"}})
	}
	allocation.Bindings[0].SourceID = "owned-department-allocation"
	for i := range allocation.Grants {
		allocation.Grants[i].SourceID = "owned-department-allocation"
	}
	allocationPlan, err := iam.PreviewAuthorizationChange(ctx, department, allocation)
	if err != nil {
		t.Fatal("department allocation with actual Catalog", err)
	}
	allocation.PlanDigest, allocation.PlanExpiresAt = allocationPlan.Digest, allocationPlan.ExpiresAt
	allocated, err := iam.CommitAuthorizationChange(ctx, department, allocation)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_notification_outbox WHERE event_id=$1`, "authorization-"+allocated.ID).Scan(&events); err != nil || events != 1 {
		t.Fatal("member allocation missing actual authorization event", err)
	}
	guard := identityConversationAgentRunAuthorizer{store: iam}
	if allowed, err := guard.AuthorizeConversationRun(ctx, member); err != nil || !allowed {
		t.Fatal("allocated member could not run", err)
	}
	if member.AuthorizationEpoch, err = guard.CurrentAuthorizationEpoch(ctx, member, "run"); err != nil || member.AuthorizationEpoch == 0 {
		t.Fatal("runtime authorization fence missing", err)
	}
	// Persisted batches use actual IAM/audit/outbox transactions, including a
	// fault after the authorization notification has already been inserted.
	iam.SetAuthorizationChangeRecorder(recordVersionedAuthorizationChange(auditor, outboxFault))
	batchCommand := identity.PermissionBatchCommand{Scope: identity.ManagementScope{Type: "department", TenantID: member.TenantID, DepartmentID: member.DepartmentID}, Kind: "authorization", IdempotencyKey: "owned-composed-user-batch", Reason: "Selected department members may use approved Agent"}
	agentUseScope := identity.ManagementScope{Type: "agent_installation", TenantID: member.TenantID, DepartmentID: member.DepartmentID, ApplicationID: member.ApplicationID, ResourceID: member.InstallationID}
	usePackage, err := iam.AgentUsePackage(ctx, department, agentUseScope)
	if err != nil || len(usePackage.Resources) != 11 || usePackage.AgentVersionID != member.AgentVersionID {
		t.Fatal("actual published Agent dependency package", err)
	}
	for _, id := range []string{"composed-batch-member-a", "composed-batch-member-b"} {
		if err := iam.CreatePrincipal(ctx, identity.Principal{Type: identity.PrincipalUser, ID: id, TenantID: member.TenantID, IsActive: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('user',$1,'v2',1,1)`, id); err != nil {
			t.Fatal(err)
		}
		change := identity.AuthorizationChangeCommand{SubjectType: identity.PrincipalUser, SubjectID: id, ExpectedRevision: 1, Memberships: []identity.MembershipMutation{{ID: id + "-member", Scope: batchCommand.Scope, Status: "active"}}, AgentUse: &identity.AgentUseSelection{Scope: agentUseScope, AgentVersionID: usePackage.AgentVersionID, PackageDigest: usePackage.Digest}}
		batchCommand.Items = append(batchCommand.Items, identity.PermissionBatchItemCommand{Authorization: &change})
	}
	batchPlan, err := iam.PreviewPermissionBatch(ctx, department, batchCommand)
	if err != nil {
		t.Fatal("actual composed batch preview", err)
	}
	if _, err := iam.CreatePermissionBatch(ctx, department, batchPlan.Change); err != nil {
		t.Fatal("actual composed batch preparation", err)
	}
	outboxFault.fail, outboxFault.onlyEventType = true, notification.AuthorizationChangedV1
	if _, err := iam.ContinuePermissionBatch(ctx, department, batchCommand.IdempotencyKey); err == nil {
		t.Fatal("batch ignored failure after actual authorization event insertion")
	}
	pendingBatch, err := iam.GetPermissionBatch(ctx, department, batchCommand.IdempotencyKey)
	if err != nil || pendingBatch.Items[0].Status != "pending" {
		t.Fatal("unknown/failed outbox write became a confirmed batch result", err)
	}
	principal, err := iam.GetPrincipal(ctx, identity.PrincipalUser, "composed-batch-member-a")
	if err != nil || principal.Revision != 1 {
		t.Fatal("failed actual notification did not roll back subject authority", err)
	}
	var failedReceipts int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_identity_authorization_change WHERE subject_id='composed-batch-member-a'`).Scan(&failedReceipts); err != nil || failedReceipts != 0 {
		t.Fatal("failed batch persisted an authorization receipt", err)
	}
	outboxFault.fail, outboxFault.onlyEventType = false, ""
	for i := 0; i < 2; i++ {
		if _, err := iam.ContinuePermissionBatch(ctx, department, batchCommand.IdempotencyKey); err != nil {
			t.Fatal("recover original composed batch", err)
		}
	}
	reopenedBatch, err := identity.NewSQLStore(db).GetPermissionBatch(ctx, department, batchCommand.IdempotencyKey)
	if err != nil {
		t.Fatal("actual composed batch repository reopen", err)
	}
	for _, item := range reopenedBatch.Items {
		if item.Status != "succeeded" || item.Authorization == nil || item.Impact.AgentDisplayName != usePackage.DisplayName || usePackage.DisplayName == "" {
			t.Fatal("actual composed batch missing per-person result")
		}
		snapshot, err := iam.PermissionSnapshot(ctx, identity.PrincipalUser, item.SubjectID)
		if err != nil || len(snapshot.Grants) != 11 || len(snapshot.Bindings) != 1 {
			t.Fatal("actual Catalog package did not allocate complete dependency facts", err)
		}
		for _, grant := range snapshot.Grants {
			decision, err := identity.EvaluatePermission(snapshot, identity.PermissionQuery{Action: grant.Action, Scope: agentUseScope, ResourceType: grant.ResourceType, ResourceID: grant.ResourceID, Now: time.Now().UTC()})
			if err != nil || !decision.Allowed || grant.DataScope.Type != "owner" || grant.DepartmentAgentActionVersion == 0 {
				t.Fatal("actual published dependency package is unusable", grant.Action, decision, err)
			}
		}
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_notification_outbox WHERE event_id=$1`, "authorization-"+item.Authorization.ID).Scan(&events); err != nil || events != 1 {
			t.Fatal("actual per-person authorization notification missing or duplicated", err)
		}
		batchMember := member
		batchMember.PrincipalID = item.SubjectID
		if allowed, err := guard.AuthorizeConversationRun(ctx, batchMember); err != nil || !allowed {
			t.Fatal("actually allocated batch member could not use Agent", err)
		}
	}
	withdraw := identity.DepartmentAgentChangeCommand{TenantID: company.TenantID, DepartmentID: company.DepartmentID, ExpectedRevision: 1, IdempotencyKey: "owned-withdraw-ceiling", Reason: "Company withdraws department Agent"}
	withdrawPlan, err := iam.PreviewDepartmentAgentChange(ctx, company, withdraw)
	if err != nil || withdrawPlan.Impact.PotentialRestrictedSubjects != 3 {
		t.Fatal("withdrawal impact did not include allocated member", err)
	}
	withdrawProof, err := iam.CreateLocalStepUp(ctx, company, identity.StepUpRequest{CurrentPassword: password, Action: withdrawPlan.StepUpAction, RequestDigest: withdrawPlan.Digest})
	if err != nil {
		t.Fatal(err)
	}
	withdraw = withdrawPlan.Command
	withdraw.StepUpToken = withdrawProof.Token
	if _, err := iam.CommitDepartmentAgentChange(ctx, company, withdraw); err != nil {
		t.Fatal(err)
	}
	if allowed, err := guard.AuthorizeConversationRun(ctx, member); err != nil || allowed {
		t.Fatal("real runtime guard retained withdrawn Agent", err)
	}
	if _, err := guard.CurrentAuthorizationEpoch(ctx, member, "run"); err == nil {
		t.Fatal("withdrawn grant could renew the old runtime authorization fence")
	}
	if _, err := iam.CurrentAuthorizationEpoch(ctx, member, "cancel"); err != nil {
		t.Fatal("valid cancellation recovery was removed", err)
	}
	for _, item := range reopenedBatch.Items {
		batchMember := member
		batchMember.PrincipalID = item.SubjectID
		if allowed, err := guard.AuthorizeConversationRun(ctx, batchMember); err != nil || allowed {
			t.Fatal("batch-issued source survived the withdrawn company ceiling", err)
		}
		if _, err := guard.CurrentAuthorizationEpoch(ctx, batchMember, "run"); err == nil {
			t.Fatal("withdrawn batch recipient could acquire a new runtime fence")
		}
	}
	state, err := iam.DepartmentAgentPolicy(ctx, department, member.TenantID, member.DepartmentID)
	if err != nil || !state.Managed || state.CanManage || len(state.Policy.Entries) != 0 {
		t.Fatal("department manager did not see current withdrawn company ceiling", err)
	}
}
