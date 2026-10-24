package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

// Decorate the real production authority, not its permission or lease checks.
// A second SQL transaction probes its execution locks while they are held.
type observedProductionBudgetAuthority struct {
	runTreeBudgetAuthority
	runs              *execution.SQLStore
	lease             sharedkernel.ExecutionLeaseBinding
	reads, admissions int
}

func (a *observedProductionBudgetAuthority) probe(ctx context.Context, scope sharedkernel.Scope) error {
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := a.runs.DB().BeginTx(bounded, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = a.runs.CheckCheckpointLeaseTx(bounded, tx, scope, a.lease); err != nil {
		return fmt.Errorf("independent checkpoint blocked by model budget fence: %w", err)
	}
	// Cancellation/takeover must still conflict with the held fence. NOWAIT
	// proves lock incompatibility without changing the execution or sleeping.
	_, err = tx.ExecContext(bounded, `SELECT run_id FROM platform_execution_run WHERE run_id=$1 FOR UPDATE NOWAIT`, scope.RunID)
	var state interface{ SQLState() string }
	if !errors.As(err, &state) || state.SQLState() != "55P03" {
		return fmt.Errorf("budget fence did not exclude execution mutation: %v", err)
	}
	return nil
}

func (a *observedProductionBudgetAuthority) Facts(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, admission bool) (usagecost.RunTreeBudgetFacts, error) {
	facts, err := a.runTreeBudgetAuthority.Facts(ctx, tx, scope, admission)
	if err == nil && admission {
		a.admissions++
		err = a.probe(ctx, scope)
	}
	return facts, err
}

func (a *observedProductionBudgetAuthority) ReadFacts(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) (usagecost.RunTreeBudgetFacts, error) {
	facts, err := a.runTreeBudgetAuthority.ReadFacts(ctx, tx, scope)
	if err == nil {
		a.reads++
		err = a.probe(ctx, scope)
	}
	return facts, err
}

type lostEmbeddingResponseFixture struct {
	modelgateway.Port
	lose bool
}

func (g *lostEmbeddingResponseFixture) EmbedWithUsage(ctx context.Context, scope sharedkernel.Scope, policy policyasset.Snapshot, texts []string) (modelgateway.EmbeddingResult, error) {
	result, err := g.Port.(modelgateway.UsageEmbeddingPort).EmbedWithUsage(ctx, scope, policy, texts)
	if err == nil && g.lose {
		// The owned HTTP provider really executed; deliberately discard its
		// response so the public accounting path must retain the original hold.
		return modelgateway.EmbeddingResult{}, &modelgateway.ProviderFailure{Category: "body_read"}
	}
	return result, err
}

func TestPostgresSignedModelBudgetCompositionSharesExecutionFence(t *testing.T) {
	adminDSN, runtimeDSN := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN"), os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	if adminDSN == "" || runtimeDSN == "" {
		t.Skip("owned PostgreSQL fixture required")
	}
	for _, dsn := range []string{adminDSN, runtimeDSN} {
		u, err := url.Parse(dsn)
		if err != nil || u.Hostname() != "127.0.0.1" || u.Path != "/knowledge_test" {
			t.Fatal("owned fixture required")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := sql.Open("pgx", adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	for _, ensure := range []func(context.Context) error{
		func(ctx context.Context) error { return execution.MigrateSchema(ctx, admin) },
		policyasset.NewSQLResolver(admin).EnsureSchema,
		audit.NewSQLStore(admin).EnsureSchema,
		usagecost.NewSQLRunTreeBudgetStore(admin).EnsureSchema,
	} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	runs, err := execution.ConnectSQLStore(ctx, "pgx", runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	db := runs.DB()
	id := fmt.Sprintf("budget-composition-%d", time.Now().UnixNano())
	scope := sharedkernel.Scope{TenantID: id, DepartmentID: id, ApplicationID: id, AgentID: id,
		AgentVersionID: "v1", AgentInstanceID: id, InstallationID: id, PrincipalType: "user",
		PrincipalID: id + "-user", RunID: id, SessionID: id, TraceID: "0123456789abcdef0123456789abcdef", AuthorizationEpoch: 1}
	app := identity.ManagementScope{Type: "application", TenantID: id, DepartmentID: id, ApplicationID: id}
	grant := identity.Grant{ID: id + "-caller-embed", SubjectType: identity.PrincipalUser, SubjectID: scope.PrincipalID,
		TenantID: id, DepartmentID: id, ApplicationID: id, AgentInstanceID: id, ResourceType: "model", ResourceID: "model",
		Action: "model.embed", Status: "active", Effect: "allow", DataScope: identity.DataScope{Type: "owner"}}
	caller := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalUser, ID: scope.PrincipalID, TenantID: id, IsActive: true},
		Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{SubjectID: scope.PrincipalID, Scope: app, Status: "active"}},
		Bindings: []identity.RoleBinding{{SubjectID: scope.PrincipalID, RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active"}}, Grants: []identity.Grant{grant}}
	machineID := id + "-machine"
	grant.ID, grant.SubjectType, grant.SubjectID, grant.DataScope = machineID+"-embed", identity.PrincipalServicePrincipal, machineID, identity.DataScope{Type: "approved_organization"}
	machine := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalServicePrincipal, ID: machineID, TenantID: id, IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Grants: []identity.Grant{grant}}
	iam := seedKnowledgeQuerySQLIdentity(t, db, scope, caller, machine, identity.WorkloadBinding{TenantID: id, DepartmentID: id, ApplicationID: id, InstallationID: id, AgentID: id, AgentVersionID: "v1", PrincipalID: machineID, Status: "active", Revision: 1})
	machineSecret := "owned-budget-composition-secret-0123456789abcdef"
	secretHash := sha256.Sum256([]byte(machineSecret))
	if _, err = admin.ExecContext(ctx, `UPDATE platform_identity_machine_credential SET secret_hash=$1 WHERE tenant_id=$2 AND principal_id=$3`, hex.EncodeToString(secretHash[:]), id, machineID); err != nil {
		t.Fatal(err)
	}
	scope.AuthorizationEpoch, err = iam.CurrentAuthorizationEpoch(ctx, scope, "run")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := policyasset.Snapshot{ModelProfileID: "model", PromptVersionID: "prompt", ToolPolicyID: "tools", MemoryPolicyID: "memory", KnowledgePolicyID: "knowledge", RuntimePolicyID: "runtime", Revision: 1, Hash: strings.Repeat("b", 64),
		Model: policyasset.ModelPolicy{MaxTokens: 64}, Prompt: policyasset.PromptPolicy{TemplateHash: "owned-prompt", Template: "approved"},
		Tool: policyasset.ToolPolicy{AllowedTools: []string{"clock.now"}}, Memory: policyasset.MemoryPolicy{MaxEntries: 10}, Knowledge: policyasset.KnowledgePolicy{AllowedScopes: []string{"docs"}},
		Runtime: policyasset.RuntimePolicy{MaxAttempts: 1, TaskTimeoutSeconds: 60, LeaseSeconds: 60, RunBudget: &policyasset.RunBudgetPolicy{LimitMicros: 1000000, LimitTokens: 1000000}}}
	billing := newIndexSQLBilling(t, admin, db, scope, &snapshot)
	snapshot.Model.BudgetCents = 100
	policies := policyasset.NewSQLResolver(db)
	if err = policies.Upsert(ctx, scope, snapshot); err != nil {
		t.Fatal(err)
	}
	command := stopAuthorityExecuteRequest(scope, snapshot.Hash)
	command.Input["policy_snapshot"], err = snapshot.ExecutionInput()
	if err != nil {
		t.Fatal(err)
	}
	bodyHash, err := contract.CanonicalExecuteBodyHash(command)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runs.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: "v1", AgentEndpoint: "http://owned-agent.invalid", IdempotencyKey: id, Fingerprint: bodyHash, RequestJSON: raw}); err != nil {
		t.Fatal(err)
	}
	claimed, err := runs.AcquireLease(id, id+"-lease", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := runs.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	if err = runs.RecordDispatchCommand(platformruntime.DispatchCommand{RunID: id, Revision: running.Revision, Operation: "run", BodyHash: bodyHash, PolicyHash: snapshot.Hash}, running.LeaseToken); err != nil {
		t.Fatal(err)
	}
	executor := execution.NewModuleWithSharedRepository("internal", runs)
	executor.SetPinnedRunTargetResolver(func(_ context.Context, actual sharedkernel.Scope, endpoint string) error {
		if actual != scope || endpoint != "http://owned-agent.invalid" {
			return errors.New("fixture target mismatch")
		}
		return nil
	})
	authority := capabilityExecutionAuthority{execution: executor, identity: iam, catalog: stopOnlyAuthorityCatalog{expected: scope}}
	tree := usagecost.NewSQLRunTreeBudgetStore(db)
	modelAuthority := treeModelBudgetAuthority{tree: tree, models: billing.invocations}
	leaseCtx := sharedkernel.BindExecutionLease(ctx, running.Revision, running.LeaseToken)
	lease, _ := sharedkernel.ExecutionLeaseFromContext(leaseCtx)
	t.Run("joined-current-authority-and-workload-use-one-connection", func(t *testing.T) {
		currentCaller, err := iam.PermissionSnapshot(ctx, identity.PrincipalUser, scope.PrincipalID)
		if err != nil {
			t.Fatal(err)
		}
		currentExecutor, err := iam.PermissionSnapshot(ctx, identity.PrincipalServicePrincipal, machineID)
		if err != nil {
			t.Fatal(err)
		}
		binding, err := iam.ResolveWorkloadIdentity(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		credential, err := iam.GetMachineCredential(ctx, scope.TenantID, machineID)
		if err != nil {
			t.Fatal(err)
		}
		facts := capability.NewCapabilityAdmissionFacts(scope, scope.AuthorizationEpoch, currentCaller, currentExecutor, binding, credential)
		if facts == nil {
			t.Fatal("verified admission fixture unavailable")
		}
		maximum := db.Stats().MaxOpenConnections
		db.SetMaxOpenConns(1)
		defer db.SetMaxOpenConns(maximum)
		owner, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer owner.Rollback()
		if err := iam.AcquirePermissionReadContinuity(ctx, owner); err != nil {
			t.Fatal(err)
		}
		bounded, stop := context.WithTimeout(leaseCtx, 2*time.Second)
		defer stop()
		bound := sqlutil.WithContinuityTransaction(bounded, db, owner)
		waits := db.Stats().WaitCount
		access := capability.CapabilityResourceAccess{Action: "model.embed", ResourceType: "model", ResourceID: "model"}
		if err := authority.RecheckCapabilityAndResource(bound, scope, "run", bodyHash, snapshot.Hash, access, facts); err != nil {
			t.Fatal("current execution and IAM recheck escaped owner", err)
		}
		if err := authority.AuthenticateWorkload(bound, scope, machineID, machineSecret, "127.0.0.1:4321"); err != nil {
			t.Fatal("workload recheck escaped owner", err)
		}
		if value, err := policies.Resolve(bound, scope, scope.AgentVersionID); err != nil || value.Hash != snapshot.Hash {
			t.Fatal("policy recheck escaped owner or changed hash", err)
		}
		if db.Stats().WaitCount != waits {
			t.Fatal("composed recheck acquired a nested connection")
		}
	})
	probe := &observedProductionBudgetAuthority{runTreeBudgetAuthority: runTreeBudgetAuthority{route: agentRouteAuthority{identity: iam, runs: runs, resources: authority}, verifyOutcome: modelAuthority.VerifyOutcome}, runs: runs, lease: lease}
	tree.SetAuthority(probe)
	tree.SetAuditRecorder(audit.NewSQLStore(db))
	budgets, err := usagecost.NewSQLRunTreeModelBudgetStore(db, tree, billing.usage, modelAuthority)
	if err != nil {
		t.Fatal(err)
	}
	if err = billing.invocations.SetModelBudgetClosureReader(billing.usage); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token, err := (conversation.Ed25519ContextTokenSigner{PrivateKey: private, Issuer: "platform", Audience: "agent-runtime", TTL: time.Minute}).Sign(leaseCtx, scope, command)
	if err != nil {
		t.Fatal(err)
	}
	module := capability.NewModuleWithGovernance("internal-budget", "owned-budget-hmac", public, "platform", "agent-runtime", nil, policies, nil, billing.invocations)
	module.SetLiveExecutionAuthority(authority)
	upstream := &lostEmbeddingResponseFixture{Port: billing.gateway}
	module.SetGovernedModelInvocation(billing.access, upstream)
	module.SetModelBilling(billing.governance, budgets)
	module.SetModelCapacity(billing.capacity)
	module.SetUsageRecorder(billing.usage)
	perform := func(key string) *httptest.ResponseRecorder {
		fields := stopAuthorityHarnessContext(scope, token, key)
		for name, value := range map[string]string{"model_profile_id": "model", "prompt_version_id": "prompt", "tool_policy_id": "tools", "memory_policy_id": "memory", "knowledge_policy_id": "knowledge", "runtime_policy_id": "runtime"} {
			fields[name] = value
		}
		body, _ := json.Marshal(map[string]any{"context": fields, "input": map[string]any{"idempotency_key": key, "texts": []string{"owned fixture input"}}})
		request := httptest.NewRequest(http.MethodPost, "/internal/model/embed", strings.NewReader(string(body))).WithContext(ctx)
		request.RemoteAddr = "127.0.0.1:4321"
		request.Header.Set("X-Internal-Token", "internal-budget")
		request.Header.Set("X-Platform-Context", "Bearer "+token)
		request.Header.Set("X-Agent-Client-ID", machineID)
		request.Header.Set("X-Agent-Client-Secret", machineSecret)
		request.Header.Set("X-Context-Signature", stopAuthorityRequestSignature(http.MethodPost, request.URL.RequestURI(), body, "owned-budget-hmac"))
		response := httptest.NewRecorder()
		module.Handler().ServeHTTP(response, request)
		return response
	}
	if got := perform("first"); got.Code != 200 || probe.admissions != 2 || probe.reads != 1 || billing.calls.Load() != 1 {
		t.Fatal("production model accounting and response fence", got.Code, got.Body.String(), probe.admissions, probe.reads, billing.calls.Load())
	}
	upstream.lose = true
	if got := perform("unknown"); got.Code == 200 || billing.calls.Load() != 2 {
		t.Fatal("lost executed response not retained", got.Code, got.Body.String())
	}
	upstream.lose = false
	if got := perform("after-unknown"); got.Code != 200 || billing.calls.Load() != 3 {
		t.Fatal("independent operation did not continue", got.Code, got.Body.String())
	}
	var held, used int64
	if err = db.QueryRowContext(ctx, `SELECT held_micros,used_micros FROM platform_run_tree_budget WHERE root_run_id=$1`, id).Scan(&held, &used); err != nil || held <= 0 || used != 10000 {
		t.Fatal("retained exposure or known usage changed", held, used, err)
	}
	if got := perform("first"); got.Code != 200 || billing.calls.Load() != 3 {
		t.Fatal("replay sent another call", got.Code, got.Body.String())
	}
	var afterHeld, afterUsed int64
	if err = db.QueryRowContext(ctx, `SELECT held_micros,used_micros FROM platform_run_tree_budget WHERE root_run_id=$1`, id).Scan(&afterHeld, &afterUsed); err != nil || held != afterHeld || used != afterUsed {
		t.Fatal("replay changed accounting", err)
	}
	// This is the real gateway workload credential check, including the narrow
	// authentication facts introduced for this capacity repair.
	if _, err = admin.ExecContext(ctx, `UPDATE platform_identity_machine_credential SET status='revoked' WHERE tenant_id=$1 AND principal_id=$2`, id, machineID); err != nil {
		t.Fatal(err)
	}
	if got := perform("first"); got.Code != 403 || billing.calls.Load() != 3 {
		t.Fatal("revoked workload disclosed receipt", got.Code, got.Body.String())
	}
}
