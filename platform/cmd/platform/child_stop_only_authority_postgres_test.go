package main

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type captureStopRouteStore struct {
	ctx      context.Context
	calls    int
	scope    sharedkernel.Scope
	request  agentcoordination.ChildCancelRequest
	identity agentcoordination.ChildStopIdentity
}

func (*captureStopRouteStore) Transact(context.Context, sharedkernel.Scope, func(agentcoordination.RouteTransaction) error) error {
	return agentcoordination.ErrUnavailable
}
func (s *captureStopRouteStore) CancelChildStopOnly(ctx context.Context, scope sharedkernel.Scope, request agentcoordination.ChildCancelRequest, identity agentcoordination.ChildStopIdentity) (agentcoordination.ChildCancellation, error) {
	s.ctx, s.scope, s.request, s.identity = ctx, scope, request, identity
	s.calls++
	return agentcoordination.ChildCancellation{Version: "agent-child-cancellation/v1", ParentRunID: scope.RunID, ChildRunID: "child-run", ChildKey: "child-key", OperationKey: request.OperationKey, Ordinal: request.Ordinal, Status: "cancelling", ExecutionRevision: request.ExpectedExecutionRevision + 1}, nil
}

func TestSQLParentForChildStopUsesLiveRunAndMachineIdentityAfterIAMRevocation(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := execution.MigrateSchema(ctx, db); err != nil {
		t.Fatal("ensure execution schema", err)
	}
	if err := identity.NewSQLStore(db).EnsureSchema(ctx); err != nil {
		t.Fatal("ensure identity schema", err)
	}
	if err := identity.NewSQLStore(db).EnsureWorkloadBindingSchema(ctx); err != nil {
		t.Fatal("ensure workload binding schema", err)
	}
	routes, err := agentcoordination.NewSQLRouteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.EnsureSchema(ctx); err != nil {
		t.Fatal("ensure route schema", err)
	}
	if err := routes.EnsureDelegationAuthoritySchema(ctx); err != nil {
		t.Fatal("ensure root authority proof schema", err)
	}
	runs, err := execution.ConnectSQLStore(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	iam := identity.NewSQLStore(db)

	suffix := fmt.Sprintf("stop-parent-authority-%d", time.Now().UnixNano())
	parent := sharedkernel.Scope{
		TenantID: suffix, DepartmentID: suffix + "-dept", ApplicationID: suffix + "-app",
		AgentInstanceID: suffix + "-install", InstallationID: suffix + "-install", AgentID: suffix + "-agent",
		AgentVersionID: "v1", PrincipalType: "user", PrincipalID: suffix + "-caller",
		SessionID: suffix + "-session", RunID: suffix + "-run", AuthorizationEpoch: 1,
		TraceID: "0123456789abcdef0123456789abcdef",
	}
	machineID, machineSecret := suffix+"-machine", "private-stop-machine-secret-0123456789abcdef"
	for _, err := range []error{
		iam.CreateTenant(ctx, identity.Tenant{ID: parent.TenantID, Code: parent.TenantID, Name: "stop fixture", Status: "active", Revision: 1}),
		iam.CreateDepartment(ctx, identity.Department{ID: parent.DepartmentID, TenantID: parent.TenantID, Code: parent.DepartmentID, Name: "stop fixture", Status: "active", Revision: 1}),
		iam.CreateApplication(ctx, identity.Application{ID: parent.ApplicationID, TenantID: parent.TenantID, DepartmentID: parent.DepartmentID, Code: parent.ApplicationID, Name: "stop fixture", Status: "active", Revision: 1}),
		iam.CreatePrincipal(ctx, identity.Principal{Type: identity.PrincipalUser, ID: parent.PrincipalID, TenantID: parent.TenantID, IsActive: true, Revision: 1}),
		iam.CreatePrincipal(ctx, identity.Principal{Type: identity.PrincipalServicePrincipal, ID: machineID, TenantID: parent.TenantID, IsActive: true, Revision: 1}),
	} {
		if err != nil {
			t.Fatal("seed scoped identity", err)
		}
	}
	for _, principal := range []identity.PrincipalType{identity.PrincipalUser, identity.PrincipalServicePrincipal} {
		subject := parent.PrincipalID
		if principal == identity.PrincipalServicePrincipal {
			subject = machineID
		}
		epoch := uint64(1)
		if principal == identity.PrincipalUser {
			// The admitted Run and its stop capability carry epoch 1. The current
			// caller epoch is 2 and has no business/delegation Grant rows.
			epoch = 2
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES($1,$2,'v2',$3,$4)`, principal, subject, epoch, epoch); err != nil {
			t.Fatal("seed current permission epoch", err)
		}
	}
	secretHash := sha256.Sum256([]byte(machineSecret))
	if err := iam.CreateMachineCredential(ctx, identity.MachineCredential{TenantID: parent.TenantID, PrincipalID: machineID, SecretHash: hex.EncodeToString(secretHash[:]), NetworkCIDRs: []string{"127.0.0.1/32"}, Status: "active", Revision: 1}); err != nil {
		t.Fatal("seed active parent machine credential", err)
	}
	binding := identity.WorkloadBinding{TenantID: parent.TenantID, DepartmentID: parent.DepartmentID, ApplicationID: parent.ApplicationID, InstallationID: parent.InstallationID, AgentID: parent.AgentID, AgentVersionID: parent.AgentVersionID, PrincipalID: machineID, Status: "active", Revision: 1}
	bindingScope, _ := json.Marshal([]string{binding.TenantID, binding.DepartmentID, binding.ApplicationID, binding.InstallationID})
	bindingHash := sha256.Sum256(bindingScope)
	bindingPayload, _ := json.Marshal(binding)
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_workload_binding(scope_hash,tenant_id,department_id,application_id,installation_id,principal_id,status,revision,payload) VALUES($1,$2,$3,$4,$5,$6,'active',1,$7)`, hex.EncodeToString(bindingHash[:]), binding.TenantID, binding.DepartmentID, binding.ApplicationID, binding.InstallationID, binding.PrincipalID, string(bindingPayload)); err != nil {
		t.Fatal("seed exact active workload binding", err)
	}
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_identity_workload_binding WHERE scope_hash=$1`, hex.EncodeToString(bindingHash[:]))
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_identity_machine_credential WHERE tenant_id=$1 AND principal_id=$2`, parent.TenantID, machineID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_identity_principal WHERE id IN ($1,$2)`, parent.PrincipalID, machineID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_identity_application WHERE id=$1`, parent.ApplicationID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_identity_department WHERE id=$1`, parent.DepartmentID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_identity_tenant WHERE id=$1`, parent.TenantID)
	}()

	policyHash := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	executionRequest := stopAuthorityExecuteRequest(parent, policyHash)
	bodyHash, err := contract.CanonicalExecuteBodyHash(executionRequest)
	if err != nil {
		t.Fatal(err)
	}
	requestBytes, _ := json.Marshal(executionRequest)
	if _, err := runs.Create(platformruntime.CreateRequest{ID: parent.RunID, Scope: parent, AgentVersionID: parent.AgentVersionID, IdempotencyKey: parent.RunID, Fingerprint: bodyHash, RequestJSON: requestBytes}); err != nil {
		t.Fatal("create persisted parent Run", err)
	}
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_execution_dispatch_command WHERE run_id=$1`, parent.RunID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_execution_session_lease WHERE run_id=$1`, parent.RunID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_execution_creation_projection WHERE run_id=$1`, parent.RunID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_execution_outcome WHERE run_id=$1`, parent.RunID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_execution_event WHERE run_id=$1`, parent.RunID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_execution_run WHERE run_id=$1`, parent.RunID)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_identity_policy_migration WHERE subject_id IN ($1,$2)`, parent.PrincipalID, machineID)
	}()
	lease, err := runs.AcquireLease(parent.RunID, suffix+"-lease", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal("claim parent Run", err)
	}
	running, err := runs.TransitionLeased(parent.RunID, platformruntime.StatusAccepted, platformruntime.StatusRunning, lease.Revision, lease.LeaseToken)
	if err != nil {
		t.Fatal("start parent Run", err)
	}
	if err := runs.RecordDispatchCommand(platformruntime.DispatchCommand{RunID: parent.RunID, Revision: running.Revision, Operation: "run", BodyHash: bodyHash, PolicyHash: policyHash}, running.LeaseToken); err != nil {
		t.Fatal("record immutable parent dispatch", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.PinRootMachineAuthorityTx(ctx, tx, agentcoordination.RootMachineAuthorityStamp{RootRunID: parent.RunID, RootInstallationID: parent.InstallationID, RootPrincipalType: parent.PrincipalType, RootPrincipalID: parent.PrincipalID, RootAuthorizationEpoch: parent.AuthorizationEpoch, MachinePrincipalID: machineID, MachineRunEpoch: 1}); err != nil {
		_ = tx.Rollback()
		t.Fatal("pin original root machine generation", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_agent_delegation_root_authority WHERE root_run_id=$1`, parent.RunID)
	}()

	executionModule := execution.NewModuleWithSharedRepository("internal", runs)
	resources := capabilityExecutionAuthority{execution: executionModule, identity: iam, catalog: stopOnlyAuthorityCatalog{expected: parent}}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := &captureStopRouteStore{}
	router, err := agentcoordination.NewRouter(store)
	if err != nil {
		t.Fatal(err)
	}
	module := capability.NewModule("internal-stop-token", "stop-request-signing-secret", publicKey, "platform", "agent-runtime")
	module.SetLiveExecutionAuthority(resources)
	module.SetAgentRouter(router)

	input := agentcoordination.ChildCancelRequest{OperationKey: "saved-operation", Ordinal: 0, ExpectedExecutionRevision: 1}
	contextFields := stopAuthorityHarnessContext(parent, "", "")
	contextFields["actor_id"] = parent.PrincipalID
	contextFields["authorization_epoch"] = parent.AuthorizationEpoch
	leaseBinding := sharedkernel.BindExecutionLease(context.Background(), running.Revision, running.LeaseToken)
	token, err := (conversation.Ed25519ContextTokenSigner{PrivateKey: privateKey, Issuer: "platform", Audience: "agent-runtime", TTL: time.Minute}).Sign(leaseBinding, parent, executionRequest)
	if err != nil {
		t.Fatal("sign exact persisted run generation", err)
	}
	contextFields["platform_context_token"] = token

	perform := func(secret, clientID, actor string) *httptest.ResponseRecorder {
		t.Helper()
		fields := make(map[string]any, len(contextFields))
		for key, value := range contextFields {
			fields[key] = value
		}
		fields["actor_id"] = actor
		body, err := json.Marshal(map[string]any{"context": fields, "input": input})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/internal/agent/cancel", strings.NewReader(string(body)))
		req.RemoteAddr = "127.0.0.1:4321"
		req.Header.Set("X-Internal-Token", "internal-stop-token")
		req.Header.Set("X-Platform-Context", "Bearer "+token)
		req.Header.Set("X-Agent-Client-ID", clientID)
		req.Header.Set("X-Agent-Client-Secret", secret)
		req.Header.Set("X-Context-Signature", stopAuthorityRequestSignature(http.MethodPost, req.URL.RequestURI(), body, "stop-request-signing-secret"))
		recorder := httptest.NewRecorder()
		module.Handler().ServeHTTP(recorder, req)
		return recorder
	}

	validResponse := perform(machineSecret, machineID, parent.PrincipalID)
	if validResponse.Code != http.StatusOK || store.calls != 1 || store.scope != parent || store.identity.MachinePrincipalID != machineID {
		t.Fatalf("signed stop-only path rejected the admitted live parent after IAM epoch change: http=%d body=%s calls=%d", validResponse.Code, validResponse.Body.String(), store.calls)
	}
	proofClient, proofSecret, proofPeer, err := capability.AgentCoordinationStopWorkloadProof(store.ctx, parent)
	if err != nil || proofClient != machineID || proofSecret != machineSecret || proofPeer != "127.0.0.1:4321" {
		t.Fatal("HTTP stop path did not bind exact authenticated workload proof", err)
	}

	// The caller's v2 agent.delegate permission is revoked. Epoch lookup is
	// action-authorized, so it must fail closed instead of returning a version
	// for an action this principal can no longer perform. Stop succeeds from
	// the persisted Run/lease/workload proof; normal business authorization
	// and missing workload credentials still fail closed.
	if _, err := iam.CurrentAuthorizationEpoch(ctx, parent, "agent.delegate"); err == nil || err.Error() != "current v2 IAM access denied" {
		t.Fatalf("expected revoked v2 agent.delegate lookup to fail closed, got err=%v", err)
	}
	var grants int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_identity_grant WHERE subject_type='user' AND subject_id=$1 AND action IN ('run','agent.delegate')`, parent.PrincipalID).Scan(&grants); err != nil || grants != 0 {
		t.Fatalf("fixture unexpectedly has caller run/delegate grants: count=%d err=%v", grants, err)
	}
	if err := resources.AuthorizeCapability(ctx, parent, "run", bodyHash, policyHash); err == nil {
		t.Fatal("ordinary execution survived current IAM epoch mismatch")
	}

	badSecretResponse := perform("wrong-secret-0123456789abcdef0123456789", machineID, parent.PrincipalID)
	if badSecretResponse.Code != http.StatusForbidden || store.calls != 1 {
		t.Fatalf("invalid machine credential reached stop route: status=%d calls=%d", badSecretResponse.Code, store.calls)
	}
	badMachineResponse := perform(machineSecret, suffix+"-foreign-machine", parent.PrincipalID)
	if badMachineResponse.Code != http.StatusForbidden || store.calls != 1 {
		t.Fatalf("foreign workload identity reached stop route: status=%d calls=%d", badMachineResponse.Code, store.calls)
	}
	foreignCallerResponse := perform(machineSecret, machineID, suffix+"-other-caller")
	if foreignCallerResponse.Code != http.StatusForbidden || store.calls != 1 {
		t.Fatalf("foreign caller scope reused signed parent capability: status=%d calls=%d", foreignCallerResponse.Code, store.calls)
	}

	production := agentRouteAuthority{identity: iam, runs: runs, routes: routes, resources: resources}
	proof := store.identity
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := production.ParentForChildStop(store.ctx, tx, parent, proof)
	_ = tx.Rollback()
	if err != nil || facts.Scope != parent || !facts.Active || facts.Depth != 0 || facts.PolicyHash != policyHash {
		t.Fatalf("production parent stop authority rejected real current lease/IAM/workload proof: facts=%#v err=%v", facts, err)
	}

	missingResources := agentRouteAuthority{identity: iam, runs: runs, routes: routes}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = missingResources.ParentForChildStop(store.ctx, tx, parent, proof)
	_ = tx.Rollback()
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("missing production resource authority did not fail closed: %v", err)
	}
}

func stopAuthorityExecuteRequest(scope sharedkernel.Scope, policyHash string) contract.ExecuteRequest {
	return contract.ExecuteRequest{
		ProtocolVersion: contract.ProtocolVersion,
		Scope:           contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, SessionID: scope.SessionID, RunID: scope.RunID, AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID, InstallationID: scope.InstallationID},
		Operation:       "run", IdempotencyKey: scope.RunID, InputSchema: "schema://agent/input/v1",
		Input: map[string]any{"policy_snapshot": map[string]any{"content_hash": policyHash}},
	}
}

func stopAuthorityHarnessContext(scope sharedkernel.Scope, token, requestID string) map[string]any {
	return map[string]any{
		"tenant_id": scope.TenantID, "department_id": scope.DepartmentID, "application_id": scope.ApplicationID,
		"agent_id": scope.AgentID, "agent_instance_id": scope.AgentInstanceID, "installation_id": scope.InstallationID,
		"agent_version_id": scope.AgentVersionID, "principal_type": scope.PrincipalType, "actor_id": scope.PrincipalID,
		"session_id": scope.SessionID, "task_id": scope.RunID, "parent_run_id": scope.ParentRunID,
		"authorization_epoch": scope.AuthorizationEpoch, "trace_id": scope.TraceID, "request_id": requestID,
		"platform_context_token": token,
	}
}

func stopAuthorityRequestSignature(method, target string, body []byte, secret string) string {
	digest := sha256.Sum256(body)
	canonical, _ := json.Marshal([]string{"platform-capability/v2", strings.ToUpper(method), target, hex.EncodeToString(digest[:])})
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(canonical)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
