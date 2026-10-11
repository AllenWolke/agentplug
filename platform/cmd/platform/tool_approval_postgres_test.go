package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/bootstrap"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/policyasset"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type deniedToolApprovalAudit struct{ called *bool }

func (a deniedToolApprovalAudit) RecordTx(*sql.Tx, audit.Event) error {
	if a.called != nil {
		*a.called = true
	}
	return errors.New("owned injected audit failure")
}

func TestPostgresToolApprovalHTTPUsesRealSessionIAMAndStepUp(t *testing.T) {
	testPostgresToolApprovalHTTP(t, false)
}

func TestPostgresToolApprovalHTTPOIDCOnly(t *testing.T) {
	testPostgresToolApprovalHTTP(t, true)
}

func testPostgresToolApprovalHTTP(t *testing.T, oidcOnly bool) {
	t.Helper()
	migrationDSN := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if migrationDSN == "" {
		t.Skip("owned PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	admin, err := sql.Open("pgx", migrationDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if err = execution.MigrateSchema(ctx, admin); err != nil {
		t.Fatal(err)
	}
	approvalSchema, _ := capability.NewSQLToolApprovalStore(admin)
	if err = approvalSchema.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	policiesAdmin := policyasset.NewSQLResolver(admin)
	if err = policiesAdmin.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	outboxAdmin := notification.NewSQLStore(admin)
	if err = outboxAdmin.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	auditAdmin := audit.NewSQLStoreWithOutbox(admin, outboxAdmin)
	if err = auditAdmin.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	runtimeDSN := os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	if runtimeDSN == "" {
		t.Fatal("DML runtime required")
	}
	runs, err := execution.ConnectSQLStore(ctx, "pgx", runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	db := runs.DB()
	if _, err = db.ExecContext(ctx, `CREATE TABLE forbidden_approval_http_ddl(id int)`); err == nil {
		t.Fatal("runtime DDL accepted")
	} else {
		var sqlState interface{ SQLState() string }
		if !errors.As(err, &sqlState) || sqlState.SQLState() != "42501" {
			t.Fatal("runtime DDL failed for a reason other than insufficient privilege", err)
		}
	}
	id := fmt.Sprintf("approval-http-%d", time.Now().UnixNano())
	scope := sharedkernel.Scope{TenantID: id, DepartmentID: id, ApplicationID: id, PrincipalID: id + "-user", PrincipalType: "user", InstallationID: "clock-install", AgentInstanceID: "clock-install", AgentID: "clock-agent", AgentVersionID: "v1", SessionID: id + "-conversation", RunID: id, TraceID: "0123456789abcdef0123456789abcdef", AuthorizationEpoch: 1}
	app := identity.ManagementScope{Type: "application", TenantID: id, DepartmentID: id, ApplicationID: id}
	grant := identity.Grant{ID: id + "-caller-tool", SubjectType: identity.PrincipalUser, SubjectID: scope.PrincipalID, TenantID: id, DepartmentID: id, ApplicationID: id, AgentInstanceID: scope.InstallationID, ResourceType: "tool", ResourceID: "clock.now", Action: "tool.invoke", Status: "active", Effect: "allow", DataScope: identity.DataScope{Type: "owner"}}
	caller := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalUser, ID: scope.PrincipalID, TenantID: id, IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{SubjectID: scope.PrincipalID, Scope: app, Status: "active"}}, Bindings: []identity.RoleBinding{{SubjectID: scope.PrincipalID, RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active"}}, Grants: []identity.Grant{grant}}
	machineID := id + "-machine"
	grant.ID = machineID + "-tool"
	grant.SubjectType = identity.PrincipalServicePrincipal
	grant.SubjectID = machineID
	grant.DataScope = identity.DataScope{Type: "approved_organization"}
	machine := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalServicePrincipal, ID: machineID, TenantID: id, IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Grants: []identity.Grant{grant}}
	binding := identity.WorkloadBinding{TenantID: id, DepartmentID: id, ApplicationID: id, InstallationID: scope.InstallationID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, PrincipalID: machineID, Status: "active", Revision: 1}
	iam := seedKnowledgeQuerySQLIdentity(t, db, scope, caller, machine, binding)
	outbox := notification.NewSQLStore(db)
	recorder := audit.NewSQLStoreWithOutbox(db, outbox)
	iam.SetAdministrativeRecorder(recordVersionedAdministration(recorder, outbox, iam))
	iam.SetRefreshSessionRecorder(func(_ context.Context, tx *sql.Tx, event identity.RefreshSessionEvent) error {
		return recorder.RecordTx(tx, audit.Event{ID: event.ID, TenantID: id, DepartmentID: id, ApplicationID: id, ActorType: "user", ActorID: scope.PrincipalID, AggregateType: "refresh_session", AggregateID: event.FamilyID, Action: "authentication.refresh_session", Outcome: "success", Summary: event.Action, CreatedAt: event.OccurredAt})
	})
	password := "owned-approval-password"
	salt := []byte("owned-fixture-salt")
	derived, err := pbkdf2.Key(sha256.New, password, salt, 600000, 32)
	if err != nil {
		t.Fatal(err)
	}
	passwordHash := "$pbkdf2-sha256$600000$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(derived)
	if _, err = db.ExecContext(ctx, `INSERT INTO platform_identity_local_credential(principal_id,tenant_id,department_id,application_id,display_name,password_hash,auth_revision,active,created_at,updated_at) VALUES($1,$2,$2,$2,'owned', $3,1,TRUE,clock_timestamp(),clock_timestamp())`, scope.PrincipalID, id, passwordHash); err != nil {
		t.Fatal(err)
	}
	login, err := iam.VerifyEnrollmentCredentials(ctx, scope.PrincipalID, password)
	if err != nil {
		t.Fatal("actual local-password login", err)
	}
	session, err := iam.CreateRefreshSession(ctx, login.PrincipalID, identity.EnrollmentScope{TenantID: id, DepartmentID: id, ApplicationID: id}, login.AuthRevision)
	if err != nil {
		t.Fatal(err)
	}
	var oidcBinding identity.OIDCBinding
	if oidcOnly {
		oidcBinding = identity.OIDCBinding{Issuer: "https://owned-fixture.example/realm", Subject: id + "-immutable-subject", PrincipalID: scope.PrincipalID, TenantID: id, DepartmentID: id, ApplicationID: id, Status: "active", Revision: 1}
		key := sha256.Sum256([]byte(oidcBinding.Issuer + "\x00" + oidcBinding.Subject))
		if _, err = db.ExecContext(ctx, `INSERT INTO platform_identity_oidc_binding(identity_key,issuer,subject,principal_id,tenant_id,department_id,application_id,status,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$5,$5,'active',1,clock_timestamp(),clock_timestamp())`, fmt.Sprintf("%x", key), oidcBinding.Issuer, oidcBinding.Subject, scope.PrincipalID, id); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `DELETE FROM platform_identity_local_credential WHERE principal_id=$1`, scope.PrincipalID); err != nil {
			t.Fatal(err)
		}
		session, err = iam.CreateOIDCRefreshSession(ctx, oidcBinding.Issuer, oidcBinding.Subject)
		if err != nil {
			t.Fatal("actual OIDC-only login", err)
		}
		var credentials int
		if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_identity_local_credential WHERE principal_id=$1`, scope.PrincipalID).Scan(&credentials); err != nil || credentials != 0 {
			t.Fatal("fixture retained a local password", credentials, err)
		}
	}
	scope.AuthorizationEpoch, err = iam.CurrentAuthorizationEpoch(ctx, scope, "run")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := policyasset.Snapshot{ModelProfileID: "model", PromptVersionID: "prompt", ToolPolicyID: "tools", MemoryPolicyID: "memory", KnowledgePolicyID: "knowledge", RuntimePolicyID: "runtime", Revision: 1, Hash: strings.Repeat("b", 64), Model: policyasset.ModelPolicy{Provider: "owned", Model: "owned", MaxTokens: 64}, Prompt: policyasset.PromptPolicy{TemplateHash: "owned-prompt", Template: "approved"}, Tool: policyasset.ToolPolicy{AllowedTools: []string{"clock.now"}, RequireConfirmation: []string{"clock.now"}}, Memory: policyasset.MemoryPolicy{MaxEntries: 10}, Knowledge: policyasset.KnowledgePolicy{AllowedScopes: []string{"docs"}}, Runtime: policyasset.RuntimePolicy{MaxAttempts: 1, TaskTimeoutSeconds: 60, LeaseSeconds: 30}}
	policies := policyasset.NewSQLResolver(db)
	if err = policies.Upsert(ctx, scope, snapshot); err != nil {
		t.Fatal(err)
	}
	policyInput, err := snapshot.ExecutionInput()
	if err != nil {
		t.Fatal(err)
	}
	runBody, _ := json.Marshal(map[string]any{"input": map[string]any{"policy_snapshot": policyInput}})
	if _, err = runs.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: "v1", IdempotencyKey: id, Fingerprint: id, RequestJSON: runBody}); err != nil {
		t.Fatal(err)
	}
	claimed, err := runs.AcquireLease(id, "owned-lease", time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runs.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, "owned-lease"); err != nil {
		t.Fatal(err)
	}
	runModule := execution.NewModuleWithSharedRepository("internal", runs)
	contextPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	approvalPublic, approvalPrivate, _ := ed25519.GenerateKey(rand.Reader)
	module := capability.NewModuleWithKnowledgeAndPolicies("internal", "owned-signature", contextPublic, "platform", "agent-runtime", nil, policies)
	approvalStore, _ := capability.NewSQLToolApprovalStore(db)
	approvalStore.SetAuditRecorder(recorder)
	module.SetToolConfirmationAuthority(approvalStore)
	keyPath := filepath.Join(t.TempDir(), "approval.key")
	if err = os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(approvalPrivate)), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PLATFORM_TOOL_CONFIRMATION_PRIVATE_KEY_FILE", keyPath)
	t.Setenv("PLATFORM_TOOL_CONFIRMATION_PUBLIC_KEY_FILE", "")
	adapter := toolApprovalAdapter{identity: iam, runs: runModule, policy: policies, resources: capabilityExecutionAuthority{identity: iam}}
	if err = configureToolApprovalControl(module, approvalStore, adapter, contextPublic); err != nil {
		t.Fatal(err)
	}
	gateway := strings.Repeat("g", 32)
	server := httptest.NewServer(bootstrap.BrowserBoundary(bootstrap.BrowserSessionBoundary(http.StripPrefix("/modules/capability", module.Handler()), identityBrowserSessionCheck(iam)), gateway, "internal"))
	defer server.Close()
	client := server.Client()
	client.Timeout = 8 * time.Second
	post := func(action string, input any) (int, map[string]json.RawMessage) {
		t.Helper()
		body, _ := json.Marshal(input)
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/modules/capability/tool-approvals/"+action, bytes.NewReader(body))
		request.Header.Set("X-Internal-Token", gateway)
		request.Header.Set("X-Browser-Module", "1")
		request.Header.Set("X-Principal-Type", "user")
		request.Header.Set("X-Principal-ID", scope.PrincipalID)
		request.Header.Set("X-Tenant-ID", id)
		request.Header.Set("X-Department-ID", id)
		request.Header.Set("X-Application-ID", id)
		request.Header.Set("X-Authentication-Session", session.SessionID)
		request.Header.Set("X-Authentication-Revision", "1")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("approval HTTP did not complete", err)
		}
		defer response.Body.Close()
		body, _ = io.ReadAll(response.Body)
		var value struct {
			Data map[string]json.RawMessage `json:"data"`
		}
		json.Unmarshal(body, &value)
		return response.StatusCode, value.Data
	}
	operation := capability.ToolApprovalOperation{RunID: id, Name: "clock.now", CallID: "owned-call", Payload: map[string]any{}}
	status, data := post("preview", map[string]any{"operation": operation})
	if status != 200 {
		t.Fatalf("preview status=%d", status)
	}
	var claims capability.ToolConfirmationClaims
	if json.Unmarshal(data["claims"], &claims) != nil {
		t.Fatal("claims missing")
	}
	stepUp := func(action string, input map[string]any) string {
		t.Helper()
		if oidcOnly {
			request := identity.OIDCStepUpRequest{Scope: scope, SessionID: session.SessionID, AuthRevision: session.Identity.AuthRevision, Action: action, RequestDigest: capability.ToolApprovalDigest(claims)}
			challenge, err := iam.CreateOIDCStepUpChallenge(ctx, request)
			if err != nil {
				t.Fatal("OIDC business challenge", err)
			}
			proof, err := iam.CompleteOIDCStepUp(ctx, identity.OIDCStepUpCompletion{OIDCStepUpRequest: request, ChallengeToken: challenge.Token, Issuer: challenge.Issuer, Subject: challenge.Subject, Nonce: challenge.Nonce, AuthenticatedAt: time.Now().UTC().Truncate(time.Second)})
			if err != nil {
				t.Fatal("OIDC business proof", err)
			}
			return proof.Token
		}
		input["current_password"] = password
		status, data := post("step-up", input)
		if status != 200 {
			t.Fatalf("local step-up status=%d", status)
		}
		var token string
		json.Unmarshal(data["step_up_token"], &token)
		delete(input, "current_password")
		return token
	}
	input := map[string]any{"operation": operation, "claims": claims, "action": "tool.approval.approve", "current_password": "wrong"}
	if status, _ = post("step-up", input); status != 403 {
		t.Fatal("wrong password accepted")
	}
	delete(input, "current_password")
	proof := stepUp("tool.approval.approve", input)
	input["step_up_token"] = proof
	if oidcOnly {
		t.Run("same-user-other-login-cannot-consume-proof", func(t *testing.T) {
			original := session
			other, err := iam.CreateOIDCRefreshSession(ctx, oidcBinding.Issuer, oidcBinding.Subject)
			if err != nil {
				t.Fatal(err)
			}
			session = other
			defer func() { session = original }()
			if status, _ := post("approve", input); status == 200 {
				t.Fatal("same-user different login consumed proof")
			}
		})
	}
	t.Run("changed-claims-cannot-use-proof", func(t *testing.T) {
		changed := claims
		changed.CallID = "different-call"
		input["claims"] = changed
		defer func() { input["claims"] = claims }()
		if status, _ := post("approve", input); status == 200 {
			t.Fatal("changed operation accepted")
		}
	})
	t.Run("audit-failure-rolls-back-approve-and-proof-consumption", func(t *testing.T) {
		called := false
		approvalStore.SetAuditRecorder(deniedToolApprovalAudit{called: &called})
		defer approvalStore.SetAuditRecorder(recorder)
		if status, _ := post("approve", input); status == 200 {
			t.Fatal("audit failure committed approval")
		}
		if !called {
			t.Fatal("request never reached the failing audit transaction")
		}
		if approvalStore.CheckApproval(ctx, claims) == nil {
			t.Fatal("failed approval persisted its grant")
		}
	})
	status, data = post("approve", input)
	if status != 200 {
		t.Fatalf("approval status=%d", status)
	}
	var token string
	json.Unmarshal(data["confirmation_token"], &token)
	verifier, _ := capability.NewToolConfirmationVerifier(approvalPublic)
	if err = verifier.Verify(token, scope, snapshot.Hash, "clock.now", "owned-call", claims.Fingerprint, time.Now()); err != nil || approvalStore.CheckApproval(ctx, claims) != nil {
		t.Fatal("actual committed approval invalid", err)
	}
	input["action"] = "tool.approval.revoke"
	delete(input, "step_up_token")
	proof = stepUp("tool.approval.revoke", input)
	input["step_up_token"] = proof
	t.Run("audit-failure-rolls-back-revoke-and-proof-consumption", func(t *testing.T) {
		called := false
		approvalStore.SetAuditRecorder(deniedToolApprovalAudit{called: &called})
		defer approvalStore.SetAuditRecorder(recorder)
		if status, _ = post("revoke", input); status == 200 {
			t.Fatal("audit failure committed revoke")
		}
		if !called {
			t.Fatal("request never reached the failing revoke audit transaction")
		}
		if approvalStore.CheckApproval(ctx, claims) != nil {
			t.Fatal("failed revoke changed approval")
		}
	})
	if status, _ = post("revoke", input); status != 200 {
		t.Fatalf("revoke status=%d", status)
	}
	if approvalStore.CheckApproval(ctx, claims) == nil {
		t.Fatal("actual revoked approval remains usable")
	}
	if oidcOnly {
		t.Run("proof-does-not-grant-tool-permission", func(t *testing.T) {
			status, data := post("preview", map[string]any{"operation": operation})
			if status != 200 || json.Unmarshal(data["claims"], &claims) != nil {
				t.Fatal("fresh independent preview missing", status)
			}
			input["claims"], input["action"] = claims, "tool.approval.approve"
			input["step_up_token"] = stepUp("tool.approval.approve", input)
			// Run authorization epochs intentionally never rewind after IAM changes.
			// Keep this revocation at the end of the independent fixture's flow.
			if _, err := db.ExecContext(ctx, `UPDATE platform_identity_grant SET status='revoked' WHERE id=$1`, id+"-caller-tool"); err != nil {
				t.Fatal(err)
			}
			if status, _ := post("approve", input); status == 200 {
				t.Fatal("authentication bypassed revoked resource permission")
			}
			var persisted int
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_tool_approval WHERE approval_id=$1`, claims.ApprovalID).Scan(&persisted); err != nil || persisted != 0 {
				t.Fatal("denied request persisted an approval", persisted, err)
			}
		})
	}
	if err = iam.RevokeRefreshSession(ctx, session.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if status, _ = post("preview", map[string]any{"operation": operation}); status != 401 {
		t.Fatal("revoked login session approved operation")
	}
}
