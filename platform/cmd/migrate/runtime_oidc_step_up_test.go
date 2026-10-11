package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// Exercise the real composition-root trust boundary with an OIDC-only human.
func assertRuntimeOIDCStepUp(t *testing.T, ctx context.Context, client *http.Client, address string, db *sql.DB) {
	t.Helper()
	const tenant, department, application = "session-fixture", "session-fixture-dept", "session-fixture-app"
	const administrator, target = "oidc-process-admin", "oidc-process-target"
	const issuer, providerSubject = "https://fixture.example/realm", "immutable-process-admin"
	const gatewayToken = "gateway-fixture-0123456789abcdef0123456789abcdef"
	store := identity.NewSQLStore(db)
	store.SetRefreshSessionRecorder(func(context.Context, *sql.Tx, identity.RefreshSessionEvent) error { return nil })
	for _, subject := range []string{administrator, target} {
		if err := store.CreatePrincipal(ctx, identity.Principal{Type: identity.PrincipalUser, ID: subject, TenantID: tenant, IsActive: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('user',?,'v2',1,1)`), subject); err != nil {
			t.Fatal(err)
		}
		member := identity.Membership{ID: subject + "-member", SubjectID: subject, Scope: identity.ManagementScope{Type: "application", TenantID: tenant, DepartmentID: department, ApplicationID: application}, Status: "active", Revision: 1}
		raw, _ := json.Marshal(member)
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES(?,?,?,?,?,'active',1,?,?)`), member.ID, subject, tenant, department, application, string(raw), fmt.Sprintf("%x", sha256.Sum256([]byte(member.ID)))); err != nil {
			t.Fatal(err)
		}
	}
	binding := identity.RoleBinding{ID: "oidc-process-super", SubjectID: administrator, RoleCode: "super_admin", RoleVersion: 1, Scope: identity.ManagementScope{Type: "global"}, Status: "active", Revision: 1, SourceID: "isolated-process-fixture"}
	raw, _ := json.Marshal(binding)
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_role_binding(id,subject_id,role_code,role_version,tenant_id,department_id,application_id,status,revision,payload,source_hash) VALUES(?,?,?,1,'','','','active',1,?,?)`), binding.ID, administrator, binding.RoleCode, string(raw), fmt.Sprintf("%x", sha256.Sum256([]byte(binding.ID)))); err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("%x", sha256.Sum256([]byte(issuer+"\x00"+providerSubject)))
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_oidc_binding(identity_key,issuer,subject,principal_id,tenant_id,department_id,application_id,status,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'active',1,clock_timestamp(),clock_timestamp())`), key, issuer, providerSubject, administrator, tenant, department, application); err != nil {
		t.Fatal(err)
	}
	// Appointment requires an actual authentication binding for the target too.
	targetSubject := "immutable-process-permission-admin"
	targetKey := fmt.Sprintf("%x", sha256.Sum256([]byte(issuer+"\x00"+targetSubject)))
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_oidc_binding(identity_key,issuer,subject,principal_id,tenant_id,department_id,application_id,status,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'active',1,clock_timestamp(),clock_timestamp())`), targetKey, issuer, targetSubject, target, tenant, department, application); err != nil {
		t.Fatal(err)
	}
	session, err := store.CreateOIDCRefreshSession(ctx, issuer, providerSubject)
	if err != nil {
		t.Fatal(err)
	}
	actor := sharedkernel.Scope{PrincipalType: "user", PrincipalID: administrator, TenantID: tenant, DepartmentID: department, ApplicationID: application}
	invoke := func(path, token string, browser bool, input any, want int) []byte {
		t.Helper()
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, "POST", "http://"+address+"/modules/identity"+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Internal-Token", token)
		if browser {
			for name, value := range map[string]string{"X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": administrator, "X-Tenant-ID": tenant, "X-Department-ID": department, "X-Application-ID": application, "X-Authentication-Revision": "1", "X-Authentication-Session": session.SessionID} {
				r.Header.Set(name, value)
			}
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		output, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Fatalf("OIDC runtime boundary %s status=%d want=%d body=%s", path, response.StatusCode, want, output)
		}
		return output
	}
	command := identity.AdministratorCommand{SubjectID: target, ExpectedRevision: 1, IdempotencyKey: "oidc-runtime-appointment", Reason: "verified same-human fresh OIDC assertion", RoleCode: "permission_admin", Scope: identity.ManagementScope{Type: "application", TenantID: tenant, DepartmentID: department, ApplicationID: application}}
	digest, err := identity.AdministratorCommandDigest(command)
	if err != nil {
		t.Fatal(err)
	}
	request := identity.OIDCStepUpRequest{Scope: actor, SessionID: session.SessionID, AuthRevision: 1, Action: "administrator.appoint", RequestDigest: digest}
	challengePath, completePath := "/internal/oidc/step-up:challenge", "/internal/oidc/step-up:complete"
	invoke(challengePath, "fixture-internal-token-with-32-bytes", false, request, 403)
	invoke(challengePath, gatewayToken, true, request, 403)
	var challenge identity.OIDCStepUpChallenge
	if err := json.Unmarshal(invoke(challengePath, gatewayToken, false, request, 200), &challenge); err != nil {
		t.Fatal(err)
	}
	assertion := identity.OIDCStepUpCompletion{OIDCStepUpRequest: request, ChallengeToken: challenge.Token, Issuer: issuer, Subject: providerSubject, Nonce: challenge.Nonce, AuthenticatedAt: time.Now().UTC().Truncate(time.Second)}
	invoke(completePath, "fixture-internal-token-with-32-bytes", false, assertion, 403)
	invoke(completePath, gatewayToken, true, assertion, 403)
	var proof identity.StepUpProof
	if err := json.Unmarshal(invoke(completePath, gatewayToken, false, assertion, 200), &proof); err != nil {
		t.Fatal(err)
	}
	invoke(completePath, gatewayToken, false, assertion, 401)
	command.StepUpToken = proof.Token
	var receipt identity.AdministratorReceipt
	if err := json.Unmarshal(invoke("/administrators:appoint", gatewayToken, true, command, 200), &receipt); err != nil || receipt.Revision != 2 || receipt.Command.StepUpToken != "" {
		t.Fatal("OIDC runtime appointment receipt", err, receipt)
	}
	delegation := identity.Delegation{ID: "oidc-process-delegation", SubjectID: target, Scope: command.Scope, Roles: []string{"operator"}, ManagementActions: []string{"authorization.change"}, MaxDurationSeconds: 3600, AllowPermanent: true, Status: "active", Revision: 1}
	delegationCommand := identity.DelegationCommand{SubjectID: target, ExpectedRevision: 2, IdempotencyKey: "oidc-runtime-delegate", Reason: "explicit grant-making delegation", Delegation: &delegation}
	var preview identity.DelegationPreview
	if err := json.Unmarshal(invoke("/delegations:preview", gatewayToken, true, delegationCommand, 200), &preview); err != nil || preview.StepUpAction != "delegation.manage" || preview.Command.ExpectedRevision != 2 || preview.Delegation.ID != delegation.ID {
		t.Fatal("actual delegation preview did not validate current target", preview, err)
	}
	invalid := delegationCommand
	invalid.ExpectedRevision = 1
	invoke("/delegations:preview", gatewayToken, true, invalid, 409)
	request.Action, request.RequestDigest = preview.StepUpAction, preview.RequestDigest
	if err := json.Unmarshal(invoke(challengePath, gatewayToken, false, request, 200), &challenge); err != nil {
		t.Fatal(err)
	}
	assertion = identity.OIDCStepUpCompletion{OIDCStepUpRequest: request, ChallengeToken: challenge.Token, Issuer: issuer, Subject: providerSubject, Nonce: challenge.Nonce, AuthenticatedAt: time.Now().UTC().Truncate(time.Second)}
	if err := json.Unmarshal(invoke(completePath, gatewayToken, false, assertion, 200), &proof); err != nil {
		t.Fatal(err)
	}
	delegationCommand = preview.Command
	delegationCommand.StepUpToken = proof.Token
	var delegationReceipt identity.DelegationReceipt
	if err := json.Unmarshal(invoke("/delegations", gatewayToken, true, delegationCommand, 200), &delegationReceipt); err != nil || delegationReceipt.Revision != 3 || delegationReceipt.Command.StepUpToken != "" {
		t.Fatal("OIDC runtime delegation receipt", delegationReceipt, err)
	}
	var businessGrants int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_grant WHERE subject_type='user' AND subject_id=?`), target).Scan(&businessGrants); err != nil || businessGrants != 0 {
		t.Fatal("delegation implicitly granted business use", businessGrants, err)
	}
	if err := store.RevokeRefreshSession(ctx, session.RefreshToken); err != nil {
		t.Fatal(err)
	}
	invoke(challengePath, gatewayToken, false, request, 401)
	invoke("/administrators:appoint", gatewayToken, true, command, 401)
}
