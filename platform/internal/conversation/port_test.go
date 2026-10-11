package conversation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func scopeForTest() Scope {
	return Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", PrincipalType: "user", PrincipalID: "alice", TraceID: "0123456789abcdef0123456789abcdef"}
}

func TestAccessPolicyBindsMineViewToTrustedPrincipal(t *testing.T) {
	policy := AccessPolicy{}
	q, err := policy.Normalize(scopeForTest(), Query{View: "mine", OwnerID: "bob", Page: 0, PageSize: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if q.OwnerID != "alice" || q.Page != 1 || q.PageSize != 100 {
		t.Fatalf("query was not normalized to trusted owner: %+v", q)
	}
	if policy.CanAccess(scopeForTest(), Summary{ID: "s", OwnerID: "bob"}) {
		t.Fatal("user view must not access another principal's history")
	}
}

func TestManagedViewRequiresExplicitPolicy(t *testing.T) {
	if _, err := (AccessPolicy{}).Normalize(scopeForTest(), Query{View: "managed"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected managed view denial, got %v", err)
	}
	if q, err := (AccessPolicy{AllowManaged: true}).Normalize(scopeForTest(), Query{View: "managed", Page: 2, PageSize: 10}); err != nil || q.View != "managed" {
		t.Fatalf("managed view should be explicit: q=%+v err=%v", q, err)
	}
}

func TestQueryRejectsUnknownKindAndInvalidScope(t *testing.T) {
	if _, err := (AccessPolicy{}).Normalize(scopeForTest(), Query{Kind: "unknown"}); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("expected kind rejection, got %v", err)
	}
	bad := scopeForTest()
	bad.TenantID = ""
	if _, err := (AccessPolicy{}).Normalize(bad, Query{}); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("expected scope rejection, got %v", err)
	}
}

func TestScopeFromContractDoesNotInventTenantData(t *testing.T) {
	input := contract.ScopeKey{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "service_principal", PrincipalID: "svc", TraceID: "0123456789abcdef0123456789abcdef"}
	got := ScopeFromContract(input)
	if got.TenantID != input.TenantID || got.PrincipalID != input.PrincipalID || got.PrincipalType != input.PrincipalType {
		t.Fatalf("scope conversion changed trusted values: %+v", got)
	}
}

func TestOwnedMessageWhereBindsSessionOwner(t *testing.T) {
	scope := scopeForTest()
	where, args := ownedMessageWhere(scope, "session-1", "message-1")
	if !strings.Contains(where, "m.id=?") || !strings.Contains(where, "s.owner_id=?") {
		t.Fatalf("message predicate must bind message and session owner: %s", where)
	}
	want := []any{"message-1", "session-1", scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("message predicate args = %#v, want %#v", args, want)
	}
}

func TestEd25519ContextTokenSignerBindsTrustedScope(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scope := sharedkernel.Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentInstanceID: "instance", AgentID: "document-assistant", AgentVersionID: "v2", PrincipalType: "user", PrincipalID: "alice", InstallationID: "installation", SessionID: "session", RunID: "run", AuthorizationEpoch: 1, TraceID: "0123456789abcdef0123456789abcdef"}
	request := contract.ExecuteRequest{
		ProtocolVersion: contract.ProtocolVersion,
		Scope: contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
			AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID,
			PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, SessionID: scope.SessionID, RunID: scope.RunID,
			AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID, InstallationID: scope.InstallationID},
		Operation: "run", IdempotencyKey: "test-idempotency", InputSchema: "schema://document-assistant/input/v1",
		Input: map[string]any{"question": "口径", "policy_snapshot": map[string]any{"content_hash": strings.Repeat("a", 64)}},
	}
	leaseContext := sharedkernel.BindExecutionLease(context.Background(), 7, "test-private-worker-lease")
	token, err := (Ed25519ContextTokenSigner{PrivateKey: private, Issuer: "platform", Audience: "agent-runtime"}).Sign(leaseContext, scope, request)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token parts=%d", len(parts))
	}
	if !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), mustDecodeTokenSignature(t, parts[2])) {
		t.Fatal("context token signature did not verify")
	}
	var claims map[string]any
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	bodyHash, hashErr := contract.CanonicalExecuteBodyHash(request)
	if err != nil || hashErr != nil || json.Unmarshal(raw, &claims) != nil || claims["sub"] != "alice" || claims["agent_instance_id"] != "instance" || claims["installation_id"] != "installation" || claims["body_hash"] != bodyHash || claims["policy_snapshot_hash"] != strings.Repeat("a", 64) {
		t.Fatalf("unexpected claims: %v", claims)
	}
	binding, _ := sharedkernel.ExecutionLeaseFromContext(leaseContext)
	if claims["execution_revision"] != float64(7) || claims["lease_token_hash"] != binding.TokenHash || strings.Contains(string(raw), "test-private-worker-lease") {
		t.Fatal("lease generation not signed or raw credential leaked")
	}
}

func TestEd25519ContextTokenSignerRefreshesAfterOriginalTTL(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scope := sharedkernel.Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentInstanceID: "instance", InstallationID: "installation", AgentID: "document-assistant", AgentVersionID: "v2", PrincipalType: "user", PrincipalID: "alice", SessionID: "session", RunID: "run", AuthorizationEpoch: 1, TraceID: "0123456789abcdef0123456789abcdef"}
	request := contract.ExecuteRequest{ProtocolVersion: contract.ProtocolVersion, Operation: "resume", IdempotencyKey: "resume-command", InputSchema: "schema://document-assistant/input/v1", Scope: contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentInstanceID: scope.AgentInstanceID, InstallationID: scope.InstallationID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, SessionID: scope.SessionID, RunID: scope.RunID, AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID}, Input: map[string]any{"policy_snapshot": map[string]any{"content_hash": strings.Repeat("a", 64)}}, ResumeInput: map[string]any{"decision": "approve"}}
	clock := time.Unix(1_800_000_000, 0).UTC()
	signer := Ed25519ContextTokenSigner{PrivateKey: private, Issuer: "platform", Audience: "agent-runtime", TTL: 2 * time.Minute, Clock: func() time.Time { return clock }}
	readClaims := func(token string) map[string]any {
		parts := strings.Split(token, ".")
		if len(parts) != 3 || !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), mustDecodeTokenSignature(t, parts[2])) {
			t.Fatal("invalid context signature")
		}
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		var claims map[string]any
		if err := json.Unmarshal(raw, &claims); err != nil {
			t.Fatal(err)
		}
		return claims
	}
	oldToken, err := signer.Sign(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	old := readClaims(oldToken)
	clock = clock.Add(3 * time.Minute)
	if old["exp"].(float64) >= float64(clock.Unix()) {
		t.Fatal("old token was not expired before delayed resume")
	}
	renewedToken, err := signer.Sign(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	renewed := readClaims(renewedToken)
	if renewedToken == oldToken || renewed["iat"].(float64) != float64(clock.Unix()) || renewed["exp"].(float64) != float64(clock.Add(2*time.Minute).Unix()) {
		t.Fatal("delayed resume did not issue a fresh bounded token")
	}
}

func TestEd25519ContextTokenSignerBindsSynchronousInvokeOperation(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scope := sharedkernel.Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentInstanceID: "instance", AgentID: "document-assistant", AgentVersionID: "v2", PrincipalType: "user", PrincipalID: "alice", InstallationID: "installation", SessionID: "session", RunID: "run", AuthorizationEpoch: 1, TraceID: "0123456789abcdef0123456789abcdef"}
	request := contract.ExecuteRequest{
		ProtocolVersion: contract.ProtocolVersion,
		Scope: contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
			AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID,
			PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, SessionID: scope.SessionID, RunID: scope.RunID,
			AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID, InstallationID: scope.InstallationID},
		Operation: "invoke", IdempotencyKey: "evaluation-case-idempotency", InputSchema: "schema://document-assistant/input/v1",
		Input: map[string]any{"question": "口径", "policy_snapshot": map[string]any{"content_hash": strings.Repeat("a", 64)}},
	}
	token, err := (Ed25519ContextTokenSigner{PrivateKey: private, Issuer: "platform", Audience: "agent-runtime"}).Sign(nil, scope, request)
	if err != nil {
		t.Fatalf("signer rejected a synchronous invoke request: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token parts=%d", len(parts))
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatal(err)
	}
	actions, ok := claims["actions"].([]any)
	if !ok || !reflect.DeepEqual(actions, []any{"invoke"}) {
		t.Fatalf("invoke token actions=%#v, want only invoke", claims["actions"])
	}
}

func TestEd25519ContextTokenSignerRejectsScopeMismatch(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scope := sharedkernel.Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentInstanceID: "instance", AgentID: "document-assistant", AgentVersionID: "v2", PrincipalType: "user", PrincipalID: "alice", InstallationID: "installation", SessionID: "session", RunID: "run", AuthorizationEpoch: 1, TraceID: "0123456789abcdef0123456789abcdef"}
	request := contract.ExecuteRequest{
		ProtocolVersion: contract.ProtocolVersion,
		Scope: contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
			AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID,
			PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, SessionID: scope.SessionID, RunID: scope.RunID,
			AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID, InstallationID: "other-installation"},
		Operation: "run", IdempotencyKey: "test-idempotency", InputSchema: "schema://document-assistant/input/v1",
		Input: map[string]any{"question": "口径", "policy_snapshot": map[string]any{"content_hash": strings.Repeat("a", 64)}},
	}
	if _, err := (Ed25519ContextTokenSigner{PrivateKey: private, Issuer: "platform", Audience: "agent-runtime"}).Sign(nil, scope, request); err == nil {
		t.Fatal("signer accepted an envelope for a different installation")
	}
}

func mustDecodeTokenSignature(t *testing.T, raw string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
