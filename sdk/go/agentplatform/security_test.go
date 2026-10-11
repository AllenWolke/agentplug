package agentplatform

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestVerifyContextRejectsScopeDrift(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	r := ExecuteRequest{ProtocolVersion: ProtocolVersion, Operation: "invoke", IdempotencyKey: "idem-key", InputSchema: "schema://x", Input: map[string]any{"q": "x", "policy_snapshot": map[string]any{"content_hash": "snapshot-hash"}}, Scope: ScopeKey{TenantID: "t", ApplicationID: "a", AgentInstanceID: "i", InstallationID: "install-i", PrincipalType: "user", PrincipalID: "u", AuthorizationEpoch: 1}}
	hash, _ := CanonicalBodyHash(r)
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA"})
	payload, _ := json.Marshal(map[string]any{"iss": "platform", "aud": "agent-runtime", "subject_type": "user", "sub": "u", "tenant_id": "t", "application_id": "a", "agent_instance_id": "i", "installation_id": "install-i", "authorization_epoch": 1, "actions": []string{"invoke"}, "policy_snapshot_hash": "snapshot-hash", "body_hash": hash, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()})
	h, p := base64.RawURLEncoding.EncodeToString(header), base64.RawURLEncoding.EncodeToString(payload)
	r.ContextToken = h + "." + p + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(h+"."+p)))
	if _, err := VerifyContext(r, public, "platform", "agent-runtime", now); err != nil {
		t.Fatal(err)
	}
	r.Scope.TenantID = "other"
	if _, err := VerifyContext(r, public, "platform", "agent-runtime", now); err == nil {
		t.Fatal("scope drift accepted")
	}
}

func TestCanonicalBodyHashMatchesLiteralEvidenceProtocolVector(t *testing.T) {
	r := ExecuteRequest{ProtocolVersion: ProtocolVersion, Operation: "invoke", IdempotencyKey: "idem-key", InputSchema: "schema://x", Input: map[string]any{"q": "<evidence>&校验", "policy_snapshot": map[string]any{"content_hash": "snapshot-hash"}}, Scope: ScopeKey{TenantID: "t", ApplicationID: "a", AgentInstanceID: "i", InstallationID: "install-i", PrincipalType: "user", PrincipalID: "u", AuthorizationEpoch: 1}}
	// Fixed protocol preimage is independent of the SDK serializer/sign helper.
	preimage := `{"idempotency_key":"idem-key","input":{"policy_snapshot":{"content_hash":"snapshot-hash"},"q":"<evidence>&校验"},"input_schema":"schema://x","operation":"invoke","protocol_version":"agent-execution/v2","scope":{"agent_id":"","agent_instance_id":"i","agent_version_id":"","application_id":"a","authorization_epoch":1,"department_id":"","installation_id":"install-i","principal_id":"u","principal_type":"user","run_id":"","session_id":"","tenant_id":"t","trace_id":""}}`
	want := sha256.Sum256([]byte(preimage))
	hash, err := CanonicalBodyHash(r)
	if err != nil || hash != hex.EncodeToString(want[:]) {
		t.Fatal("literal evidence changed the cross-SDK body hash")
	}
	changed := r
	changed.Input = map[string]any{"q": "<evidence>&tampered", "policy_snapshot": r.Input["policy_snapshot"]}
	tampered, _ := CanonicalBodyHash(changed)
	if hash == tampered {
		t.Fatal("evidence tampering retained the signature binding")
	}
}

// TestResumeDecisionIsSigned rejects tampering before any business execution.
// TestResumeDecisionIsSigned 确保恢复决策篡改在业务执行前被拒绝。
func TestResumeDecisionIsSigned(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	r := ExecuteRequest{ProtocolVersion: ProtocolVersion, Operation: "resume", IdempotencyKey: "review", InputSchema: "schema://review", Input: map[string]any{"policy_snapshot": map[string]any{"content_hash": "snapshot"}}, ResumeInput: map[string]any{"decision": "approve"}, Scope: ScopeKey{TenantID: "t", ApplicationID: "a", AgentInstanceID: "i", InstallationID: "install", PrincipalType: "user", PrincipalID: "u", AuthorizationEpoch: 1}}
	r.ContextToken = signExecute(t, private, "platform", "agent", "resume", r, now)
	if _, err := VerifyContext(r, public, "platform", "agent", now); err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []map[string]any{{"decision": "reject"}, {}, nil} {
		tampered := r
		tampered.ResumeInput = replacement
		if _, err := VerifyContext(tampered, public, "platform", "agent", now); err == nil {
			t.Fatal("tampered resume input accepted")
		}
	}
}
