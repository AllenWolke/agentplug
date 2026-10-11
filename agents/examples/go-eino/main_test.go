package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	agentplatform "github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

func TestLifecycleRequiresSignedScopedCapabilities(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := newServer(public)
	base := agentplatform.ExecuteRequest{ProtocolVersion: agentplatform.ProtocolVersion, Scope: testScope(), IdempotencyKey: "idempotency-test", InputSchema: "schema://example/input/v1", Input: map[string]any{"policy_snapshot": map[string]any{"content_hash": "policy-hash"}}}

	invoke := base
	invoke.Operation = "invoke"
	signExecute(t, &invoke, private)
	assertStatus(t, h, "/internal/agent-execution/v2/invoke", invoke, http.StatusOK)
	run := base
	run.Operation = "run"
	signExecute(t, &run, private)
	assertStatus(t, h, "/internal/agent-execution/v2/runs", run, http.StatusAccepted)
	resume := base
	resume.Operation = "resume"
	signExecute(t, &resume, private)
	assertStatus(t, h, "/internal/agent-execution/v2/runs/run-test/resume", resume, http.StatusOK)
	events := agentplatform.EventRequest{ProtocolVersion: agentplatform.ProtocolVersion, Scope: testScope(), AfterSeq: 0, PolicySnapshotHash: "policy-hash"}
	signEvent(t, &events, private)
	recorder := httptest.NewRecorder()
	body, _ := json.Marshal(events)
	req := httptest.NewRequest(http.MethodPost, "/internal/agent-execution/v2/runs/run-test/events", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+events.ContextToken)
	h.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("events=%d %q", recorder.Code, recorder.Body.String())
	}
	cancel := base
	cancel.Operation = "cancel"
	signExecute(t, &cancel, private)
	assertStatus(t, h, "/internal/agent-execution/v2/runs/run-test/cancel", cancel, http.StatusOK)

	// A token signed for one operation must never authorize a different action.
	assertStatus(t, h, "/internal/agent-execution/v2/runs/run-test/cancel", run, http.StatusUnauthorized)
}

func testScope() agentplatform.ScopeKey {
	return agentplatform.ScopeKey{TenantID: "tenant-a", DepartmentID: "business-department", ApplicationID: "business-app", AgentInstanceID: "instance-a", InstallationID: "installation-a", AgentID: "example-go-eino", AgentVersionID: "v2", PrincipalType: "user", PrincipalID: "user-a", SessionID: "session-a", RunID: "run-test", AuthorizationEpoch: 1, TraceID: "0123456789abcdef0123456789abcdef"}
}

func signExecute(t *testing.T, request *agentplatform.ExecuteRequest, key ed25519.PrivateKey) {
	t.Helper()
	hash, err := agentplatform.CanonicalBodyHash(*request)
	if err != nil {
		t.Fatal(err)
	}
	request.ContextToken = signToken(t, key, request.Scope, request.Operation, hash, "policy-hash")
}

func signEvent(t *testing.T, request *agentplatform.EventRequest, key ed25519.PrivateKey) {
	t.Helper()
	hash, err := agentplatform.CanonicalEventHash(*request)
	if err != nil {
		t.Fatal(err)
	}
	request.ContextToken = signToken(t, key, request.Scope, "events", hash, request.PolicySnapshotHash)
}

func signToken(t *testing.T, key ed25519.PrivateKey, scope agentplatform.ScopeKey, action, hash, policyHash string) string {
	t.Helper()
	now := time.Now().Unix()
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA"})
	payload, _ := json.Marshal(map[string]any{"iss": issuer, "aud": audience, "subject_type": scope.PrincipalType, "sub": scope.PrincipalID, "tenant_id": scope.TenantID, "application_id": scope.ApplicationID, "agent_instance_id": scope.AgentInstanceID, "installation_id": scope.InstallationID, "authorization_epoch": scope.AuthorizationEpoch, "actions": []string{action}, "policy_snapshot_hash": policyHash, "body_hash": hash, "iat": now, "exp": now + 60})
	h, p := base64.RawURLEncoding.EncodeToString(header), base64.RawURLEncoding.EncodeToString(payload)
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(h+"."+p)))
}

func assertStatus(t *testing.T, handler http.Handler, path string, payload agentplatform.ExecuteRequest, expected int) {
	t.Helper()
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+payload.ContextToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != expected {
		t.Fatalf("%s: got %d: %s", path, recorder.Code, recorder.Body.String())
	}
}
