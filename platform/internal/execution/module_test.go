package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type recordingConversation struct {
	calls      []sharedkernel.Scope
	body       [][]byte
	messageIDs []string
}

type machineAuthenticatorFunc func(context.Context, string, string, string) (MachineAccess, error)

func (f machineAuthenticatorFunc) AuthenticateMachine(ctx context.Context, token, remote, action string) (MachineAccess, error) {
	return f(ctx, token, remote, action)
}

func (f machineAuthenticatorFunc) AuthorizeMachineRun(ctx context.Context, token, remote, action string, scope sharedkernel.Scope, runID string) error {
	access, err := f(ctx, token, remote, action)
	if err != nil || !machineScopeOwnsRun(access.Scope, scope) || scope.RunID != runID {
		return errMachineStreamDenied
	}
	return nil
}

type machineTargetResolverFunc func(context.Context, sharedkernel.Scope) (MachineAgentTarget, error)

func (f machineTargetResolverFunc) ResolveMachineTarget(ctx context.Context, scope sharedkernel.Scope) (MachineAgentTarget, error) {
	return f(ctx, scope)
}

type machineRunPolicyResolverFunc func(context.Context, sharedkernel.Scope, string) (map[string]any, error)

func (f machineRunPolicyResolverFunc) ResolveAgentPolicy(ctx context.Context, scope sharedkernel.Scope, versionID string) (map[string]any, error) {
	return f(ctx, scope, versionID)
}

type machineRunContextSignerFunc func(context.Context, sharedkernel.Scope, contract.ExecuteRequest) (string, error)

func (f machineRunContextSignerFunc) Sign(ctx context.Context, scope sharedkernel.Scope, request contract.ExecuteRequest) (string, error) {
	return f(ctx, scope, request)
}

func setMachineRunPreparation(module *Module) {
	module.SetMachineRunPolicyResolver(machineRunPolicyResolverFunc(func(_ context.Context, scope sharedkernel.Scope, versionID string) (map[string]any, error) {
		if scope.AgentVersionID != versionID {
			return nil, errors.New("policy version mismatch")
		}
		return map[string]any{"content_hash": strings.Repeat("a", 64), "runtime": map[string]any{"max_attempts": 1}}, nil
	}))
	module.SetMachineRunContextSigner(machineRunContextSignerFunc(func(_ context.Context, scope sharedkernel.Scope, request contract.ExecuteRequest) (string, error) {
		if request.Scope.TenantID != scope.TenantID || request.Scope.AgentInstanceID != scope.AgentInstanceID || request.Scope.RunID != scope.RunID ||
			request.Input["policy_snapshot"] == nil || request.ContextToken != "" {
			return "", errors.New("untrusted execution envelope")
		}
		return strings.Repeat("s", 48), nil
	}))
}

func (r *recordingConversation) RecordRun(_ context.Context, scope sharedkernel.Scope, body []byte) error {
	r.calls = append(r.calls, scope)
	r.body = append(r.body, append([]byte(nil), body...))
	return nil
}

func (r *recordingConversation) RecordRunWithMessage(_ context.Context, scope sharedkernel.Scope, body []byte, messageID string) error {
	r.calls = append(r.calls, scope)
	r.body = append(r.body, append([]byte(nil), body...))
	r.messageIDs = append(r.messageIDs, messageID)
	return nil
}

func TestModuleProjectsOnlyNewRunAndKeepsScope(t *testing.T) {
	module := NewModule("secret")
	recorder := &recordingConversation{}
	module.SetConversationRecorder(recorder)
	scope := testScope("projection-run")
	request := createRequest{
		RunID: "projection-run", Scope: scope, AgentVersionID: "v1", IdempotencyKey: "idem-projection", Fingerprint: "projection-body",
		Request: json.RawMessage(`{"input":{"question":"project me"}}`),
	}
	if response := doJSON(t, module.Handler(), http.MethodPost, "/platform/runs", request, map[string]string{"Authorization": "Bearer secret"}); response.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	if response := doJSON(t, module.Handler(), http.MethodPost, "/platform/runs", request, map[string]string{"Authorization": "Bearer secret"}); response.Code != http.StatusOK {
		t.Fatalf("replay status=%d body=%s", response.Code, response.Body.String())
	}
	if len(recorder.calls) != 1 {
		t.Fatalf("expected one projection for a replayed request, got %d", len(recorder.calls))
	}
	if recorder.calls[0].SessionID != scope.SessionID || recorder.calls[0].AgentID != scope.AgentID || recorder.calls[0].RunID != scope.RunID {
		t.Fatalf("projection scope changed: %+v", recorder.calls[0])
	}
	if string(recorder.body[0]) != string(request.Request) {
		t.Fatalf("projection body changed: %s", recorder.body[0])
	}
}

func TestModuleStartRunWithMessageUsesExistingConversationMessage(t *testing.T) {
	module := NewModule("secret")
	recorder := &recordingConversation{}
	module.SetConversationRecorder(recorder)
	scope := testScope("message-bound-run")
	runID, err := module.StartRunWithMessage(context.Background(), scope.domain(), scope.RunID, "idem-message-bound", "fp", "http://agent", []byte(`{"question":"project me"}`), "message-1")
	if err != nil || runID != scope.RunID {
		t.Fatalf("start run = %q, err=%v", runID, err)
	}
	if len(recorder.messageIDs) != 1 || recorder.messageIDs[0] != "message-1" {
		t.Fatalf("projected message IDs = %#v", recorder.messageIDs)
	}
}

func TestMachinePublicRunUsesTrustedTargetAndIsolatesRunOperations(t *testing.T) {
	module := NewModule("internal-platform-token")
	callerScope := sharedkernel.Scope{TenantID: "tenant-machine", DepartmentID: "dept-machine", ApplicationID: "app-machine",
		AgentInstanceID: "installation-validation", PrincipalID: "external-system", PrincipalType: "service_principal"}
	module.SetMachineAccessPorts(
		machineAuthenticatorFunc(func(_ context.Context, token, remote, action string) (MachineAccess, error) {
			if token != "machine-access-token" || remote != "127.0.0.1:12345" || action == "" {
				return MachineAccess{}, errors.New("invalid machine request")
			}
			return MachineAccess{Scope: callerScope, AuthorizationEpoch: 4}, nil
		}),
		machineTargetResolverFunc(func(_ context.Context, scope sharedkernel.Scope) (MachineAgentTarget, error) {
			if scope.TenantID != callerScope.TenantID || scope.AgentInstanceID != callerScope.AgentInstanceID {
				return MachineAgentTarget{}, errors.New("scope mismatch")
			}
			return MachineAgentTarget{AgentID: "example-agent", InstallationID: "installation-validation", VersionID: "version-7", InputSchemaURI: "schema://example-agent/input/v1", Endpoint: "http://validation-agent:8001", Revision: 7}, nil
		}),
	)
	setMachineRunPreparation(module)
	handler := module.Handler()
	start := httptest.NewRequest(http.MethodPost, "/agent-runs", strings.NewReader(`{"session_id":"external-session-a","idempotency_key":"external-idem-a","input":{"batch_id":"batch-a"}}`))
	start.Header.Set("Authorization", "Bearer machine-access-token")
	start.RemoteAddr = "127.0.0.1:12345"
	start.Header.Set("Content-Type", "application/json")
	started := httptest.NewRecorder()
	handler.ServeHTTP(started, start)
	if started.Code != http.StatusAccepted {
		t.Fatalf("machine start status=%d body=%s", started.Code, started.Body.String())
	}
	var created machineRunResponse
	if err := json.Unmarshal(started.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.RunID == "" || created.Status != string(platformruntime.StatusAccepted) || created.AgentVersionID != "version-7" {
		t.Fatalf("machine run response = %+v", created)
	}
	stored, err := module.store.Get(created.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Scope.PrincipalID != callerScope.PrincipalID || stored.Scope.PrincipalType != "service_principal" || stored.Scope.InstallationID != "installation-validation" {
		t.Fatalf("machine scope = %+v", stored.Scope)
	}
	if stored.AgentEndpoint != "http://validation-agent:8001" || stored.Scope.AgentID != "example-agent" || stored.Scope.AgentVersionID != "version-7" || stored.Scope.AuthorizationEpoch != 4 {
		t.Fatalf("machine run did not use the resolved target: %+v", stored)
	}
	var executeRequest contract.ExecuteRequest
	if err := json.Unmarshal(stored.RequestJSON, &executeRequest); err != nil {
		t.Fatal(err)
	}
	if executeRequest.ContextToken != strings.Repeat("s", 48) || executeRequest.Scope.AgentID != "example-agent" ||
		executeRequest.Scope.AgentVersionID != "version-7" || executeRequest.InputSchema != "schema://example-agent/input/v1" ||
		executeRequest.Input["batch_id"] != "batch-a" || executeRequest.Input["policy_snapshot"] == nil {
		t.Fatalf("platform did not create a trusted v2 envelope from business input: %+v", executeRequest)
	}
	startReplay := httptest.NewRequest(http.MethodPost, "/agent-runs", strings.NewReader(`{"session_id":"external-session-a","idempotency_key":"external-idem-a","input":{"batch_id":"batch-a"}}`))
	startReplay.Header.Set("Authorization", "Bearer machine-access-token")
	startReplay.RemoteAddr = "127.0.0.1:12345"
	startReplay.Header.Set("Content-Type", "application/json")
	replayResponse := httptest.NewRecorder()
	handler.ServeHTTP(replayResponse, startReplay)
	var replayed machineRunResponse
	if replayResponse.Code != http.StatusOK || json.Unmarshal(replayResponse.Body.Bytes(), &replayed) != nil || !replayed.Replayed || replayed.RunID != created.RunID {
		t.Fatalf("idempotent replay status=%d body=%s", replayResponse.Code, replayResponse.Body.String())
	}
	changedPayload := httptest.NewRequest(http.MethodPost, "/agent-runs", strings.NewReader(`{"session_id":"external-session-a","idempotency_key":"external-idem-a","input":{"batch_id":"different"}}`))
	changedPayload.Header.Set("Authorization", "Bearer machine-access-token")
	changedPayload.RemoteAddr = "127.0.0.1:12345"
	changedPayload.Header.Set("Content-Type", "application/json")
	conflict := httptest.NewRecorder()
	handler.ServeHTTP(conflict, changedPayload)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("idempotency payload mismatch status=%d body=%s", conflict.Code, conflict.Body.String())
	}

	get := httptest.NewRequest(http.MethodGet, "/agent-runs/"+created.RunID, nil)
	get.Header.Set("Authorization", "Bearer machine-access-token")
	get.RemoteAddr = "127.0.0.1:12345"
	got := httptest.NewRecorder()
	handler.ServeHTTP(got, get)
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), created.RunID) {
		t.Fatalf("machine get status=%d body=%s", got.Code, got.Body.String())
	}

	if _, err := module.store.AppendEvent(created.RunID, "task_completed", map[string]any{"ok": true}); err != nil {
		t.Fatal(err)
	}
	events := httptest.NewRequest(http.MethodGet, "/agent-runs/"+created.RunID+"/events?after_seq=0", nil)
	events.Header.Set("Authorization", "Bearer machine-access-token")
	events.RemoteAddr = "127.0.0.1:12345"
	eventResponse := httptest.NewRecorder()
	handler.ServeHTTP(eventResponse, events)
	if eventResponse.Code != http.StatusOK || eventResponse.Header().Get("Content-Type") != "text/event-stream" || !strings.Contains(eventResponse.Body.String(), "event: task_completed") {
		t.Fatalf("machine events status=%d headers=%v body=%s", eventResponse.Code, eventResponse.Header(), eventResponse.Body.String())
	}

	// A second machine identity may not use the first caller's Run ID.
	module.SetMachineAccessPorts(machineAuthenticatorFunc(func(context.Context, string, string, string) (MachineAccess, error) {
		other := callerScope
		other.PrincipalID = "different-external-system"
		return MachineAccess{Scope: other, AuthorizationEpoch: 1}, nil
	}), machineTargetResolverFunc(func(context.Context, sharedkernel.Scope) (MachineAgentTarget, error) {
		return MachineAgentTarget{}, errors.New("not needed")
	}))
	getOther := httptest.NewRequest(http.MethodGet, "/agent-runs/"+created.RunID, nil)
	getOther.Header.Set("Authorization", "Bearer other-token")
	getOther.RemoteAddr = "127.0.0.1:12345"
	otherResponse := httptest.NewRecorder()
	handler.ServeHTTP(otherResponse, getOther)
	if otherResponse.Code != http.StatusNotFound {
		t.Fatalf("cross-principal run read status=%d body=%s", otherResponse.Code, otherResponse.Body.String())
	}
}

func TestMachinePublicCancelAndResumeUseServerOwnedScope(t *testing.T) {
	module := NewModule("internal-platform-token")
	callerScope := sharedkernel.Scope{TenantID: "tenant-machine", DepartmentID: "dept-machine", ApplicationID: "app-machine",
		AgentInstanceID: "installation-qa", PrincipalID: "external-system", PrincipalType: "service_principal"}
	module.SetMachineAccessPorts(machineAuthenticatorFunc(func(_ context.Context, _, _, _ string) (MachineAccess, error) {
		return MachineAccess{Scope: callerScope, AuthorizationEpoch: 1}, nil
	}), machineTargetResolverFunc(func(_ context.Context, _ sharedkernel.Scope) (MachineAgentTarget, error) {
		return MachineAgentTarget{AgentID: "document-assistant", InstallationID: "installation-qa", VersionID: "version-1", InputSchemaURI: "schema://document-assistant/input/v1", Endpoint: "http://qa-agent:8002", Revision: 2}, nil
	}))
	setMachineRunPreparation(module)
	handler := module.Handler()
	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer machine-token")
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "127.0.0.1:6789"
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	start := post("/agent-runs", `{"session_id":"session-cancel","idempotency_key":"idem-cancel","input":{"question":"cancel me"}}`)
	if start.Code != http.StatusAccepted {
		t.Fatalf("start status=%d body=%s", start.Code, start.Body.String())
	}
	var cancelRun machineRunResponse
	if err := json.Unmarshal(start.Body.Bytes(), &cancelRun); err != nil {
		t.Fatal(err)
	}
	cancelled := post("/agent-runs/"+cancelRun.RunID+"/cancel", `{"expected_revision":1}`)
	if cancelled.Code != http.StatusOK || !strings.Contains(cancelled.Body.String(), `"status":"cancelled"`) {
		t.Fatalf("cancel status=%d body=%s", cancelled.Code, cancelled.Body.String())
	}

	start = post("/agent-runs", `{"session_id":"session-resume","idempotency_key":"idem-resume","input":{"question":"resume me"}}`)
	if start.Code != http.StatusAccepted {
		t.Fatalf("resume run start status=%d body=%s", start.Code, start.Body.String())
	}
	var resumeRun machineRunResponse
	if err := json.Unmarshal(start.Body.Bytes(), &resumeRun); err != nil {
		t.Fatal(err)
	}
	run, err := module.store.Get(resumeRun.RunID)
	if err != nil {
		t.Fatal(err)
	}
	run, err = module.store.Transition(run.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	lease, leaseErr := module.store.AcquireLease(run.ID, "non-review-lease", time.Now().UTC(), time.Minute)
	if leaseErr != nil {
		t.Fatal(leaseErr)
	}
	if _, err = module.store.FinalizeLeased(run.ID, platformruntime.StatusWaiting, lease.Revision, lease.LeaseToken, map[string]any{"stage": "waiting_input"}, map[string]any{"source": "fixture"}); err != nil {
		t.Fatal(err)
	}
	resumed := post("/agent-runs/"+resumeRun.RunID+"/resume", `{"input":{"approved":true}}`)
	if resumed.Code != http.StatusOK || !strings.Contains(resumed.Body.String(), `"status":"running"`) {
		t.Fatalf("resume status=%d body=%s", resumed.Code, resumed.Body.String())
	}
}

func TestMachinePublicRunRejectsClientSelectedTargetAndMissingPorts(t *testing.T) {
	module := NewModule("internal-token")
	request := httptest.NewRequest(http.MethodPost, "/agent-runs", strings.NewReader(`{"session_id":"s","idempotency_key":"i","input":{},"agent_endpoint":"http://attacker.invalid"}`))
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	module.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing machine ports status=%d body=%s", response.Code, response.Body.String())
	}

	callerScope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentInstanceID: "i", PrincipalID: "sp", PrincipalType: "service_principal"}
	module.SetMachineAccessPorts(machineAuthenticatorFunc(func(context.Context, string, string, string) (MachineAccess, error) {
		return MachineAccess{Scope: callerScope, AuthorizationEpoch: 1}, nil
	}), machineTargetResolverFunc(func(context.Context, sharedkernel.Scope) (MachineAgentTarget, error) {
		return MachineAgentTarget{AgentID: "agent", InstallationID: "i", VersionID: "v", InputSchemaURI: "schema://agent/input/v1", Endpoint: "http://agent:8000", Revision: 1}, nil
	}))
	request = httptest.NewRequest(http.MethodPost, "/agent-runs", strings.NewReader(`{"session_id":"s","idempotency_key":"i","input":{},"agent_endpoint":"http://attacker.invalid"}`))
	request.Header.Set("Authorization", "Bearer token")
	response = httptest.NewRecorder()
	module.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("client-selected target must be rejected status=%d body=%s", response.Code, response.Body.String())
	}
}

func testScope(runID string) scopeDTO {
	return scopeDTO{TenantID: "tenant", DepartmentID: "dept", ApplicationID: "app", AgentInstanceID: "instance", AgentID: "agent", PrincipalID: "user", PrincipalType: "user", InstallationID: "install", AgentVersionID: "v1", SessionID: "session", RunID: runID, AuthorizationEpoch: 1, TraceID: "0123456789abcdef0123456789abcdef"}
}

func doJSON(t *testing.T, handler http.Handler, method, path string, value any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func TestModuleCreateTransitionAndReplay(t *testing.T) {
	module := NewModule("secret")
	handler := module.Handler()
	headers := map[string]string{"Authorization": "Bearer secret"}
	scope := testScope("run-1")
	create := createRequest{RunID: "run-1", Scope: scope, AgentVersionID: "v1", IdempotencyKey: "idem-0001", Fingerprint: "fp"}
	response := doJSON(t, handler, http.MethodPost, "/platform/runs", create, headers)
	if response.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	response = doJSON(t, handler, http.MethodPost, "/platform/runs", createRequest{RunID: "run-2", Scope: testScope("run-2"), AgentVersionID: "v1", IdempotencyKey: "idem-0001", Fingerprint: "fp"}, headers)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"replayed":true`)) {
		t.Fatalf("replay status=%d body=%s", response.Code, response.Body.String())
	}
	response = doJSON(t, handler, http.MethodPost, "/platform/runs/run-1/transition", transitionRequest{Scope: scope, From: "accepted", To: "running", ExpectedRevision: 1}, headers)
	if response.Code != http.StatusOK {
		t.Fatalf("transition status=%d body=%s", response.Code, response.Body.String())
	}
	event := doJSON(t, handler, http.MethodPost, "/platform/runs/run-1/events", eventRequest{Scope: scope, EventType: "progress", Payload: map[string]any{"stage": "unit"}}, headers)
	if event.Code != http.StatusOK || !bytes.Contains(event.Body.Bytes(), []byte(`"event_type":"progress"`)) {
		t.Fatalf("append event status=%d body=%s", event.Code, event.Body.String())
	}
}

func TestModuleRejectsForgedScopeAndMalformedJSON(t *testing.T) {
	module := NewModule("secret")
	handler := module.Handler()
	response := doJSON(t, handler, http.MethodPost, "/platform/runs", createRequest{RunID: "run-1", Scope: testScope("run-1"), AgentVersionID: "v1", IdempotencyKey: "idem-0001", Fingerprint: "fp"}, map[string]string{"Authorization": "Bearer wrong"})
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("auth status=%d", response.Code)
	}
	created := doJSON(t, handler, http.MethodPost, "/platform/runs", createRequest{RunID: "run-1", Scope: testScope("run-1"), AgentVersionID: "v1", IdempotencyKey: "idem-0001", Fingerprint: "fp"}, map[string]string{"Authorization": "Bearer secret"})
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	get := httptest.NewRequest(http.MethodGet, "/platform/runs/run-1", nil)
	get.Header.Set("Authorization", "Bearer secret")
	get.Header.Set("X-Tenant-ID", "other")
	get.Header.Set("X-Department-ID", "dept")
	get.Header.Set("X-Application-ID", "app")
	get.Header.Set("X-Agent-Instance-ID", "instance")
	get.Header.Set("X-Principal-ID", "user")
	get.Header.Set("X-Installation-ID", "")
	get.Header.Set("X-Agent-Version-ID", "")
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, get)
	if result.Code != http.StatusNotFound {
		t.Fatalf("forged scope status=%d body=%s", result.Code, result.Body.String())
	}
	malformed := httptest.NewRequest(http.MethodPost, "/platform/runs", bytes.NewBufferString("{} extra"))
	malformed.Header.Set("Authorization", "Bearer secret")
	result = httptest.NewRecorder()
	handler.ServeHTTP(result, malformed)
	if result.Code != http.StatusBadRequest {
		t.Fatalf("malformed status=%d body=%s", result.Code, result.Body.String())
	}
}

func TestModuleLifecycle(t *testing.T) {
	module := NewModule("")
	if err := module.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := module.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestModuleResumableSSEReadsDurableEvents(t *testing.T) {
	module := NewModule("secret")
	scope := testScope("sse-run")
	created := doJSON(t, module.Handler(), http.MethodPost, "/platform/runs", createRequest{RunID: "sse-run", Scope: scope, AgentVersionID: "v1", IdempotencyKey: "idem-sse", Fingerprint: "fp"}, map[string]string{"Authorization": "Bearer secret"})
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d", created.Code)
	}
	if _, err := module.store.AppendEvent("sse-run", "task_completed", map[string]any{"ok": true}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/platform/runs/sse-run/events?after_seq=0", nil)
	request.Header.Set("Authorization", "Bearer secret")
	for key, value := range map[string]string{
		"X-Tenant-ID": scope.TenantID, "X-Department-ID": scope.DepartmentID, "X-Application-ID": scope.ApplicationID,
		"X-Agent-Instance-ID": scope.AgentInstanceID, "X-Agent-ID": scope.AgentID, "X-Principal-ID": scope.PrincipalID,
		"X-Principal-Type": scope.PrincipalType, "X-Installation-ID": scope.InstallationID, "X-Agent-Version-ID": scope.AgentVersionID,
		"X-Session-ID": scope.SessionID, "X-Authorization-Epoch": "1", "X-Trace-ID": scope.TraceID,
	} {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	module.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/event-stream" || !bytes.Contains(response.Body.Bytes(), []byte("event: task_completed")) {
		t.Fatalf("sse response status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	for _, test := range []struct {
		query  string
		status int
	}{
		{"", http.StatusOK}, {"after_seq=invalid", http.StatusBadRequest}, {"after_seq=-1", http.StatusBadRequest},
	} {
		probe := request.Clone(context.Background())
		probe.URL.RawQuery = test.query
		recorder := httptest.NewRecorder()
		module.Handler().ServeHTTP(recorder, probe)
		if recorder.Code != test.status {
			t.Fatalf("cursor %q status=%d expected=%d", test.query, recorder.Code, test.status)
		}
		if test.status == http.StatusOK && !strings.Contains(recorder.Body.String(), "event: task_completed") {
			t.Fatal("default cursor lost durable events")
		}
	}
}

func TestModuleResumeAtomicallyEnqueuesWaitingRun(t *testing.T) {
	module := NewModule("secret")
	created := doJSON(t, module.Handler(), http.MethodPost, "/platform/runs", createRequest{
		RunID: "resume-module", Scope: testScope("resume-module"), AgentVersionID: "v1", IdempotencyKey: "idem-resume-module", Fingerprint: "fp",
		Request: json.RawMessage(`{"protocol_version":"agent-execution/v2","operation":"run","context_token":"ctx-token"}`),
	}, map[string]string{"Authorization": "Bearer secret"})
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	run, err := module.store.Get("resume-module")
	if err != nil {
		t.Fatal(err)
	}
	run, err = module.store.Transition(run.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	run, err = module.store.Transition(run.ID, platformruntime.StatusRunning, platformruntime.StatusWaiting, run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	scope := testScope("resume-module")
	response := doJSON(t, module.Handler(), http.MethodPost, "/platform/runs/resume-module/resume", resumeRequest{Scope: scope, Input: map[string]any{"approved": true}}, map[string]string{"Authorization": "Bearer secret"})
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"status":"running"`)) {
		t.Fatalf("resume status=%d body=%s", response.Code, response.Body.String())
	}
	updated, err := module.store.Get("resume-module")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != platformruntime.StatusRunning || len(updated.ResumeInputJSON) == 0 || bytes.Contains(updated.RequestJSON, []byte(`"operation":"resume"`)) {
		t.Fatalf("resume was not persisted: %+v", updated)
	}
	replayed := doJSON(t, module.Handler(), http.MethodPost, "/platform/runs/resume-module/resume", resumeRequest{Scope: scope, Input: map[string]any{"approved": true}}, map[string]string{"Authorization": "Bearer secret"})
	if replayed.Code != http.StatusOK || !bytes.Contains(replayed.Body.Bytes(), []byte(`"replayed":true`)) {
		t.Fatalf("identical resume was not replayed: status=%d body=%s", replayed.Code, replayed.Body.String())
	}
	changed := doJSON(t, module.Handler(), http.MethodPost, "/platform/runs/resume-module/resume", resumeRequest{Scope: scope, Input: map[string]any{"approved": false}}, map[string]string{"Authorization": "Bearer secret"})
	if changed.Code != http.StatusConflict {
		t.Fatalf("changed resume was admitted: status=%d body=%s", changed.Code, changed.Body.String())
	}
	latest, err := module.store.Get("resume-module")
	if err != nil || latest.Revision != updated.Revision {
		t.Fatalf("resume replay changed durable revision: %+v, %v", latest, err)
	}
}

func TestModuleCancelWithoutSignedStopTransportRemainsPending(t *testing.T) {
	// The transport blocks until its request context is cancelled. / 传输层阻塞到
	// 请求上下文被取消，验证平台取消不会留下成功状态。
	store := platformruntime.NewStore()
	dispatcher := NewDispatcher(store, "token", 1)
	dispatcher.client.Transport = blockingRoundTripper{}
	module := NewModuleWithDispatcher("token", store, dispatcher)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dispatcher.Start(ctx)

	scopeDTO := testScope("cancel-run")
	scope := scopeDTO.domain()
	request := platformruntime.CreateRequest{ID: scope.RunID, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: "cancel-idem", Fingerprint: "cancel-fingerprint", RequestJSON: gatewayRequest(t, scopeDTO, "invoke"), AgentEndpoint: "http://agent.invalid"}
	created, err := store.Create(request)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Enqueue(created.Run)
	deadline := time.Now().Add(time.Second)
	for {
		current, getErr := store.Get(scope.RunID)
		if getErr == nil && current.Status == platformruntime.StatusRunning && current.LeaseToken != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dispatcher did not claim run: %+v", current)
		}
		time.Sleep(10 * time.Millisecond)
	}

	body, _ := json.Marshal(map[string]any{"scope": scopeDTO, "expected_revision": 0})
	req := httptest.NewRequest(http.MethodPost, "/platform/runs/cancel-run/cancel", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")
	for key, value := range map[string]string{
		"X-Tenant-ID": scopeDTO.TenantID, "X-Department-ID": scopeDTO.DepartmentID, "X-Application-ID": scopeDTO.ApplicationID,
		"X-Agent-Instance-ID": scopeDTO.AgentInstanceID, "X-Agent-ID": scopeDTO.AgentID, "X-Principal-ID": scopeDTO.PrincipalID,
		"X-Principal-Type": scopeDTO.PrincipalType, "X-Installation-ID": scopeDTO.InstallationID, "X-Agent-Version-ID": scopeDTO.AgentVersionID,
		"X-Session-ID": scopeDTO.SessionID, "X-Authorization-Epoch": "1", "X-Trace-ID": scopeDTO.TraceID,
	} {
		req.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	module.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected unconfirmed cancel 202, got %d: %s", recorder.Code, recorder.Body.String())
	}
	run, err := store.Get(scope.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != platformruntime.StatusCancelling || run.LeaseToken == "" {
		t.Fatalf("expected cancelling with retained lease, got %s", run.Status)
	}
	events, err := store.Events(scope.RunID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 2 || events[len(events)-1].Type != "cancel_requested" {
		t.Fatalf("expected durable cancel_requested event, got %#v", events)
	}
	cancel()
	dispatcher.Close(context.Background())
}

func TestModuleCancelIsIdempotentAndKeepsStatusAndAuditTogether(t *testing.T) {
	module := NewModule("secret")
	handler := module.Handler()
	scope := testScope("cancel-idempotent")
	created := doJSON(t, handler, http.MethodPost, "/platform/runs", createRequest{
		RunID: "cancel-idempotent", Scope: scope, AgentVersionID: "v1", IdempotencyKey: "idem-cancel-idempotent", Fingerprint: "fp",
	}, map[string]string{"Authorization": "Bearer secret"})
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	body, _ := json.Marshal(cancelRequest{Scope: scope, ExpectedRevision: 0})
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/platform/runs/cancel-idempotent/cancel", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer secret")
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("cancel %d status=%d body=%s", i, response.Code, response.Body.String())
		}
	}
	run, err := module.store.Get(scope.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != platformruntime.StatusCancelled || run.Revision != 3 {
		t.Fatalf("unexpected cancelled run: %+v", run)
	}
	events, err := module.store.Events(scope.RunID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 || events[1].Type != "cancel_requested" || events[2].Type != "status" || events[3].Type != "task_cancelled" {
		t.Fatalf("expected one atomic status/audit pair, got %#v", events)
	}
}

type blockingRoundTripper struct{}

func (blockingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	<-request.Context().Done()
	return nil, request.Context().Err()
}
