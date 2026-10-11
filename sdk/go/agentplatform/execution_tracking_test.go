package agentplatform

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func trackingGeneration(t *testing.T, kit *fixtureKit, request ExecuteRequest, revision uint64, leaseHash ...string) ExecuteRequest {
	t.Helper()
	request.ContextToken = signExecute(t, kit.private, "platform-runtime-gateway", "sdk-test-agent", request.Operation, request, kit.now)
	parts := strings.Split(request.ContextToken, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(raw, &claims)
	claims["execution_revision"] = revision
	claims["lease_token_hash"] = strings.Repeat("b", 64)
	if len(leaseHash) > 0 {
		claims["lease_token_hash"] = leaseHash[0]
	}
	request.ContextToken = signToken(t, kit.private, claims)
	return request
}

func trackingPost(t *testing.T, server *httptest.Server, path string, request ExecuteRequest) (int, ExecuteResponse) {
	status, response, _ := trackingPostWithErrorCode(t, server, path, request)
	return status, response
}

func trackingPostWithErrorCode(t *testing.T, server *httptest.Server, path string, request ExecuteRequest) (int, ExecuteResponse, string) {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	httpRequest, _ := http.NewRequest(http.MethodPost, server.URL+path, bytes.NewReader(raw))
	httpRequest.Header.Set("Authorization", "Bearer "+request.ContextToken)
	response, err := server.Client().Do(httpRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode >= http.StatusBadRequest {
		var apiError AppError
		if err := json.Unmarshal(body, &apiError); err == nil {
			return response.StatusCode, ExecuteResponse{}, apiError.Code
		}
		return response.StatusCode, ExecuteResponse{}, "unreadable_error_body"
	}
	var decoded ExecuteResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, decoded, ""
}

func TestResumeDoesNotDuplicateStartedLifecycleEvent(t *testing.T) {
	var calls atomic.Int32
	kit := newFixtureServer(t, []string{"run", "resume", "cancel", "events"}, func(_ context.Context, request ExecuteRequest, _ EventSink, _ <-chan struct{}) (map[string]any, error) {
		if calls.Add(1) == 1 {
			return nil, &HarnessPause{Key: "approval-1", ToolName: "example.skill", CallID: "call-1"}
		}
		handoff, ok := request.ResumeInput["handler_handoff"].(map[string]any)
		return map[string]any{"resumed": ok && request.ResumeInput["decision"] == "approve" &&
			handoff["run_id"] == request.Scope.RunID && handoff["harness_key"] == "approval-1" &&
			handoff["tool_name"] == "example.skill" && handoff["call_id"] == "call-1"}, nil
	})
	defer kit.server.Close()

	run := trackingGeneration(t, kit, kit.executeRequest(t, "resume-started-run", "run", "resume-started-idem"), 1)
	if code, _ := trackingPost(t, kit.server, "/internal/agent-execution/v2/runs", run); code != http.StatusAccepted {
		t.Fatalf("run was not accepted: %d", code)
	}
	waitForStatus(t, kit.store, run.Scope.RunID, RunStatusWaiting)

	waiting, ok := kit.store.GetRun(run.Scope.RunID)
	if !ok || countLifecycleEvent(waiting.Events, EventStarted) != 1 {
		t.Fatalf("fresh generation should have one started event: %+v", waiting.Events)
	}
	handoff := waitForParkedHandlerHandoff(t, kit.execution, run.Scope.RunID)
	resume := kit.executeRequest(t, run.Scope.RunID, "resume", run.IdempotencyKey)
	resume.ResumeInput["handler_handoff"] = handoff
	resume = trackingGeneration(t, kit, resume, 2, strings.Repeat("c", 64))
	if code, response, errorCode := trackingPostWithErrorCode(t, kit.server, "/internal/agent-execution/v2/runs/"+run.Scope.RunID+"/resume", resume); code != http.StatusAccepted || response.Status != "running" {
		t.Fatalf("resume was not accepted: status=%d error_code=%s response=%+v", code, errorCode, response)
	}
	waitForStatus(t, kit.store, run.Scope.RunID, RunStatusSucceeded)

	completed, ok := kit.store.GetRun(run.Scope.RunID)
	if !ok || countLifecycleEvent(completed.Events, EventStarted) != 2 {
		t.Fatalf("resume generation must add exactly one started event: %+v", completed.Events)
	}
	if completed.Output["resumed"] != true {
		t.Fatalf("RunHandler did not receive the current controlled handoff: %+v", completed.Output)
	}
	lastStarted := lastLifecycleEvent(completed.Events, EventStarted)
	if operation, _ := lastStarted.Payload["operation"].(string); operation != "resume" {
		t.Fatalf("resumed generation marker was not preserved: %+v", lastStarted.Payload)
	}
}

func waitForParkedHandlerHandoff(t *testing.T, server *ExecutionServer, runID string) *HandlerHandoff {
	t.Helper()
	server.activeMu.Lock()
	active := server.active[runID]
	parked := active != nil && active.parked
	var done <-chan struct{}
	if active != nil {
		done = active.done
	}
	server.activeMu.Unlock()
	if !parked {
		t.Fatal("waiting projection did not have a supervised parked execution")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("parked RunHandler did not produce an observed exit")
	}
	handoff := server.handlerHandoff(active, runID)
	if handoff == nil {
		t.Fatal("current handler-exit handoff could not be verified")
	}
	return handoff
}

func countLifecycleEvent(events []ExecutionEvent, eventType string) int {
	count := 0
	for _, event := range events {
		if event.EventType == eventType {
			count++
		}
	}
	return count
}

func lastLifecycleEvent(events []ExecutionEvent, eventType string) ExecutionEvent {
	for index := len(events) - 1; index >= 0; index-- {
		if events[index].EventType == eventType {
			return events[index]
		}
	}
	return ExecutionEvent{}
}

// A handler deliberately lingers after observing cancellation. A stop receipt
// must wait for actual exit, for both synchronous invoke and asynchronous run.
func TestExecutionCancellationRequiresHandlerExit(t *testing.T) {
	for _, operation := range []string{"invoke", "run"} {
		t.Run(operation, func(t *testing.T) {
			started, observed, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			handler := func(ctx context.Context, _ ExecuteRequest) (map[string]any, error) {
				calls.Add(1)
				close(started)
				<-ctx.Done()
				close(observed)
				<-release
				return map[string]any{"must_not_publish": true}, nil
			}
			kit := newFixtureServer(t, []string{"invoke", "run", "resume", "cancel", "events"}, func(ctx context.Context, request ExecuteRequest, _ EventSink, _ <-chan struct{}) (map[string]any, error) {
				return handler(ctx, request)
			})
			defer kit.server.Close()
			kit.execution.cfg.Invoke = handler
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			request := trackingGeneration(t, kit, kit.executeRequest(t, "tracked-run", operation, "tracked-idem"), 7)
			path := "/internal/agent-execution/v2/invoke"
			if operation == "run" {
				path = "/internal/agent-execution/v2/runs"
			}
			invokeDone := make(chan ExecuteResponse, 1)
			go func() { _, response := trackingPost(t, kit.server, path, request); invokeDone <- response }()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("handler did not start")
			}
			cancelRequest := trackingGeneration(t, kit, kit.executeRequest(t, "tracked-run", "cancel", "cancel-idem"), 7)
			cancelPath := "/internal/agent-execution/v2/runs/tracked-run/cancel"
			foreign := cancelRequest
			foreign.Scope.PrincipalID = "other-user"
			foreign = trackingGeneration(t, kit, foreign, 7)
			if code, _ := trackingPost(t, kit.server, cancelPath, foreign); code != 409 {
				t.Fatalf("foreign signed scope allowed: %d", code)
			}
			wrongGeneration := trackingGeneration(t, kit, cancelRequest, 8)
			if code, _ := trackingPost(t, kit.server, cancelPath, wrongGeneration); code != 409 {
				t.Fatalf("foreign generation allowed: %d", code)
			}
			wrongLease := trackingGeneration(t, kit, cancelRequest, 7, strings.Repeat("c", 64))
			if code, _ := trackingPost(t, kit.server, cancelPath, wrongLease); code != 409 {
				t.Fatalf("foreign lease allowed: %d", code)
			}
			changed := request
			changed.Input = map[string]any{"policy_snapshot": map[string]any{"content_hash": "snapshot-hash"}, "business": "changed"}
			changed = trackingGeneration(t, kit, changed, 7)
			if code, _ := trackingPost(t, kit.server, path, changed); code != 409 {
				t.Fatalf("same key accepted changed input: %d", code)
			}
			if code, response := trackingPost(t, kit.server, cancelPath, cancelRequest); code != 202 || response.Status != "cancelling" {
				t.Fatalf("premature stop receipt: %d %+v", code, response)
			}
			select {
			case <-observed:
			case <-time.After(2 * time.Second):
				t.Fatal("handler context not cancelled")
			}
			if kit.execution.executionExited(request.Scope) {
				t.Fatal("handler still alive but claimed exited")
			}
			if code, response := trackingPost(t, kit.server, path, request); code != 202 || response.Status != "running" {
				t.Fatalf("in-flight replay exposed terminal state: %d %+v", code, response)
			}
			// SSE must not turn store cancellation intent into a completion proof.
			eventRequest := EventRequest{ProtocolVersion: ProtocolVersion, Scope: request.Scope, PolicySnapshotHash: "snapshot-hash"}
			eventRequest.ContextToken = signEvent(t, kit.private, "platform-runtime-gateway", "sdk-test-agent", eventRequest, kit.now)
			eventBody, _ := json.Marshal(eventRequest)
			eventHTTP, _ := http.NewRequest(http.MethodPost, kit.server.URL+"/internal/agent-execution/v2/runs/tracked-run/events", bytes.NewReader(eventBody))
			eventHTTP.Header.Set("Authorization", "Bearer "+eventRequest.ContextToken)
			eventResponse, err := kit.server.Client().Do(eventHTTP)
			if err != nil {
				t.Fatal(err)
			}
			events, _ := io.ReadAll(eventResponse.Body)
			eventResponse.Body.Close()
			if bytes.Contains(events, []byte("event: cancelled")) {
				t.Fatal("SSE claimed stop before handler exit")
			}
			close(release)
			deadline := time.Now().Add(2 * time.Second)
			for !kit.execution.executionExited(request.Scope) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if !kit.execution.executionExited(request.Scope) {
				t.Fatal("exit barrier not released")
			}
			if code, response := trackingPost(t, kit.server, cancelPath, cancelRequest); code != 202 || response.Status != "cancelled" {
				t.Fatalf("stop not acknowledged after exit: %d %+v", code, response)
			}
			if calls.Load() != 1 {
				t.Fatalf("replay executed handler %d times", calls.Load())
			}
			original := <-invokeDone
			if operation == "invoke" && (original.Status != "cancelled" || original.Output != nil) {
				t.Fatalf("cancelled invoke published result: %+v", original)
			}
			// A new process cannot infer an exit proof from a retained record.
			restarted, err := NewExecutionServer(kit.execution.cfg)
			if err != nil {
				t.Fatal(err)
			}
			restartedHTTP := httptest.NewServer(restarted.Handler())
			defer restartedHTTP.Close()
			if code, _ := trackingPost(t, restartedHTTP, cancelPath, cancelRequest); code != 409 {
				t.Fatalf("restart fabricated stop receipt: %d", code)
			}
		})
	}
}

func TestStopAuthorityDoesNotReturnBusinessOutput(t *testing.T) {
	kit := newFixtureServer(t, []string{"invoke", "cancel"}, nil)
	defer kit.server.Close()
	request := trackingGeneration(t, kit, kit.executeRequest(t, "completed-run", "invoke", "completed-idem"), 1)
	if code, response := trackingPost(t, kit.server, "/internal/agent-execution/v2/invoke", request); code != 200 || response.Output == nil {
		t.Fatalf("business invoke did not complete: %d %+v", code, response)
	}
	cancelRequest := trackingGeneration(t, kit, kit.executeRequest(t, "completed-run", "cancel", "stop-idem"), 1)
	if code, response := trackingPost(t, kit.server, "/internal/agent-execution/v2/runs/completed-run/cancel", cancelRequest); code != 202 || response.Status != "cancelled" || response.Output != nil {
		t.Fatalf("stop control exposed business output: %d %+v", code, response)
	}
}
