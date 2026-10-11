package agentplatform

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAgentGroupResumeDoesNotReleaseBeforeBoundGather(t *testing.T) {
	binding := &agentGroupResumeBinding{groupKey: "original", operationKey: "original-operation", childKeys: []string{strings.Repeat("a", 64)}}
	client := &CapabilityClient{}
	client.setAgentGroupResumeBinding(binding)
	if client.consumeAgentGroupResume(binding) || client.hasConsumedAgentGroupResume() {
		t.Fatal("continuation released without the original Gather")
	}
	wrong := *binding
	wrong.operationKey = "other-operation"
	if client.allowAgentGroupGather(&wrong) || client.agentGroupResumeAllowsPostLocked("/internal/model/generate", map[string]any{}) {
		t.Fatal("unbound Gather or model request escaped the fence")
	}
	if !client.allowAgentGroupGather(binding) || !client.agentGroupResumeAllowsPostLocked("/internal/agent/gather", map[string]any{"operation_key": binding.operationKey}) {
		t.Fatal("bound original Gather was denied")
	}
	if client.agentGroupResumeAllowsPostLocked("/internal/agent/gather", map[string]any{"operation_key": binding.operationKey}) ||
		client.agentGroupResumeAllowsPostLocked("/internal/model/generate", map[string]any{}) {
		t.Fatal("Gather permit allowed a replay or early disclosure")
	}
	if !client.consumeAgentGroupResume(binding) || client.currentAgentGroupResumeBinding() != nil || !client.hasConsumedAgentGroupResume() {
		t.Fatal("verified terminal Gather did not consume the one-shot fence")
	}
}

func TestAgentGroupResumeDiagnosticsOmitUntrustedErrorDetails(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	defer slog.SetDefault(previous)
	logAgentGroupResumeRejection("diagnostic-run", "original_gather", &AppError{Code: "SECRET-IN-CODE", Message: "SECRET-IN-MESSAGE"})
	if strings.Contains(output.String(), "SECRET") || !strings.Contains(output.String(), "UNCLASSIFIED") {
		t.Fatal("diagnostic emitted untrusted error details")
	}
	output.Reset()
	logAgentGroupResumeRejection("diagnostic-run", "checkpoint_readback", &AppError{Code: "STATE_AUTHORITY_DENIED", Message: "SECRET-IN-MESSAGE"})
	if strings.Contains(output.String(), "SECRET") || !strings.Contains(output.String(), "STATE_AUTHORITY_DENIED") {
		t.Fatal("diagnostic did not preserve only the known failure category")
	}
}

// Exercise the transport, waiting ledger, checkpoint readback and original
// Gather together, including the fresh ACL read immediately before disclosure.
func TestAgentGroupResumeThenFreshGather(t *testing.T) {
	kit := newFixtureServer(t, []string{"invoke", "resume", "cancel", "events"}, nil)
	defer kit.server.Close()
	request := kit.executeRequest(t, "group-resume-run", "invoke", "group-resume-idem")
	request.Scope.SessionID = "group-resume-session"
	policy := request.Input["policy_snapshot"].(map[string]any)
	for _, key := range []string{"model_profile_id", "prompt_version_id", "tool_policy_id", "memory_policy_id", "knowledge_policy_id", "runtime_policy_id"} {
		policy[key] = key + "-v1"
	}
	request = trackingGeneration(t, kit, request, 3)
	businessHash, err := executionBusinessHash(request)
	if err != nil {
		t.Fatal(err)
	}
	options := AgentGroupOptions{Key: "documents-collaboration", OperationKey: "diagnosis-documents", TaskType: "documents.answer"}
	inputs := []map[string]any{{"question": "Find published documentation"}}
	inputHash, err := AgentGroupPlanInputHash(options.OperationKey, options.TaskType, inputs)
	if err != nil {
		t.Fatal(err)
	}
	childKey := strings.Repeat("d", 64)
	state := agentGroupState{
		Version: "agent-group/v1", ParentRunID: request.Scope.RunID, GroupKey: options.Key,
		OperationKey: options.OperationKey, InputFingerprint: businessHash, InputHash: inputHash,
		Phase: "gather", Ordinal: 1,
		Targets:   []agentGroupTarget{{"schema://documents/input/v1", "schema://documents/output/v1"}},
		Bindings:  []agentGroupBinding{{childKey, strings.Repeat("e", 64), "schema://documents/output/v1"}},
		ChildKeys: []string{childKey},
	}
	stateKey, _ := expectedAgentGroupStateKey(request.Scope, options.Key)
	expires := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Microsecond)
	reference := AgentGroupCheckpointReference{StateKey: stateKey, Revision: 4, SchemaID: AgentGroupStateSchema,
		ContentHash: strings.Repeat("a", 64), ExecutionRevision: 3, ExpiresAt: expires}
	checkpoints := []runtimeRecoveryCheckpoint{
		{StateKey: strings.Repeat("1", 64), Revision: 1, SchemaID: "schema://example/evidence/v1", ContentHash: strings.Repeat("f", 64), ExecutionRevision: 3, ExpiresAt: expires},
		{StateKey: stateKey, Revision: reference.Revision, SchemaID: reference.SchemaID, ContentHash: reference.ContentHash, ExecutionRevision: 3, ExpiresAt: expires},
		{StateKey: strings.Repeat("2", 64), Revision: 1, SchemaID: "schema://example/collaboration/v1", ContentHash: strings.Repeat("b", 64), ExecutionRevision: 3, ExpiresAt: expires},
	}
	sort.Slice(checkpoints, func(i, j int) bool { return checkpoints[i].StateKey < checkpoints[j].StateKey })
	responses := map[string]map[string]any{}
	for _, cp := range checkpoints {
		value := map[string]any{"version": "fixture/v1"}
		if cp.StateKey == stateKey {
			if err := groupDecode(state, &value); err != nil {
				t.Fatal(err)
			}
		}
		responses[cp.StateKey] = map[string]any{"state_key": cp.StateKey, "checkpoint": map[string]any{
			"revision": cp.Revision, "schema_id": cp.SchemaID, "value": value,
			"content_hash": cp.ContentHash, "execution_revision": cp.ExecutionRevision, "expires_at": cp.ExpiresAt.Format(time.RFC3339Nano),
		}}
	}
	var gathers, checkpointReads, renewalReads atomic.Int32
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var envelope struct {
			Input map[string]any `json:"input"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.UseNumber()
		if decoder.Decode(&envelope) != nil {
			t.Error("invalid capability envelope")
			w.WriteHeader(400)
			return
		}
		var data any
		switch r.URL.Path {
		case "/internal/context/renew":
			renewalReads.Add(1)
			data = map[string]any{"context_token": strings.TrimPrefix(r.Header.Get("X-Platform-Context"), "Bearer ")}
		case "/internal/state/checkpoint":
			checkpointReads.Add(1)
			if cp, ok := envelope.Input["reference"].(map[string]any); ok {
				data = responses[cp["state_key"].(string)]
			} else if envelope.Input["namespace"] == "coordination" && envelope.Input["key"] == options.Key {
				data = responses[stateKey]
			}
		case "/internal/agent/gather":
			gathers.Add(1)
			data = map[string]any{"group": map[string]any{
				"version": "agent-group-result/v1", "parent_run_id": request.Scope.RunID, "operation_key": options.OperationKey,
				"status": "completed", "terminal": true, "outputs_complete": true, "completed": 1,
				"failed": 0, "cancelled": 0, "pending": 0, "outputs_omitted": 0, "instruction_trust": "untrusted_data",
				"children": []any{map[string]any{
					"version": "agent-child-result/v1", "parent_run_id": request.Scope.RunID, "operation_key": options.OperationKey,
					"child_run_id": "child-" + childKey[:48], "child_key": childKey, "ordinal": 0,
					"status": "completed", "execution_revision": 4, "output_schema": "schema://documents/output/v1",
					"output": map[string]any{"answer": "Published documentation"}, "output_bytes": 36,
					"output_omitted": false, "output_digest": strings.Repeat("c", 64), "instruction_trust": "untrusted_data",
				}},
			}}
		default:
			t.Errorf("unexpected side-effecting capability path: %s", r.URL.Path)
		}
		if data == nil {
			w.WriteHeader(403)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	defer platform.Close()
	kit.execution.cfg.Capability = &CapabilityConfig{BaseURL: platform.URL, InternalToken: "fixture-internal", SigningSecret: "fixture-signing"}
	kit.execution.cfg.Invoke = func(ctx context.Context, current ExecuteRequest) (map[string]any, error) {
		if current.Operation == "invoke" {
			return nil, newAgentGroupPause(options.Key, options.OperationKey, reference, []string{childKey})
		}
		client, ok := CapabilityFromContext(ctx)
		if !ok {
			t.Fatal("missing capability client")
		}
		if _, err := client.RunAgentGroup(ctx, inputs, options); err != nil {
			t.Errorf("original Gather failed: %v", err)
			return nil, err
		}
		if _, err := client.RunAgentGroup(ctx, inputs, options); err != nil {
			t.Errorf("fresh ACL Gather after consumed continuation failed: %v", err)
			return nil, err
		}
		return map[string]any{"gathered": true}, nil
	}
	status, waiting, code := trackingPostWithErrorCode(t, kit.server, "/internal/agent-execution/v2/invoke", request)
	if status != 200 || waiting.Status != "waiting" || waiting.AgentGroupHandoff == nil {
		t.Fatalf("original invocation did not park: status=%d code=%s", status, code)
	}
	resume := request
	resume.Operation = "resume"
	if err := groupDecode(agentGroupResumeCommand{Version: agentGroupResumeVersion, OriginOperation: "invoke", WaitingRevision: 4,
		Handoff: *waiting.AgentGroupHandoff, Checkpoints: checkpoints}, &resume.ResumeInput); err != nil {
		t.Fatal(err)
	}
	resume = trackingGeneration(t, kit, resume, 6, strings.Repeat("c", 64))
	status, result, code := trackingPostWithErrorCode(t, kit.server, "/internal/agent-execution/v2/runs/"+request.Scope.RunID+"/resume", resume)
	if status != 200 || result.Status != "succeeded" || result.Output["gathered"] != true {
		t.Fatalf("resume and fresh disclosure were not completed: status=%d code=%s checkpoint_reads=%d renewals=%d gathers=%d", status, code, checkpointReads.Load(), renewalReads.Load(), gathers.Load())
	}
	if checkpointReads.Load() != 5 || renewalReads.Load() != 2 || gathers.Load() != 2 {
		t.Fatalf("expected three exact-reference checks and two freshly authorized Gathers: checkpoint_reads=%d renewals=%d gathers=%d", checkpointReads.Load(), renewalReads.Load(), gathers.Load())
	}
}
