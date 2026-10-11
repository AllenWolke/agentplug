package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type approvedResumeCheckpointFixture struct {
	head      capability.Checkpoint
	history   capability.Checkpoint
	requested []uint64
}

func (f *approvedResumeCheckpointFixture) Load(_ context.Context, _ sharedkernel.Scope, _, _, _ string, revision uint64) (capability.Checkpoint, bool, error) {
	f.requested = append(f.requested, revision)
	if revision == 0 {
		return f.head, true, nil
	}
	if revision == f.history.Revision {
		return f.history, true, nil
	}
	return capability.Checkpoint{}, false, nil
}

func (*approvedResumeCheckpointFixture) Save(context.Context, capability.StateWrite, func(context.Context) error) (capability.Checkpoint, error) {
	return capability.Checkpoint{}, errors.New("unused")
}

func TestApprovedResumeRenewalUsesHistoricalCheckpointAfterHeadAdvances(t *testing.T) {
	scope := sharedkernel.Scope{PrincipalType: "user", PrincipalID: "owner", InstallationID: "install", RunID: "resume-run"}
	payload := map[string]any{"timezone": "UTC"}
	fingerprint, err := capability.ToolCommandFingerprint("clock.now", payload)
	if err != nil {
		t.Fatal(err)
	}
	claims := capability.ToolConfirmationClaims{Version: "tool-confirmation/v1", ApprovalID: "approval-1", ActorID: scope.PrincipalID,
		PolicyHash: "policy-hash", ToolName: "clock.now", CallID: "call-1", Fingerprint: fingerprint,
		IssuedAt: 100, ExpiresAt: 200, PendingKey: "harness", CheckpointRevision: 2}
	state := map[string]any{"version": "harness-loop/v1", "phase": "approval_required", "pending": []any{map[string]any{
		"name": "clock.now", "call_id": "call-1", "payload": payload, "model_call_id": "model-call-1", "run_id": scope.RunID,
	}}}
	history := capability.Checkpoint{Revision: 2, SchemaID: "schema://agentplug/harness-loop/v1", Value: state,
		ContentHash: "original-checkpoint-hash", ExpiresAt: time.Now().Add(time.Hour), ExecutionRevision: 2}
	head := capability.Checkpoint{Revision: 4, SchemaID: history.SchemaID, Value: map[string]any{
		"version": "harness-loop/v1", "phase": "tool_running", "pending": []any{},
	}, ContentHash: "advanced-head-hash", ExpiresAt: history.ExpiresAt, ExecutionRevision: 6}
	fixture := &approvedResumeCheckpointFixture{head: head, history: history}
	reference := execution.ApprovedToolResume{Version: "harness-tool-resume/v1", WaitingRevision: 3,
		Claims: execution.ApprovedToolResumeClaims{Version: claims.Version, ApprovalID: claims.ApprovalID, ActorID: claims.ActorID,
			ScopeHash: claims.ScopeHash, AuthorizationEpoch: claims.AuthorizationEpoch, PolicyHash: claims.PolicyHash, ToolName: claims.ToolName,
			CallID: claims.CallID, Fingerprint: claims.Fingerprint, IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt,
			PendingKey: claims.PendingKey, CheckpointRevision: claims.CheckpointRevision},
		Handoff: contract.HandlerHandoff{Version: "sdk-handler-exit/v1", RunID: scope.RunID, ExecutionRevision: 2,
			HarnessKey: "harness", ToolName: "clock.now", CallID: "call-1"}, CheckpointHash: history.ContentHash}
	run := execution.ToolApprovalRun{Scope: scope, Active: true, Revision: 7}

	if _, _, err = loadApprovedResumeCheckpoint(context.Background(), fixture, scope, reference, claims, run, false); err == nil {
		t.Fatal("dispatch accepted an approval after its current checkpoint head advanced")
	}
	if len(fixture.requested) != 1 || fixture.requested[0] != 0 {
		t.Fatalf("dispatch did not inspect the current head: revisions=%v", fixture.requested)
	}

	checkpoint, operation, err := loadApprovedResumeCheckpoint(context.Background(), fixture, scope, reference, claims, run, true)
	if err != nil || checkpoint.Revision != claims.CheckpointRevision || operation.Name != claims.ToolName || operation.CallID != claims.CallID || operation.Payload["timezone"] != "UTC" {
		t.Fatalf("renewal did not resolve the approved historical command: checkpoint=%+v operation=%+v err=%v", checkpoint, operation, err)
	}
	if len(fixture.requested) != 2 || fixture.requested[1] != claims.CheckpointRevision {
		t.Fatalf("renewal did not request the exact historical checkpoint: revisions=%v", fixture.requested)
	}

	fixture.history.Value = map[string]any{"version": "harness-loop/v1", "phase": "tool_running", "pending": []any{}}
	if _, _, err = loadApprovedResumeCheckpoint(context.Background(), fixture, scope, reference, claims, run, true); err == nil {
		t.Fatal("renewal accepted a historical checkpoint without the approved pending command")
	}
}
