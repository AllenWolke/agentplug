package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/conversation"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type replaySourceFixture struct {
	run      platformruntime.Run
	creation platformruntime.CreationProjection
	resource conversation.SessionResource
	err      error
}

func (s replaySourceFixture) Get(string) (platformruntime.Run, error) { return s.run, s.err }
func (s replaySourceFixture) GetCreation(string) (platformruntime.CreationProjection, error) {
	return s.creation, s.err
}
func (s replaySourceFixture) GetSessionResource(context.Context, conversation.Scope, string) (conversation.SessionResource, error) {
	return s.resource, s.err
}

func TestConversationReplayUsesAcceptedScopeBodyAndMessageProvenance(t *testing.T) {
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "alice", AgentInstanceID: "install", InstallationID: "install", AgentID: "qa", AgentVersionID: "v1", SessionID: "session", RunID: "accepted", AuthorizationEpoch: 1, TraceID: strings.Repeat("a", 32)}
	wireScope := contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, InstallationID: scope.InstallationID, SessionID: scope.SessionID, RunID: scope.RunID, AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID}
	accepted := map[string]any{"protocol_version": contract.ProtocolVersion, "operation": "run", "idempotency_key": "key", "scope": wireScope, "input": map[string]any{"question": "original", "policy_snapshot": map[string]any{"hash": "old"}}}
	raw, _ := json.Marshal(accepted)
	fixture := replaySourceFixture{run: platformruntime.Run{ID: "accepted", Scope: scope, AgentVersionID: "v1", IdempotencyKey: "key", RequestJSON: raw, AgentEndpoint: "http://approved-agent:8080"}, creation: platformruntime.CreationProjection{RunID: "accepted"}, resource: conversation.SessionResource{ID: "session", OwnerID: "alice", PrincipalType: "user", InstallationID: "install", AgentID: "qa", AgentVersionID: "v1", MessageCount: 2}}
	actor := conversation.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "alice"}
	request := conversation.RunStartRequest{RunID: "accepted", IdempotencyKey: "key", Request: json.RawMessage(`{"question":"original","policy_snapshot":{"hash":"forged"}}`)}
	if matched, err := (conversationRunReplay{repository: fixture, sessions: fixture}).MatchRunReplay(context.Background(), actor, "session", request); err != nil || !matched {
		t.Fatal("owned replay rejected", matched, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*replaySourceFixture, *conversation.Scope, *conversation.RunStartRequest)
		want   error
	}{
		{"owner", func(_ *replaySourceFixture, a *conversation.Scope, _ *conversation.RunStartRequest) {
			a.PrincipalID = "other"
		}, conversation.ErrForbidden},
		{"application", func(_ *replaySourceFixture, a *conversation.Scope, _ *conversation.RunStartRequest) {
			a.ApplicationID = "other"
		}, conversation.ErrForbidden},
		{"session installation", func(f *replaySourceFixture, _ *conversation.Scope, _ *conversation.RunStartRequest) {
			f.resource.InstallationID = "other"
		}, conversation.ErrForbidden},
		{"session version", func(f *replaySourceFixture, _ *conversation.Scope, _ *conversation.RunStartRequest) {
			f.resource.AgentVersionID = "v2"
		}, conversation.ErrForbidden},
		{"body", func(_ *replaySourceFixture, _ *conversation.Scope, r *conversation.RunStartRequest) {
			r.Request = json.RawMessage(`{"question":"changed"}`)
		}, conversation.ErrRunReplayConflict},
		{"idempotency key", func(_ *replaySourceFixture, _ *conversation.Scope, r *conversation.RunStartRequest) {
			r.IdempotencyKey = "new"
		}, conversation.ErrRunReplayConflict},
		{"endpoint", func(_ *replaySourceFixture, _ *conversation.Scope, r *conversation.RunStartRequest) {
			r.AgentEndpoint = "http://attacker"
		}, conversation.ErrRunReplayConflict},
		{"installation", func(_ *replaySourceFixture, _ *conversation.Scope, r *conversation.RunStartRequest) {
			r.InstallationID = "other"
		}, conversation.ErrRunReplayConflict},
		{"message", func(_ *replaySourceFixture, _ *conversation.Scope, r *conversation.RunStartRequest) {
			r.MessageID = "forged"
		}, conversation.ErrRunReplayConflict},
		{"fingerprint", func(_ *replaySourceFixture, _ *conversation.Scope, r *conversation.RunStartRequest) {
			r.Fingerprint = "forged"
		}, conversation.ErrRunReplayConflict},
		{"corrupt creation", func(f *replaySourceFixture, _ *conversation.Scope, _ *conversation.RunStartRequest) {
			f.creation.RunID = "other"
		}, conversation.ErrRunReplayConflict},
		{"SQL failure", func(f *replaySourceFixture, _ *conversation.Scope, _ *conversation.RunStartRequest) {
			f.err = errors.New("database unavailable")
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, a, r := fixture, actor, request
			tc.change(&f, &a, &r)
			matched, err := (conversationRunReplay{repository: f, sessions: f}).MatchRunReplay(context.Background(), a, "session", r)
			if matched || err == nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatal("altered replay allowed", matched, err)
			}
		})
	}
	fixture.err = platformruntime.ErrRunNotFound
	if matched, err := (conversationRunReplay{repository: fixture, sessions: fixture}).MatchRunReplay(context.Background(), actor, "session", request); matched || err != nil {
		t.Fatal("missing run treated as an accepted command", matched, err)
	}
}
