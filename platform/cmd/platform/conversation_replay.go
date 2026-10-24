package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/policyasset"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

type conversationReplayRepository interface {
	Get(string) (platformruntime.Run, error)
	GetCreation(string) (platformruntime.CreationProjection, error)
}

type conversationReplaySessionSource interface {
	GetSessionResource(context.Context, conversation.Scope, string) (conversation.SessionResource, error)
}

type conversationRunReplay struct {
	repository      conversationReplayRepository
	sessions        conversationReplaySessionSource
	modelSelections policyasset.ModelSelectionStore
}

func (a conversationRunReplay) MatchRunReplay(ctx context.Context, actor conversation.Scope, session string, request conversation.RunStartRequest) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if a.repository == nil || a.sessions == nil || actor.Validate() != nil || actor.PrincipalType != "user" || session == "" {
		return false, conversation.ErrForbidden
	}
	run, err := a.repository.Get(request.RunID)
	if errors.Is(err, platformruntime.ErrRunNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	scope := run.Scope
	if scope.ValidateTrusted() != nil || run.ID != request.RunID || scope.RunID != run.ID || run.AgentVersionID != scope.AgentVersionID || scope.TenantID != actor.TenantID || scope.DepartmentID != actor.DepartmentID || scope.ApplicationID != actor.ApplicationID || scope.PrincipalType != actor.PrincipalType || scope.PrincipalID != actor.PrincipalID || scope.SessionID != session {
		return false, conversation.ErrForbidden
	}
	source, err := a.sessions.GetSessionResource(ctx, actor, session)
	if err != nil {
		return false, err
	}
	if source.ID != session || source.OwnerID != scope.PrincipalID || source.PrincipalType != scope.PrincipalType || source.InstallationID != scope.InstallationID || source.AgentID != scope.AgentID || source.AgentVersionID != scope.AgentVersionID {
		return false, conversation.ErrForbidden
	}
	if run.IdempotencyKey != request.IdempotencyKey || request.AgentEndpoint != "" && request.AgentEndpoint != run.AgentEndpoint || request.AgentInstanceID != "" && request.AgentInstanceID != scope.AgentInstanceID || request.InstallationID != "" && request.InstallationID != scope.InstallationID || request.AuthorizationEpoch != 0 && request.AuthorizationEpoch != scope.AuthorizationEpoch {
		return false, conversation.ErrRunReplayConflict
	}
	selection := policyasset.ModelSelection{}
	if a.modelSelections != nil {
		binding, found, err := a.modelSelections.LookupModelSelection(ctx, scope)
		if err != nil {
			return false, err
		}
		if found {
			selection = binding.Selection
		}
	}
	if selection.EffectiveMode() != request.ModelSelection.EffectiveMode() || request.ModelSelection.Validate() != nil {
		return false, conversation.ErrRunReplayConflict
	}
	creation, err := a.repository.GetCreation(run.ID)
	if err != nil {
		return false, err
	}
	if creation.RunID != run.ID || creation.MessageID != request.MessageID {
		return false, conversation.ErrRunReplayConflict
	}
	var accepted struct {
		ProtocolVersion string            `json:"protocol_version"`
		Scope           contract.ScopeKey `json:"scope"`
		Operation       string            `json:"operation"`
		IdempotencyKey  string            `json:"idempotency_key"`
		Input           json.RawMessage   `json:"input"`
	}
	if json.Unmarshal(run.RequestJSON, &accepted) != nil || accepted.ProtocolVersion != "agent-execution/v2" || len(accepted.Input) == 0 {
		return false, conversation.ErrInvalidQuery
	}
	acceptedScope := contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, InstallationID: scope.InstallationID, PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, SessionID: scope.SessionID, RunID: scope.RunID, AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID, ParentRunID: scope.ParentRunID}
	if accepted.Scope != acceptedScope || accepted.Operation != "run" || accepted.IdempotencyKey != run.IdempotencyKey {
		return false, conversation.ErrForbidden
	}
	expected, err := conversation.BusinessRequestHash(accepted.Input)
	if err != nil {
		return false, err
	}
	actual, err := conversation.BusinessRequestHash(request.Request)
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return false, conversation.ErrRunReplayConflict
	}
	if request.Fingerprint != "" {
		fingerprint, err := conversation.RunCommandSelectionFingerprint(scope, run.IdempotencyKey, accepted.Input, selection)
		if err != nil {
			return false, err
		}
		if subtle.ConstantTimeCompare([]byte(request.Fingerprint), []byte(fingerprint)) != 1 {
			return false, conversation.ErrRunReplayConflict
		}
	}
	return true, nil
}
