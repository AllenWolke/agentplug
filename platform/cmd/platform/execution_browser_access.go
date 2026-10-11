package main

import (
	"encoding/json"

	"context"
	"errors"
	agenteval "github.com/lexagent/agent-evaluation"
	"github.com/lexagent/platform/internal/evaluationproduct"

	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type identityExecutionBrowserControl struct {
	store identity.Store
	runs  *execution.SQLStore
}

func (a identityExecutionBrowserControl) Authorize(ctx context.Context, owner sharedkernel.Scope, actor execution.BrowserRunActor, action string) error {
	if a.store == nil || actor.Scope.PrincipalType != "user" || actor.Scope.Validate() != nil || actor.Scope.TenantID != owner.TenantID || actor.Scope.DepartmentID != owner.DepartmentID || actor.Scope.ApplicationID != owner.ApplicationID || action != "history.read" && action != "cancel" {
		return execution.ErrRunPermissionDenied
	}
	validator, ok := a.store.(interface {
		ValidateBrowserSession(context.Context, sharedkernel.Scope, string, uint64) error
	})
	if !ok {
		return errors.New("browser session authority unavailable")
	}
	if err := validator.ValidateBrowserSession(ctx, actor.Scope, actor.AuthenticationSession, actor.AuthenticationRevision); err != nil {
		if errors.Is(err, identity.ErrRefreshSessionRejected) {
			return execution.ErrBrowserSessionInvalid
		}
		return err
	}
	if err := authorizeBusinessResource(ctx, a.store, owner, actor.Scope.PrincipalID, action); err != nil {
		if errors.Is(err, errBusinessReviewForbidden) {
			return execution.ErrRunPermissionDenied
		}
		return err
	}
	if action == "history.read" && owner.AgentID == "agent-eval-judge" {
		if a.runs == nil {
			return execution.ErrRunPermissionDenied
		}
		run, e := a.runs.GetContext(ctx, owner.RunID)
		if e != nil {
			return execution.ErrRunPermissionDenied
		}
		var envelope struct {
			Input map[string]json.RawMessage `json:"input"`
		}
		if json.Unmarshal(run.RequestJSON, &envelope) != nil {
			return execution.ErrRunPermissionDenied
		}
		delete(envelope.Input, "policy_snapshot")
		b, _ := json.Marshal(envelope.Input)
		var frozen agenteval.JudgeInput
		if json.Unmarshal(b, &frozen) != nil {
			return execution.ErrRunPermissionDenied
		}
		ref, e := frozen.SourceReference()
		if e != nil || (evaluationInspection{runs: a.runs, identity: a.store}).AuthorizeSources(ctx, evaluationproduct.Actor{Scope: evaluationProductScope(owner), PrincipalType: actor.Scope.PrincipalType, PrincipalID: actor.Scope.PrincipalID}, []agenteval.SourceReference{ref}) != nil {
			return execution.ErrRunPermissionDenied
		}
	}
	return nil
}
