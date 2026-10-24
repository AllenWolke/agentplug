package main

import (
	"context"

	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type conversationProgressRepository interface {
	LatestSessionProgress(context.Context, sharedkernel.Scope) (*execution.SessionProgress, error)
}

type conversationRunProgress struct {
	repository conversationProgressRepository
	sessions   conversationReplaySessionSource
}

func (a conversationRunProgress) ResolveRunProgress(ctx context.Context, actor conversation.Scope, summary conversation.Summary) (*conversation.RunProgress, error) {
	if a.repository == nil || a.sessions == nil || actor.Validate() != nil || summary.ID == "" {
		return nil, conversation.ErrForbidden
	}
	source, err := a.sessions.GetSessionResource(ctx, actor, summary.ID)
	if err != nil {
		return nil, err
	}
	if source.ID != summary.ID || source.OwnerID == "" || source.OwnerID != summary.OwnerID || source.InstallationID != summary.InstallationID || source.AgentID != summary.AgentID || source.AgentVersionID != summary.AgentVersionID {
		return nil, conversation.ErrForbidden
	}
	// Pre-runtime legacy sessions have no installed execution to look up.
	if source.InstallationID == "" {
		return nil, nil
	}
	value, err := a.repository.LatestSessionProgress(ctx, sharedkernel.Scope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, PrincipalType: source.PrincipalType, PrincipalID: source.OwnerID, SessionID: source.ID, InstallationID: source.InstallationID, AgentID: source.AgentID})
	if err != nil || value == nil {
		return nil, err
	}
	result := &conversation.RunProgress{RunID: value.RunID, Status: string(value.Status), Revision: value.Revision, WaitingReview: value.WaitingReview}
	if value.WaitingReview && value.ReviewFeedback != nil {
		result.ReviewFeedback = &conversation.ReviewFeedback{Comment: value.ReviewFeedback.Comment, ReviewerID: value.ReviewFeedback.ReviewerID}
	}
	return result, nil
}
