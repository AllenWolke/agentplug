package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/execution"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type progressRepositoryFixture struct {
	scope sharedkernel.Scope
	calls int
	value *execution.SessionProgress
	err   error
}

func (f *progressRepositoryFixture) LatestSessionProgress(_ context.Context, scope sharedkernel.Scope) (*execution.SessionProgress, error) {
	f.scope = scope
	f.calls++
	return f.value, f.err
}

func TestConversationProgressUsesPersistedOwnerAndExactScope(t *testing.T) {
	actor := conversation.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "authorized-reader"}
	resource := conversation.SessionResource{ID: "session", OwnerID: "owner", PrincipalType: "user", InstallationID: "install", AgentID: "qa", AgentVersionID: "v1"}
	summary := conversation.Summary{ID: "session", OwnerID: "owner", InstallationID: "install", AgentID: "qa", AgentVersionID: "v1"}
	repository := &progressRepositoryFixture{value: &execution.SessionProgress{RunID: "run", Status: platformruntime.StatusWaiting, Revision: 4, WaitingReview: true}}
	adapter := conversationRunProgress{repository: repository, sessions: replaySourceFixture{resource: resource}}
	value, err := adapter.ResolveRunProgress(context.Background(), actor, summary)
	if err != nil || value == nil || value.RunID != "run" || !value.WaitingReview || repository.scope.PrincipalID != "owner" || repository.scope.SessionID != "session" || repository.scope.TenantID != "t" || repository.scope.DepartmentID != "d" || repository.scope.ApplicationID != "a" || repository.scope.InstallationID != "install" {
		t.Fatal("persisted session scope was not used", value, err, repository.scope)
	}
	repository.value.ReviewFeedback = &execution.SessionReviewFeedback{Comment: "materials", ReviewerID: "reviewer"}
	value, err = adapter.ResolveRunProgress(context.Background(), actor, summary)
	if err != nil || value.ReviewFeedback == nil || value.ReviewFeedback.Comment != "materials" {
		t.Fatal("review feedback not projected", value, err)
	}
	repository.value.WaitingReview = false
	value, err = adapter.ResolveRunProgress(context.Background(), actor, summary)
	if err != nil || value.ReviewFeedback != nil {
		t.Fatal("non-review state exposed reviewer feedback", value, err)
	}
	repository.value.WaitingReview = true
	for _, field := range []string{"id", "owner", "install", "agent", "version"} {
		bad := summary
		switch field {
		case "id":
			bad.ID = "other"
		case "owner":
			bad.OwnerID = "other"
		case "install":
			bad.InstallationID = "other"
		case "agent":
			bad.AgentID = "other"
		case "version":
			bad.AgentVersionID = "other"
		}
		before := repository.calls
		if _, err := adapter.ResolveRunProgress(context.Background(), actor, bad); !errors.Is(err, conversation.ErrForbidden) || repository.calls != before {
			t.Fatal("mismatched source reached execution", field, err)
		}
	}
	repository.err = errors.New("database unavailable")
	if _, err := adapter.ResolveRunProgress(context.Background(), actor, summary); !errors.Is(err, repository.err) {
		t.Fatal("progress error was hidden", err)
	}
}
