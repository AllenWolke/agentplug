package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type SessionProgress struct {
	RunID          string
	Status         platformruntime.Status
	Revision       uint64
	WaitingReview  bool
	ReviewFeedback *SessionReviewFeedback
}

type SessionReviewFeedback struct {
	Comment    string
	ReviewerID string
}

// LatestSessionProgress reads only this repository's tables. The composition
// supplies persisted session ownership after Conversation has authorized it.
// A matching outcome revision is required before waiting is called a review.
func (s *SQLStore) LatestSessionProgress(ctx context.Context, scope sharedkernel.Scope) (*SessionProgress, error) {
	for _, value := range []string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalID, scope.SessionID, scope.InstallationID, scope.AgentID} {
		if strings.TrimSpace(value) == "" {
			return nil, platformruntime.ErrInvalidRequest
		}
	}
	if scope.PrincipalType != "user" && scope.PrincipalType != "service_principal" {
		return nil, platformruntime.ErrInvalidRequest
	}
	var result SessionProgress
	var event, stage string
	var resumeInput string
	var outcomeRevision uint64
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT r.run_id,r.status,r.revision,coalesce(o.event_type,''),coalesce(o.revision,0),coalesce(o.output_json->>'stage',''),coalesce(r.resume_input_json,'') FROM platform_execution_run r LEFT JOIN platform_execution_outcome o ON o.run_id=r.run_id WHERE r.tenant_id=? AND r.department_id=? AND r.application_id=? AND r.principal_type=? AND r.principal_id=? AND r.session_id=? AND r.installation_id=? AND r.agent_id=? ORDER BY r.created_at DESC,r.run_id DESC LIMIT 1`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID, scope.SessionID, scope.InstallationID, scope.AgentID).Scan(&result.RunID, &result.Status, &result.Revision, &event, &outcomeRevision, &stage, &resumeInput)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if result.Status == platformruntime.StatusWaiting && event == "waiting" && outcomeRevision == result.Revision {
		result.WaitingReview = stage == "waiting_review"
		if result.WaitingReview && len(resumeInput) <= 8192 {
			var decision struct {
				Decision   string `json:"decision"`
				Comment    string `json:"comment"`
				ReviewerID string `json:"reviewer_id"`
			}
			if json.Unmarshal([]byte(resumeInput), &decision) == nil && decision.Decision == "request_changes" && strings.TrimSpace(decision.Comment) != "" && len(decision.Comment) <= 2000 && decision.ReviewerID != "" && len(decision.ReviewerID) <= 128 && decision.ReviewerID != scope.PrincipalID {
				result.ReviewFeedback = &SessionReviewFeedback{Comment: decision.Comment, ReviewerID: decision.ReviewerID}
			}
		}
	}
	return &result, nil
}
