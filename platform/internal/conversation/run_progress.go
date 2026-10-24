package conversation

import "context"

// RunProgress contains no draft, token, request or checkpoint content.
// It is projected only after the current session history-read authorization.
type RunProgress struct {
	RunID          string          `json:"run_id"`
	Status         string          `json:"status"`
	Revision       uint64          `json:"revision"`
	WaitingReview  bool            `json:"waiting_review"`
	ReviewFeedback *ReviewFeedback `json:"review_feedback,omitempty"`
}

type ReviewFeedback struct {
	Comment    string `json:"comment"`
	ReviewerID string `json:"reviewer_id"`
}

type RunProgressResolver interface {
	ResolveRunProgress(context.Context, Scope, Summary) (*RunProgress, error)
}

func (m *Module) SetRunProgressResolver(resolver RunProgressResolver) { m.progress = resolver }
