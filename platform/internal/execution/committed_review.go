package execution

import (
	"context"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func humanReviewAction(action string) string { return "execution.review." + action }

// ValidateCommittedReviewDecision exposes a narrow check, never the signed
// envelope or arbitrary run input. Tool finalization must match the durable
// human decision and the reviewer's current independent resource permission.
func (m *Module) ValidateCommittedReviewDecision(ctx context.Context, scope sharedkernel.Scope, reviewer, decision string) error {
	if scope.Validate() != nil || reviewer == "" || reviewer == scope.PrincipalID || decision != "approve" && decision != "reject" {
		return ErrReviewPermissionDenied
	}
	run, err := m.store.Get(scope.RunID)
	if err != nil {
		return err
	}
	// Capability's business command intentionally omits authorization epochs;
	// the capability boundary validates its signed epoch independently.
	scope.AuthorizationEpoch = run.Scope.AuthorizationEpoch
	if !sameScope(run.Scope, scope) || len(run.ResumeInputJSON) == 0 || len(run.ResumeInputJSON) > 1<<16 {
		return ErrReviewPermissionDenied
	}
	committed := committedBusinessReview(run.ResumeInputJSON, run.Scope)
	if committed == nil || committed.Reviewer != reviewer || committed.Decision != decision || m.reviewAuthorizer == nil {
		return ErrReviewPermissionDenied
	}
	return m.reviewAuthorizer(ctx, run.Scope, reviewer, "business.review")
}
