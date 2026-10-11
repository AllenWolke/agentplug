package execution

import (
	"context"
	"net/http"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestBusinessReviewBindsCommittedHumanAndRechecksRevocation(t *testing.T) {
	m, scope := newWaitingReviewRun(t, "ticket-assistant")
	allowed := true
	m.SetReviewPermissionAuthorizer(func(_ context.Context, got sharedkernel.Scope, reviewer, action string) error {
		if got != scope || reviewer != "reviewer" || !allowed || action != "business.review" {
			return ErrReviewPermissionDenied
		}
		return nil
	})
	if err := m.ValidateCommittedReviewDecision(context.Background(), scope, "reviewer", "approve"); err == nil {
		t.Fatal("Agent-supplied reviewer accepted before actual human command")
	}
	if w := browserReview(t, m, scope, "initiator", `{"decision":"approve"}`, nil); w.Code != http.StatusForbidden {
		t.Fatal("self approval accepted", w.Code)
	}
	if w := browserReview(t, m, scope, "reviewer", `{"decision":"approve"}`, nil); w.Code != http.StatusOK {
		t.Fatal("explicit independent review rejected", w.Code, w.Body.String())
	}
	if err := m.ValidateCommittedReviewDecision(context.Background(), scope, "reviewer", "approve"); err != nil {
		t.Fatal("committed independent human decision rejected", err)
	}
	for _, v := range []struct{ reviewer, decision string }{{"forged", "approve"}, {"reviewer", "reject"}} {
		if err := m.ValidateCommittedReviewDecision(context.Background(), scope, v.reviewer, v.decision); err == nil {
			t.Fatal("decision did not match committed reviewer and decision")
		}
	}
	other := scope
	other.AgentInstanceID = "other"
	if err := m.ValidateCommittedReviewDecision(context.Background(), other, "reviewer", "approve"); err == nil {
		t.Fatal("committed review reused across installation")
	}
	if w := browserReview(t, m, scope, "reviewer", `{"decision":"approve"}`, nil); w.Code != http.StatusOK {
		t.Fatal("identical human command did not replay", w.Code)
	}
	allowed = false
	if err := m.ValidateCommittedReviewDecision(context.Background(), scope, "reviewer", "approve"); err == nil {
		t.Fatal("reviewer revocation ignored by finalization")
	}
	if w := browserReview(t, m, scope, "reviewer", `{"decision":"approve"}`, nil); w.Code != http.StatusForbidden {
		t.Fatal("revoked review command replayed", w.Code)
	}
}
