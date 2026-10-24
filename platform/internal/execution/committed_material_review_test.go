package execution

import (
	"github.com/lexagent/platform/internal/sharedkernel"
	"testing"
)

func TestCommittedMaterialReviewPreservesDecisionAndReviewer(t *testing.T) {
	scope := sharedkernel.Scope{PrincipalID: "owner"}
	value := committedBusinessReview([]byte(`{"decision":"request_changes","reviewer_id":"assigned-reviewer","comment":"Supply the effective date."}`), scope)
	if value == nil || value.Decision != "request_changes" || value.Reviewer != "assigned-reviewer" {
		t.Fatal("Committed material request was lost")
	}
	for _, raw := range []string{`{"decision":"request_changes","reviewer_id":"owner"}`, `{"decision":"unknown","reviewer_id":"reviewer"}`} {
		if committedBusinessReview([]byte(raw), scope) != nil {
			t.Fatal("Invalid review was accepted")
		}
	}
}
