package execution

import (
	"encoding/json"
	"testing"
)

func TestCommittedBusinessReviewSurvivesToolApprovalChain(t *testing.T) {
	fixture := newResumeRenewalCase(t, "runtime-recovery-approved")
	scope := fixture.running.Scope
	review := committedBusinessReview([]byte(`{"reviewer_id":"independent-reviewer","decision":"approve"}`), scope)
	if review == nil {
		t.Fatal("valid committed decision missing")
	}
	var reference ApprovedToolResume
	if err := json.Unmarshal(fixture.running.ResumeInputJSON, &reference); err != nil {
		t.Fatal(err)
	}
	reference.PreviousReview = review
	for i := 0; i < 3; i++ {
		input, err := json.Marshal(reference)
		if err != nil {
			t.Fatal(err)
		}
		got := committedBusinessReview(input, scope)
		if got == nil || *got != *review {
			t.Fatal("later tool resume discarded original review")
		}
		reference.PreviousReview = got
	}
	t.Run("self-review", func(t *testing.T) {
		reference.PreviousReview = &CommittedBusinessReview{Reviewer: scope.PrincipalID, Decision: "approve"}
		input, _ := json.Marshal(reference)
		if committedBusinessReview(input, scope) != nil {
			t.Fatal("self approval accepted")
		}
	})
	t.Run("unknown-envelope", func(t *testing.T) {
		if committedBusinessReview([]byte(`{"version":"agent-supplied/v1","reviewer_id":"independent-reviewer","decision":"approve"}`), scope) != nil {
			t.Fatal("unknown envelope became review")
		}
	})
	t.Run("invalid-approved-reference", func(t *testing.T) {
		reference.PreviousReview = review
		reference.Claims.ActorID = "another-actor"
		input, _ := json.Marshal(reference)
		if committedBusinessReview(input, scope) != nil {
			t.Fatal("approval actor binding ignored")
		}
	})
}
