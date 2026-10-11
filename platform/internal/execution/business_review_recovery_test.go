package execution

import (
	"context"
	"testing"
)

func TestRecoveryDispatchAcceptsBoundCommittedBusinessReviewWithoutToolToken(t *testing.T) {
	d, repo, run, request := recoveryDispatchFixture()
	run.Scope.PrincipalID = "business-owner"
	run.ResumeInputJSON = []byte(`{"decision":"approve","reviewer_id":"assigned-reviewer","comment":"checked"}`)
	repo.ref.Operation = "resume"
	repo.ref.ResumeInputHash = stopHash(run.ResumeInputJSON)
	ok, err := d.prepareRecoveryDispatch(context.Background(), run, &request)
	if err != nil || !ok {
		t.Fatalf("committed business review recovery: %v %v", ok, err)
	}
	if _, exists := request.ResumeInput["confirmation_token"]; exists {
		t.Fatal("business approval fabricated a write-tool token")
	}
	review, ok := request.ResumeInput["business_review"].(map[string]any)
	if !ok || len(review) != 2 || review["decision"] != "approve" || review["reviewer_id"] != "assigned-reviewer" {
		t.Fatal("committed actor-bound review missing or private comment disclosed")
	}
	if string(run.ResumeInputJSON) != `{"decision":"approve","reviewer_id":"assigned-reviewer","comment":"checked"}` {
		t.Fatal("committed business review modified")
	}
}
func TestRecoveryDispatchRejectsUnboundOrSelfBusinessReview(t *testing.T) {
	for _, scenario := range []string{"self", "missing_reviewer", "changed", "invoke", "unknown_version"} {
		t.Run(scenario, func(t *testing.T) {
			d, repo, run, request := recoveryDispatchFixture()
			run.Scope.PrincipalID = "business-owner"
			run.ResumeInputJSON = []byte(`{"decision":"approve","reviewer_id":"assigned-reviewer"}`)
			repo.ref.Operation = "resume"
			repo.ref.ResumeInputHash = stopHash(run.ResumeInputJSON)
			switch scenario {
			case "self":
				run.ResumeInputJSON = []byte(`{"decision":"approve","reviewer_id":"business-owner"}`)
				repo.ref.ResumeInputHash = stopHash(run.ResumeInputJSON)
			case "missing_reviewer":
				run.ResumeInputJSON = []byte(`{"decision":"approve"}`)
				repo.ref.ResumeInputHash = stopHash(run.ResumeInputJSON)
			case "changed":
				run.ResumeInputJSON = []byte(`{"decision":"reject","reviewer_id":"assigned-reviewer"}`)
			case "invoke":
				repo.ref.Operation = "invoke"
			case "unknown_version":
				run.ResumeInputJSON = []byte(`{"version":"custom/v1","decision":"approve","reviewer_id":"assigned-reviewer"}`)
				repo.ref.ResumeInputHash = stopHash(run.ResumeInputJSON)
			}
			if ok, err := d.prepareRecoveryDispatch(context.Background(), run, &request); ok || err == nil {
				t.Fatal("unbound business review accepted")
			}
		})
	}
}
