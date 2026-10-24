package execution

import (
	"context"
	"testing"
)

func TestRecoveryDispatchPreservesBoundMaterialRequestWithoutPrivateComment(t *testing.T) {
	d, repo, run, request := recoveryDispatchFixture()
	run.Scope.PrincipalID = "business-owner"
	run.ResumeInputJSON = []byte(`{"decision":"request_changes","reviewer_id":"assigned-reviewer","comment":"Supply the effective year."}`)
	repo.ref.Operation = "resume"
	repo.ref.ResumeInputHash = stopHash(run.ResumeInputJSON)
	ok, err := d.prepareRecoveryDispatch(context.Background(), run, &request)
	if err != nil || !ok {
		t.Fatalf("Material review recovery: %v %v", ok, err)
	}
	value, ok := request.ResumeInput["business_review"].(map[string]any)
	if !ok || len(value) != 2 || value["decision"] != "request_changes" || value["reviewer_id"] != "assigned-reviewer" {
		t.Fatal("Material decision lost or private comment leaked")
	}
	if _, exists := request.ResumeInput["confirmation_token"]; exists {
		t.Fatal("Business review created a tool token")
	}
}
