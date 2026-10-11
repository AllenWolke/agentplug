package evaluationproduct

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	agenteval "github.com/lexagent/agent-evaluation"
)

type sourceGuard func(context.Context, Actor, []agenteval.SourceReference) error

func (f sourceGuard) AuthorizeSources(ctx context.Context, a Actor, r []agenteval.SourceReference) error {
	return f(ctx, a, r)
}

func judgingDataset() DatasetData {
	rubric := agenteval.Rubric{Version: agenteval.RubricVersion, ID: "teaching-v1", Criteria: map[string]string{"faithfulness": "Check support from the teaching evidence"}}
	in := agenteval.JudgeInput{Version: "agent-eval-judge-input/v1", SourceRunID: "business-run", SourceOutputHash: strings.Repeat("a", 64), Rubric: rubric, RubricHash: agenteval.RubricDigest(rubric), Evidence: map[string]json.RawMessage{"output": json.RawMessage(`{"answer":"private business result"}`)}}
	sample, _ := json.Marshal(map[string]any{"case_id": "grade-1", "input": in, "expected": map[string]any{}})
	return DatasetData{Name: "grading", Version: "1.0.0", SourceType: "imported_redacted", Cases: []json.RawMessage{sample}}
}
func TestDerivedDatasetCannotDropSourceHistoryAuthority(t *testing.T) {
	d := judgingDataset()
	m := NewModule(newMemoryStore(), "module-secret", nil, nil)
	a := Actor{Scope: Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}, PrincipalType: "user", PrincipalID: "reviewer", Browser: true}
	if m.authorizeDatasetSources(context.Background(), a, d) != ErrUnavailable {
		t.Fatal("derived source admitted without a guard")
	}
	m.SetSourceAuthorizer(sourceGuard(func(_ context.Context, actor Actor, refs []agenteval.SourceReference) error {
		if actor.PrincipalID != a.PrincipalID || len(refs) != 1 || refs[0].RunID != "business-run" || refs[0].RedactedOutputHash == "" {
			t.Fatal("incomplete source proof")
		}
		return ErrForbidden
	}))
	if m.authorizeDatasetSources(context.Background(), a, d) != ErrForbidden {
		t.Fatal("current revocation ignored")
	}
	d.SourceType = "manual_gold"
	if m.authorizeDatasetSources(context.Background(), a, d) != ErrInvalid {
		t.Fatal("derived private data disguised as ordinary gold")
	}
}
func TestDerivedDatasetReadAndReviewRequireSourceAccess(t *testing.T) {
	s := newMemoryStore()
	m := NewModule(s, "module-secret", allowAuthorizer(func(context.Context, Actor, Action, Scope) error { return nil }), nil)
	m.SetSourceAuthorizer(sourceGuard(func(context.Context, Actor, []agenteval.SourceReference) error { return ErrForbidden }))
	a := Actor{Scope: Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}, PrincipalType: "user", PrincipalID: "creator", Browser: true}
	d := judgingDataset()
	d.ReviewStatus = "pending_human_review"
	row := newResource(a, KindDataset, "derived", "draft", d)
	if s.Create(context.Background(), row) != nil {
		t.Fatal("fixture failed")
	}
	for _, test := range []struct{ method, path, body string }{{"GET", "/datasets/derived", ""}, {"POST", "/datasets/derived/review", `{"expected_revision":1,"decision":"approved","reason":"explicit review"}`}} {
		w := request(m, test.method, test.path, test.body, "reviewer", true)
		if w.Code != 403 || strings.Contains(w.Body.String(), "private business result") {
			t.Fatal("derived result exposed or unauthorized approval accepted", w.Code)
		}
	}
}
