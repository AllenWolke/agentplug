package evaluationproduct

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	agenteval "github.com/lexagent/agent-evaluation"
)

type unusedRoutingCaseVerifier struct{ calls int }

func (v *unusedRoutingCaseVerifier) VerifyRoutingCaseModel(context.Context, Scope, string, int, string, RoutingQualificationTarget) (RoutingQualifiedCase, error) {
	v.calls++
	return RoutingQualifiedCase{}, ErrUnavailable
}

func routingQualificationRequest() string {
	return `{"evidence_id":"evidence-a","report_hash":"` + strings.Repeat("a", 64) +
		`","model_version_id":"model-version-a","maximum_complexity":"simple","target":{"agent_id":"qa-agent","agent_version_id":"qa-version","execution_context_sha256":"` + strings.Repeat("b", 64) + `"}}`
}

func TestRoutingQualificationReadbackHasNoMutationOrFallbackWhenUnavailable(t *testing.T) {
	store := newMemoryStore()
	module := NewModule(store, "module-secret", allowAuthorizer(func(context.Context, Actor, Action, Scope) error { return nil }), nil)
	path := "/model-routing/qualifications:verify"
	if request(module, http.MethodPost, path, routingQualificationRequest(), "reader", true).Code != 503 {
		t.Fatal("missing native verifier silently qualified or used output heuristics")
	}
	if request(module, http.MethodGet, path, "", "reader", true).Code != 405 {
		t.Fatal("unexpected qualification method")
	}
	if len(store.rows) != 0 {
		t.Fatal("readback created quality grants or Runs")
	}
	module.authorizer = allowAuthorizer(func(context.Context, Actor, Action, Scope) error { return ErrForbidden })
	if request(module, http.MethodPost, path, routingQualificationRequest(), "reader", true).Code != 403 {
		t.Fatal("revoked reader reached source lookup")
	}
}

func TestRoutingQualificationReadbackProtectsOriginalSourcesBeforeQualification(t *testing.T) {
	store := newMemoryStore()
	scope := Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}
	dataset, _ := json.Marshal(judgingDataset())
	suite, _ := json.Marshal(map[string]string{"dataset_id": "dataset-a"})
	evidence, _ := json.Marshal(EvidenceData{SuiteID: "suite-a", ReportHash: strings.Repeat("a", 64)})
	for _, row := range []Resource{
		{ID: "dataset-a", Kind: KindDataset, Scope: scope, Status: "published", Revision: 1, Data: dataset},
		{ID: "suite-a", Kind: KindSuite, Scope: scope, Status: "published", Revision: 1, Data: suite},
		{ID: "evidence-a", Kind: KindEvidence, Scope: scope, Status: "completed", Revision: 1, Data: evidence},
	} {
		if err := store.Create(context.Background(), row); err != nil {
			t.Fatal(err)
		}
	}
	readChecks := 0
	module := NewModule(store, "module-secret", allowAuthorizer(func(_ context.Context, actor Actor, action Action, target Scope) error {
		readChecks++
		if action != ActionRead || actor.Scope != target {
			t.Error("qualification changed permission or trusted Scope")
		}
		return nil
	}), nil)
	verifier := &unusedRoutingCaseVerifier{}
	module.SetRoutingCaseModelVerifier(verifier)
	sourceChecks := 0
	module.SetSourceAuthorizer(sourceGuard(func(_ context.Context, actor Actor, refs []agenteval.SourceReference) error {
		sourceChecks++
		if actor.PrincipalID != "reader" || len(refs) != 1 || refs[0].RunID != "business-run" {
			t.Error("missing original source authority")
		}
		return ErrForbidden
	}))
	path := "/model-routing/qualifications:verify"
	if request(module, http.MethodPost, path, routingQualificationRequest(), "reader", true).Code != 403 || sourceChecks != 1 || verifier.calls != 0 {
		t.Fatal("revoked business-source access reached native qualification")
	}
	module.SetSourceAuthorizer(sourceGuard(func(context.Context, Actor, []agenteval.SourceReference) error { return nil }))
	response := request(module, http.MethodPost, path, routingQualificationRequest(), "reader", true)
	var result struct {
		Qualified bool   `json:"qualified"`
		Code      string `json:"reason_code"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Qualified || result.Code != "QUALIFICATION_NOT_MET" {
		t.Fatal("unmeasured evidence became qualified")
	}
	invalid := strings.Replace(routingQualificationRequest(), `"target":{`, `"target":{"model_version_id":"caller-extra",`, 1)
	if request(module, http.MethodPost, path, invalid, "reader", true).Code != 400 {
		t.Fatal("unexpected target override accepted")
	}
	if len(store.rows) != 3 || verifier.calls != 0 || readChecks < 2 {
		t.Fatal("readback mutated state or dispatched work")
	}
}
