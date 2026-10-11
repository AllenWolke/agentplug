package evaluationproduct

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAgentAssertionsPreserveLargeIntegerBounds(t *testing.T) {
	input := json.RawMessage(`{"case_id":"large-counter","input":{},"expected":{"assertions":[{"path":"value","op":"gte","value":9007199254740993}]}}`)
	result, err := EvaluateAgentAssertions(context.Background(), MetricSnapshot{ID: "assertions"}, input, json.RawMessage(`{"value":9007199254740992}`))
	if err != nil || result.Value == nil || *result.Value != 0 {
		t.Fatalf("rounded unequal integers into success: %+v %v", result, err)
	}
}

func TestPublicEvaluationRunDoesNotDiscloseWorkerLease(t *testing.T) {
	d := RunData{SuiteID: "suite", LeaseOwner: "worker-private", LeaseToken: "private-lease", LeaseUntil: time.Now().Add(time.Hour)}
	raw, _ := json.Marshal(d)
	r := Resource{Kind: KindRun, ID: "run", Revision: 5, Data: raw}
	projected := publicEvaluationValue(map[string]any{"items": []Resource{r}})
	public, _ := json.Marshal(projected)
	if strings.Contains(string(public), "private-lease") || strings.Contains(string(public), "worker-private") {
		t.Fatal("worker credentials in browser projection")
	}
	if !strings.Contains(string(r.Data), "private-lease") || r.Revision != 5 {
		t.Fatal("projection mutated stored Run")
	}
}
func TestFrozenInstallationBindingCannotOmitItsRevision(t *testing.T) {
	d := SuiteData{InstallationID: "installation"}
	if validateSuiteSnapshot(d) == nil {
		t.Fatal("missing installation revision accepted")
	}
	snapshot := json.RawMessage(`{"installation_id":"installation","installation_revision":0}`)
	if _, e := decodeSuiteSnapshot(snapshot); e == nil {
		t.Fatal("incomplete installation snapshot accepted")
	}
}
