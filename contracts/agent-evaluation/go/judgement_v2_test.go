package agenteval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func largeFrozenOutput(t *testing.T, size int) json.RawMessage {
	t.Helper()
	// Separate bounded strings resemble complete multi-step citations. This
	// verifies byte limits without relying on a sanitizer-truncated long value.
	rows := []string{}
	for i := 0; i < size/1024; i++ {
		rows = append(rows, strings.Repeat("a", 1024))
	}
	b, err := json.Marshal(map[string]any{"sub_answers": rows, "answer": ""})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestV2RetainsCompleteMultiStepOutputAndSourceBinding(t *testing.T) {
	in := reviewInput()
	in.Evidence["output"] = largeFrozenOutput(t, 80<<10)
	if in.Validate() == nil {
		t.Fatal("legacy input limit was widened")
	}
	in.Version = JudgeInputV2
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	ref, err := in.SourceReference()
	if err != nil {
		t.Fatal(err)
	}
	var value any
	_ = json.Unmarshal(in.Evidence["output"], &value)
	b, _ := json.Marshal(Sanitize(value))
	h := sha256.Sum256(b)
	if ref.OutputHash != in.SourceOutputHash || ref.RedactedOutputHash != hex.EncodeToString(h[:]) {
		t.Fatal("full output source binding was replaced by a projection")
	}
}

func TestV2KeepsEventGoldAndTotalBounds(t *testing.T) {
	for _, scenario := range []string{"output", "event", "expected", "total", "unknown-version"} {
		t.Run(scenario, func(t *testing.T) {
			in := reviewInput()
			in.Version = JudgeInputV2
			switch scenario {
			case "output":
				in.Evidence["output"] = largeFrozenOutput(t, 96<<10)
			case "event", "expected":
				in.Evidence[scenario] = largeFrozenOutput(t, 49<<10)
			case "total":
				in.Evidence["output"] = largeFrozenOutput(t, 90<<10)
				in.Evidence["event:1"] = largeFrozenOutput(t, 40<<10)
			case "unknown-version":
				in.Version = "agent-eval-judge-input/v99"
			}
			if in.Validate() == nil {
				t.Fatal("bounded or unknown input admitted")
			}
		})
	}
	if IsJudgeInputVersion(map[string]any{"version": JudgeInputV2}) || IsJudgeInputVersion(nil) {
		t.Fatal("untyped version tag admitted")
	}
}

func TestV2CannotCertifySafetyOrInventVerdictEvidence(t *testing.T) {
	in := reviewInput()
	in.Version = JudgeInputV2
	in.Rubric.Criteria["permission_violation"] = "Assert absence of permission violations."
	in.RubricHash = RubricDigest(in.Rubric)
	if in.Validate() == nil {
		t.Fatal("new input version enabled model safety certification")
	}
	delete(in.Rubric.Criteria, "permission_violation")
	in.RubricHash = RubricDigest(in.Rubric)
	value := true
	if ValidateVerdicts(in, []Verdict{{MetricID: "faithfulness", Value: &value, Evidence: []string{"invented"}, Reason: "invented evidence is disallowed"}}) == nil {
		t.Fatal("invented evidence accepted")
	}
}
