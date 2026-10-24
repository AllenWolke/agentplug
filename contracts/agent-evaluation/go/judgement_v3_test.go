package agenteval

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestV3CompleteUTF8OutputPreservesBindingWithoutWideningV2(t *testing.T) {
	in := reviewInput()
	// Chinese UTF-8 bytes, not character count, cross the original 96 KiB cap.
	rows := make([]string, 40)
	for i := range rows {
		rows[i] = strings.Repeat("证", 1024)
	}
	in.Evidence["output"], _ = json.Marshal(map[string]any{"sub_answers": rows})
	in.Version = JudgeInputV2
	if in.Validate() == nil {
		t.Fatal("V2 capacity silently widened")
	}
	in.Version = JudgeInputV3
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	ref, err := in.SourceReference()
	if err != nil || ref.OutputHash != in.SourceOutputHash || ref.RedactedOutputHash == "" {
		t.Fatal("full source binding lost", err)
	}
	changed := in
	changed.Evidence = map[string]json.RawMessage{"output": json.RawMessage(`{"answer":"projection"}`)}
	other, _ := changed.SourceReference()
	if other.RedactedOutputHash == ref.RedactedOutputHash {
		t.Fatal("projected and full outputs acquired the same binding")
	}
}

func TestV3KeepsEvidenceTotalAndVerdictSafetyBounds(t *testing.T) {
	for _, scenario := range []string{"output", "event", "total", "safety", "unknown"} {
		t.Run(scenario, func(t *testing.T) {
			in := reviewInput()
			in.Version = JudgeInputV3
			switch scenario {
			case "output":
				in.Evidence["output"] = largeFrozenOutput(t, 256<<10)
			case "event":
				in.Evidence["event:1"] = largeFrozenOutput(t, 49<<10)
			case "total":
				in.Evidence["output"] = largeFrozenOutput(t, 250<<10)
				for _, id := range []string{"event:1", "event:2", "event:3"} {
					in.Evidence[id] = largeFrozenOutput(t, 46<<10)
				}
			case "safety":
				in.Rubric.Criteria["permission_violation"] = "Model must not certify absence of safety violations"
				in.RubricHash = RubricDigest(in.Rubric)
			case "unknown":
				in.Version = "agent-eval-judge-input/v99"
			}
			if in.Validate() == nil {
				t.Fatal("invalid or unsafe evidence admitted")
			}
		})
	}
}
