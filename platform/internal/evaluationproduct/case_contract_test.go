package evaluationproduct

import (
	"encoding/json"
	"testing"
)

func TestDatasetRequiresSeparatedAgentInputAndGold(t *testing.T) {
	valid := json.RawMessage(`{"case_id":"case-1","input":{"question":"q"},"expected":{"answer":"a"},"split":"frozen"}`)
	if err := validateDataset(DatasetData{Name: "quality", Version: "1", SourceType: "manual_gold", Cases: []json.RawMessage{valid}}); err != nil {
		t.Fatalf("valid separated case rejected: %v", err)
	}
	for _, test := range []struct {
		name string
		raw  json.RawMessage
	}{
		{"flat gold leak", json.RawMessage(`{"case_id":"case-1","question":"q","expected":{"answer":"a"}}`)},
		{"missing gold", json.RawMessage(`{"case_id":"case-1","input":{"question":"q"}}`)},
		{"string input", json.RawMessage(`{"case_id":"case-1","input":"q","expected":{"answer":"a"}}`)},
		{"unknown field", json.RawMessage(`{"case_id":"case-1","input":{"question":"q"},"expected":{"answer":"a"},"prompt_override":"leak"}`)},
		{"invalid split", json.RawMessage(`{"case_id":"case-1","input":{"question":"q"},"expected":{"answer":"a"},"split":"production"}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateDataset(DatasetData{Name: "quality", Version: "1", SourceType: "manual_gold", Cases: []json.RawMessage{test.raw}}); err == nil {
				t.Fatalf("invalid case accepted: %s", test.raw)
			}
		})
	}
	if err := validateDataset(DatasetData{Name: "quality", Version: "1", SourceType: "manual_gold", Cases: []json.RawMessage{valid, valid}}); err == nil {
		t.Fatal("duplicate case id accepted")
	}
}
