package capability

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestStructuredToolResultPreservesFullDatasetWhileBoundingModelContext(t *testing.T) {
	for _, count := range []int{302, 3002} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			rows := make([]any, count)
			for i := range rows {
				rows[i] = map[string]any{"row_id": fmt.Sprint(i), "value": "60000000", "unit": "万元"}
			}
			input := map[string]any{"sheets": []any{map[string]any{"sheet_id": "dataset", "rows": rows}}}
			observation, output := newToolObservation(sharedkernel.Scope{RunID: "dataset-root"}, "dataset.read", "dataset-call", nil, "succeeded", "completed", "", input)
			want, _ := json.Marshal(input)
			got, _ := json.Marshal(output)
			if string(got) != string(want) || observation.Truncated {
				t.Fatalf("structured data lost rows: expected %d complete rows", count)
			}
			context, _ := json.Marshal(observation.ContextOutput)
			if !observation.ContextTruncated || len(context) > observationContextLimit || observation.OutputBytes != len(got) {
				t.Fatal("full business result expanded model context or lost byte measurement")
			}
			if rows[count-1].(map[string]any)["row_id"] != fmt.Sprint(count-1) {
				t.Fatal("provider-owned input was mutated")
			}
		})
	}
}

func TestStructuredToolResultStillBoundsUntrustedArrays(t *testing.T) {
	items := make([]any, observationArrayLimit+1)
	for i := range items {
		items[i] = "small"
	}
	observation, result := newToolObservation(sharedkernel.Scope{RunID: "bounded-root"}, "dataset.read", "bounded-call", nil, "succeeded", "completed", "", map[string]any{"items": items, "password": "sensitive-value"})
	if !observation.Truncated || result["password"] != "[REDACTED]" || len(result["items"].([]any)) != observationArrayLimit {
		t.Fatal("array bound or credential filtering was lost")
	}
}
