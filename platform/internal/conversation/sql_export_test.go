package conversation

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExportEncodesEveryMessageAndSnapshotCount(t *testing.T) {
	index := 0
	payload, err := encodeConversationExport(Summary{ID: "session", MessageCount: 1}, func() (Message, bool, error) {
		if index == 305 {
			return Message{}, false, nil
		}
		index++
		return Message{ID: fmt.Sprintf("message-%03d", index), Content: "完整导出", Metadata: map[string]any{"index": index}}, true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var export struct {
		Summary  Summary   `json:"summary"`
		Messages []Message `json:"messages"`
	}
	if err := json.Unmarshal(payload, &export); err != nil {
		t.Fatal(err)
	}
	if export.Summary.MessageCount != 305 || len(export.Messages) != 305 || export.Messages[304].ID != "message-305" {
		t.Fatalf("incomplete export: summary=%d messages=%d", export.Summary.MessageCount, len(export.Messages))
	}
}

func TestExportNeverReturnsPartialPayloadOnFailure(t *testing.T) {
	readError := errors.New("message read failed")
	for _, failure := range []string{"read", "oversize"} {
		t.Run(failure, func(t *testing.T) {
			calls := 0
			payload, err := encodeConversationExport(Summary{}, func() (Message, bool, error) {
				calls++
				if calls == 1 {
					return Message{Content: "first"}, true, nil
				}
				if failure == "read" {
					return Message{}, false, readError
				}
				return Message{Content: strings.Repeat("x", maxExportPayloadBytes)}, true, nil
			})
			if payload != nil || err == nil {
				t.Fatal("failed export returned a partial payload")
			}
			if failure == "oversize" && !errors.Is(err, ErrExportTooLarge) {
				t.Fatalf("wrong size error: %v", err)
			}
		})
	}
	recorder := httptest.NewRecorder()
	(&Module{}).storeError(recorder, fmt.Errorf("encode: %w", ErrExportTooLarge))
	if recorder.Code != 413 || !strings.Contains(recorder.Body.String(), "EXPORT_TOO_LARGE") {
		t.Fatalf("wrong HTTP size response: %d %s", recorder.Code, recorder.Body.String())
	}
}
