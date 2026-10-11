package knowledge

import (
	"errors"
	"testing"
)

func TestBusinessDateDoesNotGuessMissingMetadata(t *testing.T) {
	for _, metadata := range []map[string]string{nil, {"status": "effective"}, {"effective_date": "2025-01-01", "status": "draft"}, {"effective_date": "2025-01-01", "valid_to": "2024-01-01", "status": "effective"}} {
		if ok, err := BusinessDate(metadata, "2025-10-08"); ok || !errors.Is(err, ErrDocumentValidityUnavailable) {
			t.Fatalf("missing validity accepted: %v %v", ok, err)
		}
	}
}

func TestBusinessDateHalfOpenLegalInterval(t *testing.T) {
	m := map[string]string{"effective_date": "2024-01-01", "valid_to": "2025-01-01", "status": "historical"}
	for day, expected := range map[string]bool{"2023-12-31": false, "2024-01-01": true, "2024-12-31": true, "2025-01-01": false} {
		if got, err := BusinessDate(m, day); err != nil || got != expected {
			t.Fatalf("%s: %v %v", day, got, err)
		}
	}
	if ok, err := BusinessDate(nil, ""); !ok || err != nil {
		t.Fatal("generic non-temporal corpus changed")
	}
}
