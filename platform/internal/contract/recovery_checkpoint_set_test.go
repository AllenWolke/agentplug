package contract

import (
	"encoding/json"
	"os"
	"testing"
)

func TestRecoveryCheckpointSetCrossLanguageDigest(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/fixtures/recovery-checkpoint-set-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		References []RecoveryCheckpointReference  `json:"references"`
		Set        RecoveryCheckpointSetReference `json:"set"`
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("fixture invalid")
	}
	actual, err := RecoveryCheckpointSet(fixture.References)
	if err != nil || actual != fixture.Set {
		t.Fatalf("digest mismatch: %v", err)
	}
	duplicate := append([]RecoveryCheckpointReference(nil), fixture.References...)
	duplicate[1] = duplicate[0]
	if _, err := RecoveryCheckpointSet(duplicate); err == nil {
		t.Fatal("duplicate state keys admitted")
	}
	if _, err := RecoveryCheckpointSet(fixture.References[:128]); err == nil {
		t.Fatal("legacy inline set changed")
	}
}
