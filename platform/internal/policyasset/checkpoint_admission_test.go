package policyasset

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCheckpointAdmissionPublishedOptInKeepsLegacyShape(t *testing.T) {
	legacy := MemoryPolicy{MaxEntries: 8192, TaskTTLSeconds: 3600}
	raw, _ := json.Marshal(legacy)
	if strings.Contains(string(raw), "checkpoint_admission") || legacy.ReservedCheckpointQuota() {
		t.Fatal("legacy shape changed")
	}
	candidate := legacy
	candidate.CheckpointAdmission = &CheckpointAdmissionPolicy{Version: "checkpoint-admission/v1", Mode: "reserved_quota"}
	raw, _ = json.Marshal(candidate)
	if validateAssetContent(AssetMemory, raw) != nil || !candidate.ReservedCheckpointQuota() {
		t.Fatal("published bounded admission denied")
	}
	for _, invalid := range []string{`{"version":"v2","mode":"reserved_quota"}`, `{"version":"checkpoint-admission/v1","mode":"skip_quota"}`, `{"version":"checkpoint-admission/v1","mode":"reserved_quota","skip_auth":true}`, `{"version":true,"mode":"reserved_quota"}`} {
		if validateAssetContent(AssetMemory, []byte(`{"max_entries":8192,"checkpoint_admission":`+invalid+`}`)) == nil {
			t.Fatal("invalid admission published", invalid)
		}
	}
}
