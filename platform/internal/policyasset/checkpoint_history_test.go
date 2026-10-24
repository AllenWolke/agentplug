package policyasset

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCheckpointHistoryPublishedCapacityKeepsLegacyIdentity(t *testing.T) {
	legacy := MemoryPolicy{MaxEntries: 8192, TaskTTLSeconds: 3600}
	raw, err := json.Marshal(legacy)
	if err != nil || strings.Contains(string(raw), "checkpoint_history") || legacy.CheckpointRevisionLimit() != 64 {
		t.Fatal("legacy policy serialization/default changed", err)
	}
	for _, limit := range []uint64{1, 64, 4002, 4096} {
		candidate := legacy
		candidate.CheckpointHistory = &CheckpointHistoryPolicy{Version: "checkpoint-history/v1", MaxRevisions: limit}
		raw, _ := json.Marshal(candidate)
		if validateAssetContent(AssetMemory, raw) != nil || candidate.CheckpointRevisionLimit() != limit {
			t.Fatal("bounded published capacity rejected", limit)
		}
	}
	for _, history := range []string{
		`{"version":"unknown","max_revisions":4096}`,
		`{"version":"checkpoint-history/v1","max_revisions":0}`,
		`{"version":"checkpoint-history/v1","max_revisions":4097}`,
		`{"version":"checkpoint-history/v1","max_revisions":1.5}`,
		`{"version":"checkpoint-history/v1","max_revisions":true}`,
		`{"version":"checkpoint-history/v1","max_revisions":4096,"override":true}`,
	} {
		if validateAssetContent(AssetMemory, []byte(`{"max_entries":8192,"checkpoint_history":`+history+`}`)) == nil {
			t.Fatal("invalid capacity published", history)
		}
	}
}
