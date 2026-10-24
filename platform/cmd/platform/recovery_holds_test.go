package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestAutomaticRecoveryHoldManifestBindsReviewedBytes(t *testing.T) {
	for _, variant := range []string{"valid", "disabled", "missing digest", "missing file", "wrong digest", "extra field", "wrong version", "duplicate Run", "null Runs", "invalid Run", "trailing JSON", "directory", "oversize", "offset without group", "negative Kafka offset", "duplicate Kafka partition", "invalid tool hash", "duplicate tool hash"} {
		t.Run(variant, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "holds.json")
			raw := []byte(`{"version":"automatic-recovery-holds/v1","run_ids":["old-run"]}`)
			switch variant {
			case "invalid tool hash":
				raw = []byte(`{"version":"automatic-recovery-holds/v1","run_ids":[],"tool_scope_hashes":["bad"]}`)
			case "duplicate tool hash":
				raw = []byte(`{"version":"automatic-recovery-holds/v1","run_ids":[],"tool_scope_hashes":["` + strings.Repeat("a", 64) + `","` + strings.Repeat("a", 64) + `"]}`)
			case "extra field":
				raw = []byte(`{"version":"automatic-recovery-holds/v1","run_ids":[],"release_all":true}`)
			case "wrong version":
				raw = []byte(`{"version":"automatic-recovery-holds/v2","run_ids":[]}`)
			case "duplicate Run":
				raw = []byte(`{"version":"automatic-recovery-holds/v1","run_ids":["old-run","old-run"]}`)
			case "null Runs":
				raw = []byte(`{"version":"automatic-recovery-holds/v1","run_ids":null}`)
			case "invalid Run":
				raw = []byte(`{"version":"automatic-recovery-holds/v1","run_ids":[" old-run"]}`)
			case "trailing JSON":
				raw = append(raw, []byte(` {}`)...)
			case "oversize":
				raw = []byte(strings.Repeat(" ", (8<<20)+1))
			case "offset without group":
				raw = []byte(`{"version":"automatic-recovery-holds/v1","run_ids":[],"kafka_start_offsets":[{"topic":"platform.audit","partition":0,"offset":11}]}`)
			case "negative Kafka offset":
				raw = []byte(`{"version":"automatic-recovery-holds/v1","run_ids":[],"kafka_group_id":"owned","kafka_start_offsets":[{"topic":"platform.audit","partition":0,"offset":-1}]}`)
			case "duplicate Kafka partition":
				raw = []byte(`{"version":"automatic-recovery-holds/v1","run_ids":[],"kafka_group_id":"owned","kafka_start_offsets":[{"topic":"platform.audit","partition":0,"offset":11},{"topic":"platform.audit","partition":0,"offset":12}]}`)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			digest := hex.EncodeToString(sum[:])
			switch variant {
			case "disabled":
				path, digest = "", ""
			case "missing digest":
				digest = ""
			case "wrong digest":
				digest = strings.Repeat("0", 64)
			case "missing file":
				path += ".absent"
			case "directory":
				path = filepath.Dir(path)
			}
			holds, err := readAutomaticRecoveryHolds(path, digest)
			if variant == "valid" {
				if err != nil || !holds.Contains("old-run") || holds.Contains("new-run") {
					t.Fatal("reviewed manifest binding failed", err)
				}
			} else if variant == "disabled" {
				if err != nil || holds.Len() != 0 {
					t.Fatal("legacy default changed", err)
				}
			} else if err == nil {
				t.Fatal("invalid manifest admitted")
			}
		})
	}
	ids := []string{"old-run"}
	holds, err := sharedkernel.NewRecoveryHolds(ids)
	if err != nil {
		t.Fatal(err)
	}
	ids[0] = "new-run"
	if !holds.Contains("old-run") || holds.Contains("new-run") {
		t.Fatal("caller mutated frozen holds")
	}
}
