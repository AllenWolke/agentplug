package policyasset

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublishedBatchProfileKeepsTaskAndItemBoundsConsistent(t *testing.T) {
	for _, elapsed := range []int{300, 1800} {
		p := RuntimePolicy{TaskTimeoutSeconds: elapsed, Batch: &BatchPolicy{MaxItems: 1000, ItemTimeoutSeconds: 30, ElapsedSeconds: elapsed}}
		if err := p.ValidateContext(); err != nil {
			t.Fatal(err)
		}
		p.Batch.ElapsedSeconds++
		if p.ValidateContext() == nil {
			t.Fatal("conflicting batch/task deadline accepted")
		}
	}
	for _, p := range []BatchPolicy{{0, 30, 300}, {10001, 30, 300}, {100, 301, 300}, {100, 0, 300}, {100, 30, 3601}} {
		if p.Validate(p.ElapsedSeconds) == nil {
			t.Fatal("unbounded batch profile accepted", p)
		}
	}
	raw, err := json.Marshal(RuntimePolicy{TaskTimeoutSeconds: 300})
	if err != nil || strings.Contains(string(raw), `"batch"`) {
		t.Fatal("optional extension changed legacy serialization", err)
	}
}
