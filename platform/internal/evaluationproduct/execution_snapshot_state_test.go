package evaluationproduct

import (
	"testing"
	"time"
)

func TestExecutionSnapshotLiveAndHistoricalLeaseRules(t *testing.T) {
	now := time.Now().UTC()
	expired := RunData{ExecutionState: "running", LeaseOwner: "worker", LeaseToken: "old-token", LeaseUntil: now.Add(-time.Minute)}
	if executionSnapshotRunStateAllowed("running", expired, false, now) {
		t.Fatal("live snapshot resolution accepted an expired product lease")
	}
	if !executionSnapshotRunStateAllowed("running", expired, true, now) {
		t.Fatal("historical accounting provenance depended on the expired parent lease")
	}

	for _, status := range []string{"succeeded", "failed", "cancelling", "cancelled"} {
		data := RunData{ExecutionState: status}
		if !executionSnapshotRunStateAllowed(status, data, true, now) {
			t.Errorf("matching terminal parent %q rejected as historical provenance", status)
		}
		if executionSnapshotRunStateAllowed(status, data, false, now) {
			t.Errorf("terminal parent %q authorized a live execution", status)
		}
		data.ExecutionState = "running"
		if executionSnapshotRunStateAllowed(status, data, true, now) {
			t.Errorf("inconsistent terminal state %q was accepted", status)
		}
	}
	if executionSnapshotRunStateAllowed("queued", RunData{ExecutionState: "queued"}, true, now) {
		t.Fatal("queued product run was accepted as historical billing provenance")
	}
}
