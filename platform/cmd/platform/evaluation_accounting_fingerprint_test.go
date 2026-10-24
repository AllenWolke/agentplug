package main

import (
	"encoding/json"
	"testing"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func TestEvaluationOldNumericFingerprintAllowsOnlyAccountingAfterStopIntent(t *testing.T) {
	request := contract.ExecuteRequest{Input: map[string]any{"coverage": json.Number("1.0")}}
	old := legacyEvaluationAccountingFingerprint(request)
	current, err := contract.CanonicalExecuteBodyHash(request)
	if err != nil || old == current {
		t.Fatal("fixture must reproduce actual old numeric signature")
	}
	for _, status := range []platformruntime.Status{platformruntime.StatusAccepted, platformruntime.StatusRunning, platformruntime.StatusWaiting, platformruntime.StatusRecovering, platformruntime.StatusCancelling, platformruntime.StatusCancelled, platformruntime.StatusFailed, platformruntime.StatusSucceeded} {
		stopping := status == platformruntime.StatusCancelling || status == platformruntime.StatusCancelled || status == platformruntime.StatusFailed || status == platformruntime.StatusSucceeded
		if evaluationAccountingFingerprintMatches(request, old, false, status) != stopping {
			t.Fatalf("unexpected accounting authority at %s", status)
		}
		if evaluationAccountingFingerprintMatches(request, old, true, status) {
			t.Fatalf("old fingerprint admitted new work at %s", status)
		}
		if !evaluationAccountingFingerprintMatches(request, current, false, status) {
			t.Fatal("current fingerprint rejected")
		}
	}
	request.Input["coverage"] = json.Number("0.0")
	if evaluationAccountingFingerprintMatches(request, old, false, platformruntime.StatusCancelling) {
		t.Fatal("changed persisted evidence accepted")
	}
}
