package policyasset

import "testing"

func TestModelRouteExecutionPolicyRequiresExplicitBoundedOptIn(t *testing.T) {
	base := ModelRouteAvailabilityPolicy{Version: "model-route-availability/v2", FailureThreshold: 1, CooldownSeconds: 30, ProbeSeconds: 10, MaxAttempts: 3, AttemptTimeoutSeconds: 10, UnknownOutcome: "retain_and_continue", ManualFallback: true}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, damage := range []string{"legacy-unknown", "legacy-manual", "legacy-timeout", "missing-timeout", "timeout-limit", "unknown-mode", "attempt-limit"} {
		t.Run(damage, func(t *testing.T) {
			p := base
			switch damage {
			case "legacy-unknown":
				p.Version = "model-route-availability/v1"
				p.ManualFallback = false
				p.AttemptTimeoutSeconds = 0
			case "legacy-manual":
				p.Version = "model-route-availability/v1"
				p.UnknownOutcome = ""
				p.AttemptTimeoutSeconds = 0
			case "legacy-timeout":
				p.Version = "model-route-availability/v1"
				p.UnknownOutcome = ""
				p.ManualFallback = false
			case "missing-timeout":
				p.AttemptTimeoutSeconds = 0
			case "timeout-limit":
				p.AttemptTimeoutSeconds = 61
			case "unknown-mode":
				p.UnknownOutcome = "assume_refunded"
			case "attempt-limit":
				p.MaxAttempts = 4
			}
			if p.Validate() == nil {
				t.Fatal("unbounded or legacy opt-in accepted")
			}
		})
	}
}
