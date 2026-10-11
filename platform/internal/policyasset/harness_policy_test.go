package policyasset

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHarnessLimitsRequireExplicitBoundedPublishedBehavior(t *testing.T) {
	legacy := RuntimePolicy{MaxAttempts: 1, TaskTimeoutSeconds: 300, LeaseSeconds: 30}
	encoded, err := json.Marshal(legacy)
	if err != nil || strings.Contains(string(encoded), `"harness"`) {
		t.Fatal("absence changed historical runtime serialization")
	}
	defaults, err := legacy.EffectiveHarnessPolicy()
	if err != nil || defaults != (HarnessPolicy{MaxRounds: 8, MaxToolCalls: 16, MaxRepeatedCalls: 1, MaxElapsedSeconds: 300, LimitBehavior: "error"}) {
		t.Fatal("unsafe legacy default")
	}
	valid := HarnessPolicy{MaxRounds: 4, MaxToolCalls: 8, MaxRepeatedCalls: 2, MaxElapsedSeconds: 120, LimitBehavior: "incomplete"}
	for _, change := range []func(*HarnessPolicy){
		func(p *HarnessPolicy) { p.MaxRounds = 0 }, func(p *HarnessPolicy) { p.MaxRounds = 9 },
		func(p *HarnessPolicy) { p.MaxToolCalls = 17 }, func(p *HarnessPolicy) { p.MaxRepeatedCalls = 0 },
		func(p *HarnessPolicy) { p.MaxRepeatedCalls = 5 }, func(p *HarnessPolicy) { p.MaxElapsedSeconds = 9 },
		func(p *HarnessPolicy) { p.MaxElapsedSeconds = 3601 }, func(p *HarnessPolicy) { p.LimitBehavior = "ignore" },
	} {
		invalid := valid
		change(&invalid)
		if (RuntimePolicy{Harness: &invalid}).ValidateContext() == nil {
			t.Fatal("invalid harness publication accepted")
		}
	}
	runtimePolicy := RuntimePolicy{Harness: &valid}
	selected, err := runtimePolicy.EffectiveHarnessPolicy()
	if err != nil || selected != valid {
		t.Fatal("approved bounds were replaced")
	}
	selected.MaxRounds = 8
	if runtimePolicy.Harness.MaxRounds != 4 {
		t.Fatal("caller mutated published policy")
	}
}
