package evaluationproduct

import "testing"

func routingTierFixture(tiers ...string) (map[string]float64, map[string]int, map[string]map[string]int) {
	reported, counts, correct := map[string]float64{}, map[string]int{}, map[string]map[string]int{}
	for _, tier := range tiers {
		counts[tier], correct[tier] = 20, map[string]int{}
		for metric := range routingQualityThresholds() {
			correct[tier][metric], reported[metric] = 20, 1
		}
	}
	return reported, counts, correct
}

func TestRoutingQualificationRequiresEveryEligibleTier(t *testing.T) {
	for maximum, tiers := range map[string][]string{"simple": {"simple"}, "medium": {"simple", "medium"}, "complex": {"simple", "medium", "complex"}} {
		t.Run(maximum, func(t *testing.T) {
			reported, counts, correct := routingTierFixture(tiers...)
			if err := verifyRoutingTierQuality(maximum, reported, counts, correct); err != nil {
				t.Fatal("fully qualified tiers were rejected", err)
			}
			counts[tiers[0]] = 19
			if verifyRoutingTierQuality(maximum, reported, counts, correct) == nil {
				t.Fatal("19 independent cases qualified a tier")
			}
		})
	}
	reported, counts, correct := routingTierFixture("complex")
	if verifyRoutingTierQuality("complex", reported, counts, correct) == nil {
		t.Fatal("complex-only evidence qualified simpler tasks")
	}
	if verifyRoutingTierQuality("unknown", reported, counts, correct) == nil {
		t.Fatal("unknown tier qualified")
	}
}

func TestRoutingQualificationDoesNotHideBadTierInAverage(t *testing.T) {
	reported, counts, correct := routingTierFixture("simple", "medium", "complex")
	// Overall 58/60 meets 95%, but complex 18/20 does not. Refuse publication.
	correct["complex"]["citation_accuracy"] = 18
	reported["citation_accuracy"] = 58.0 / 60
	if verifyRoutingTierQuality("complex", reported, counts, correct) == nil {
		t.Fatal("overall average hid an unsafe tier")
	}
	correct["complex"]["citation_accuracy"] = 19
	reported["citation_accuracy"] = 59.0 / 60
	correct["complex"]["task_success"] = 18
	reported["task_success"] = 58.0 / 60
	if err := verifyRoutingTierQuality("complex", reported, counts, correct); err != nil {
		t.Fatal("exact 90%/95% tier thresholds rejected", err)
	}
	reported["task_success"] = 1
	if verifyRoutingTierQuality("complex", reported, counts, correct) == nil {
		t.Fatal("reported quality did not match actual independent verdicts")
	}
	delete(reported, "domain_correctness")
	if verifyRoutingTierQuality("complex", reported, counts, correct) == nil {
		t.Fatal("missing quality metric qualified")
	}
}
