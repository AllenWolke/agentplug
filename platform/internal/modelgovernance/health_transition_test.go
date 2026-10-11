package modelgovernance

import "testing"

func TestDeploymentHealthStatusMatchesPersistentCapacityTransition(t *testing.T) {
	for _, health := range []string{"unknown", "warming", "ready", "degraded", "unavailable", "draining"} {
		status, ok := DeploymentStatusForHealth(health)
		if !ok || !validHealthTransition(health, status) {
			t.Fatalf("HTTP/controller health %s status %s rejected by persistence", health, status)
		}
	}
	if status, _ := DeploymentStatusForHealth("degraded"); status != DeploymentReady {
		t.Fatal("degraded deployment must remain eligible for reduced capacity")
	}
	if _, ok := DeploymentStatusForHealth("invented"); ok {
		t.Fatal("unrecognized health accepted")
	}
	if validHealthTransition("ready", DeploymentFailed) {
		t.Fatal("conflicting status accepted")
	}
}
