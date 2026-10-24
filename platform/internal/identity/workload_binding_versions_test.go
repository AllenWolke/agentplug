package identity

import "testing"

func TestWorkloadBindingVersionSchemaFailsClosed(t *testing.T) {
	legacy := WorkloadBinding{AgentVersionID: "old"}
	if validateWorkloadBindingVersions(legacy) != nil || !workloadBindingAllowsVersion(legacy, "old") || workloadBindingAllowsVersion(legacy, "new") {
		t.Fatal("legacy binding changed")
	}
	valid := WorkloadBinding{SchemaVersion: WorkloadBindingSchemaV2, AgentVersionID: "new", AllowedAgentVersionIDs: []string{"new", "old"}}
	if validateWorkloadBindingVersions(valid) != nil || !workloadBindingAllowsVersion(valid, "old") || workloadBindingAllowsVersion(valid, "undeclared") {
		t.Fatal("explicit version set not enforced")
	}
	for _, tc := range []WorkloadBinding{
		{AgentVersionID: "old", AllowedAgentVersionIDs: []string{"old", "new"}},
		{SchemaVersion: "workload-binding/v3", AgentVersionID: "old", AllowedAgentVersionIDs: []string{"old"}},
		{SchemaVersion: WorkloadBindingSchemaV2, AgentVersionID: "new", AllowedAgentVersionIDs: []string{"old"}},
		{SchemaVersion: WorkloadBindingSchemaV2, AgentVersionID: "new", AllowedAgentVersionIDs: []string{"new", "new"}},
		{SchemaVersion: WorkloadBindingSchemaV2, AgentVersionID: "new", AllowedAgentVersionIDs: []string{"new", ""}},
		{SchemaVersion: WorkloadBindingSchemaV2, AgentVersionID: "new"},
	} {
		if validateWorkloadBindingVersions(tc) == nil {
			t.Fatal("ambiguous or undeclared version accepted", tc)
		}
	}
}
