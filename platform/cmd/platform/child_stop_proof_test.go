package main

import (
	"testing"

	"github.com/lexagent/platform/internal/agentcoordination"
)

func TestStopProofPinsOriginalRootCallerAndMachineGeneration(t *testing.T) {
	proof := agentcoordination.DelegationAuthorityProof{
		Version: "agent-delegation-authority/v1", RootRunID: "root-run", RootInstallationID: "root-install",
		RootPrincipalType: "user", RootPrincipalID: "caller", RootAuthorizationEpoch: 4,
		RootMachinePrincipalID: "root-machine", RootMachineRunEpoch: 9,
		Edges: []agentcoordination.DelegationAuthorityProofEdge{{
			ParentRunID: "root-run", ChildRunID: "child-run", ParentInstallationID: "root-install",
			ParentMachinePrincipalID: "root-machine", TargetInstallationID: "target-install",
			TargetAgentID: "target-agent", TargetVersionID: "target-v1",
			TargetManifestHash:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			CallerDelegateEpoch: 4, ParentMachineDelegateEpoch: 9,
			TargetMachinePrincipalID: "target-machine", TargetMachineRunEpoch: 12,
		}},
	}
	stamp := agentcoordination.RootMachineAuthorityStamp{
		RootRunID: proof.RootRunID, RootInstallationID: proof.RootInstallationID,
		RootPrincipalType: proof.RootPrincipalType, RootPrincipalID: proof.RootPrincipalID,
		RootAuthorizationEpoch: proof.RootAuthorizationEpoch,
		MachinePrincipalID:     proof.RootMachinePrincipalID, MachineRunEpoch: proof.RootMachineRunEpoch,
	}
	if !agentcoordination.ValidDelegationAuthorityProof(proof) || !stopProofMatchesRootStamp(proof, stamp) {
		t.Fatal("valid persisted root/child stop proof rejected")
	}
	mutations := map[string]func(*agentcoordination.RootMachineAuthorityStamp){
		"root run":          func(v *agentcoordination.RootMachineAuthorityStamp) { v.RootRunID = "other-run" },
		"root installation": func(v *agentcoordination.RootMachineAuthorityStamp) { v.RootInstallationID = "other-install" },
		"caller":            func(v *agentcoordination.RootMachineAuthorityStamp) { v.RootPrincipalID = "other-caller" },
		"caller epoch":      func(v *agentcoordination.RootMachineAuthorityStamp) { v.RootAuthorizationEpoch++ },
		"machine identity":  func(v *agentcoordination.RootMachineAuthorityStamp) { v.MachinePrincipalID = "other-machine" },
		"machine generation": func(v *agentcoordination.RootMachineAuthorityStamp) {
			v.MachineRunEpoch++
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := stamp
			mutate(&changed)
			if stopProofMatchesRootStamp(proof, changed) {
				t.Fatal("stop proof accepted a substituted persisted root identity or generation")
			}
		})
	}

	// A changed caller epoch in the current IAM system does not rewrite the
	// historical Run stamp; only changing the persisted stamp invalidates the
	// exact edge. Current execution is separately denied by normal auth checks.
	currentIAMCallerEpoch := uint64(5)
	if currentIAMCallerEpoch == stamp.RootAuthorizationEpoch || !stopProofMatchesRootStamp(proof, stamp) {
		t.Fatal("stop proof was incorrectly coupled to a newer caller IAM epoch")
	}
}
