package agentcoordination

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func validAuthorityProof() DelegationAuthorityProof {
	return DelegationAuthorityProof{
		Version: "agent-delegation-authority/v1", RootRunID: "root-run", RootInstallationID: "root-install",
		RootPrincipalType: "user", RootPrincipalID: "root-user", RootAuthorizationEpoch: 7,
		RootMachinePrincipalID: "root-machine", RootMachineRunEpoch: 4,
		Edges: []DelegationAuthorityProofEdge{
			{ParentRunID: "root-run", ChildRunID: "child-one", ParentInstallationID: "root-install", ParentMachinePrincipalID: "root-machine", TargetInstallationID: "install-one", TargetAgentID: "agent-one", TargetVersionID: "v1", TargetManifestHash: "sha256:manifest-one", CallerDelegateEpoch: 2, ParentMachineDelegateEpoch: 3, TargetMachinePrincipalID: "machine-one", TargetMachineRunEpoch: 8},
			{ParentRunID: "child-one", ChildRunID: "child-two", ParentInstallationID: "install-one", ParentMachinePrincipalID: "machine-one", TargetInstallationID: "install-two", TargetAgentID: "agent-two", TargetVersionID: "v2", TargetManifestHash: "sha256:manifest-two", CallerDelegateEpoch: 5, ParentMachineDelegateEpoch: 6, TargetMachinePrincipalID: "machine-two", TargetMachineRunEpoch: 9},
		},
	}
}

func TestValidDelegationAuthorityProofRequiresContinuousExactIAMEdges(t *testing.T) {
	if !ValidDelegationAuthorityProof(validAuthorityProof()) {
		t.Fatal("valid two-edge internal authority proof was rejected")
	}
	cases := map[string]func(*DelegationAuthorityProof){
		"missing caller target delegation epoch":   func(p *DelegationAuthorityProof) { p.Edges[0].CallerDelegateEpoch = 0 },
		"missing parent workload delegation epoch": func(p *DelegationAuthorityProof) { p.Edges[0].ParentMachineDelegateEpoch = 0 },
		"missing target workload run epoch":        func(p *DelegationAuthorityProof) { p.Edges[0].TargetMachineRunEpoch = 0 },
		"broken parent child chain":                func(p *DelegationAuthorityProof) { p.Edges[1].ParentRunID = "unrelated-run" },
		"workload identity changed between edges":  func(p *DelegationAuthorityProof) { p.Edges[1].ParentMachinePrincipalID = "other-machine" },
		"replayed child run":                       func(p *DelegationAuthorityProof) { p.Edges[1].ChildRunID = p.Edges[0].ChildRunID },
		"wrong root workload":                      func(p *DelegationAuthorityProof) { p.Edges[0].ParentMachinePrincipalID = "other-root-machine" },
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			proof := validAuthorityProof()
			alter(&proof)
			if ValidDelegationAuthorityProof(proof) {
				t.Fatal("malformed authority proof was accepted")
			}
		})
	}
}

func TestDelegationAuthorityJSONRejectsUntrustedExtensions(t *testing.T) {
	raw, err := json.Marshal(validAuthorityProof())
	if err != nil || !validDelegationAuthorityJSON(string(raw)) {
		t.Fatal("valid internal proof JSON was rejected", err)
	}
	for _, suffix := range []string{` {"parent_run_id":"forged"}`, ` {"context_token":"must-never-persist"}`} {
		if validDelegationAuthorityJSON(string(raw) + suffix) {
			t.Fatal("untrusted JSON extension was accepted")
		}
	}
	var extended map[string]any
	if json.Unmarshal(raw, &extended) != nil {
		t.Fatal("test fixture decode failed")
	}
	extended["parent_run_id"] = "forged"
	encoded, _ := json.Marshal(extended)
	if validDelegationAuthorityJSON(string(encoded)) {
		t.Fatal("unknown parent field was accepted")
	}
}

func TestLockWaitErrorKeepsStatementCancelAndDeadlineOnly(t *testing.T) {
	if lockWaitError(nil) || lockWaitError(context.Canceled) || lockWaitError(errors.New("denied")) || lockWaitError(&pgconn.PgError{Code: "23505"}) {
		t.Fatal("non-wait classified as a lock wait")
	}
	if !lockWaitError(context.DeadlineExceeded) || !lockWaitError(fmt.Errorf("secret: %w", context.DeadlineExceeded)) || !lockWaitError(&pgconn.PgError{Code: "55P03"}) || !lockWaitError(&pgconn.PgError{Code: "57014"}) {
		t.Fatal("lock wait was dropped")
	}
}
