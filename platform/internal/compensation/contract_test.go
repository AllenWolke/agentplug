package compensation

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func hash(value string) string { h := sha256.Sum256([]byte(value)); return hex.EncodeToString(h[:]) }
func testScope() sharedkernel.Scope {
	return sharedkernel.Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "app", AgentInstanceID: "instance", AgentID: "agent", PrincipalID: "user", PrincipalType: "user", InstallationID: "install", AgentVersionID: "version", SessionID: "session", RunID: "run", TraceID: "trace", AuthorizationEpoch: 1}
}
func testStep() Step {
	scope := testScope()
	s := Step{Root: scope, Scope: scope, Kind: "tool", Tool: "example.write", Provider: "example", ProviderVersion: "v1", CallID: "call", Fingerprint: hash("immutable forward request"), Ref: "effect-call"}
	s.ID = StepID(s.Scope, s.Kind, s.CallID)
	return s
}
func testReceipt(s Step, action string) Receipt {
	return Receipt{Version: ContractVersion, StepDigest: s.Digest(), Key: s.CompensationKey(), Action: action, EvidenceDigest: hash("actual inverse receipt")}
}

func TestStepCanonicalDependencySetAndBoundedOpaqueReference(t *testing.T) {
	s := testStep()
	s.DependsOn = []string{hash("b"), hash("a")}
	other := s
	other.DependsOn = []string{hash("a"), hash("b")}
	if s.Validate() != nil || s.Digest() != other.Digest() || s.CompensationKey() != other.CompensationKey() {
		t.Fatal("equivalent dependency sets changed the operation binding")
	}
	for _, ref := range []string{"https://service/undo", "secret\nvalue", strings.Repeat("x", 256)} {
		other := s
		other.Ref = ref
		if other.Validate() == nil {
			t.Fatal("non-opaque or oversized reference accepted")
		}
	}
	s.DependsOn = append(s.DependsOn, s.DependsOn[0])
	if s.Validate() == nil {
		t.Fatal("duplicate dependency accepted")
	}
}

func TestScopeVersionAndProviderChangesDoNotReuseCompensation(t *testing.T) {
	s := testStep()
	for _, modify := range []func(*Step){
		func(v *Step) { v.Scope.PrincipalID = "other"; v.ID = StepID(v.Scope, v.Kind, v.CallID) },
		func(v *Step) { v.ProviderVersion = "v2" },
		func(v *Step) { v.Fingerprint = hash("different request") },
		func(v *Step) { v.Scope.AgentVersionID = "v2"; v.ID = StepID(v.Scope, v.Kind, v.CallID) },
	} {
		other := s
		modify(&other)
		if s.CompensationKey() == other.CompensationKey() || testReceipt(s, "rolled_back").Validate(other) == nil {
			t.Fatal("operation/identity/version changed without invalidating the receipt")
		}
	}
	other := s
	other.Scope.TenantID = "other"
	other.ID = StepID(other.Scope, other.Kind, other.CallID)
	if other.Validate() == nil {
		t.Fatal("cross-tenant effect root accepted")
	}
}

func TestOnlyCompleteBusinessDispositionsAreReceipts(t *testing.T) {
	s := testStep()
	for _, action := range []string{"rolled_back", "withdrawn", "corrected", "no_effect"} {
		if testReceipt(s, action).Validate(s) != nil {
			t.Fatal(action)
		}
	}
	for _, action := range []string{"accepted", "queued", "http_200", "sent", "unknown", "applied"} {
		if testReceipt(s, action).Validate(s) == nil {
			t.Fatal("nonterminal disposition accepted", action)
		}
	}
	r := testReceipt(s, "rolled_back")
	r.EvidenceDigest = ""
	if r.Validate(s) == nil {
		t.Fatal("missing authoritative evidence accepted")
	}
}

func TestStopProofCannotCrossRunOrLoseRevision(t *testing.T) {
	s := testScope()
	proof := StopProof{Version: "cancellation-tree-stop/v1", ScopeDigest: ScopeDigest(s), Revision: 2, EvidenceDigest: hash("complete stopped tree")}
	if proof.Validate(s) != nil {
		t.Fatal("bound proof rejected")
	}
	other := s
	other.RunID = "other"
	if proof.Validate(other) == nil {
		t.Fatal("stop proof crossed Run")
	}
	proof.Revision = 0
	if proof.Validate(s) == nil {
		t.Fatal("unversioned proof accepted")
	}
}
