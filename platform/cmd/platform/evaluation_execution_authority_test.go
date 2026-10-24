package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/evaluationproduct"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestEvaluationInvocationAuthorityBindsParentCaseAndUser(t *testing.T) {
	parentID, parentKey := "eval-parent-1", "eval-idem-key-1"
	scope := sharedkernel.Scope{
		TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a",
		AgentInstanceID: "installation-a", InstallationID: "installation-a", AgentID: "agent-a", AgentVersionID: "version-a",
		PrincipalType: string(identity.PrincipalUser), PrincipalID: "alice", AuthorizationEpoch: 7,
		SessionID: evaluationSessionID(parentID, 1), RunID: evaluationExecutionRunID(parentID, 1), ParentRunID: parentID,
	}
	request := contract.ExecuteRequest{
		Scope: evaluationContractScope(scope), Operation: "invoke", IdempotencyKey: evaluationCaseIdempotencyKey(parentKey, 1),
	}
	if index, ok := evaluationInvocationIndex(parentID, parentKey, scope, request, 2); !ok || index != 1 {
		t.Fatalf("exact case binding rejected: index=%d ok=%v", index, ok)
	}

	cases := map[string]func(*sharedkernel.Scope, *contract.ExecuteRequest){
		"foreign parent": func(s *sharedkernel.Scope, r *contract.ExecuteRequest) { r.Scope.ParentRunID = "other-parent" },
		"wrong case key": func(_ *sharedkernel.Scope, r *contract.ExecuteRequest) {
			r.IdempotencyKey = evaluationCaseIdempotencyKey(parentKey, 0)
		},
		"wrong child run": func(s *sharedkernel.Scope, r *contract.ExecuteRequest) {
			s.RunID = evaluationExecutionRunID(parentID, 0)
			r.Scope.RunID = s.RunID
		},
		"wrong session": func(s *sharedkernel.Scope, _ *contract.ExecuteRequest) {
			s.SessionID = evaluationSessionID(parentID, 0)
		},
		"delegated depth": func(_ *sharedkernel.Scope, r *contract.ExecuteRequest) { r.Scope.DelegationDepth = 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			badScope, badRequest := scope, request
			mutate(&badScope, &badRequest)
			if _, ok := evaluationInvocationIndex(parentID, parentKey, badScope, badRequest, 2); ok {
				t.Fatal("forged parent/case binding was accepted")
			}
		})
	}

	parent := evaluationproduct.Resource{
		ID: parentID, Kind: evaluationproduct.KindRun, Scope: evaluationProductScope(scope), Status: "running", CreatedBy: "alice",
	}
	if !evaluationCreatorMatches(parent, scope) {
		t.Fatal("matching persisted creator was rejected")
	}
	foreign := scope
	foreign.PrincipalID = "bob"
	if evaluationCreatorMatches(parent, foreign) {
		t.Fatal("foreign user matched evaluation parent")
	}
	foreignScope := scope
	foreignScope.ApplicationID = "application-b"
	if evaluationCreatorMatches(parent, foreignScope) {
		t.Fatal("foreign application matched evaluation parent")
	}
}

func TestEvaluationInvocationAuthorityRejectsForgedInputAndPolicy(t *testing.T) {
	caseInput := json.RawMessage(`{"case_id":"sample-1","input":{"question":"approved?"},"expected":{"answer":"yes"}}`)
	request := map[string]any{"question": "approved?", "policy_snapshot": map[string]any{"runtime": map[string]any{"max_attempts": 1}}}
	if !evaluationCaseRequestMatches(caseInput, request) {
		t.Fatal("exact evaluator-visible input was rejected")
	}
	request["question"] = "foreign question"
	if evaluationCaseRequestMatches(caseInput, request) {
		t.Fatal("case input substitution was accepted")
	}
	request["question"] = "approved?"
	request["unexpected"] = true
	if evaluationCaseRequestMatches(caseInput, request) {
		t.Fatal("extra Agent input was accepted")
	}
	request = map[string]any{"question": "approved?"}
	if evaluationCaseRequestMatches(json.RawMessage(`{"case_id":"sample-1","input":{"question":"approved?","policy_snapshot":{}},"expected":{"answer":"yes"}}`), request) {
		t.Fatal("dataset-supplied policy snapshot was accepted")
	}
	if !evaluationInputHasPolicy(map[string]any{"question": "q", "policy_snapshot": map[string]any{"revision": 2}}, map[string]any{"revision": 2}) {
		t.Fatal("exact published policy input was rejected")
	}
	if evaluationInputHasPolicy(map[string]any{"policy_snapshot": map[string]any{"revision": 1}}, map[string]any{"revision": 2}) {
		t.Fatal("different policy snapshot was accepted")
	}
}

func TestFrozenEvaluationNumbersSurviveDurableExecutionBoundaries(t *testing.T) {
	caseInput := json.RawMessage(`{"case_id":"numeric-source","input":{"evidence":{"facts_check":{"citation_coverage":1.0,"large_id":9007199254740993,"thresholds":[-0.0,1e+3]}}},"expected":{}}`)
	var sample struct {
		Input json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(caseInput, &sample); err != nil {
		t.Fatal(err)
	}
	raw := append(append([]byte(`{"input":`), sample.Input...), '}')
	for boundary := 0; boundary < 5; boundary++ {
		var request contract.ExecuteRequest
		if err := contract.DecodeJSONPreservingNumbers(raw, &request); err != nil {
			t.Fatal(err)
		}
		request.Input["policy_snapshot"] = map[string]any{"revision": 1}
		if !evaluationCaseRequestMatches(caseInput, request.Input) {
			t.Fatalf("unchanged source rejected at durable boundary %d", boundary)
		}
		var err error
		raw, err = json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
	}
	var lossy contract.ExecuteRequest
	if json.Unmarshal(raw, &lossy) != nil || evaluationCaseRequestMatches(caseInput, lossy.Input) {
		t.Fatal("lossy float64 reconstruction must remain rejected")
	}
	var changed contract.ExecuteRequest
	if err := contract.DecodeJSONPreservingNumbers(raw, &changed); err != nil {
		t.Fatal(err)
	}
	facts := changed.Input["evidence"].(map[string]any)["facts_check"].(map[string]any)
	facts["citation_coverage"] = json.Number("0.0")
	if evaluationCaseRequestMatches(caseInput, changed.Input) {
		t.Fatal("actual source evidence substitution was accepted")
	}
}

func TestFrozenEvaluationNativeNumericCorpus(t *testing.T) {
	files := os.Getenv("EVALUATION_NUMBER_CORPUS_FILES")
	if files == "" {
		// This project's public fixture exercises exact numeric boundaries
		// without importing either reference Agent's business corpus.
		raw, err := json.Marshal([]string{filepath.Join("..", "..", "..", "contracts", "fixtures", "evaluation-numeric-public-v1.json")})
		if err != nil {
			t.Fatal(err)
		}
		files = string(raw)
	}
	var paths []string
	if json.Unmarshal([]byte(files), &paths) != nil || len(paths) == 0 {
		t.Fatal("invalid frozen corpus configuration")
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var dataset struct {
			Cases []json.RawMessage `json:"cases"`
		}
		if json.Unmarshal(raw, &dataset) != nil || len(dataset.Cases) != 60 {
			t.Fatal("exact frozen 60-case dataset required")
		}
		for index, sample := range dataset.Cases {
			var fields struct {
				Input json.RawMessage `json:"input"`
			}
			if json.Unmarshal(sample, &fields) != nil {
				t.Fatal("case input unavailable")
			}
			envelope := append(append([]byte(`{"input":`), fields.Input...), '}')
			var request contract.ExecuteRequest
			if contract.DecodeJSONPreservingNumbers(envelope, &request) != nil || !evaluationCaseRequestMatches(sample, request.Input) {
				t.Fatalf("native case %d changed at durable decode", index)
			}
			forwarded, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			var restored contract.ExecuteRequest
			if contract.DecodeJSONPreservingNumbers(forwarded, &restored) != nil || !evaluationCaseRequestMatches(sample, restored.Input) {
				t.Fatalf("native case %d changed after forwarding", index)
			}
		}
		t.Logf("preserved all %d frozen native cases", len(dataset.Cases))
	}
}

func TestEvaluationContinuationRequiresLiveLeaseExactMachineAndCurrentEpoch(t *testing.T) {
	scope := sharedkernel.Scope{
		TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a",
		InstallationID: "installation-a", AgentID: "agent-a", AgentVersionID: "version-a",
	}
	binding := identity.WorkloadBinding{
		TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
		InstallationID: scope.InstallationID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID,
		PrincipalID: "machine-a", Status: "active", Revision: 3,
	}
	if !evaluationWorkloadBindingMatches(scope, binding) {
		t.Fatal("exact active workload binding was rejected")
	}
	credential := identity.MachineCredential{TenantID: scope.TenantID, PrincipalID: binding.PrincipalID, Status: "active", Revision: 2}
	if !workloadCredentialMatches(binding, credential) {
		t.Fatal("exact active machine credential was rejected")
	}
	credentialCases := map[string]func(*identity.MachineCredential){
		"revoked":           func(c *identity.MachineCredential) { c.Status = "disabled" },
		"missing revision":  func(c *identity.MachineCredential) { c.Revision = 0 },
		"foreign principal": func(c *identity.MachineCredential) { c.PrincipalID = "machine-b" },
	}
	for name, mutate := range credentialCases {
		t.Run("credential/"+name, func(t *testing.T) {
			bad := credential
			mutate(&bad)
			if workloadCredentialMatches(binding, bad) {
				t.Fatal("revoked or foreign machine credential was accepted")
			}
		})
	}
	mutations := map[string]func(*identity.WorkloadBinding){
		"inactive":            func(b *identity.WorkloadBinding) { b.Status = "revoked" },
		"wrong installation":  func(b *identity.WorkloadBinding) { b.InstallationID = "installation-b" },
		"wrong agent version": func(b *identity.WorkloadBinding) { b.AgentVersionID = "version-b" },
		"missing revision":    func(b *identity.WorkloadBinding) { b.Revision = 0 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			bad := binding
			mutate(&bad)
			if evaluationWorkloadBindingMatches(scope, bad) {
				t.Fatal("inactive or foreign workload binding was accepted")
			}
		})
	}
	if !evaluationRunEpochMatches(9, 9) || evaluationRunEpochMatches(9, 10) || evaluationRunEpochMatches(9, 0) || evaluationRunEpochMatches(0, 0) {
		t.Fatal("revoked or missing actor run epoch was accepted")
	}
	if !evaluationScopeMatchesSnapshot(scope, "agent-a", "version-a") || evaluationScopeMatchesSnapshot(scope, "agent-b", "version-a") || evaluationScopeMatchesSnapshot(scope, "agent-a", "version-b") {
		t.Fatal("evaluation scope did not stay bound to the suite agent/version")
	}
	if !evaluationEndpointMatches("http://agent-a/internal", "http://agent-a/internal") || evaluationEndpointMatches("http://agent-a/internal", "http://attacker/internal") || evaluationEndpointMatches("", "http://agent-a/internal") {
		t.Fatal("synchronous Agent endpoint bypassed the Catalog binding")
	}
	parent := evaluationproduct.Resource{Status: "running"}
	lease := evaluationRunLease{ExecutionState: "running", LeaseOwner: "worker", LeaseToken: "opaque-token", LeaseUntil: time.Now().UTC().Add(time.Minute), AgentID: "agent-a", AgentVersionID: "version-a", IdempotencyKey: "eval-idem-key-1"}
	if !evaluationParentLeaseMatches(parent, lease, time.Now().UTC()) {
		t.Fatal("live product Evaluation lease was rejected")
	}
	if evaluationParentLeaseMatches(parent, lease, lease.LeaseUntil) {
		t.Fatal("expired parent lease was accepted")
	}
	parent.Status = "cancelled"
	if evaluationParentLeaseMatches(parent, lease, time.Now().UTC()) {
		t.Fatal("cancelled product Evaluation Run was accepted")
	}
}

func TestEvaluationBudgetAccountingAcceptsExpiredRunningParentButAdmissionDoesNot(t *testing.T) {
	now := time.Now().UTC()
	parent := evaluationproduct.Resource{Status: "running"}
	lease := evaluationRunLease{
		ExecutionState: "running", LeaseOwner: "worker", LeaseToken: "expired-token",
		LeaseUntil: now.Add(-time.Minute), AgentID: "agent-a", AgentVersionID: "version-a", IdempotencyKey: "evaluation-key",
	}
	if evaluationParentBudgetStateMatches(parent, lease, true, now) {
		t.Fatal("new admission accepted an expired Evaluation parent lease")
	}
	if !evaluationParentBudgetStateMatches(parent, lease, false, now) {
		t.Fatal("historical accounting rejected known work only because the Evaluation parent lease expired")
	}
	lease.ExecutionState = "failed"
	if evaluationParentBudgetStateMatches(parent, lease, false, now) {
		t.Fatal("historical accounting accepted inconsistent parent head and payload state")
	}
	parent.Status, lease.ExecutionState = "succeeded", "succeeded"
	if !evaluationParentBudgetStateMatches(parent, lease, false, now) {
		t.Fatal("historical accounting rejected a matching completed Evaluation parent")
	}
	if evaluationParentBudgetStateMatches(parent, lease, true, now) {
		t.Fatal("new admission accepted a completed Evaluation parent")
	}
}

func TestEvaluationBudgetPolicyComesFromExactFrozenInputAndKeepsFiniteLimits(t *testing.T) {
	snapshot := policyasset.Snapshot{
		ModelProfileID: "model-v1", PromptVersionID: "prompt-v1", ToolPolicyID: "tool-v1",
		MemoryPolicyID: "memory-v1", KnowledgePolicyID: "knowledge-v1", RuntimePolicyID: "runtime-v1",
		Revision: 2, Hash: strings.Repeat("a", 64),
		Model:     policyasset.ModelPolicy{Provider: "local", Model: "approved", MaxTokens: 512},
		Prompt:    policyasset.PromptPolicy{TemplateHash: "prompt-hash", Template: "approved"},
		Tool:      policyasset.ToolPolicy{AllowedTools: []string{"knowledge.search"}},
		Memory:    policyasset.MemoryPolicy{MaxEntries: 10},
		Knowledge: policyasset.KnowledgePolicy{AllowedScopes: []string{"public-reference"}},
		Runtime:   policyasset.RuntimePolicy{MaxAttempts: 2, TaskTimeoutSeconds: 60, LeaseSeconds: 120, RunBudget: &policyasset.RunBudgetPolicy{LimitTokens: 16_000, LimitMicros: 1_600_000}},
	}
	input, err := snapshot.ExecutionInput()
	if err != nil {
		t.Fatalf("materialize approved policy input: %v", err)
	}
	got, ok := policyFromEvaluationInput(map[string]any{"policy_snapshot": input})
	if !ok || got.Hash != snapshot.Hash || got.Runtime.RunBudget == nil || got.Runtime.RunBudget.LimitTokens != 16_000 || got.Runtime.RunBudget.LimitMicros != 1_600_000 {
		t.Fatalf("exact finite policy snapshot was not recovered: ok=%v snapshot=%+v", ok, got)
	}
	if !evaluationPolicyInputMatchesCurrent(input, snapshot) {
		t.Fatal("exact current policy snapshot failed its admission comparison")
	}
	changedHash := make(map[string]any, len(input))
	for key, value := range input {
		changedHash[key] = value
	}
	changedHash["content_hash"] = strings.Repeat("b", 64)
	if evaluationPolicyInputMatchesCurrent(changedHash, snapshot) {
		t.Fatal("admission accepted a different current policy hash")
	}

	mutations := map[string]func(map[string]any){
		"extra policy field": func(policy map[string]any) { policy["unapproved_override"] = true },
		"negative token limit": func(policy map[string]any) {
			runtime := policy["runtime"].(policyasset.RuntimePolicy)
			runtime.RunBudget.LimitTokens = -1
			policy["runtime"] = runtime
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := make(map[string]any, len(input))
			for key, value := range input {
				changed[key] = value
			}
			mutate(changed)
			if _, ok := policyFromEvaluationInput(map[string]any{"policy_snapshot": changed}); ok {
				t.Fatal("changed or extended policy input was accepted")
			}
		})
	}
}

func TestDelegationTargetScopeUsesVerifiedCallerEpoch(t *testing.T) {
	parent := sharedkernel.Scope{
		TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a",
		InstallationID: "caller-installation", AgentID: "caller", AgentVersionID: "caller-v1",
		AgentInstanceID: "caller-installation", PrincipalType: string(identity.PrincipalUser), PrincipalID: "alice",
		AuthorizationEpoch: 4, SessionID: "session-a", RunID: "parent-run", TraceID: "0123456789abcdef0123456789abcdef",
	}
	target := agentcoordination.Target{TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a", InstallationID: "target-installation", AgentID: "target", VersionID: "target-v1"}
	got := delegationTargetScopeWithEpoch(parent, target, parent.PrincipalType, parent.PrincipalID, 12)
	if got.AuthorizationEpoch != 12 || got.AuthorizationEpoch == parent.AuthorizationEpoch || got.InstallationID != target.InstallationID || got.AgentVersionID != target.VersionID || got.ValidateTrusted() != nil {
		t.Fatalf("target scope failed to carry verified caller epoch and exact target: %+v", got)
	}
}
