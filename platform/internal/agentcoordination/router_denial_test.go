package agentcoordination

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type denialStageStore struct{ tx denialStageTransaction }

func (s denialStageStore) Transact(ctx context.Context, _ sharedkernel.Scope, operation func(RouteTransaction) error) error {
	return operation(s.tx)
}

type denialStageTransaction struct {
	parent     ParentFacts
	candidates []Target
	authorize  error
}

func (t denialStageTransaction) Parent(context.Context, sharedkernel.Scope) (ParentFacts, error) {
	return t.parent, nil
}
func (t denialStageTransaction) Candidates(context.Context, ParentFacts, string) ([]Target, error) {
	return t.candidates, nil
}
func (t denialStageTransaction) AuthorizeTarget(context.Context, ParentFacts, Target) error {
	return t.authorize
}
func (denialStageTransaction) Existing(string) (RoutePlan, bool, error) {
	return RoutePlan{}, false, nil
}
func (denialStageTransaction) Reserve(RoutePlan) error { return nil }
func (denialStageTransaction) Audit(RoutePlan) error   { return nil }

func TestClassifiedRouteErrorPreservesIdentityAndRedactsCause(t *testing.T) {
	secret := errors.New("private-permission-row-and-request-body")
	err := ClassifyRouteError(RouteDenialTargetAuthorization, RouteReasonCallerDelegate, fmt.Errorf("sensitive details: %w", ErrDenied))
	if !errors.Is(err, ErrDenied) {
		t.Fatal("classified denial no longer matches ErrDenied")
	}
	if strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "private") {
		t.Fatalf("classified denial exposed underlying details: %q", err.Error())
	}
	stage, reason, ok := RouteErrorClassification(err)
	if !ok || stage != RouteDenialTargetAuthorization || reason != RouteReasonCallerDelegate {
		t.Fatalf("classification lost: stage=%q reason=%q ok=%v", stage, reason, ok)
	}

	backend := ClassifyRouteError(RouteDenialCandidates, RouteReasonCandidateCatalog, secret)
	if errors.Is(backend, ErrDenied) || !errors.Is(backend, secret) || strings.Contains(backend.Error(), secret.Error()) {
		t.Fatalf("backend error identity or redaction changed: %q", backend.Error())
	}
	if _, _, ok := RouteErrorClassification(ClassifyRouteError("caller_input", "untrusted-value", ErrDenied)); ok {
		t.Fatal("unallowlisted route classification became loggable")
	}
}

func TestEligibilityClassificationSeparatesScopePolicyTaskAndAncestor(t *testing.T) {
	parent := ParentFacts{
		Scope:  sharedkernel.Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentID: "go-agent", InstallationID: "go-install"},
		Policy: &policyasset.AgentDelegationPolicy{AllowedAgentIDs: []string{"python-agent"}},
	}
	target := Target{
		TenantID: "tenant", DepartmentID: "department", ApplicationID: "application",
		AgentID: "python-agent", InstallationID: "python-install", InstallationRevision: 1,
		VersionID: "python-v1", DeploymentID: "deploy-1", DeploymentRevision: 1,
		ManifestHash: "sha256:" + strings.Repeat("a", 64),
		InputSchema:  "schema://python/input/v1", OutputSchema: "schema://python/output/v1",
		TaskTypes: []string{"documents.answer"}, Published: true, Ready: true,
	}
	if reason := eligibilityDenial(parent, target, "documents.answer"); reason != "" || !eligible(parent, target, "documents.answer") {
		t.Fatalf("valid candidate rejected: reason=%q", reason)
	}

	wrongScope := target
	wrongScope.TenantID = "other-tenant"
	if got := eligibilityDenial(parent, wrongScope, "documents.answer"); got != RouteReasonCandidateScope {
		t.Fatalf("scope mismatch classified as %q", got)
	}
	wrongPolicy := parent
	wrongPolicy.Policy = &policyasset.AgentDelegationPolicy{AllowedAgentIDs: []string{"java-agent"}}
	if got := eligibilityDenial(wrongPolicy, target, "documents.answer"); got != RouteReasonCandidatePolicy {
		t.Fatalf("policy mismatch classified as %q", got)
	}
	if got := eligibilityDenial(parent, target, "documents.read"); got != RouteReasonCandidateTask {
		t.Fatalf("task mismatch classified as %q", got)
	}
	ancestor := parent
	ancestor.AncestorInstallations = []string{target.InstallationID}
	if got := eligibilityDenial(ancestor, target, "documents.answer"); got != RouteReasonCandidateAncestor {
		t.Fatalf("ancestor cycle classified as %q", got)
	}
	malformed := target
	malformed.ManifestHash = "secret-manifest"
	if got := eligibilityDenial(parent, malformed, "documents.answer"); got != RouteReasonCandidateShape {
		t.Fatalf("malformed target classified as %q", got)
	}
}

func TestRouterPlanClassifiesFirstTargetDenialWithoutChangingErrDenied(t *testing.T) {
	scope := sharedkernel.Scope{
		TenantID: "tenant", DepartmentID: "department", ApplicationID: "application",
		AgentInstanceID: "go-install", InstallationID: "go-install", AgentID: "go-agent", AgentVersionID: "go-v1",
		PrincipalType: "user", PrincipalID: "caller", SessionID: "session", RunID: "root-run",
		AuthorizationEpoch: 3, TraceID: "0123456789abcdef0123456789abcdef",
	}
	parent := ParentFacts{Scope: scope, PolicyHash: strings.Repeat("b", 64), Active: true,
		Policy: &policyasset.AgentDelegationPolicy{AllowedAgentIDs: []string{"python-agent"}, TaskTypes: []string{"documents.answer"}, MaxDepth: 1, MaxChildren: 1}}
	target := Target{
		TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
		AgentID: "python-agent", InstallationID: "python-install", InstallationRevision: 1,
		VersionID: "python-v1", DeploymentID: "deploy-1", DeploymentRevision: 1,
		ManifestHash: "sha256:" + strings.Repeat("a", 64), InputSchema: "schema://python/input/v1",
		OutputSchema: "schema://python/output/v1", TaskTypes: []string{"documents.answer"}, Published: true, Ready: true,
	}

	cases := []struct {
		name       string
		candidates []Target
		authorize  error
		request    RouteRequest
		stage      RouteDenialStage
		reason     RouteDenialReason
	}{
		{name: "candidate target authorization", candidates: []Target{target}, authorize: ErrDenied, request: RouteRequest{OperationKey: "op1", TaskType: "documents.answer", Count: 1}, stage: RouteDenialTargetAuthorization, reason: RouteReasonCandidateAuthorization},
		{name: "caller target delegate branch", candidates: []Target{target}, authorize: ClassifyRouteError(RouteDenialTargetAuthorization, RouteReasonCallerDelegate, ErrDenied), request: RouteRequest{OperationKey: "op5", TaskType: "documents.answer", Count: 1}, stage: RouteDenialTargetAuthorization, reason: RouteReasonCallerDelegate},
		{name: "no resolved candidates", request: RouteRequest{OperationKey: "op2", TaskType: "documents.answer", Count: 1}, stage: RouteDenialCandidates, reason: RouteReasonCandidateEmpty},
		{name: "candidate task mismatch", candidates: []Target{target}, request: RouteRequest{OperationKey: "op3", TaskType: "documents.read", Count: 1}, stage: RouteDenialParent, reason: RouteReasonParentTask},
		{name: "invalid command", candidates: []Target{target}, request: RouteRequest{OperationKey: "op4", TaskType: "documents.answer", Count: 0}, stage: RouteDenialRequest, reason: RouteReasonInvalidRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, err := NewRouter(denialStageStore{tx: denialStageTransaction{parent: parent, candidates: tc.candidates, authorize: tc.authorize}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = router.Plan(context.Background(), scope, tc.request)
			if !errors.Is(err, ErrDenied) {
				t.Fatalf("denial identity changed: %v", err)
			}
			stage, reason, ok := RouteErrorClassification(err)
			if !ok || stage != tc.stage || reason != tc.reason {
				t.Fatalf("got stage=%q reason=%q ok=%v err=%v", stage, reason, ok, err)
			}
		})
	}
}
