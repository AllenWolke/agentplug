package architecture_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Explicit Port/DTO symbols: no automatic adoption of a passing baseline.
// 显式Port/DTO符号，不自动收编违规实现为通过基线。
var publicSymbols = map[string]string{
	"sqlutil":  "Bind IsUniqueViolation OpenPostgres SQLState TransactionDB",
	"identity": "AccessContext PrincipalType PrincipalUser PrincipalServicePrincipal",
	"audit":    "TxRecorder Event",
	// Typed denial classifications are a bounded diagnostic DTO, not a repository
	// or an authorization bypass. Capability uses them without raw error text.
	"agentcoordination": "AdmissionState ChildAdmission ChildAdmitRequest ChildCancellation ChildCancelRequest ChildPreparation ChildPrepareRequest ChildReadRequest ChildResult ChildStopControlConflictVersion ChildStopIdentity ChildStopRevisionConflict ClassifyRouteError RouteErrorClassification RouteDenialParent RouteReasonParentBoundContext RouteReasonParentLiveCheck RouteReasonParentPolicy ErrConflict ErrDenied GroupReadRequest GroupResult RoutePlan RouteRequest Router",
	"notification":      "TxEnqueuer Event ChannelAdapter ErrAdapterUnavailable ErrInvalidEvent",
	// Reviewed cancellation protocol ports, immutable DTOs and safe errors.
	// Concrete SQLStore/LocalEffectLedger constructors remain private to their owner.
	"compensation":    "Authority ContractVersion Coordinator CurrentLeaseFromContext EffectRegistry Engine ErrConflict ErrInvalid ErrNotSubmitted ErrPending ErrUnavailable LeaseFromContext LocalEffect LocalEffectRecorder MaxSteps OpenCoordinator OriginalEffect Port Progress Receipt Registration ScopeDigest Step StepID StopProof SweepStats WorkerStore",
	"reversibleapi":   "Hash Protocol Provider Request Response",
	"capability":      "ToolReceiptQuery ErrToolInvocationConflict ToolReceiptScopeHash ToolCommitGuard BusinessIssueCommand ToolCommandFingerprint BusinessReviewCommand BusinessToolStore",
	"agentgateway":    "Target ErrInvalidResponse ErrInvalidTarget EventStream CompletedExecutionFailure NewCompletedExecutionFailure",
	"modelcapacity":   "CapacityProvider Deployment ErrExceeded ErrUnavailable Lease ParseCapacityUnits RegisterPoolTx Request RuntimeDeployment UpdatePoolStateTx",
	"modelgateway":    "AccessResolver ErrEndpointUnresolved ErrModelUnavailable ErrRequestTooLarge ErrSecretUnavailable ErrUnsafeEndpoint GenerateRequest GenerateResult EmbeddingResult UsageEmbeddingPort Message ModelMetadata ModelMetadataPort Port ProviderMetadata ProviderMetadataPort Selection WithEmbeddingPurpose SafeProviderFailureKind ErrProviderUnavailable ErrResponseTooLarge ErrProviderResponse SecretResolver ValidateFunctionRequest",
	"modelgovernance": "ActionApprove Actor Authorizer ErrForbidden ErrModelAccessDenied ErrNotFound PriceVersion Scope StatusApproved TrustExternal TrustLocal",
	"policyasset":     "KnowledgeDocumentBinding ModelPolicy Resolver Snapshot SnapshotFromContext ToolPolicy FunctionDefinition ErrFunctionDenied AgentDelegationPolicy",
	"usagecost":       "ErrBudgetExceeded ErrBudgetReservationClosed ErrInvalidUsage Event ModelBudgetManualReleaseStore ModelBudgetReconciliationStore ModelBudgetRequest ModelBudgetReservation ModelBudgetScope ModelBudgetStore ModelBudgetWindow Recorder Scope StableModelUsageStepID ErrBudgetScopeMismatch ModelBudgetExecutionBindingStore RunTreeBudgetReceipt",
}

func importViolations(owner string, source []byte) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), "source.go", source, 0)
	if err != nil {
		return nil, err
	}
	aliases := map[string]string{}
	var findings []string
	const prefix = "github.com/lexagent/platform/internal/"
	for _, item := range file.Imports {
		path, err := strconv.Unquote(item.Path.Value)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		target := strings.TrimPrefix(path, prefix)
		if strings.Split(target, "/")[0] == owner {
			continue
		}
		switch target {
		case "bootstrap", "contract", "runtime", "sharedkernel", "telemetry":
			continue
		}
		alias := filepath.Base(path)
		if item.Name != nil {
			alias = item.Name.Name
		}
		if alias == "." || alias == "_" {
			findings = append(findings, "unverifiable import: "+path)
			continue
		}
		if _, ok := publicSymbols[target]; !ok {
			findings = append(findings, "non-public package: "+path)
			continue
		}
		aliases[alias] = target
	}
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		target, ok := aliases[id.Name]
		if !ok {
			return true
		}
		if !strings.Contains(" "+publicSymbols[target]+" ", " "+selector.Sel.Name+" ") {
			findings = append(findings, fmt.Sprintf("non-public symbol: %s.%s", target, selector.Sel.Name))
		}
		return true
	})
	return findings, nil
}

func TestModuleBoundaries(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(file))
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".pb.go") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		owner := strings.Split(filepath.ToSlash(relative), "/")[0]
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		findings, err := importViolations(owner, source)
		if err != nil {
			return err
		}
		for _, finding := range findings {
			t.Errorf("%s: %s", relative, finding)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestImportBoundaryNegativeFixtures(t *testing.T) {
	for _, f := range []struct {
		name, source string
		allowed      bool
	}{
		{"legal-port", `package x; import p "github.com/lexagent/platform/internal/agentgateway"; var _ p.Target`, true},
		{"compensation-port", `package x; import p "github.com/lexagent/platform/internal/compensation"; var _ p.EffectRegistry`, true},
		{"compensation-repository", `package x; import p "github.com/lexagent/platform/internal/compensation"; var _ = p.NewSQLStore`, false},
		{"compensation-storage", `package x; import p "github.com/lexagent/platform/internal/compensation"; var _ *p.SQLStore`, false},
		{"compensation-ledger", `package x; import p "github.com/lexagent/platform/internal/compensation"; var _ *p.LocalEffectLedger`, false},
		{"alias-flat", `package x; import p "github.com/lexagent/platform/internal/modelcapacity"; var _ = p.NewSQLProvider`, false},
		{"nested", `package x; import "github.com/lexagent/platform/internal/identity/repository"; var _ repository.SQLStore`, false},
		{"dot", `package x; import . "github.com/lexagent/platform/internal/modelcapacity"; var _ = NewSQLProvider`, false},
		{"blank", `package x; import _ "github.com/lexagent/platform/internal/modelcapacity"`, false},
		{"comment", `package x; // import "github.com/lexagent/platform/internal/identity/repository"`, true},
	} {
		t.Run(f.name, func(t *testing.T) {
			findings, err := importViolations("capability", []byte(f.source))
			if err != nil {
				t.Fatal(err)
			}
			if (len(findings) == 0) != f.allowed {
				t.Fatalf("allowed=%v findings=%v", f.allowed, findings)
			}
		})
	}
	if _, err := importViolations("x", []byte("invalid Go source")); err == nil {
		t.Fatal("invalid syntax passed")
	}
}
