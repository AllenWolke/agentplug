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
	"compensation":  "ContractVersion ErrConflict ErrInvalid ErrNotSubmitted ErrPending ErrUnavailable LeaseFromContext CurrentLeaseFromContext OriginalEffect Receipt Registration Step StepID ScopeDigest StopProof Progress Authority Coordinator EffectLedger LocalEffects LocalEffect LocalEffectOwner Port Engine SweepStats WorkerStore MaxSteps",
	"reversibleapi": "Hash Protocol Provider Request Response",
	"knowledge":     "BusinessDate ErrDocumentValidityUnavailable ErrKnowledgeAuthorityChanged ErrKnowledgeAuthorityUnavailable",
	// SchemaWriter exposes bound statements only, and excludes transaction
	// completion. WithSchemaTransaction joins the migration owner's transaction.
	// ContinuityTransaction carries only a trusted same-database transaction;
	// it grants no authority and cannot commit it. IAM rechecks remain live.
	// The rollback helper retries only a complete local transaction after an
	// explicit PostgreSQL abort. Its report is a value DTO; neither database
	// ownership nor unknown-commit replay authority crosses this boundary.
	"sqlutil": "Bind IsUniqueViolation OpenPostgres SQLState TransactionDB SchemaWriter WithSchemaTransaction WithContinuityTransaction ContinuityTransaction ContinuityReader ContinuityQueryer IsTransactionRollback RetryRolledBack IsKnownRollback TransactionRetryReport LockTransactionResources",
	// IAM fact DTOs are read inside the shared continuity fence transaction
	// (WithCurrentAuthorizationSnapshotContext): the snapshot, workload binding,
	// machine credential, validity window and data scope are plain JSON DTOs
	// with no repository, signer or connection. Authority stays live: every read
	// is rechecked before disclosure or commit, and revocation still fails
	// closed. They carry no secret material beyond what the caller may read.
	"identity": "AccessContext PrincipalType PrincipalUser PrincipalServicePrincipal PermissionSnapshot WorkloadBinding MachineCredential Validity DataScope",
	// The writer port accepts validated, scoped telemetry DTOs only. Its
	// constructor carries no database access; the audit repository stays private.
	"audit": "TxRecorder Event PerformanceRecorder PerformanceObservation NewPerformanceObservation ErrInvalidPerformanceObservation",
	// Typed denial classifications are a bounded diagnostic DTO, not a repository
	// or an authorization bypass. Capability uses them without raw error text.
	"agentcoordination": "AdmissionState ChildAdmission ChildAdmitRequest ChildCancellation ChildCancelRequest ChildPreparation ChildPrepareRequest ChildReadRequest ChildResult ChildStopControlConflictVersion ChildStopIdentity ChildStopRevisionConflict ClassifyRouteError RouteErrorClassification RouteDenialParent RouteReasonParentBoundContext RouteReasonParentLiveCheck RouteReasonParentPolicy ErrConflict ErrDenied GroupReadRequest GroupResult RoutePlan RouteRequest Router",
	"notification":      "TxEnqueuer Event ChannelAdapter ErrAdapterUnavailable ErrInvalidEvent",
	"capability":        "ToolReceiptQuery ErrToolInvocationConflict ToolReceiptScopeHash ToolCommitGuard BusinessIssueCommand ToolCommandFingerprint BusinessReviewCommand BusinessToolStore ToolNoEffectError",
	"agentgateway":      "Target ErrInvalidResponse ErrInvalidTarget EventStream CompletedExecutionFailure NewCompletedExecutionFailure",
	"modelcapacity":     "CapacityProvider Deployment ErrExceeded ErrUnavailable Lease ParseCapacityUnits RegisterPoolTx Request RuntimeDeployment UpdatePoolStateTx",
	// Routing crosses modules through reviewed DTOs, pure validators and scoped
	// ports. Catalog, policy and invocation SQL repositories remain private.
	// Published-stage rendering and cache prefix preparation are pure functions.
	// ResolvedModel contains catalog identity/status only, with no secret or SQL.
	"prompt": "InvocationMessages",
	// This utility only decodes immutable bytes and clones values. It carries
	// no storage, authorization, policy freshness or request execution port.
	"jsonvaluecache": "Cache New",
	// Attempt tracing exposes bounded redacted values and a request-local
	// observer only; provider transports, retry decisions and secrets stay private.
	"modelgateway":    "AccessResolver ErrEndpointUnresolved ErrModelUnavailable ErrRequestTooLarge ErrSecretUnavailable ErrUnsafeEndpoint GenerateRequest GenerateResult EmbeddingResult UsageEmbeddingPort Message ModelMetadata ModelMetadataPort Port ProviderMetadata ProviderMetadataPort SafeProviderFailureKind SafeProviderTransportDetail WithProviderAttemptTrace ProviderAttemptTrace ProviderAttemptObservation ErrProviderResponse ErrProviderUnavailable ErrResponseTooLarge Selection WithEmbeddingPurpose SecretResolver ValidateFunctionRequest RoutingMetadata RoutingMetadataResolver ParseWireCapabilities ValidateWireReasoning PrepareContextCachePrefix NormalizeResponseSchema ResponseSchemaDialect ResponseSchemaReceipt SupportsResponseSchema ProvablyUnsent",
	"modelgovernance": "ActionApprove Actor Authorizer ErrForbidden ErrModelAccessDenied ErrNotFound PriceVersion PriceResolver ResolvedModel Scope StatusApproved TrustExternal TrustLocal TrustPrivate ModelKindChat",
	"policyasset":     "KnowledgeDocumentBinding ModelPolicy RulePolicy Resolver Snapshot SnapshotFromContext ToolPolicy FunctionDefinition ErrFunctionDenied AgentDelegationPolicy ModelRoutingPolicy ModelRouteAvailabilityPolicy ModelRouteQualificationReuse ModelSelection ModelSelectionBinding ModelSelectionStore ModelRoutingReceipt RunModelRoutingSummary ModelRoutingSummaryReader BindRoutingTask RoutingExecutionContextSHA256 ModelComplexityRank ErrMissingPolicy MaximumCheckpointRevisions DefaultCheckpointRevisions",
	// Failed preparation repair uses narrow transaction ports; SQL stores stay
	// private. The ports cannot release money or complete the caller transaction.
	// Reservation contention is an explicit retryable result of the public
	// budget admission port; it grants no direct store or transaction access.
	"usagecost": "ModelPreparationBindingReader ModelPreparationReconciliationWriter ModelBudgetClosureReader ModelBudgetClosure ModelBudgetRetentionReader ErrBudgetExceeded ErrBudgetReservationClosed ErrBudgetReservationConflict ErrInvalidUsage Event ModelBudgetManualReleaseStore ModelBudgetReconciliationStore ModelBudgetRequest ModelBudgetReservation ModelBudgetScope ModelBudgetStore ModelBudgetWindow Recorder Scope StableModelUsageStepID ErrBudgetScopeMismatch ModelBudgetExecutionBindingStore RunTreeBudgetReceipt",
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
		{"schema-writer-port", `package x; import p "github.com/lexagent/platform/internal/sqlutil"; var _ p.SchemaWriter; var _ = p.WithSchemaTransaction`, true},
		{"confirmed-rollback-port", `package x; import p "github.com/lexagent/platform/internal/sqlutil"; var _ = p.IsTransactionRollback; var _ = p.RetryRolledBack[int]; var _ = p.IsKnownRollback; var _ p.TransactionRetryReport`, true},
		{"rollback-proof-private", `package x; import p "github.com/lexagent/platform/internal/sqlutil"; var _ p.confirmedRollback`, false},
		{"transaction-resource-port", `package x; import p "github.com/lexagent/platform/internal/sqlutil"; var _ = p.LockTransactionResources`, true},
		{"resource-key-implementation-private", `package x; import p "github.com/lexagent/platform/internal/sqlutil"; var _ = p.transactionResourceIDs`, false},
		{"performance-writer-port", `package x; import p "github.com/lexagent/platform/internal/audit"; var _ p.PerformanceRecorder; var _ p.PerformanceObservation; var _ = p.NewPerformanceObservation`, true},
		{"performance-repository-private", `package x; import p "github.com/lexagent/platform/internal/audit"; var _ p.SQLStore`, false},
		{"preparation-recovery-ports", `package x; import p "github.com/lexagent/platform/internal/usagecost"; var _ p.ModelPreparationBindingReader; var _ p.ModelPreparationReconciliationWriter`, true},
		{"budget-window-repository-private", `package x; import p "github.com/lexagent/platform/internal/usagecost"; var _ p.SQLStore`, false},
		{"budget-tree-repository-private", `package x; import p "github.com/lexagent/platform/internal/usagecost"; var _ p.SQLRunTreeBudgetStore`, false},
		{"routing-scoped-port", `package x; import p "github.com/lexagent/platform/internal/policyasset"; var _ p.ModelSelectionBinding; var _ p.ModelSelectionStore; var _ = p.BindRoutingTask`, true},
		{"routing-policy-repository-private", `package x; import p "github.com/lexagent/platform/internal/policyasset"; var _ p.SQLStore`, false},
		{"routing-catalog-repository-private", `package x; import p "github.com/lexagent/platform/internal/modelgovernance"; var _ p.SQLStore`, false},
		{"known-billing-catalog-dto", `package x; import p "github.com/lexagent/platform/internal/modelgovernance"; var _ p.ResolvedModel`, true},
		{"published-stage-renderer", `package x; import p "github.com/lexagent/platform/internal/prompt"; var _ = p.InvocationMessages`, true},
		{"prompt-repository-private", `package x; import p "github.com/lexagent/platform/internal/prompt"; var _ = p.NewSQLStore`, false},
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
