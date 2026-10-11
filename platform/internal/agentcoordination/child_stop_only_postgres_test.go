package agentcoordination

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type childStopOnlyPGAuthority struct {
	parent         sharedkernel.Scope
	policyHash     string
	machineID      string
	ordinaryChecks int
	stopChecks     int
}

func (a *childStopOnlyPGAuthority) Parent(context.Context, *sql.Tx, sharedkernel.Scope) (ParentFacts, error) {
	a.ordinaryChecks++
	return ParentFacts{}, ErrDenied
}
func (*childStopOnlyPGAuthority) Candidates(context.Context, *sql.Tx, ParentFacts, string) ([]Target, error) {
	return nil, ErrDenied
}
func (*childStopOnlyPGAuthority) AuthorizeTarget(context.Context, *sql.Tx, ParentFacts, Target) error {
	return ErrDenied
}
func (a *childStopOnlyPGAuthority) ParentForChildStop(_ context.Context, _ *sql.Tx, scope sharedkernel.Scope, identity ChildStopIdentity) (ParentFacts, error) {
	a.stopChecks++
	if scope != a.parent || identity.MachinePrincipalID != a.machineID || identity.PolicyHash != a.policyHash {
		return ParentFacts{}, ErrDenied
	}
	return ParentFacts{Scope: scope, PolicyHash: a.policyHash, Depth: 0, Active: true}, nil
}

type childStopOnlyPGExecution struct {
	parent   sharedkernel.Scope
	childID  string
	childRun sharedkernel.Scope
	called   int
	staleCAS bool
}

func (*childStopOnlyPGExecution) AdmitChild(context.Context, *sql.Tx, ChildExecutionAdmission) (AdmittedChildExecution, error) {
	return AdmittedChildExecution{}, ErrDenied
}
func (e *childStopOnlyPGExecution) CancelChildForStop(_ context.Context, _ *sql.Tx, read ChildExecutionRead, _ ChildStopIdentity, expected uint64) (ChildExecutionResult, error) {
	e.called++
	if read.Parent.Scope != e.parent || read.RunID != e.childID || read.Depth != 1 {
		return ChildExecutionResult{}, ErrDenied
	}
	if e.staleCAS {
		return ChildExecutionResult{}, &ChildStopRevisionConflict{Status: "waiting", ExecutionRevision: expected + 1}
	}
	return ChildExecutionResult{Scope: e.childRun, Status: "cancelling", Revision: 5}, nil
}

type childStopOnlyPGAudit struct{}

func (childStopOnlyPGAudit) RecordTx(*sql.Tx, audit.Event) error { return nil }

func TestSQLChildStopOnlyUsesRecordedEdgeWithoutReauthorizingGrants(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	suffix := fmt.Sprintf("child-stop-only-%d", time.Now().UnixNano())
	parent := sharedkernel.Scope{
		TenantID: suffix, DepartmentID: suffix, ApplicationID: suffix,
		AgentInstanceID: suffix + "-parent-install", InstallationID: suffix + "-parent-install",
		AgentID: suffix + "-parent-agent", AgentVersionID: "parent-v1",
		PrincipalType: "user", PrincipalID: suffix + "-caller", SessionID: suffix + "-session",
		RunID: suffix + "-parent-run", AuthorizationEpoch: 5, TraceID: "0123456789abcdef0123456789abcdef",
	}
	target := Target{
		TenantID: parent.TenantID, DepartmentID: parent.DepartmentID, ApplicationID: parent.ApplicationID,
		AgentID: suffix + "-child-agent", InstallationID: suffix + "-child-install", InstallationRevision: 1,
		VersionID: "child-v1", DeploymentID: suffix + "-deployment", DeploymentRevision: 1,
		ManifestHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		InputSchema:  "schema://child/input/v1", OutputSchema: "schema://child/output/v1",
		TaskTypes: []string{"documents.read"}, Published: true, Ready: true,
	}
	if parent.ValidateTrusted() != nil || !recordedStopTarget(parent, target, "documents.read") {
		t.Fatal("invalid exact fixture scope or target")
	}
	policyHash := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	operation := "stop-existing-child"
	plan := RoutePlan{Version: "agent-route/v1", OperationKey: operation, Fingerprint: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", ParentRunID: parent.RunID, PolicyHash: policyHash, TaskType: "documents.read", ChildDepth: 1, Targets: []Target{target}}
	plan.EvidenceDigest = digest(plan.Targets)
	rawPlan, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	parentKey := routeScopeKey(parent)
	childKey := digest([]any{parentKey, operation, 0, plan.Fingerprint})
	childID := "child-" + childKey[:48]
	childScope := parent
	childScope.AgentInstanceID = target.InstallationID
	childScope.InstallationID = target.InstallationID
	childScope.AgentID = target.AgentID
	childScope.AgentVersionID = target.VersionID
	childScope.ParentRunID = parent.RunID
	childScope.RunID = childID
	requestFingerprint := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

	store, err := NewSQLRouteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal("ensure isolated route schema", err)
	}
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_agent_route WHERE parent_key=$1 AND operation_key=$2`, parentKey, operation)
	}()
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_agent_route(parent_key,operation_key,parent_run_id,fingerprint,policy_hash,task_type,child_depth,reserved_children,plan_json,evidence_digest) VALUES($1,$2,$3,$4,$5,$6,1,1,$7,$8)`, parentKey, operation, parent.RunID, plan.Fingerprint, plan.PolicyHash, plan.TaskType, string(rawPlan), plan.EvidenceDigest); err != nil {
		t.Fatal("insert exact saved route plan", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_agent_child_reservation(parent_key,operation_key,ordinal,child_key,target_installation_id,target_version_id,target_manifest_hash,status,revision,child_run_id,request_fingerprint) VALUES($1,$2,0,$3,$4,$5,$6,'accepted',3,$7,$8)`, parentKey, operation, childKey, target.InstallationID, target.VersionID, target.ManifestHash, childID, requestFingerprint); err != nil {
		t.Fatal("insert exact admitted child edge", err)
	}

	const machineID = "parent-machine"
	authority := &childStopOnlyPGAuthority{parent: parent, policyHash: policyHash, machineID: machineID}
	children := &childStopOnlyPGExecution{parent: parent, childID: childID, childRun: childScope}
	store.SetAuthority(authority)
	store.SetAuditRecorder(childStopOnlyPGAudit{})
	store.SetChildExecutionAdmitter(children)
	identity := ChildStopIdentity{Lease: sharedkernel.ExecutionLeaseBinding{Revision: 8, TokenHash: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}, PolicyHash: policyHash, MachinePrincipalID: machineID}
	request := ChildCancelRequest{OperationKey: operation, Ordinal: 0, ExpectedExecutionRevision: 4}

	result, err := store.CancelChildStopOnly(ctx, parent, request, identity)
	if err != nil {
		t.Fatal("recorded stop denied after current route grants were withdrawn", err)
	}
	if result.ChildRunID != childID || result.ParentRunID != parent.RunID || result.Status != "cancelling" || result.ExecutionRevision != 5 {
		t.Fatalf("unexpected stop intent response: %#v", result)
	}
	if authority.stopChecks != 1 || authority.ordinaryChecks != 0 || children.called != 1 {
		t.Fatalf("stop-only path re-entered ordinary current authorization: stop=%d ordinary=%d child=%d", authority.stopChecks, authority.ordinaryChecks, children.called)
	}
	foreignOperation := request
	foreignOperation.OperationKey = operation + "-foreign"
	if _, err := store.CancelChildStopOnly(ctx, parent, foreignOperation, identity); !errors.Is(err, ErrDenied) {
		t.Fatalf("foreign operation key reused the recorded stop edge: %v", err)
	}
	foreignOrdinal := request
	foreignOrdinal.Ordinal = 1
	if _, err := store.CancelChildStopOnly(ctx, parent, foreignOrdinal, identity); !errors.Is(err, ErrDenied) {
		t.Fatalf("foreign route ordinal reused the recorded stop edge: %v", err)
	}
	if children.called != 1 {
		t.Fatalf("foreign operation or ordinal reached the execution stop port: calls=%d", children.called)
	}

	// A different caller scope or machine credential cannot reuse the saved edge.
	otherScope := parent
	otherScope.PrincipalID += "-other"
	if _, err := store.CancelChildStopOnly(ctx, otherScope, request, identity); !errors.Is(err, ErrDenied) {
		t.Fatalf("other principal reused the exact stop edge: %v", err)
	}
	wrongMachine := identity
	wrongMachine.MachinePrincipalID = "other-machine"
	if _, err := store.CancelChildStopOnly(ctx, parent, request, wrongMachine); !errors.Is(err, ErrDenied) {
		t.Fatalf("wrong parent machine reused the exact stop edge: %v", err)
	}
	if authority.ordinaryChecks != 0 || children.called != 1 {
		t.Fatal("failed scope/machine proof reached the execution stop port")
	}

	children.staleCAS = true
	conflict, err := store.CancelChildStopOnly(ctx, parent, request, identity)
	var stale *ChildStopRevisionConflict
	if !errors.As(err, &stale) || stale.Status != "waiting" || stale.ExecutionRevision != request.ExpectedExecutionRevision+1 || conflict.ChildRunID != "" {
		t.Fatalf("stale positive CAS did not preserve a narrow current stop hint: result=%#v err=%v", conflict, err)
	}
	zeroCAS := request
	zeroCAS.ExpectedExecutionRevision = 0
	if _, err := store.CancelChildStopOnly(ctx, parent, zeroCAS, identity); !errors.Is(err, ErrDenied) {
		t.Fatalf("zero revision bypassed positive CAS: %v", err)
	}
}
