package agentcoordination

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type childResultPGAuthority struct {
	parent ParentFacts
	target Target
	denied bool
}

func (a *childResultPGAuthority) Parent(_ context.Context, _ *sql.Tx, scope sharedkernel.Scope) (ParentFacts, error) {
	if a.denied || scope != a.parent.Scope {
		return ParentFacts{}, ErrDenied
	}
	return a.parent, nil
}
func (a *childResultPGAuthority) Candidates(context.Context, *sql.Tx, ParentFacts, string) ([]Target, error) {
	return []Target{a.target}, nil
}
func (a *childResultPGAuthority) AuthorizeTarget(_ context.Context, _ *sql.Tx, parent ParentFacts, target Target) error {
	if a.denied || parent.Scope != a.parent.Scope || digest(target) != digest(a.target) {
		return ErrDenied
	}
	return nil
}

type childResultPGExecution struct{ result ChildExecutionResult }

func (*childResultPGExecution) AdmitChild(context.Context, *sql.Tx, ChildExecutionAdmission) (AdmittedChildExecution, error) {
	return AdmittedChildExecution{}, ErrDenied
}
func (e *childResultPGExecution) ReadChild(_ context.Context, _ *sql.Tx, read ChildExecutionRead) (ChildExecutionResult, error) {
	if read.RunID != e.result.Scope.RunID || read.Parent.Scope.RunID != e.result.Scope.ParentRunID || read.Depth != 1 {
		return ChildExecutionResult{}, ErrDenied
	}
	return e.result, nil
}

// The execution/IAM Ports are bounded fixtures; projection, reservation
// fingerprint matching and final disclosure execute real PostgreSQL queries.
func TestSQLChildResultProjectsAdmissionFingerprintAndRejectsTampering(t *testing.T) {
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
	suffix := fmt.Sprintf("result-fingerprint-%d", time.Now().UnixNano())
	parent := sharedkernel.Scope{TenantID: suffix, DepartmentID: suffix, ApplicationID: suffix,
		AgentInstanceID: suffix + "-parent-install", InstallationID: suffix + "-parent-install",
		AgentID: suffix + "-parent", AgentVersionID: "parent-v1", PrincipalType: "user", PrincipalID: suffix + "-caller",
		SessionID: suffix + "-session", RunID: suffix + "-run", AuthorizationEpoch: 1, TraceID: strings.Repeat("a", 32)}
	target := Target{TenantID: parent.TenantID, DepartmentID: parent.DepartmentID, ApplicationID: parent.ApplicationID,
		AgentID: suffix + "-child", InstallationID: suffix + "-child-install", InstallationRevision: 1,
		VersionID: "child-v1", DeploymentID: suffix + "-deployment", DeploymentRevision: 1,
		ManifestHash: "sha256:" + strings.Repeat("a", 64), InputSchema: "schema://child/input/v1",
		OutputSchema: "schema://child/output/v1", TaskTypes: []string{"documents.answer"}, Published: true, Ready: true}
	operation := "read-original-output"
	plan := RoutePlan{Version: "agent-route/v1", OperationKey: operation, Fingerprint: strings.Repeat("b", 64),
		ParentRunID: parent.RunID, PolicyHash: strings.Repeat("c", 64), TaskType: "documents.answer", ChildDepth: 1, Targets: []Target{target}}
	plan.EvidenceDigest = digest(plan.Targets)
	rawPlan, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	parentKey := routeScopeKey(parent)
	childKey := digest([]any{parentKey, operation, 0, plan.Fingerprint})
	childScope := parent
	childScope.RunID, childScope.ParentRunID = "child-"+childKey[:48], parent.RunID
	childScope.AgentID, childScope.AgentVersionID = target.AgentID, target.VersionID
	childScope.AgentInstanceID, childScope.InstallationID = target.InstallationID, target.InstallationID
	fingerprint := strings.Repeat("d", 64)
	store, err := NewSQLRouteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_agent_child_reservation WHERE parent_key=$1`, parentKey)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM platform_agent_route WHERE parent_key=$1`, parentKey)
	}()
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_agent_route(parent_key,operation_key,parent_run_id,fingerprint,policy_hash,task_type,child_depth,reserved_children,plan_json,evidence_digest) VALUES($1,$2,$3,$4,$5,$6,1,1,$7,$8)`, parentKey, operation, parent.RunID, plan.Fingerprint, plan.PolicyHash, plan.TaskType, string(rawPlan), plan.EvidenceDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_agent_child_reservation(parent_key,operation_key,ordinal,child_key,target_installation_id,target_version_id,target_manifest_hash,status,revision,child_run_id,request_fingerprint) VALUES($1,$2,0,$3,$4,$5,$6,'completed',5,$7,$8)`, parentKey, operation, childKey, target.InstallationID, target.VersionID, target.ManifestHash, childScope.RunID, fingerprint); err != nil {
		t.Fatal(err)
	}
	authority := &childResultPGAuthority{parent: ParentFacts{Scope: parent, PolicyHash: plan.PolicyHash, Active: true,
		Policy: &policyasset.AgentDelegationPolicy{AllowedAgentIDs: []string{target.AgentID}, TaskTypes: target.TaskTypes, MaxDepth: 1, MaxChildren: 1}}, target: target}
	output := map[string]any{"answer": "teaching evidence"}
	encoded, _ := json.Marshal(output)
	reader := &childResultPGExecution{result: ChildExecutionResult{RequestFingerprint: fingerprint, Scope: childScope,
		Status: "completed", Revision: 4, Output: output, OutputBytes: int64(len(encoded)), OutputDigest: digest(output)}}
	store.SetAuthority(authority)
	store.SetAuditRecorder(childStopOnlyPGAudit{})
	store.SetChildExecutionAdmitter(reader)
	request := ChildReadRequest{OperationKey: operation, Ordinal: 0}
	result, err := store.ReadChild(ctx, parent, request)
	if err != nil || result.InputFingerprint != fingerprint {
		t.Fatalf("verified child input fingerprint missing: err=%v", err)
	}
	group, err := store.ReadGroup(ctx, parent, GroupReadRequest{OperationKey: operation})
	if err != nil || !group.OutputsComplete || len(group.Children) != 1 || group.Children[0].InputFingerprint != fingerprint {
		t.Fatalf("whole-plan projection lost child input binding: err=%v", err)
	}
	if err := store.CheckChildResult(ctx, parent, request, result); err != nil {
		t.Fatal("original fingerprint rejected", err)
	}
	result.InputFingerprint = strings.Repeat("e", 64)
	if err := store.CheckChildResult(ctx, parent, request, result); !errors.Is(err, ErrConflict) {
		t.Fatalf("tampered input binding accepted: %v", err)
	}
	group.Children[0].InputFingerprint = result.InputFingerprint
	if err := store.CheckGroupResult(ctx, parent, GroupReadRequest{OperationKey: operation}, group); !errors.Is(err, ErrConflict) {
		t.Fatalf("tampered whole-plan binding accepted: %v", err)
	}
	authority.denied = true
	if _, err := store.ReadChild(ctx, parent, request); !errors.Is(err, ErrDenied) {
		t.Fatalf("revoked authority disclosed result: %v", err)
	}
}
