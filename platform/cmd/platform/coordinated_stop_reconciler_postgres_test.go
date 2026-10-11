package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type reconcilerStopTestChild struct {
	fingerprints map[string]string
}

func (*reconcilerStopTestChild) AdmitChild(context.Context, *sql.Tx, agentcoordination.ChildExecutionAdmission) (agentcoordination.AdmittedChildExecution, error) {
	return agentcoordination.AdmittedChildExecution{}, agentcoordination.ErrDenied
}
func (c *reconcilerStopTestChild) ObserveChildLifecycle(_ context.Context, _ *sql.Tx, request agentcoordination.ChildExecutionRead) (agentcoordination.ObservedChildLifecycle, error) {
	child := request.Parent.Scope
	child.AgentInstanceID, child.InstallationID = request.Target.InstallationID, request.Target.InstallationID
	child.AgentID, child.AgentVersionID = request.Target.AgentID, request.Target.VersionID
	child.ParentRunID, child.RunID = request.Parent.Scope.RunID, request.RunID
	return agentcoordination.ObservedChildLifecycle{Scope: child, Status: "accepted", Revision: 1, RequestFingerprint: c.fingerprints[request.RunID]}, nil
}

func TestCoordinatedStopReconcilerStopsOnlyAfterParentLeaseEndsOrWaitProofIsLost(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if err := execution.MigrateSchema(ctx, admin); err != nil {
		t.Fatal("ensure execution schema", err)
	}
	identityStore := identity.NewSQLStore(admin)
	if err := identityStore.EnsureSchema(ctx); err != nil {
		t.Fatal("ensure identity schema", err)
	}
	if err := identityStore.EnsurePermissionSchema(ctx); err != nil {
		t.Fatal("ensure permission continuity schema", err)
	}
	routes, err := agentcoordination.NewSQLRouteStore(admin)
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.EnsureSchema(ctx); err != nil {
		t.Fatal("ensure route schema", err)
	}
	if err := routes.EnsureLifecycleSchema(ctx); err != nil {
		t.Fatal("ensure route lifecycle schema", err)
	}
	recorder := audit.NewSQLStore(admin)
	if err := recorder.EnsureSchema(ctx); err != nil {
		t.Fatal("ensure audit schema", err)
	}
	runs, err := execution.ConnectSQLStore(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer runs.Close()

	suffix := fmt.Sprintf("orphan-child-stop-%d", time.Now().UnixNano())
	fingerprints := map[string]string{}
	childObserver := &reconcilerStopTestChild{fingerprints: fingerprints}
	routes.SetChildExecutionAdmitter(childObserver)
	routes.SetAuditRecorder(recorder)
	reconciler := &coordinatedStopReconciler{
		db: admin, runs: runs, routes: routes, audit: recorder,
		route: agentRouteAuthority{identity: identityStore, runs: runs, routes: routes},
	}
	var routeCleanup []struct{ key, operation string }
	var runCleanup []string
	defer func() {
		for _, route := range routeCleanup {
			_, _ = admin.ExecContext(context.Background(), `DELETE FROM platform_agent_route WHERE parent_key=$1 AND operation_key=$2`, route.key, route.operation)
		}
		for _, id := range runCleanup {
			_, _ = admin.ExecContext(context.Background(), `DELETE FROM platform_execution_session_lease WHERE run_id=$1`, id)
			_, _ = admin.ExecContext(context.Background(), `DELETE FROM platform_execution_creation_projection WHERE run_id=$1`, id)
			_, _ = admin.ExecContext(context.Background(), `DELETE FROM platform_execution_outcome WHERE run_id=$1`, id)
			_, _ = admin.ExecContext(context.Background(), `DELETE FROM platform_execution_event WHERE run_id=$1`, id)
			_, _ = admin.ExecContext(context.Background(), `DELETE FROM platform_execution_run WHERE run_id=$1`, id)
		}
	}()

	makePair := func(name string, parentStatus platformruntime.Status) (sharedkernel.Scope, sharedkernel.Scope, agentcoordination.ChildLifecycleCandidate) {
		t.Helper()
		parentID, childID := suffix+"-"+name+"-parent", suffix+"-"+name+"-child"
		parent := sharedkernel.Scope{
			TenantID: suffix, DepartmentID: suffix, ApplicationID: suffix,
			AgentInstanceID: suffix + "-parent-install", InstallationID: suffix + "-parent-install",
			AgentID: suffix + "-parent-agent", AgentVersionID: "parent-v1", PrincipalType: "user",
			PrincipalID: suffix + "-caller", SessionID: suffix + "-" + name + "-session", RunID: parentID,
			AuthorizationEpoch: 3, TraceID: "0123456789abcdef0123456789abcdef",
		}
		child := parent
		child.AgentInstanceID, child.InstallationID = suffix+"-"+name+"-child-install", suffix+"-"+name+"-child-install"
		child.AgentID, child.AgentVersionID = suffix+"-"+name+"-child-agent", "child-v1"
		child.ParentRunID = parentID
		operation := "operation-" + name
		child.RunID = reconcilerRecordedChildRunID(parent, child, operation)
		childID = child.RunID
		parentRequest := reconcilerStopExecuteRequest(parent, 0)
		childRequest := reconcilerStopExecuteRequest(child, 1)
		parentRaw, _ := json.Marshal(parentRequest)
		childRaw, _ := json.Marshal(childRequest)
		if _, err := runs.Create(platformruntime.CreateRequest{ID: parentID, Scope: parent, AgentVersionID: parent.AgentVersionID, IdempotencyKey: parentID, Fingerprint: reconcilerStopDigest(parentID), RequestJSON: parentRaw}); err != nil {
			t.Fatal("create parent run", err)
		}
		if _, err := runs.Create(platformruntime.CreateRequest{ID: childID, Scope: child, AgentVersionID: child.AgentVersionID, IdempotencyKey: childID, Fingerprint: reconcilerChildRequestFingerprint(), RequestJSON: childRaw}); err != nil {
			t.Fatal("create child run", err)
		}
		runCleanup = append(runCleanup, parentID, childID)
		if parentStatus == platformruntime.StatusRunning || parentStatus == platformruntime.StatusWaiting {
			lease, err := runs.AcquireLease(parentID, suffix+"-lease-"+name, time.Now().UTC(), time.Minute)
			if err != nil {
				t.Fatal("claim parent lease", err)
			}
			running, err := runs.TransitionLeased(parentID, platformruntime.StatusAccepted, platformruntime.StatusRunning, lease.Revision, lease.LeaseToken)
			if err != nil {
				t.Fatal("start parent run", err)
			}
			if parentStatus == platformruntime.StatusWaiting {
				if _, err := runs.TransitionLeased(parentID, platformruntime.StatusRunning, platformruntime.StatusWaiting, running.Revision, running.LeaseToken); err != nil {
					t.Fatal("place parent in waiting without a persisted wait proof", err)
				}
			}
		}
		candidate, fingerprint := seedReconcilerRecordedChildEdge(t, ctx, admin, parent, child, operation)
		fingerprints[childID] = fingerprint
		return parent, child, candidate
	}

	// A running parent with a live lease retains its admitted child. Expiry of
	// that same lease permits only a durable cancelling intent, not a fake exit.
	_, liveChild, liveCandidate := makePair("lease", platformruntime.StatusRunning)
	if err := reconciler.stopOrphan(ctx, liveCandidate); err != nil {
		t.Fatal("live parent lease reconciliation", err)
	}
	if run, err := runs.Get(liveChild.RunID); err != nil || run.Status != platformruntime.StatusAccepted || run.Revision != 1 {
		t.Fatalf("child stopped while parent lease was live: run=%#v err=%v", run, err)
	}
	if _, err := admin.ExecContext(ctx, `UPDATE platform_execution_run SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE run_id=$1`, liveCandidate.ParentRunID); err != nil {
		t.Fatal("expire parent Run lease", err)
	}
	if _, err := admin.ExecContext(ctx, `UPDATE platform_execution_session_lease SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE run_id=$1`, liveCandidate.ParentRunID); err != nil {
		t.Fatal("expire parent session lease", err)
	}
	if err := reconciler.stopOrphan(ctx, liveCandidate); err != nil {
		t.Fatal("expired parent lease reconciliation", err)
	}
	assertReconcilerOnlyStopIntent(t, ctx, admin, runs, liveChild.RunID)

	// A waiting parent without a trusted persisted AgentGroup wait reference
	// cannot retain a child or resume it; the reconciler stops the child only.
	waitingParent, waitingChild, waitingCandidate := makePair("waiting", platformruntime.StatusWaiting)
	if err := reconciler.stopOrphan(ctx, waitingCandidate); err != nil {
		t.Fatal("waiting parent without verified handoff reconciliation", err)
	}
	assertReconcilerOnlyStopIntent(t, ctx, admin, runs, waitingChild.RunID)
	if run, err := runs.Get(waitingParent.RunID); err != nil || run.Status != platformruntime.StatusWaiting {
		t.Fatalf("child-only stop changed the parent Run: run=%#v err=%v", run, err)
	}
}

func seedReconcilerRecordedChildEdge(t *testing.T, ctx context.Context, db *sql.DB, parent, child sharedkernel.Scope, operation string) (agentcoordination.ChildLifecycleCandidate, string) {
	t.Helper()
	target := agentcoordination.Target{
		TenantID: parent.TenantID, DepartmentID: parent.DepartmentID, ApplicationID: parent.ApplicationID,
		AgentID: child.AgentID, InstallationID: child.InstallationID, InstallationRevision: 1,
		VersionID: child.AgentVersionID, DeploymentID: operation + "-deployment", DeploymentRevision: 1,
		ManifestHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		InputSchema:  "schema://child/input/v1", OutputSchema: "schema://child/output/v1",
		TaskTypes: []string{"documents.read"}, Published: true, Ready: true,
	}
	parentKey := reconcilerRouteScopeKey(parent)
	policyHash := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	request := agentcoordination.RouteRequest{OperationKey: operation, TaskType: "documents.read", Count: 1}
	fingerprint := reconcilerStopDigest([]any{parentKey, policyHash, request})
	plan := agentcoordination.RoutePlan{Version: "agent-route/v1", OperationKey: operation, Fingerprint: fingerprint, ParentRunID: parent.RunID, PolicyHash: policyHash, TaskType: request.TaskType, ChildDepth: 1, Targets: []agentcoordination.Target{target}}
	plan.EvidenceDigest = reconcilerStopDigest(plan.Targets)
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	childKey := reconcilerStopDigest([]any{parentKey, operation, 0, fingerprint})
	if child.RunID != "child-"+childKey[:48] {
		t.Fatalf("child run ID is not derived from its exact persisted edge: %q", child.RunID)
	}
	requestFingerprint := reconcilerChildRequestFingerprint()
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_agent_route(parent_key,operation_key,parent_run_id,fingerprint,policy_hash,task_type,child_depth,reserved_children,plan_json,evidence_digest) VALUES($1,$2,$3,$4,$5,$6,1,1,$7,$8)`, parentKey, operation, parent.RunID, fingerprint, policyHash, request.TaskType, string(encoded), plan.EvidenceDigest); err != nil {
		t.Fatal("insert reconciler saved route", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_agent_child_reservation(parent_key,operation_key,ordinal,child_key,target_installation_id,target_version_id,target_manifest_hash,status,revision,child_run_id,request_fingerprint) VALUES($1,$2,0,$3,$4,$5,$6,'accepted',3,$7,$8)`, parentKey, operation, childKey, target.InstallationID, target.VersionID, target.ManifestHash, child.RunID, requestFingerprint); err != nil {
		t.Fatal("insert reconciler admitted edge", err)
	}
	return agentcoordination.ChildLifecycleCandidate{ParentRunID: parent.RunID, ChildRunID: child.RunID, Depth: 1}, requestFingerprint
}

func assertReconcilerOnlyStopIntent(t *testing.T, ctx context.Context, db *sql.DB, runs *execution.SQLStore, childID string) {
	t.Helper()
	run, err := runs.Get(childID)
	if err != nil || run.Status != platformruntime.StatusCancelling || run.Revision != 2 {
		t.Fatalf("expected durable child cancellation intent, got run=%#v err=%v", run, err)
	}
	var terminalOutcome bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM platform_execution_outcome WHERE run_id=$1 AND event_type IN ('task_cancelled','task_succeeded','task_failed'))`, childID).Scan(&terminalOutcome); err != nil {
		t.Fatal(err)
	}
	if terminalOutcome {
		t.Fatal("reconciler stop intent fabricated remote exit or terminal outcome")
	}
}

func reconcilerStopExecuteRequest(scope sharedkernel.Scope, depth uint32) contract.ExecuteRequest {
	return contract.ExecuteRequest{
		ProtocolVersion: contract.ProtocolVersion,
		Scope:           contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, SessionID: scope.SessionID, RunID: scope.RunID, AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID, ParentRunID: scope.ParentRunID, DelegationDepth: depth, InstallationID: scope.InstallationID},
		Operation:       "run", IdempotencyKey: scope.RunID, InputSchema: "schema://task/input/v1", Input: map[string]any{},
	}
}

func reconcilerRouteScopeKey(scope sharedkernel.Scope) string {
	return reconcilerStopDigest([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentInstanceID, scope.InstallationID, scope.AgentVersionID, scope.PrincipalType, scope.PrincipalID, scope.SessionID, scope.RunID})
}

func reconcilerRecordedChildRunID(parent, child sharedkernel.Scope, operation string) string {
	parentKey := reconcilerRouteScopeKey(parent)
	policyHash := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	request := agentcoordination.RouteRequest{OperationKey: operation, TaskType: "documents.read", Count: 1}
	fingerprint := reconcilerStopDigest([]any{parentKey, policyHash, request})
	childKey := reconcilerStopDigest([]any{parentKey, operation, 0, fingerprint})
	return "child-" + childKey[:48]
}

func reconcilerChildRequestFingerprint() string {
	return "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
}

func reconcilerStopDigest(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
