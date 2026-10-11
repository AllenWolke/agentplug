package execution

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestInternalTaskCancellationCompensationRequiresExactOwnerReceiptPostgres(t *testing.T) {
	for _, kind := range []string{"exact", "missing", "wrong_lease", "wrong_revision", "remote_endpoint"} {
		t.Run(kind, func(t *testing.T) {
			f := newCancellationFixture(t)
			id := f.id + "-internal-" + kind
			scope := testScope(id).domain()
			scope.SessionID = id
			command := contract.ExecuteRequest{ProtocolVersion: contract.ProtocolVersion, Operation: "run", IdempotencyKey: id, InputSchema: KnowledgeIndexInputSchema,
				Scope: contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
					AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID,
					PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, InstallationID: scope.InstallationID,
					SessionID: scope.SessionID, RunID: scope.RunID, AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID},
				Input: map[string]any{"knowledge_id": "internal-cancellation-fixture"}}
			raw, err := json.Marshal(command)
			if err != nil {
				t.Fatal(err)
			}
			fingerprint, err := contract.CanonicalExecuteBodyHash(command)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := ""
			if kind == "remote_endpoint" {
				endpoint = "http://fixture-agent:8080"
			}
			created, err := f.runs.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: fingerprint, RequestJSON: raw, AgentEndpoint: endpoint})
			if err != nil {
				t.Fatal(err)
			}
			claimed, err := f.runs.AcquireLease(created.Run.ID, id+"-owner", time.Now().UTC(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			running, err := f.runs.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "exact" {
				if err := f.runs.RecordInternalTaskStopped(f.ctx, running.Scope, running.LeaseToken, running.Revision); err != nil {
					t.Fatal(err)
				}
			} else if kind != "missing" {
				proof := internalStopReceipt{ExecutionRevision: running.Revision, LeaseDigest: stopHash([]byte(running.LeaseToken))}
				if kind == "wrong_lease" {
					proof.LeaseDigest = stopHash([]byte("another-owner"))
				}
				if kind == "wrong_revision" {
					proof.ExecutionRevision++
				}
				payload, _ := json.Marshal(proof)
				if _, err := f.runs.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES(?,'internal_task_stopped',?,?)`), id, payload, time.Now().UTC()); err != nil {
					t.Fatal(err)
				}
			}
			pending, err := f.runs.BeginCancellation(id, running.Revision)
			if err != nil {
				t.Fatal(err)
			}
			done, err := f.runs.Cancel(id, pending.Revision)
			if kind != "exact" {
				if !errors.Is(err, ErrStopEvidenceAbsent) {
					t.Fatalf("unproven stop accepted: %v", err)
				}
				actual, readErr := f.runs.Get(id)
				if readErr != nil || actual.Status != platformruntime.StatusCancelling || actual.Revision != pending.Revision {
					t.Fatal("failed proof changed cancellation state")
				}
				return
			}
			if err != nil || done.Status != platformruntime.StatusCancelled {
				t.Fatalf("exact internal stop did not complete: %v/%s", err, done.Status)
			}
			progress, found, err := f.coordinator.Progress(f.ctx, running.Scope)
			if err != nil || !found || !progress.StopConfirmed || progress.Phase != "complete" {
				t.Fatal("terminal cancellation lacks atomic compensation proof")
			}
		})
	}
}
