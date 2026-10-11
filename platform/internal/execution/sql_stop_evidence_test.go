package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func TestSQLControllerStopEvidenceAtomicAuditAndCAS(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	store, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	proof := StopEvidence{Source: "runtime-process-stop/v1", Digest: strings.Repeat("d", 64), RuntimeID: strings.Repeat("a", 64)}
	for _, mode := range []string{"cancel", "recovery"} {
		t.Run(mode, func(t *testing.T) {
			id := fmt.Sprintf("controller-stop-%s-%d", mode, time.Now().UnixNano())
			scopeDTO := testScope(id)
			scopeDTO.SessionID = id
			scope := scopeDTO.domain()
			scope.SessionID = id
			create := platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: id}
			var requestBody []byte
			resumeInput := []byte(`{"decision":"approve"}`)
			if mode == "recovery" {
				requestBody = gatewayRequest(t, scopeDTO, "invoke")
				create.RequestJSON = requestBody
				create.AgentEndpoint = "http://agent.example"
			}
			created, err := store.Create(create)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "recovery" {
				if _, err := store.db.Exec(`UPDATE platform_execution_run SET resume_input_json=$1 WHERE run_id=$2`, resumeInput, id); err != nil {
					t.Fatal(err)
				}
			}
			claimed, err := store.AcquireLease(id, "original-worker", time.Now().UTC(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			running, err := store.TransitionLeased(id, created.Run.Status, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
			if err != nil {
				t.Fatal(err)
			}
			var dispatch platformruntime.DispatchCommand
			if mode == "recovery" {
				var request contract.ExecuteRequest
				if err := json.Unmarshal(requestBody, &request); err != nil {
					t.Fatal(err)
				}
				bodyHash, err := contract.CanonicalExecuteBodyHash(request)
				if err != nil {
					t.Fatal(err)
				}
				policy, ok := request.Input["policy_snapshot"].(map[string]any)
				if !ok {
					t.Fatal("gateway request has no policy snapshot")
				}
				policyHash, ok := policy["content_hash"].(string)
				if !ok || policyHash == "" {
					t.Fatal("gateway request has no policy hash")
				}
				dispatch = platformruntime.DispatchCommand{RunID: id, Revision: running.Revision, Operation: request.Operation, BodyHash: bodyHash, PolicyHash: policyHash}
				if err := store.RecordDispatchCommand(dispatch, running.LeaseToken); err != nil {
					t.Fatal(err)
				}
			}
			var pending platformruntime.Run
			var finish func(string, uint64, StopEvidence) (platformruntime.Run, error)
			if mode == "cancel" {
				pending, err = store.BeginCancellation(id, running.Revision)
				finish = store.CancelWithStopEvidence
			} else {
				pending, err = store.BeginRecovery(id, running.Revision, running.LeaseUntil.Add(time.Millisecond))
				finish = store.CompleteRecoveryWithStopEvidence
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := finish(id, pending.Revision+1, proof); !errors.Is(err, platformruntime.ErrRevisionConflict) {
				t.Fatal("stale CAS accepted", err)
			}
			_, err = store.db.Exec(`CREATE FUNCTION controller_stop_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type IN ('runtime_process_stop_confirmed','recovery_stop_confirmed') THEN RAISE EXCEPTION 'stop proof audit unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER controller_stop_fault BEFORE INSERT ON platform_execution_event FOR EACH ROW EXECUTE FUNCTION controller_stop_fault_fn()`)
			if err != nil {
				t.Fatal(err)
			}
			defer store.db.Exec(`DROP FUNCTION IF EXISTS controller_stop_fault_fn() CASCADE`)
			if _, err := finish(id, pending.Revision, proof); err == nil {
				t.Fatal("proof audit failure committed stop")
			}
			unchanged, err := store.Get(id)
			if err != nil || unchanged.Status != pending.Status || unchanged.Revision != pending.Revision || unchanged.LeaseToken != pending.LeaseToken {
				t.Fatal("partial stop committed", err)
			}
			_, err = store.db.Exec(`DROP FUNCTION controller_stop_fault_fn() CASCADE`)
			if err != nil {
				t.Fatal(err)
			}
			result, err := finish(id, pending.Revision, proof)
			if err != nil {
				t.Fatal(err)
			}
			if result.LeaseToken != "" {
				t.Fatal("proven stop retained execution lease")
			}
			if mode == "cancel" && result.Status != platformruntime.StatusCancelled || mode == "recovery" && result.Status != platformruntime.StatusRunning {
				t.Fatal("wrong stop outcome")
			}
			if mode == "recovery" {
				if !bytes.Equal(result.ResumeInputJSON, resumeInput) {
					t.Fatal("recovery changed the durable resume input")
				}
				var payload []byte
				if err := store.db.QueryRow(`SELECT payload FROM platform_execution_event WHERE run_id=$1 AND event_type='recovery_stop_confirmed' ORDER BY seq DESC LIMIT 1`, id).Scan(&payload); err != nil {
					t.Fatal("recovery reference event missing", err)
				}
				if bytes.Contains(payload, []byte(running.LeaseToken)) {
					t.Fatal("recovery reference persisted the lease token")
				}
				var event struct {
					RecoveryReference struct {
						Version         string `json:"version"`
						RunID           string `json:"run_id"`
						StoppedRevision uint64 `json:"stopped_revision"`
						ReadyRevision   uint64 `json:"ready_revision"`
						Operation       string `json:"operation"`
						BodyHash        string `json:"body_hash"`
						PolicyHash      string `json:"policy_hash"`
						LeaseTokenHash  string `json:"lease_token_hash"`
						RequestHash     string `json:"request_hash"`
						ResumeInputHash string `json:"resume_input_hash"`
						Source          string `json:"source"`
						Digest          string `json:"proof_digest"`
						RuntimeID       string `json:"runtime_id"`
					} `json:"recovery_reference"`
				}
				if err := json.Unmarshal(payload, &event); err != nil {
					t.Fatal("invalid recovery reference event", err)
				}
				reference := event.RecoveryReference
				if reference.Version != "runtime-recovery-stop/v1" || reference.RunID != id ||
					reference.StoppedRevision != running.Revision || reference.ReadyRevision != result.Revision ||
					reference.Operation != dispatch.Operation || reference.BodyHash != dispatch.BodyHash || reference.PolicyHash != dispatch.PolicyHash ||
					reference.LeaseTokenHash != stopHash([]byte(running.LeaseToken)) || reference.RequestHash != stopHash(requestBody) ||
					reference.ResumeInputHash != stopHash(resumeInput) || reference.Source != proof.Source || reference.Digest != proof.Digest || reference.RuntimeID != proof.RuntimeID {
					t.Fatalf("recovery reference mismatch: %+v", reference)
				}
			}
			var count int
			if mode == "cancel" {
				if err := store.db.QueryRow(`SELECT COUNT(*) FROM platform_execution_event WHERE run_id=$1 AND event_type='runtime_process_stop_confirmed' AND payload::jsonb->>'digest'=$2`, id, proof.Digest).Scan(&count); err != nil || count != 1 {
					t.Fatal("proof audit missing or duplicated", err)
				}
			} else if err := store.db.QueryRow(`SELECT COUNT(*) FROM platform_execution_event WHERE run_id=$1 AND event_type='recovery_stop_confirmed'`, id).Scan(&count); err != nil || count != 1 {
				t.Fatal("recovery reference event missing or duplicated", err)
			}
			if mode == "cancel" {
				if _, err := finish(id, pending.Revision, proof); err != nil {
					t.Fatal("terminal retry not idempotent", err)
				}
			} else {
				if _, err := finish(id, pending.Revision, proof); !errors.Is(err, platformruntime.ErrRevisionConflict) {
					t.Fatal("recovery stale retry accepted", err)
				}
			}
		})
	}
}
