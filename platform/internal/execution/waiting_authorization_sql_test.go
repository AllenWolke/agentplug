package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func waitingAuthorizationSQLFixture(t *testing.T) (*SQLStore, context.Context) {
	t.Helper()
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL fixture required")
	}
	ctx := context.Background()
	store, err := openMigratedSQLFixture(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, ctx
}

func seedAuthorizationWaiting(t *testing.T, store *SQLStore, handoff bool) (platformruntime.Run, contract.HandlerHandoff) {
	t.Helper()
	id := fmt.Sprintf("waiting-renew-%d", time.Now().UnixNano())
	scope := testScope(id)
	scope.SessionID = id
	request := gatewayRequest(t, scope, "run")
	created, err := store.Create(platformruntime.CreateRequest{ID: id, Scope: scope.domain(), AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: "immutable-request-and-policy", RequestJSON: request, AgentEndpoint: "http://original-agent:8080"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.AcquireLease(id, "owned-handler-lease", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.TransitionLeased(created.Run.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	bodyHash := strings.Repeat("a", 64)
	if err = store.RecordDispatchCommand(platformruntime.DispatchCommand{RunID: id, Revision: running.Revision, Operation: "invoke", BodyHash: bodyHash, PolicyHash: strings.Repeat("b", 64)}, running.LeaseToken); err != nil {
		t.Fatal(err)
	}
	leaseHash := sha256.Sum256([]byte(running.LeaseToken))
	receipt := contract.HandlerHandoff{Version: "sdk-handler-exit/v1", RunID: id, ExecutionRevision: running.Revision, BodyHash: bodyHash, LeaseTokenHash: hex.EncodeToString(leaseHash[:]), InputFingerprint: strings.Repeat("c", 64), OriginOperation: "invoke", HarnessKey: "original-harness", ToolName: "clock.now", CallID: "original-call", LastEventSeq: 1}
	payload := map[string]any{"source": "platform_agent_gateway"}
	if handoff {
		payload["handoff"] = receipt
	}
	waiting, err := store.FinalizeLeased(id, platformruntime.StatusWaiting, running.Revision, running.LeaseToken, map[string]any{}, payload)
	if err != nil {
		t.Fatal(err)
	}
	// Compare durable PostgreSQL values, including its timestamp precision.
	waiting, err = store.Get(waiting.ID)
	if err != nil {
		t.Fatal(err)
	}
	return waiting, receipt
}

func renewalActor(run platformruntime.Run) BrowserRunActor {
	return BrowserRunActor{Scope: sharedkernel.Scope{TenantID: run.Scope.TenantID, DepartmentID: run.Scope.DepartmentID, ApplicationID: run.Scope.ApplicationID, PrincipalType: "user", PrincipalID: run.Scope.PrincipalID}, AuthenticationSession: "concrete-authentication-family", AuthenticationRevision: 1}
}

func renewalRequest(run platformruntime.Run) WaitingAuthorizationRequest {
	return WaitingAuthorizationRequest{Version: WaitingAuthorizationVersion, RequestID: "explicit-renewal", ExpectedRevision: run.Revision, ExpectedAuthorizationEpoch: run.Scope.AuthorizationEpoch}
}

func renewalTestPorts(store *SQLStore, denied, auditFailure bool) WaitingAuthorizationPorts {
	return WaitingAuthorizationPorts{
		Fence: func(context.Context, *sql.Tx) error { return nil },
		Authorize: func(context.Context, *sql.Tx, BrowserRunActor, BudgetRunFacts) (uint64, error) {
			if denied {
				return 0, ErrRunPermissionDenied
			}
			return 2, nil
		},
		RenewRootAuthority: func(ctx context.Context, tx *sql.Tx, old, next sharedkernel.Scope) error {
			_, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES(?,'renewal-root-probe','{}',?)`), old.RunID, time.Now().UTC())
			return err
		},
		Audit: func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, r WaitingAuthorizationReceipt) error {
			_, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES(?,'renewal-audit-probe','{}',?)`), scope.RunID, time.Now().UTC())
			if err != nil {
				return err
			}
			if auditFailure {
				return errors.New("injected audit failure")
			}
			return nil
		},
	}
}

func TestSQLWaitingAuthorizationPreservesExecutionAndReplaysOnlyReceipt(t *testing.T) {
	store, ctx := waitingAuthorizationSQLFixture(t)
	original, _ := seedAuthorizationWaiting(t, store, true)
	actor, request := renewalActor(original), renewalRequest(original)
	store.SetWaitingAuthorizationPorts(renewalTestPorts(store, false, false))
	receipt, err := store.RenewWaitingAuthorization(ctx, actor, original.ID, request)
	if err != nil || receipt.Replayed || receipt.AuthorizationEpoch != 2 || receipt.ExecutionRevision != original.Revision {
		t.Fatal("renewal failed", receipt, err)
	}
	actual, err := store.Get(original.ID)
	if err != nil {
		t.Fatal(err)
	}
	expectedScope := original.Scope
	if actual.Scope != expectedScope || actual.Revision != original.Revision || actual.Status != original.Status || actual.AgentVersionID != original.AgentVersionID || actual.AgentEndpoint != original.AgentEndpoint || actual.LeaseToken != original.LeaseToken || !actual.LeaseUntil.Equal(original.LeaseUntil) || !bytes.Equal(actual.RequestJSON, original.RequestJSON) || !bytes.Equal(actual.ResumeInputJSON, original.ResumeInputJSON) || !actual.UpdatedAt.Equal(original.UpdatedAt) {
		t.Fatal("renewal changed execution identity, input, lease or progress")
	}
	if epoch, proofErr := store.ExpectedAuthorizationEpoch(ctx, original.Scope); proofErr != nil || epoch != 2 {
		t.Fatal("current authority receipt does not resolve independently", epoch, proofErr)
	}
	var fp string
	if err = store.db.QueryRow(`SELECT fingerprint FROM platform_execution_run WHERE run_id=$1`, original.ID).Scan(&fp); err != nil || fp != "immutable-request-and-policy" {
		t.Fatal("request fingerprint changed", err)
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.WaitingHandlerHandoffTx(ctx, tx, actual.Scope, actual.Revision); err != nil {
		t.Fatal("original handler receipt no longer resolves", err)
	}
	if epoch, proofErr := store.ExpectedAuthorizationEpochTx(ctx, tx, original.Scope); proofErr != nil || epoch != 2 {
		t.Fatal("transactional current authority differs", epoch, proofErr)
	}
	_ = tx.Rollback()
	replayed, err := store.RenewWaitingAuthorization(ctx, actor, original.ID, request)
	if err != nil || !replayed.Replayed || replayed.OccurredAt != receipt.OccurredAt {
		t.Fatal("receipt replay failed", replayed, err)
	}
	store.SetWaitingAuthorizationPorts(renewalTestPorts(store, true, false))
	if _, err = store.RenewWaitingAuthorization(ctx, actor, original.ID, request); !errors.Is(err, ErrRunPermissionDenied) {
		t.Fatal("receipt replay bypassed revocation", err)
	}
	store.SetWaitingAuthorizationPorts(renewalTestPorts(store, false, false))
	var count int
	if err = store.db.QueryRow(`SELECT COUNT(*) FROM platform_execution_event WHERE run_id=$1 AND event_type IN ('run_authorization_renewed','renewal-audit-probe','renewal-root-probe')`, original.ID).Scan(&count); err != nil || count != 3 {
		t.Fatal("duplicate renewal or audit", count, err)
	}
	changed := request
	changed.ExpectedRevision++
	if _, err = store.RenewWaitingAuthorization(ctx, actor, original.ID, changed); !errors.Is(err, platformruntime.ErrRevisionConflict) {
		t.Fatal("changed idempotency request accepted", err)
	}
	if _, err = store.AppendEvent(original.ID, waitingAuthorizationEvent, map[string]any{"request_id": "forged"}); err == nil {
		t.Fatal("generic event API forged renewal receipt")
	}
	var old contract.ExecuteRequest
	if err = json.Unmarshal(actual.RequestJSON, &old); err != nil {
		t.Fatal(err)
	}
	if err = bindRunAuthorization(actual, &old); err != nil || old.Scope.AuthorizationEpoch != original.Scope.AuthorizationEpoch {
		t.Fatal("renewed command cannot be signed", err)
	}
	pending, err := store.BeginCancellation(actual.ID, actual.Revision)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := NewDispatcherWithGateway(store, "", &cancelTestGateway{}, 1)
	dispatcher.SetSecurity(machineRunContextSignerFunc(func(_ context.Context, scope sharedkernel.Scope, request contract.ExecuteRequest) (string, error) {
		if scope.AuthorizationEpoch != original.Scope.AuthorizationEpoch || request.Scope.AuthorizationEpoch != original.Scope.AuthorizationEpoch || request.Operation != "cancel" {
			t.Fatal("renewed stop command differs from server scope")
		}
		return "signed-stop-only", nil
	}), func(context.Context, sharedkernel.Scope) error {
		t.Fatal("cancellation admitted business execution")
		return nil
	})
	if err = dispatcher.confirmCancellation(ctx, pending); err != nil {
		t.Fatal("renewed waiting task cannot complete cancellation", err)
	}
	terminal, err := store.Get(actual.ID)
	if err != nil || terminal.Status != platformruntime.StatusCancelled {
		t.Fatal("cancellation did not become terminal", err)
	}
}

func TestSQLWaitingAuthorizationProofFailsClosedOnMismatch(t *testing.T) {
	store, ctx := waitingAuthorizationSQLFixture(t)
	for _, variant := range []string{"scope", "input", "future revision", "downgrade", "legacy receipt", "malformed", "invalid digest", "foreign scope"} {
		t.Run(variant, func(t *testing.T) {
			original, _ := seedAuthorizationWaiting(t, store, true)
			if epoch, err := store.ExpectedAuthorizationEpoch(ctx, original.Scope); err != nil || epoch != original.Scope.AuthorizationEpoch {
				t.Fatal("legacy run default authority changed", epoch, err)
			}
			store.SetWaitingAuthorizationPorts(renewalTestPorts(store, false, false))
			receipt, err := store.RenewWaitingAuthorization(ctx, renewalActor(original), original.ID, renewalRequest(original))
			if err != nil {
				t.Fatal(err)
			}
			lookup := original.Scope
			switch variant {
			case "scope":
				receipt.ScopeHash = strings.Repeat("f", 64)
			case "input":
				receipt.RequestHash = strings.Repeat("f", 64)
			case "future revision":
				receipt.ExecutionRevision = original.Revision + 1
			case "downgrade":
				receipt.AuthorizationEpoch = 0
			case "legacy receipt":
				receipt.Version = "waiting-run-authorization/v1"
			case "foreign scope":
				lookup.AgentVersionID = "foreign-version"
			case "invalid digest":
				receipt.RequestDigest = strings.Repeat("z", 64)
			}
			raw, _ := json.Marshal(receipt)
			if variant == "malformed" {
				raw = []byte(`{"version":"invalid"}`)
			}
			// Database corruption is a fixture; generic APIs cannot write this reserved event.
			if _, err = store.db.Exec(`UPDATE platform_execution_event SET payload=$1 WHERE run_id=$2 AND event_type=$3`, raw, original.ID, waitingAuthorizationEvent); err != nil {
				t.Fatal(err)
			}
			if _, err = store.ExpectedAuthorizationEpoch(ctx, lookup); !errors.Is(err, ErrRunPermissionDenied) {
				t.Fatal("invalid proof fell back to original authority", err)
			}
		})
	}
}

func TestSQLWaitingAuthorizationRepeatedRenewalUsesCurrentProofCAS(t *testing.T) {
	store, ctx := waitingAuthorizationSQLFixture(t)
	original, _ := seedAuthorizationWaiting(t, store, true)
	ports := renewalTestPorts(store, false, false)
	ports.RenewRootAuthority = func(_ context.Context, _ *sql.Tx, before, after sharedkernel.Scope) error {
		if before != original.Scope || after != before {
			return ErrRunPermissionDenied
		}
		return nil
	}
	store.SetWaitingAuthorizationPorts(ports)
	first := renewalRequest(original)
	if _, err := store.RenewWaitingAuthorization(ctx, renewalActor(original), original.ID, first); err != nil {
		t.Fatal(err)
	}
	ports.Authorize = func(context.Context, *sql.Tx, BrowserRunActor, BudgetRunFacts) (uint64, error) { return 3, nil }
	store.SetWaitingAuthorizationPorts(ports)
	second := first
	second.RequestID = "second-explicit-renewal"
	// Original Scope epoch is 1, but the next CAS must use current proof epoch 2.
	if _, err := store.RenewWaitingAuthorization(ctx, renewalActor(original), original.ID, second); !errors.Is(err, platformruntime.ErrRevisionConflict) {
		t.Fatal("original epoch reused as current authority CAS", err)
	}
	second.ExpectedAuthorizationEpoch = 2
	proof, err := store.RenewWaitingAuthorization(ctx, renewalActor(original), original.ID, second)
	if err != nil || proof.AuthorizationEpoch != 3 || proof.PreviousAuthorizationEpoch != 2 || proof.OriginalAuthorizationEpoch != 1 {
		t.Fatal("sequential renewal failed", proof, err)
	}
	if _, err = store.RenewWaitingAuthorization(ctx, renewalActor(original), original.ID, first); !errors.Is(err, platformruntime.ErrRevisionConflict) {
		t.Fatal("obsolete proof replayed after newer authority", err)
	}
	actual, err := store.Get(original.ID)
	if err != nil || actual.Scope != original.Scope || actual.Revision != original.Revision || actual.UpdatedAt != original.UpdatedAt || !bytes.Equal(actual.RequestJSON, original.RequestJSON) {
		t.Fatal("sequential authority renewal changed execution", err)
	}
}

func TestSQLWaitingAuthorizationDenialAndAuditRollback(t *testing.T) {
	store, ctx := waitingAuthorizationSQLFixture(t)
	for _, variant := range []string{"foreign actor", "stale revision", "stale epoch", "revoked", "audit failure", "no exit proof"} {
		t.Run(variant, func(t *testing.T) {
			original, _ := seedAuthorizationWaiting(t, store, variant != "no exit proof")
			actor, request := renewalActor(original), renewalRequest(original)
			if variant == "foreign actor" {
				actor.Scope.PrincipalID = "foreign"
			}
			if variant == "stale revision" {
				request.ExpectedRevision++
			}
			if variant == "stale epoch" {
				request.ExpectedAuthorizationEpoch++
			}
			store.SetWaitingAuthorizationPorts(renewalTestPorts(store, variant == "revoked", variant == "audit failure"))
			if _, err := store.RenewWaitingAuthorization(ctx, actor, original.ID, request); err == nil {
				t.Fatal("invalid renewal accepted")
			}
			actual, err := store.Get(original.ID)
			if err != nil || actual.Scope != original.Scope || actual.Status != original.Status || actual.Revision != original.Revision {
				t.Fatal("denial changed run", err)
			}
			var count int
			if err = store.db.QueryRow(`SELECT COUNT(*) FROM platform_execution_event WHERE run_id=$1 AND event_type IN ('run_authorization_renewed','renewal-audit-probe','renewal-root-probe')`, original.ID).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed transaction left renewal/audit/root changes", count, err)
			}
		})
	}
}

func TestSQLWaitingAuthorizationFencesConcurrentCancellation(t *testing.T) {
	store, ctx := waitingAuthorizationSQLFixture(t)
	original, handoff := seedAuthorizationWaiting(t, store, true)
	store.SetWaitingAuthorizationPorts(renewalTestPorts(store, false, false))
	var wg sync.WaitGroup
	wg.Add(2)
	var renewalErr, cancelErr error
	go func() {
		defer wg.Done()
		_, renewalErr = store.RenewWaitingAuthorization(ctx, renewalActor(original), original.ID, renewalRequest(original))
	}()
	go func() {
		defer wg.Done()
		pending, beginErr := store.BeginCancellation(original.ID, original.Revision)
		if beginErr != nil {
			cancelErr = beginErr
			return
		}
		_, cancelErr = store.CancelWithWaitingHandoff(original.ID, pending.Revision, handoff)
	}()
	wg.Wait()
	if cancelErr != nil {
		t.Fatal("owned cancellation failed", cancelErr)
	}
	if renewalErr != nil && !errors.Is(renewalErr, platformruntime.ErrInvalidTransition) {
		t.Fatal("renewal failed outside expected terminal race", renewalErr)
	}
	actual, err := store.Get(original.ID)
	if err != nil || actual.Status != platformruntime.StatusCancelled || actual.Revision != original.Revision+2 {
		t.Fatal("cancellation status/revision lost", err)
	}
}
