package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/execution"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// The rows below are non-secret transport fixtures, independent of Agent gold.
// Actual run leases, SQL capture, stop commit and pagination use production code.
func TestSQLLargeRecoveryReferencesBoundToStopAndLease(t *testing.T) {
	testSQLLargeRecoveryReferences(t, 4000)
}

func TestSQLRecoveryReferenceSetAbsoluteCapacity(t *testing.T) {
	testSQLLargeRecoveryReferences(t, contract.MaxRecoveryCheckpointSet)
}

func testSQLLargeRecoveryReferences(t *testing.T, total int) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	runs, err := execution.ConnectSQLStore(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	if err := execution.MigrateSchema(ctx, runs.DB()); err != nil {
		t.Fatal(err)
	}
	states, err := NewSQLCheckpointStore(runs.DB())
	if err != nil {
		t.Fatal(err)
	}
	if err := states.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	runs.SetRecoveryCheckpointCapture(states.CaptureRecoveryCheckpointsTx)
	runs.SetRecoveryCheckpointSetCapture(states.CaptureRecoveryCheckpointSetTx)
	id := fmt.Sprintf("large-recovery-%d", time.Now().UnixNano())
	scope := mcpTestScope()
	scope.RunID, scope.SessionID, scope.TraceID = id, id, id
	scope.TenantID = id
	policyHash := strings.Repeat("c", 64)
	request := contract.ExecuteRequest{ProtocolVersion: contract.ProtocolVersion, ContextToken: strings.Repeat("a", 64),
		Scope: contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
			AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID,
			PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, SessionID: scope.SessionID,
			InstallationID: scope.InstallationID, RunID: id, AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID},
		Operation: "invoke", IdempotencyKey: id, InputSchema: "schema://fixture/input/v1",
		Input: map[string]any{"policy_snapshot": map[string]any{"content_hash": policyHash,
			"runtime": map[string]any{"recovery_references": "paged/v1"}}}}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runs.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID,
		IdempotencyKey: id, Fingerprint: "large-reference-fixture", RequestJSON: raw, AgentEndpoint: "http://agent.example"}); err != nil {
		t.Fatal(err)
	}
	claimed, err := runs.AcquireLease(id, "old-owner", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	run, err := runs.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	bodyHash, err := contract.CanonicalExecuteBodyHash(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := runs.RecordDispatchCommand(platformruntime.DispatchCommand{RunID: id, Revision: run.Revision,
		Operation: "invoke", BodyHash: bodyHash, PolicyHash: policyHash}, run.LeaseToken); err != nil {
		t.Fatal(err)
	}
	prefix, _, err := stateKeys(scope, "recovery", "snapshot")
	if err != nil {
		t.Fatal(err)
	}
	schema := "schema://fixture/large-recovery/v1"
	content, err := stateContentHash(schema, map[string]any{"fixture": "transport-only"})
	if err != nil {
		t.Fatal(err)
	}
	value := `{"fixture":"transport-only"}`
	entries := make([]map[string]any, 0, total)
	for index := 0; index < total; index++ {
		_, key, err := stateKeys(scope, "fixture", fmt.Sprintf("step-%04d", index))
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, map[string]any{"key": key})
	}
	encoded, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := runs.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_business_state_head(scope_key,scope_prefix,schema_id,revision,expires_at)
  SELECT key,?,?,1,clock_timestamp()+interval '1 hour' FROM jsonb_to_recordset(?::jsonb) AS item(key text)`), prefix, schema, encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_business_checkpoint(scope_key,revision,idempotency_key,fingerprint,schema_id,value_json,content_hash,execution_revision,expires_at,created_at)
  SELECT scope_key,1,'fixture',?,?,?, ?,?,expires_at,clock_timestamp() FROM platform_business_state_head WHERE scope_prefix=?`), content, schema, value, content, run.Revision, prefix); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	capture := func(maximum int) ([]contract.RecoveryCheckpointReference, error) {
		locked, err := runs.DB().BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer locked.Rollback()
		var rev uint64
		if err := locked.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_execution_run WHERE run_id=? FOR UPDATE`), id).Scan(&rev); err != nil {
			return nil, err
		}
		return states.CaptureRecoveryCheckpointSetTx(ctx, locked, scope, run.Revision, maximum)
	}
	if _, err := capture(contract.MaxRecoveryCheckpoints); !errors.Is(err, ErrStateLimit) {
		t.Fatalf("legacy bound changed: %v", err)
	}
	started := time.Now()
	refs, err := capture(contract.MaxRecoveryCheckpointSet)
	if err != nil || len(refs) != total {
		t.Fatalf("large capture: n=%d error=%v", len(refs), err)
	}
	t.Logf("captured %d independently hashed heads in %s", len(refs), time.Since(started))
	firstKey := refs[0].StateKey
	t.Run("corrupt-payload", func(t *testing.T) {
		if _, err := runs.DB().ExecContext(ctx, sqlutil.Bind(`UPDATE platform_business_checkpoint SET value_json='{}' WHERE scope_key=?`), firstKey); err != nil {
			t.Fatal(err)
		}
		if _, err := capture(contract.MaxRecoveryCheckpointSet); !errors.Is(err, ErrStateUnavailable) {
			t.Fatalf("corrupt payload admitted: %v", err)
		}
		if _, err := runs.DB().ExecContext(ctx, sqlutil.Bind(`UPDATE platform_business_checkpoint SET value_json=? WHERE scope_key=?`), value, firstKey); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("missing-payload", func(t *testing.T) {
		fault, err := runs.DB().BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer fault.Rollback()
		if _, err := fault.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_business_checkpoint WHERE scope_key=?`), firstKey); err != nil {
			t.Fatal(err)
		}
		if _, err := states.CaptureRecoveryCheckpointSetTx(ctx, fault, scope, run.Revision, contract.MaxRecoveryCheckpointSet); !errors.Is(err, ErrStateContinuityLost) {
			t.Fatalf("missing payload admitted: %v", err)
		}
	})
	expired := time.Now().UTC().Add(-time.Second)
	if _, err := runs.DB().ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_run SET lease_until=? WHERE run_id=?`), expired, id); err != nil {
		t.Fatal(err)
	}
	if _, err := runs.DB().ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_session_lease SET lease_until=? WHERE run_id=?`), expired, id); err != nil {
		t.Fatal(err)
	}
	pending, err := runs.BeginRecovery(id, run.Revision, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	stopped, err := runs.CompleteRecovery(id, pending.Revision)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := runs.AcquireLease(id, "new-owner", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Revision != stopped.Revision+1 {
		t.Fatal("new generation revision mismatch")
	}
	reference, err := runs.CurrentRecoveryStopReference(ctx, fresh)
	if err != nil || reference == nil || reference.Version != "runtime-recovery-stop/v2" || reference.CheckpointSet == nil {
		t.Fatalf("reference=%+v err=%v", reference, err)
	}
	leaseHash := sha256.Sum256([]byte(fresh.LeaseToken))
	lease := sharedkernel.ExecutionLeaseBinding{Revision: fresh.Revision, TokenHash: fmt.Sprintf("%x", leaseHash)}
	set := *reference.CheckpointSet
	collected := []contract.RecoveryCheckpointReference{}
	for offset := 0; offset < total; offset += contract.RecoveryCheckpointPageSize {
		page, err := runs.ReadRecoveryCheckpointPage(ctx, scope, lease, set, offset, contract.RecoveryCheckpointPageSize)
		if err != nil || page.Offset != offset || page.Set != set {
			t.Fatalf("page %d: %+v %v", offset, page, err)
		}
		collected = append(collected, page.References...)
	}
	actual, err := contract.RecoveryCheckpointSet(collected)
	if err != nil || actual != set {
		t.Fatal("paging omitted, duplicated or altered reference metadata", err)
	}
	t.Run("signed-http-pages-use-real-stop-and-current-sql-lease", func(t *testing.T) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		resolver := governedInvocationResolver()
		resolver.snapshot.Hash = policyHash
		module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, resolver)
		module.SetCheckpointStore(states)
		module.SetRecoveryCheckpointPager(runs)
		revoked := false
		// IAM/workload/resource admission is an explicit fixture here. The
		// signed current execution lease and committed stop are real SQL facts.
		module.SetLiveExecutionAuthority(contextPreparationAuthority{
			testLiveAuthorityFunc: func(ctx context.Context, candidate sharedkernel.Scope, operation, body, policy string) error {
				if operation != "invoke" || body != bodyHash || policy != policyHash {
					return errors.New("signed command mismatch")
				}
				binding, ok := sharedkernel.ExecutionLeaseFromContext(ctx)
				if !ok {
					return errors.New("signed lease missing")
				}
				tx, err := runs.DB().BeginTx(ctx, nil)
				if err != nil {
					return err
				}
				defer tx.Rollback()
				return runs.CheckCapabilityLeaseTx(ctx, tx, candidate, binding)
			},
			resource: func(access CapabilityResourceAccess) error {
				if revoked || access.Action != "memory.read" || access.ResourceType != "memory" || access.ResourceID != "memory-a" {
					return errors.New("current fixture resource denied")
				}
				return nil
			},
		})
		actor := capabilityContext()
		actor.TenantID, actor.DepartmentID, actor.ApplicationID = scope.TenantID, scope.DepartmentID, scope.ApplicationID
		actor.ActorID, actor.PrincipalType = scope.PrincipalID, scope.PrincipalType
		actor.AgentID, actor.AgentVersionID = scope.AgentID, scope.AgentVersionID
		actor.InstallationID, actor.AgentInstanceID = scope.InstallationID, scope.AgentInstanceID
		actor.TaskID, actor.SessionID, actor.TraceID = scope.RunID, scope.SessionID, scope.TraceID
		actor.AuthorizationEpoch = scope.AuthorizationEpoch
		issue := func(actor harnessContext, revision uint64, tokenHash string) string {
			original := signedContextToken(t, private, actor, time.Now().Unix()-1, time.Now().Unix()+120)
			parts := strings.Split(original, ".")
			body, err := base64.RawURLEncoding.DecodeString(parts[1])
			var claims map[string]any
			if err != nil || json.Unmarshal(body, &claims) != nil {
				t.Fatal("fixture JWT unavailable")
			}
			claims["execution_revision"], claims["lease_token_hash"] = revision, tokenHash
			claims["body_hash"], claims["policy_snapshot_hash"] = bodyHash, policyHash
			raw, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			message := parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw)
			return message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(message)))
		}
		actor.PlatformContextToken = issue(actor, lease.Revision, lease.TokenHash)
		for _, offset := range []int{0, 64, total - 32} {
			response := capabilityRequest(t, module, "/internal/state/checkpoint", actor,
				map[string]any{"operation": "load", "reference_set": set, "offset": offset, "limit": 64})
			var result struct {
				Data contract.RecoveryCheckpointReferencePage `json:"data"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil ||
				result.Data.Set != set || result.Data.Offset != offset || len(result.Data.References) != min(64, total-offset) {
				t.Fatal("signed page unavailable", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "transport-only") {
				t.Fatal("metadata page disclosed checkpoint business values")
			}
		}
		for _, fault := range []string{"wrong-lease", "foreign-principal", "wrong-digest", "oversize", "mixed-write", "revoked-resource", "forged-token"} {
			t.Run(fault, func(t *testing.T) {
				input := map[string]any{"operation": "load", "reference_set": set, "offset": 0, "limit": 64}
				candidate := actor
				switch fault {
				case "wrong-lease":
					candidate.PlatformContextToken = issue(candidate, lease.Revision, strings.Repeat("a", 64))
				case "foreign-principal":
					candidate.ActorID = "foreign-user"
					candidate.PlatformContextToken = issue(candidate, lease.Revision, lease.TokenHash)
				case "wrong-digest":
					changed := set
					changed.Digest = strings.Repeat("b", 64)
					input["reference_set"] = changed
				case "oversize":
					input["limit"] = 65
				case "mixed-write":
					input["operation"], input["value"] = "save", map[string]any{"untrusted": true}
				case "revoked-resource":
					revoked = true
					defer func() { revoked = false }()
				case "forged-token":
					candidate.PlatformContextToken += "x"
				}
				response := capabilityRequest(t, module, "/internal/state/checkpoint", candidate, input)
				if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), `"references"`) {
					t.Fatal("unbound signed page admitted", response.Code, response.Body.String())
				}
			})
		}
	})
	for _, kind := range []string{"foreign-scope", "foreign-lease", "foreign-generation", "wrong-digest", "bad-offset", "oversize-page"} {
		t.Run(kind, func(t *testing.T) {
			candidateScope, candidateLease, candidateSet := scope, lease, set
			offset, limit := 0, 64
			switch kind {
			case "foreign-scope":
				candidateScope.PrincipalID = "other-user"
			case "foreign-lease":
				candidateLease.TokenHash = strings.Repeat("a", 64)
			case "foreign-generation":
				candidateLease.Revision--
			case "wrong-digest":
				candidateSet.Digest = strings.Repeat("b", 64)
			case "bad-offset":
				offset = total
			case "oversize-page":
				limit = 65
			}
			if _, err := runs.ReadRecoveryCheckpointPage(ctx, candidateScope, candidateLease, candidateSet, offset, limit); err == nil {
				t.Fatal("unbound page disclosed")
			}
		})
	}
	t.Run("expired-reference", func(t *testing.T) {
		original := reference.Checkpoints[0].ExpiresAt
		reference.Checkpoints[0].ExpiresAt = expired
		updated, err := contract.RecoveryCheckpointSet(reference.Checkpoints)
		if err != nil {
			t.Fatal(err)
		}
		reference.CheckpointSet = &updated
		event, err := json.Marshal(map[string]any{"revision": reference.ReadyRevision, "recovery_reference": reference})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runs.DB().ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_event SET payload=? WHERE run_id=? AND event_type='recovery_stop_confirmed'`), event, id); err != nil {
			t.Fatal(err)
		}
		if _, err := runs.ReadRecoveryCheckpointPage(ctx, scope, lease, updated, 0, 64); err == nil {
			t.Fatal("expired reference disclosed")
		}
		reference.Checkpoints[0].ExpiresAt = original
	})
	t.Logf("verified %d paged references with real stop commit and rejected foreign/expired inputs", len(collected))
}
