package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/policyasset"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/usagecost"
)

func TestPostgresIndexTaskCompositionUsesLiveIAMLeaseAndAudit(t *testing.T) {
	for _, mode := range []string{"allowed", "supervised", "scheduled", "admission-service", "admission-billing", "issued-index", "cancel-service", "cancel-running", "cancel-settlement", "stop-recovery", "admission-tx", "command-tx", "manager-revoked", "model-denied", "model-no-rows", "canceled", "batch-manager-revoked", "batch-model-revoked", "batch-source-changed", "audit-fault", "publication-fault", "wrong-task"} {
		t.Run(mode, func(t *testing.T) {
			dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
			if dsn == "" {
				t.Skip("isolated PostgreSQL required")
			}
			uri, err := url.Parse(dsn)
			if err != nil || uri.Hostname() != "127.0.0.1" || uri.Path != "/knowledge_test" {
				t.Fatal("owned loopback fixture required")
			}
			ctx := context.Background()
			admin, err := sql.Open("pgx", dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer admin.Close()
			db, err := sql.Open("pgx", os.Getenv("KNOWLEDGE_TEST_POSTGRES_DSN"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			iamAdmin := identity.NewSQLStore(admin)
			for _, ensure := range []func(context.Context) error{iamAdmin.EnsureSchema, notification.NewSQLStore(admin).EnsureSchema, audit.NewSQLStore(admin).EnsureSchema, func(ctx context.Context) error { return execution.MigrateSchema(ctx, admin) }} {
				if err := ensure(ctx); err != nil {
					t.Fatal(err)
				}
			}
			id := fmt.Sprintf("index-task-%d", time.Now().UnixNano())
			for _, err := range []error{iamAdmin.CreateTenant(ctx, identity.Tenant{ID: id, Code: id, Name: "fixture", Status: "active", Revision: 1}), iamAdmin.CreateDepartment(ctx, identity.Department{ID: id, TenantID: id, Code: id, Name: "fixture", Status: "active", Revision: 1}), iamAdmin.CreateApplication(ctx, identity.Application{ID: id, TenantID: id, DepartmentID: id, Code: id, Name: "fixture", Status: "active", Revision: 1}), iamAdmin.CreatePrincipal(ctx, identity.Principal{ID: id, Type: identity.PrincipalUser, TenantID: id, IsActive: true})} {
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := admin.Exec(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('user',$1,'v2',1,1)`, id); err != nil {
				t.Fatal(err)
			}
			binding := identity.RoleBinding{ID: id, SubjectID: id, RoleCode: "super_admin", RoleVersion: 1, Scope: identity.ManagementScope{Type: "global"}, Status: "active", Revision: 1, SourceID: "isolated-fixture"}
			setBinding := func() {
				t.Helper()
				raw, err := json.Marshal(binding)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := admin.Exec(`INSERT INTO platform_identity_role_binding(id,subject_id,role_code,role_version,tenant_id,department_id,application_id,status,revision,payload,source_hash) VALUES($1,$1,'super_admin',1,'','','',$2,1,$3,$1) ON CONFLICT(id) DO UPDATE SET status=EXCLUDED.status,payload=EXCLUDED.payload`, id, binding.Status, string(raw)); err != nil {
					t.Fatal(err)
				}
			}
			setBinding()
			ex, err := execution.OpenSQLStore(ctx, "pgx", os.Getenv("KNOWLEDGE_TEST_POSTGRES_DSN"))
			if err != nil {
				t.Fatal(err)
			}
			defer ex.Close()
			fault := &releaseAuditFault{recorder: audit.NewSQLStoreWithOutbox(db, notification.NewSQLStore(db))}
			p := knowledgePersistence{db: db, iam: identity.NewSQLStore(db), execution: ex, audit: fault}
			actor := sharedkernel.Scope{TenantID: id, DepartmentID: id, ApplicationID: id, PrincipalID: id, PrincipalType: "user", TraceID: "index-task-trace", AgentID: "indexer", AgentInstanceID: "indexer", AgentVersionID: "v1", InstallationID: "indexer", SessionID: id, RunID: id, AuthorizationEpoch: 1}
			scope := knowledge.ProjectionScope{TenantID: id, DepartmentID: id, ApplicationID: id, KnowledgeID: "docs"}
			if _, err := p.source(actor).Change(ctx, scope, knowledge.SourceChange{DocumentID: "doc", ActorPrincipalID: id, IdempotencyKey: "create", Body: "private-index-body abcdefghijklmnopqrstuvwxyz", ACL: knowledge.DocumentACL{OwnerPrincipalID: id}}); err != nil {
				t.Fatal(err)
			}
			requestJSON, err := json.Marshal(contract.ExecuteRequest{ProtocolVersion: contract.ProtocolVersion, Operation: "invoke", InputSchema: execution.KnowledgeIndexInputSchema, IdempotencyKey: "index-task", Scope: contract.ScopeKey{TenantID: id, DepartmentID: id, ApplicationID: id, PrincipalID: id, PrincipalType: "user", TraceID: actor.TraceID, AgentID: actor.AgentID, AgentInstanceID: actor.AgentInstanceID, AgentVersionID: actor.AgentVersionID, InstallationID: actor.InstallationID, SessionID: id, RunID: id, AuthorizationEpoch: 1}, Input: map[string]any{"knowledge_id": "docs"}})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "admission-service" || mode == "admission-billing" || mode == "issued-index" || mode == "cancel-service" || mode == "cancel-running" || mode == "cancel-settlement" || mode == "stop-recovery" {
				credential := seedIndexModelResources(t, admin, actor)
				snapshot := policyasset.Snapshot{ModelProfileID: "model", PromptVersionID: "prompt", ToolPolicyID: "tools", MemoryPolicyID: "memory", KnowledgePolicyID: "knowledge", RuntimePolicyID: "runtime", Revision: 1, Hash: strings.Repeat("a", 64), Model: policyasset.ModelPolicy{ModelVersionID: "embedding", Provider: "vectors", Model: "vectors", MaxTokens: 64}, Prompt: policyasset.PromptPolicy{TemplateHash: "prompt", Template: "approved"}, Tool: policyasset.ToolPolicy{AllowedTools: []string{"json.validate"}}, Memory: policyasset.MemoryPolicy{MaxEntries: 10}, Knowledge: policyasset.KnowledgePolicy{AllowedScopes: []string{"docs"}}, Runtime: policyasset.RuntimePolicy{MaxAttempts: 1, TaskTimeoutSeconds: 60, LeaseSeconds: 30}}
				var billing *indexSQLBilling
				if mode == "admission-billing" || mode == "issued-index" || mode == "cancel-settlement" || mode == "stop-recovery" {
					billing = newIndexSQLBilling(t, admin, db, actor, &snapshot)
				}
				control := knowledgeControl{persistence: p, targets: indexAdmissionCatalogFixture{{AgentID: "indexer", VersionID: "v1", InstallationID: "indexer"}}, policies: policyasset.StaticResolver{Snapshot: snapshot}}
				request := knowledge.IndexTaskRequest{InstallationID: "indexer", IdempotencyKey: "service-index", Mode: "full", Config: knowledge.IndexSettings{Dimensions: 2, WindowRunes: 8, OverlapRunes: 2, MaximumDocuments: 10, MaximumChunks: 100}}
				// Indexing must preserve management authority without business run rights.
				if _, err := p.iam.CurrentAuthorizationEpoch(ctx, actor, "policy.manage"); err != nil {
					t.Fatal(err)
				}
				if _, err := admin.Exec(`UPDATE platform_identity_principal SET revision=revision+1 WHERE principal_type='user' AND id=$1`, id); err != nil {
					t.Fatal(err)
				}
				if mode == "issued-index" {
					snapshot.Model.BudgetCents = 10
					control.policies = policyasset.StaticResolver{Snapshot: snapshot}
					request.Config.WindowRunes = 8
					request.Config.OverlapRunes = 6
				}
				if mode == "stop-recovery" {
					// Recovery tests the stop barrier; reserve enough for the ordinary
					// conservative multi-text estimate. Budget denial has separate cases.
					snapshot.Model.BudgetCents = 10
					control.policies = policyasset.StaticResolver{Snapshot: snapshot}
				}
				first, err := control.SubmitIndex(ctx, actor, scope, request)
				if err != nil || first.Replayed {
					t.Fatal("production admission service", err)
				}
				pending, err := control.QueryIndex(ctx, actor, scope, first.RunID)
				if err != nil || pending.Status != "accepted" || pending.Result != nil || pending.Mode != "full" {
					t.Fatal("query accepted index", err, pending)
				}
				foreignApp := scope
				foreignApp.ApplicationID = "other-application"
				if _, err := control.QueryIndex(ctx, actor, foreignApp, first.RunID); !errors.Is(err, knowledge.ErrManagementDenied) {
					t.Fatal("foreign workspace query", err)
				}
				second, err := control.SubmitIndex(ctx, actor, scope, request)
				if err != nil || !second.Replayed || second.RunID != first.RunID {
					t.Fatal("service replay", err)
				}
				stored, err := ex.Get(first.RunID)
				if err != nil {
					t.Fatal(err)
				}
				currentRunEpoch, err := p.iam.CurrentAuthorizationEpoch(ctx, stored.Scope, "policy.manage")
				if err != nil || stored.Scope.AuthorizationEpoch != currentRunEpoch {
					t.Fatal("index job uses a stale management permission epoch", err, stored.Scope.AuthorizationEpoch, currentRunEpoch)
				}
				var command contract.ExecuteRequest
				if json.Unmarshal(stored.RequestJSON, &command) != nil || command.Input["policy_snapshot"].(map[string]any)["content_hash"] != snapshot.Hash || command.Input["index_mode"] != "full" || stored.AgentEndpoint != "" || command.ContextToken != "" {
					t.Fatal("untrusted or missing policy in job")
				}
				if _, err := p.iam.CurrentAuthorizationEpoch(ctx, stored.Scope, "run"); err == nil {
					t.Fatal("management-only user acquired implicit business run rights")
				}
				if mode == "cancel-service" {
					fault.fail = true
					if _, err := control.CancelIndex(ctx, actor, scope, stored.ID, knowledge.IndexCancelRequest{ExpectedRevision: stored.Revision}); err == nil {
						t.Fatal("cancel audit fault succeeded")
					}
					fault.fail = false
					unchanged, err := ex.Get(stored.ID)
					if err != nil || unchanged.Status != stored.Status || unchanged.Revision != stored.Revision {
						t.Fatal("cancel audit fault left intent", err)
					}
					if _, err := control.CancelIndex(ctx, actor, scope, stored.ID, knowledge.IndexCancelRequest{ExpectedRevision: stored.Revision + 1}); !errors.Is(err, knowledge.ErrIndexTaskConflict) {
						t.Fatal("stale cancellation CAS", err)
					}
					foreign := scope
					foreign.KnowledgeID = "foreign"
					if _, err := control.CancelIndex(ctx, actor, foreign, stored.ID, knowledge.IndexCancelRequest{ExpectedRevision: stored.Revision}); !errors.Is(err, knowledge.ErrIndexTaskNotFound) {
						t.Fatal("foreign cancel", err)
					}
					final, err := control.CancelIndex(ctx, actor, scope, stored.ID, knowledge.IndexCancelRequest{ExpectedRevision: stored.Revision})
					if err != nil || final.Status != "cancelled" {
						t.Fatal("unclaimed cancellation not terminal", err, final)
					}
					replay, err := control.CancelIndex(ctx, actor, scope, stored.ID, knowledge.IndexCancelRequest{ExpectedRevision: stored.Revision})
					if err != nil || replay != final {
						t.Fatal("cancel replay changed receipt", err, replay)
					}
					outcome, err := ex.GetOutcome(stored.ID)
					if err != nil || outcome.EventType != "task_cancelled" || outcome.Revision != final.Revision {
						t.Fatal("cancel outcome missing", err)
					}
					assertIndexCancelEvents(t, admin, stored.ID)
					return
				}
				lease, err := ex.AcquireLease(stored.ID, "index-management-owner", time.Now().UTC(), time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				running, err := ex.TransitionLeased(stored.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, lease.Revision, lease.LeaseToken)
				if err != nil {
					t.Fatal(err)
				}
				bodyHash, err := contract.CanonicalExecuteBodyHash(command)
				if err != nil {
					t.Fatal(err)
				}
				tx, err := db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := ex.RecordInternalTaskCommandTx(ctx, tx, running.Scope, running.LeaseToken, running.Revision, platformruntime.DispatchCommand{RunID: running.ID, Revision: running.Revision, Operation: command.Operation, BodyHash: bodyHash, PolicyHash: snapshot.Hash}); err != nil {
					tx.Rollback()
					t.Fatal(err)
				}
				if err := tx.Commit(); err != nil {
					t.Fatal(err)
				}
				executionModule := execution.NewModuleWithSharedRepository("internal", ex)
				proof := sharedkernel.BindExecutionLease(ctx, running.Revision, running.LeaseToken)
				authority := capabilityExecutionAuthority{execution: executionModule, identity: p.iam, catalog: control.targets.(indexAdmissionCatalogFixture)}
				if err := authority.AuthorizeCapability(proof, running.Scope, command.Operation, bodyHash, snapshot.Hash); err != nil {
					t.Fatal("management index incorrectly requires business run grant", err)
				}
				action, err := executionModule.CapabilityAuthorizationAction(proof, running.Scope, command.Operation, bodyHash, snapshot.Hash)
				if err != nil || action != "policy.manage" {
					t.Fatal("wrong internal command action", err, action)
				}
				public, private, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				signer := conversation.Ed25519ContextTokenSigner{PrivateKey: private, Issuer: "platform", Audience: "agent-runtime", TTL: time.Minute}
				capabilityModule := capability.NewModuleWithKnowledgeAndPolicies("internal", "index-hmac", public, "platform", "agent-runtime", nil, control.policies)
				if billing != nil {
					capabilityModule = capability.NewModuleWithGovernance("internal", "index-hmac", public, "platform", "agent-runtime", nil, control.policies, nil, billing.invocations)
				}
				capabilityModule.SetLiveExecutionAuthority(authority)
				gateway := &indexNoSendGateway{}
				capabilityModule.SetGovernedModelInvocation(indexModelSelectionFixture{}, gateway)
				if billing != nil {
					capabilityModule.SetGovernedModelInvocation(billing.access, billing.gateway)
					capabilityModule.SetModelBilling(billing.governance, billing.usage)
					capabilityModule.SetModelCapacity(billing.capacity)
				}
				invalid := credential
				invalid.Secret = "invalid-index-secret-value-12345678"
				if _, err := p.openIndexTaskModels(ctx, running, scope, signer, capabilityModule, invalid); err == nil {
					t.Fatal("wrong SQL machine credential opened session")
				}
				session, err := p.openIndexTaskModels(ctx, running, scope, signer, capabilityModule, credential)
				if err != nil {
					t.Fatal("signed SQL index model session", err)
				}
				defer session.Close()
				if err := session.Check(ctx, "embed"); err != nil {
					t.Fatal("initial SQL model check", err)
				}
				if _, err := admin.Exec(`UPDATE platform_identity_grant SET status='revoked',revision=revision+1 WHERE id=$1`, credential.ClientID+"-embed"); err != nil {
					t.Fatal(err)
				}
				if err := session.Check(ctx, "embed"); err == nil {
					t.Fatal("machine model revocation ignored")
				}
				if _, err := admin.Exec(`UPDATE platform_identity_grant SET status='active',revision=revision+1 WHERE id=$1`, credential.ClientID+"-embed"); err != nil {
					t.Fatal(err)
				}
				if err := session.Check(ctx, "embed"); err != nil {
					t.Fatal("restored machine model grant", err)
				}
				if gateway.calls != 0 {
					t.Fatal("opening or checking session sent model", gateway.calls)
				}

				if mode == "stop-recovery" {
					// Owned fixture expires the SQL lease without pretending its
					// owner exited. The first reconciliation must stop at recovering.
					if _, err := admin.Exec(`UPDATE platform_execution_run SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE run_id=$1`, running.ID); err != nil {
						t.Fatal(err)
					}
					if _, err := admin.Exec(`UPDATE platform_execution_session_lease SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE run_id=$1`, running.ID); err != nil {
						t.Fatal(err)
					}
					if err := p.reconcileIndexStops(ctx, capabilityModule); err != nil {
						t.Fatal("expired owner scan", err)
					}
					held, err := ex.Get(running.ID)
					if err != nil || held.Status != platformruntime.StatusRecovering || held.LeaseToken != running.LeaseToken {
						t.Fatal("expiry inferred stop", err, held.Status)
					}
					if err := session.Check(ctx, "embed"); err == nil {
						t.Fatal("expired owner model authority survived")
					}
					_, oldConfig, _, err := indexRunParameters(running)
					if err != nil {
						t.Fatal(err)
					}
					if err := p.executeIndexWithStopReceipt(ctx, running, func(ctx context.Context) error {
						return p.executeIssuedIndexTask(ctx, running, scope, oldConfig, false, signer, capabilityModule, credential, time.Minute)
					}); err == nil {
						t.Fatal("expired owner executed")
					}
					if err := p.reconcileIndexStops(ctx, capabilityModule); err != nil {
						t.Fatal("acknowledged recovery", err)
					}
					ready, err := ex.Get(running.ID)
					if err != nil || ready.Status != platformruntime.StatusRunning || ready.LeaseToken != "" {
						t.Fatal("recovery not requeued", err, ready.Status)
					}
					var stopReceiptCount int
					if err := admin.QueryRow(`SELECT COUNT(*) FROM platform_execution_event WHERE run_id=$1 AND event_type='internal_task_stopped'`, running.ID).Scan(&stopReceiptCount); err != nil || stopReceiptCount != 1 {
						t.Fatal("internal task stop receipt missing or duplicated", err, stopReceiptCount)
					}
					var stopReceiptPayload []byte
					if err := admin.QueryRow(`SELECT payload FROM platform_execution_event WHERE run_id=$1 AND event_type='internal_task_stopped' ORDER BY seq DESC LIMIT 1`, running.ID).Scan(&stopReceiptPayload); err != nil {
						t.Fatal("internal task stop receipt missing", err)
					}
					var stopReceipt struct {
						ExecutionRevision uint64 `json:"execution_revision"`
						LeaseDigest       string `json:"lease_digest"`
					}
					if err := json.Unmarshal(stopReceiptPayload, &stopReceipt); err != nil {
						t.Fatal("invalid internal task stop receipt", err)
					}
					leaseHash := fmt.Sprintf("%x", sha256.Sum256([]byte(running.LeaseToken)))
					originalInput, err := json.Marshal(command.Input)
					if err != nil {
						t.Fatal(err)
					}
					if stopReceipt.ExecutionRevision != running.Revision || stopReceipt.LeaseDigest != leaseHash || bytes.Contains(stopReceiptPayload, []byte(running.LeaseToken)) || bytes.Contains(stopReceiptPayload, running.RequestJSON) || bytes.Contains(stopReceiptPayload, originalInput) {
						t.Fatal("internal task stop receipt does not bind the original generation safely")
					}
					receiptJSON, err := json.Marshal(struct {
						ExecutionRevision uint64 `json:"execution_revision"`
						LeaseDigest       string `json:"lease_digest"`
					}{ExecutionRevision: running.Revision, LeaseDigest: leaseHash})
					if err != nil {
						t.Fatal(err)
					}
					var recoveryPayload []byte
					if err := admin.QueryRow(`SELECT payload FROM platform_execution_event WHERE run_id=$1 AND event_type='recovery_stop_confirmed' ORDER BY seq DESC LIMIT 1`, running.ID).Scan(&recoveryPayload); err != nil {
						t.Fatal("internal recovery reference missing", err)
					}
					var recoveryEvent map[string]json.RawMessage
					if err := json.Unmarshal(recoveryPayload, &recoveryEvent); err != nil {
						t.Fatal("invalid internal recovery event", err)
					}
					if _, external := recoveryEvent["recovery_reference"]; external {
						t.Fatal("internal recovery emitted an external SDK reference")
					}
					internalRaw, exists := recoveryEvent["internal_recovery_reference"]
					if !exists {
						t.Fatal("internal recovery reference was not recorded")
					}
					var internalReference struct {
						Version         string `json:"version"`
						RunID           string `json:"run_id"`
						StoppedRevision uint64 `json:"stopped_revision"`
						ReadyRevision   uint64 `json:"ready_revision"`
						RequestHash     string `json:"request_hash"`
						ResumeInputHash string `json:"resume_input_hash"`
						LeaseHash       string `json:"lease_token_hash"`
						ReceiptHash     string `json:"receipt_hash"`
						Source          string `json:"source"`
					}
					if err := json.Unmarshal(internalRaw, &internalReference); err != nil {
						t.Fatal("invalid internal recovery reference", err)
					}
					requestHash := fmt.Sprintf("%x", sha256.Sum256(running.RequestJSON))
					resumeInputHash := fmt.Sprintf("%x", sha256.Sum256(running.ResumeInputJSON))
					receiptHash := fmt.Sprintf("%x", sha256.Sum256(receiptJSON))
					if internalReference.Version != "internal-task-recovery-stop/v1" || internalReference.RunID != running.ID ||
						internalReference.StoppedRevision != running.Revision || internalReference.ReadyRevision != ready.Revision ||
						internalReference.RequestHash != requestHash || internalReference.ResumeInputHash != resumeInputHash ||
						internalReference.LeaseHash != leaseHash || internalReference.ReceiptHash != receiptHash ||
						internalReference.Source != "internal-task-stopped/v1" {
						t.Fatalf("internal recovery reference mismatch: %+v", internalReference)
					}
					if bytes.Contains(recoveryPayload, []byte(running.LeaseToken)) || bytes.Contains(recoveryPayload, running.RequestJSON) || bytes.Contains(recoveryPayload, originalInput) || (len(running.ResumeInputJSON) > 0 && bytes.Contains(recoveryPayload, running.ResumeInputJSON)) {
						t.Fatal("internal recovery event contains plaintext lease or command input")
					}
					scheduler := execution.InternalTaskScheduler{Repository: ex, InputSchema: execution.KnowledgeIndexInputSchema, LeaseTTL: time.Minute, Authorize: func(ctx context.Context, owner sharedkernel.Scope) error {
						tx, err := db.BeginTx(ctx, nil)
						if err != nil {
							return err
						}
						defer tx.Rollback()
						if err := p.authorize(ctx, tx, owner, scope); err != nil {
							return err
						}
						return tx.Commit()
					}, Execute: func(ctx context.Context, claimed platformruntime.Run) error {
						return p.executeIndexWithStopReceipt(ctx, claimed, func(ctx context.Context) error {
							projection, config, incremental, err := indexRunParameters(claimed)
							if err != nil {
								return err
							}
							return p.executeIssuedIndexTask(ctx, claimed, projection, config, incremental, signer, capabilityModule, credential, time.Minute)
						})
					}}
					if err := scheduler.Dispatch(ctx, ready.ID); err != nil {
						t.Fatal("recovered signed index dispatch", err)
					}
					finished, err := ex.Get(ready.ID)
					if err != nil || finished.Status != platformruntime.StatusSucceeded || billing.calls.Load() != 1 {
						t.Fatal("recovered index not complete once", err, finished.Status)
					}
					if err := ex.RecordInternalTaskStopped(ctx, running.Scope, running.LeaseToken, running.Revision); err != nil {
						t.Fatal("terminal receipt replay", err)
					}
					return
				}
				if mode == "cancel-running" || mode == "cancel-settlement" {
					pending, err := control.CancelIndex(ctx, actor, scope, running.ID, knowledge.IndexCancelRequest{ExpectedRevision: running.Revision})
					if err != nil || pending.Status != "cancelling" || pending.Revision != running.Revision+1 {
						t.Fatal("running cancel intent", err, pending)
					}
					current, err := ex.Get(running.ID)
					if err != nil || current.LeaseToken != running.LeaseToken {
						t.Fatal("pending stop released lease", err)
					}
					if err := session.Check(ctx, "embed"); err == nil {
						t.Fatal("cancelled command kept model authority")
					}
					if _, err := ex.GetOutcome(running.ID); !errors.Is(err, platformruntime.ErrRunNotFound) {
						t.Fatal("pending stop fabricated outcome", err)
					}
					_, config, _, err := indexRunParameters(running)
					if err != nil {
						t.Fatal(err)
					}
					if err := p.executeIssuedIndexTask(ctx, running, scope, config, false, signer, capabilityModule, credential, time.Minute); err == nil {
						t.Fatal("cancelled owner executed")
					}
					if gateway.calls != 0 {
						t.Fatal("pending cancellation sent model")
					}
					if err := p.reconcileIndexStops(ctx, capabilityModule); err != nil {
						t.Fatal("unacknowledged stop scan", err)
					}
					beforeAck, err := ex.Get(running.ID)
					if err != nil || beforeAck.Status != platformruntime.StatusCancelling {
						t.Fatal("ledger quiet replaced stop proof", err)
					}
					replay, err := control.CancelIndex(ctx, actor, scope, running.ID, knowledge.IndexCancelRequest{ExpectedRevision: running.Revision})
					if err != nil || replay != pending {
						t.Fatal("pending cancel replay", err)
					}
					assertIndexCancelEvents(t, admin, running.ID)
					binding.Status = "revoked"
					setBinding()
					if _, err := control.CancelIndex(ctx, actor, scope, running.ID, knowledge.IndexCancelRequest{ExpectedRevision: running.Revision}); !errors.Is(err, knowledge.ErrManagementDenied) {
						t.Fatal("revoked manager canceled", err)
					}
					if err := ex.RecordInternalTaskStopped(ctx, running.Scope, "foreign-owner", running.Revision); err == nil {
						t.Fatal("forged stop owner accepted")
					}
					if err := p.executeIndexWithStopReceipt(ctx, running, func(ctx context.Context) error {
						return p.executeIssuedIndexTask(ctx, running, scope, config, false, signer, capabilityModule, credential, time.Minute)
					}); err == nil {
						t.Fatal("cancelled execution succeeded")
					}
					if err := ex.RecordInternalTaskStopped(ctx, running.Scope, running.LeaseToken, running.Revision); err != nil {
						t.Fatal("stop receipt replay", err)
					}
					var stopCount int
					if err := admin.QueryRow(`SELECT COUNT(*) FROM platform_execution_event WHERE run_id=$1 AND event_type='internal_task_stopped'`, running.ID).Scan(&stopCount); err != nil || stopCount != 1 {
						t.Fatal("stop acknowledgment duplicated", err, stopCount)
					}
					var hash string
					if billing != nil {
						s := running.Scope
						raw, _ := json.Marshal([]string{s.TenantID, s.DepartmentID, s.ApplicationID, s.AgentID, s.AgentInstanceID, s.PrincipalType, s.PrincipalID, s.InstallationID, s.AgentVersionID, s.SessionID})
						hash = fmt.Sprintf("%x", sha256.Sum256(raw))
						if _, _, err := billing.invocations.Reserve(ctx, hash, "unsettled-stop", "fixture", 0, 0); err != nil {
							t.Fatal(err)
						}
						if err := p.reconcileIndexStops(ctx, capabilityModule); err == nil {
							t.Fatal("running model invocation released session")
						}
						if err := billing.invocations.MarkReconciliationNeeded(ctx, hash, "unsettled-stop", "fixture", nil, 0); err != nil {
							t.Fatal(err)
						}
						if err := p.reconcileIndexStops(ctx, capabilityModule); err == nil {
							t.Fatal("unknown model invocation released session")
						}
						hold, err := ex.Get(running.ID)
						if err != nil || hold.Status != platformruntime.StatusCancelling || hold.LeaseToken != running.LeaseToken {
							t.Fatal("unsettled stop lost owner", err)
						}
						if err := billing.invocations.Complete(ctx, hash, "unsettled-stop", "fixture", map[string]any{}, 0); err != nil {
							t.Fatal("fixture ledger completion", err)
						}
					}
					if err := p.reconcileIndexStops(ctx, capabilityModule); err != nil {
						t.Fatal("acknowledged settled stop", err)
					}
					final, err := ex.Get(running.ID)
					if err != nil || final.Status != platformruntime.StatusCancelled || final.LeaseToken != "" {
						t.Fatal("stopped index not cancelled", err, final.Status)
					}
					if billing != nil && billing.calls.Load() != 0 {
						t.Fatal("stop reconciliation resent provider")
					}
					return
				}
				if mode == "issued-index" {
					session.Close()
					projection, indexConfig, incremental, err := indexRunParameters(running)
					if err != nil {
						t.Fatal(err)
					}
					if err := p.executeIssuedIndexTask(ctx, running, projection, indexConfig, incremental, signer, capabilityModule, credential, time.Minute); err != nil {
						t.Fatal("full signed and billed index execution", err)
					}
					completed, err := ex.Get(running.ID)
					if err != nil || completed.Status != platformruntime.StatusSucceeded {
						t.Fatal("index did not finalize", err, completed.Status)
					}
					result, err := ex.GetOutcome(running.ID)
					if err != nil {
						t.Fatal(err)
					}
					if result.ProjectionPending {
						t.Fatal("internal index enqueued a synthetic conversation result")
					}
					detail, err := control.QueryIndex(ctx, actor, scope, running.ID)
					if err != nil || detail.Status != "succeeded" || detail.Mode != "full" || detail.Result == nil || detail.Result.IndexRevision != 1 {
						t.Fatal("query completed full index", err, detail)
					}
					foreign := scope
					foreign.KnowledgeID = "other"
					if _, err := control.QueryIndex(ctx, actor, foreign, running.ID); !errors.Is(err, knowledge.ErrIndexTaskNotFound) {
						t.Fatal("query exposed foreign knowledge task", err)
					}
					if _, err := control.QueryIndex(ctx, actor, scope, "missing-index-task"); !errors.Is(err, knowledge.ErrIndexTaskNotFound) {
						t.Fatal("unknown query not concealed", err)
					}
					var output map[string]any
					if json.Unmarshal(result.OutputJSON, &output) != nil || output["schema_version"] != "knowledge-index-result/v1" || output["index_revision"] != float64(1) || output["embedded_chunks"].(float64) <= 16 {
						t.Fatal("index receipt not published")
					}
					usage, err := billing.usage.GetSnapshot(ctx, usagecost.Scope{TenantID: running.Scope.TenantID, DepartmentID: running.Scope.DepartmentID, ApplicationID: running.Scope.ApplicationID, AgentID: running.Scope.AgentID, AgentVersionID: running.Scope.AgentVersionID, RunID: running.ID})
					if err != nil || usage.InputTokens != 100 || usage.UsedMicros != 10000 || billing.calls.Load() != 2 {
						t.Fatal("full index did not settle exactly once", err, usage.InputTokens, usage.UsedMicros, billing.calls.Load())
					}
					if _, err := p.checkpoints(scope).Load(ctx, running.Scope, scope.KnowledgeID, running.LeaseToken, running.Revision); !errors.Is(err, platformruntime.ErrLeaseConflict) {
						t.Fatal("completed index retained checkpoint authority", err)
					}
					if _, err := p.source(actor).Change(ctx, scope, knowledge.SourceChange{DocumentID: "doc", ActorPrincipalID: id, IdempotencyKey: "incremental-source", ExpectedSourceRevision: 1, ExpectedDocumentVersion: 1, Body: "private-index-body abcdefghijklmnopqrstuvwxyz new", ACL: knowledge.DocumentACL{OwnerPrincipalID: id}}); err != nil {
						t.Fatal("incremental source update", err)
					}
					request.Mode = "incremental"
					request.IdempotencyKey = "incremental-index-task"
					receipt, err := control.SubmitIndex(ctx, actor, scope, request)
					if err != nil {
						t.Fatal("incremental admission", err)
					}
					claimed, err := ex.AcquireLease(receipt.RunID, "incremental-owner", time.Now().UTC(), time.Minute)
					if err != nil {
						t.Fatal(err)
					}
					incrementalRun, err := ex.TransitionLeased(receipt.RunID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
					if err != nil {
						t.Fatal(err)
					}
					incrementalScope, incrementalConfig, isIncremental, err := indexRunParameters(incrementalRun)
					if err != nil || !isIncremental {
						t.Fatal("incremental parameters", err)
					}
					if err := p.executeIssuedIndexTask(ctx, incrementalRun, incrementalScope, incrementalConfig, true, signer, capabilityModule, credential, time.Minute); err != nil {
						t.Fatal("signed billed incremental index", err)
					}
					incrementalOutcome, err := ex.GetOutcome(incrementalRun.ID)
					if err != nil {
						t.Fatal(err)
					}
					if incrementalOutcome.ProjectionPending {
						t.Fatal("incremental index enqueued a synthetic conversation result")
					}
					incrementalDetail, err := control.QueryIndex(ctx, actor, scope, incrementalRun.ID)
					if err != nil || incrementalDetail.Mode != "incremental" || incrementalDetail.Result == nil || incrementalDetail.Result.IndexRevision != 2 {
						t.Fatal("query incremental publication", err, incrementalDetail)
					}
					if json.Unmarshal(incrementalOutcome.OutputJSON, &output) != nil || output["index_revision"] != float64(2) || output["source_revision"] != float64(2) || output["reused_chunks"].(float64) <= 0 || output["embedded_chunks"].(float64) <= 0 {
						t.Fatal("incremental index did not reuse and advance versions")
					}
					incrementalUsage, err := billing.usage.GetSnapshot(ctx, usagecost.Scope{TenantID: incrementalRun.Scope.TenantID, DepartmentID: incrementalRun.Scope.DepartmentID, ApplicationID: incrementalRun.Scope.ApplicationID, AgentID: incrementalRun.Scope.AgentID, AgentVersionID: incrementalRun.Scope.AgentVersionID, RunID: incrementalRun.ID})
					if err != nil || incrementalUsage.InputTokens-usage.InputTokens != 50 || incrementalUsage.UsedMicros-usage.UsedMicros != 5000 || billing.calls.Load() != 3 {
						t.Fatal("reused chunks billed again", err, incrementalUsage.InputTokens, incrementalUsage.UsedMicros, billing.calls.Load())
					}
					binding.Status = "revoked"
					setBinding()
					if _, err := control.QueryIndex(ctx, actor, scope, incrementalRun.ID); !errors.Is(err, knowledge.ErrManagementDenied) {
						t.Fatal("revoked manager read completed index", err)
					}

					return
				}
				if billing != nil {
					input := map[string]any{"texts": []string{"index text"}}
					if _, err := session.Call(ctx, "embed", input); err != nil {
						t.Fatal("signed SQL billable embedding", err)
					}
					session.Close()
					session, err = p.openIndexTaskModels(ctx, running, scope, signer, capabilityModule, credential)
					if err != nil {
						t.Fatal("fresh signed billing session", err)
					}
					defer session.Close()
					if _, err := session.Call(ctx, "embed", input); err != nil {
						t.Fatal("embedding ledger replay", err)
					}
					if billing.calls.Load() != 1 {
						t.Fatal("replay sent duplicate model", billing.calls.Load())
					}
					usage, err := billing.usage.GetSnapshot(ctx, usagecost.Scope{TenantID: running.Scope.TenantID, DepartmentID: running.Scope.DepartmentID, ApplicationID: running.Scope.ApplicationID, AgentID: running.Scope.AgentID, AgentVersionID: running.Scope.AgentVersionID, RunID: running.ID})
					if err != nil || usage.InputTokens != 50 || usage.UsedMicros != 5000 {
						t.Fatal("signed index usage not settled", err, usage.InputTokens, usage.UsedMicros)
					}
					_, budgetErr := session.Call(ctx, "embed", map[string]any{"texts": []string{strings.Repeat("hello ", 10)}})
					var modelFailure *capability.KnowledgeModelError
					if !errors.As(budgetErr, &modelFailure) || modelFailure.Status != 402 || modelFailure.Code != "MODEL_BUDGET_EXCEEDED" {
						t.Fatal("budget must reject before provider", budgetErr)
					}
					if billing.calls.Load() != 1 {
						t.Fatal("budget failure sent provider")
					}
				}
				request.Config.WindowRunes = 16
				if _, err := control.SubmitIndex(ctx, actor, scope, request); !errors.Is(err, knowledge.ErrIndexTaskConflict) {
					t.Fatal("changed service request", err)
				}
				request.Config.WindowRunes = 8
				request.InstallationID = "foreign"
				if _, err := control.SubmitIndex(ctx, actor, scope, request); !errors.Is(err, knowledge.ErrInvalidProjection) {
					t.Fatal("foreign installation", err)
				}
				request.InstallationID = "indexer"
				if _, err := admin.Exec(`UPDATE platform_identity_grant SET status='revoked',revision=revision+1 WHERE id=$1`, actor.PrincipalID+"-embed"); err != nil {
					t.Fatal(err)
				}
				if err := session.Check(ctx, "embed"); err == nil {
					t.Fatal("caller model revocation ignored")
				}
				if gateway.calls != 0 {
					t.Fatal("revocation checks sent model")
				}
				session.Close()
				binding.Status = "revoked"
				setBinding()
				if _, err := control.SubmitIndex(ctx, actor, scope, request); !errors.Is(err, knowledge.ErrManagementDenied) {
					t.Fatal("revoked service", err)
				}
				if _, err := control.QueryIndex(ctx, actor, scope, first.RunID); !errors.Is(err, knowledge.ErrManagementDenied) {
					t.Fatal("revoked manager read running index", err)
				}
				return
			}
			if mode == "admission-tx" {
				var command contract.ExecuteRequest
				if json.Unmarshal(requestJSON, &command) != nil {
					t.Fatal("command")
				}
				digest, err := contract.CanonicalExecuteBodyHash(command)
				if err != nil {
					t.Fatal(err)
				}
				req := platformruntime.CreateRequest{ID: id, Scope: actor, AgentVersionID: actor.AgentVersionID, IdempotencyKey: "index-task", Fingerprint: digest, RequestJSON: requestJSON}
				create := func(request platformruntime.CreateRequest, commit bool) (platformruntime.CreateResult, error) {
					tx, err := db.BeginTx(ctx, nil)
					if err != nil {
						return platformruntime.CreateResult{}, err
					}
					defer tx.Rollback()
					if err := p.authorize(ctx, tx, actor, scope); err != nil {
						return platformruntime.CreateResult{}, err
					}
					result, err := ex.CreateInternalTaskTx(ctx, tx, request)
					if err != nil {
						return result, err
					}
					if !result.Replayed {
						if err := p.record(tx, actor, scope, "knowledge.index.requested", map[string]any{"run_id": result.Run.ID}); err != nil {
							return result, err
						}
					}
					if err := p.authorize(ctx, tx, actor, scope); err != nil {
						return result, err
					}
					if commit {
						err = tx.Commit()
					}
					return result, err
				}
				if _, err := create(req, false); err != nil {
					t.Fatal("admission rollback", err)
				}
				if _, err := ex.Get(id); !errors.Is(err, platformruntime.ErrRunNotFound) {
					t.Fatal("rolled-back task visible", err)
				}
				fault.fail = true
				if _, err := create(req, true); err == nil {
					t.Fatal("audit fault accepted")
				}
				fault.fail = false
				if _, err := ex.Get(id); !errors.Is(err, platformruntime.ErrRunNotFound) {
					t.Fatal("audit fault left task", err)
				}
				first, err := create(req, true)
				if err != nil || first.Replayed {
					t.Fatal("admission", err)
				}
				second, err := create(req, true)
				if err != nil || !second.Replayed || second.Run.ID != first.Run.ID {
					t.Fatal("admission replay", err)
				}
				if _, err := ex.GetCreation(id); !errors.Is(err, platformruntime.ErrRunNotFound) {
					t.Fatal("internal task created business projection", err)
				}
				command.Input["knowledge_id"] = "other"
				req.RequestJSON, _ = json.Marshal(command)
				req.Fingerprint, _ = contract.CanonicalExecuteBodyHash(command)
				if _, err := create(req, true); !errors.Is(err, platformruntime.ErrIdempotencyConflict) {
					t.Fatal("changed admission replay", err)
				}
				binding.Status = "revoked"
				setBinding()
				req.RequestJSON = requestJSON
				req.Fingerprint = digest
				if _, err := create(req, true); !errors.Is(err, identity.ErrPermissionDenied) {
					t.Fatal("revoked admission replay", err)
				}
				return
			}
			if _, err := ex.Create(platformruntime.CreateRequest{ID: id, Scope: actor, AgentVersionID: "v1", IdempotencyKey: "index-task", Fingerprint: "fixture", RequestJSON: requestJSON}); err != nil {
				t.Fatal(err)
			}
			run, err := ex.Get(id)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "scheduled" {
				claim, err := ex.AcquireLease(id, "private-lease-owner", time.Now().UTC(), time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				run, err = ex.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claim.Revision, claim.LeaseToken)
				if err != nil {
					t.Fatal(err)
				}
			}
			allowed := true
			calls := 0
			checks := 0
			models := knowledgeIndexEmbeddings{scope: actor, request: capability.KnowledgeSearchRequest{Policy: policyasset.Snapshot{Model: policyasset.ModelPolicy{ModelVersionID: "chat", Provider: "chat", Model: "chat", EmbeddingModelVersionID: "embedding", EmbeddingProvider: "vectors", EmbeddingModel: "vectors"}}, ModelCheck: func(_ context.Context, op string) error {
				checks++
				if op != "embed" {
					t.Fatal("wrong model operation")
				}
				if mode == "model-no-rows" {
					return sql.ErrNoRows
				}
				if !allowed {
					return identity.ErrPermissionDenied
				}
				return nil
			}, ModelCall: func(_ context.Context, op string, input map[string]any) (map[string]any, error) {
				calls++
				texts, ok := input["texts"].([]string)
				if op != "embed" || !ok || len(texts) == 0 {
					t.Fatal("invalid governed batch")
				}
				vectors := make([][]float32, len(texts))
				for i := range vectors {
					vectors[i] = []float32{1, .5}
				}
				if mode == "batch-manager-revoked" {
					binding.Status = "revoked"
					setBinding()
				}
				if mode == "batch-model-revoked" {
					allowed = false
				}
				if mode == "batch-source-changed" {
					_, err := p.source(actor).Change(ctx, scope, knowledge.SourceChange{DocumentID: "doc", ActorPrincipalID: id, IdempotencyKey: "new-source", ExpectedSourceRevision: 1, ExpectedDocumentVersion: 1, Body: "updated-index-body", ACL: knowledge.DocumentACL{OwnerPrincipalID: id}})
					if err != nil {
						t.Fatal(err)
					}
				}
				if mode == "publication-fault" {
					fault.fail = true
				}
				return map[string]any{"model_version_id": "embedding", "invocation_id": "fixture-governed-call", "vectors": vectors}, nil
			}}}
			config := knowledge.IndexConfig{EmbeddingModelVersion: "embedding", Dimensions: 2, WindowRunes: 8, OverlapRunes: 2, MaximumDocuments: 10, MaximumChunks: 100}
			if mode == "manager-revoked" {
				binding.Status = "revoked"
				setBinding()
			}
			if mode == "model-denied" {
				allowed = false
			}
			if mode == "canceled" {
				if _, err := ex.BeginCancellation(id, run.Revision); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "audit-fault" {
				fault.fail = true
			}
			if mode == "wrong-task" {
				models.scope.RunID = "foreign"
			}
			if mode == "scheduled" {
				scheduler := execution.InternalTaskScheduler{Repository: ex, InputSchema: execution.KnowledgeIndexInputSchema, LeaseTTL: time.Minute, Authorize: func(ctx context.Context, owner sharedkernel.Scope) error {
					tx, err := db.BeginTx(ctx, nil)
					if err != nil {
						return err
					}
					defer tx.Rollback()
					if err := p.authorize(ctx, tx, owner, scope); err != nil {
						return err
					}
					return tx.Commit()
				}, Execute: func(ctx context.Context, current platformruntime.Run) error {
					return p.executeIndexTask(ctx, current, scope, config, false, models, time.Minute)
				}}
				pending, err := ex.ListPending(1000)
				if err != nil {
					t.Fatal(err)
				}
				for _, candidate := range pending {
					if candidate.ID == id {
						t.Fatal("internal work entered remote dispatcher queue")
					}
				}
				for attempt := 0; attempt < 2; attempt++ {
					if err := scheduler.Sweep(ctx); err != nil {
						t.Fatal("durable scheduler", err)
					}
				}
				finished, err := ex.Get(id)
				if err != nil || finished.Status != platformruntime.StatusSucceeded || calls != 1 {
					t.Fatal("scheduled task not finalized once", err, finished.Status, calls)
				}
				return
			}
			driver, err := p.indexTask(actor, scope, run.LeaseToken, run.Revision, models)
			if mode == "wrong-task" {
				if err == nil || calls != 0 {
					t.Fatal("foreign task composed", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "command-tx" {
				command := platformruntime.DispatchCommand{RunID: id, Revision: run.Revision, Operation: "invoke", BodyHash: strings.Repeat("b", 64), PolicyHash: strings.Repeat("c", 64)}
				write := func(c platformruntime.DispatchCommand, commit bool) error {
					tx, err := db.BeginTx(ctx, nil)
					if err != nil {
						return err
					}
					defer tx.Rollback()
					if err := p.authorize(ctx, tx, actor, scope); err != nil {
						return err
					}
					if err := ex.RecordInternalTaskCommandTx(ctx, tx, actor, run.LeaseToken, run.Revision, c); err != nil {
						return err
					}
					if commit {
						return tx.Commit()
					}
					return nil
				}
				if err := write(command, false); err != nil {
					t.Fatal(err)
				}
				if _, err := ex.GetDispatchCommand(id); !errors.Is(err, platformruntime.ErrRunNotFound) {
					t.Fatal("rolled back command visible", err)
				}
				for i := 0; i < 2; i++ {
					if err := write(command, true); err != nil {
						t.Fatal("command/replay", err)
					}
				}
				changed := command
				changed.BodyHash = strings.Repeat("d", 64)
				if err := write(changed, true); !errors.Is(err, platformruntime.ErrRevisionConflict) {
					t.Fatal("same revision changed command", err)
				}
				stored, err := ex.GetDispatchCommand(id)
				if err != nil || stored != command {
					t.Fatal("immutable command receipt changed", err)
				}
				binding.Status = "revoked"
				setBinding()
				if err := write(command, true); !errors.Is(err, identity.ErrPermissionDenied) {
					t.Fatal("revoked command replay", err)
				}
				binding.Status = "active"
				setBinding()
				if _, err := ex.BeginCancellation(id, run.Revision); err != nil {
					t.Fatal(err)
				}
				if err := write(command, true); !errors.Is(err, platformruntime.ErrLeaseConflict) {
					t.Fatal("canceled command replay", err)
				}
				return
			}
			if mode == "supervised" {
				if err := p.executeIndexTask(ctx, run, scope, config, false, models, time.Minute); err != nil {
					t.Fatal("supervised indexing", err)
				}
				finished, err := ex.Get(id)
				if err != nil || finished.Status != platformruntime.StatusSucceeded || calls != 1 {
					t.Fatal("index task not durably finalized", finished.Status, calls, err)
				}
				outcome, err := ex.GetOutcome(id)
				var result map[string]any
				if err != nil || json.Unmarshal(outcome.OutputJSON, &result) != nil || outcome.Revision != finished.Revision || result["schema_version"] != "knowledge-index-result/v1" || result["index_revision"] != float64(1) {
					t.Fatal("durable index receipt missing", err)
				}
				if _, err := p.checkpoints(scope).Load(ctx, actor, scope.KnowledgeID, run.LeaseToken, run.Revision); !errors.Is(err, platformruntime.ErrLeaseConflict) {
					t.Fatal("finished task retained checkpoint write authority", err)
				}
				return
			}
			if mode == "publication-fault" {
				// Inject at publication after the completed vector checkpoint, not
				// at the earlier checkpoint audit, to verify pointer rollback.
				original := driver.Coordinator.RecordPublish
				driver.Coordinator.RecordPublish = func(ctx context.Context, tx *sql.Tx, s knowledge.ProjectionScope, g string, sr, ir int64) error {
					fault.fail = true
					return original(ctx, tx, s, g, sr, ir)
				}
				models.request.ModelCall = func(_ context.Context, _ string, input map[string]any) (map[string]any, error) {
					calls++
					texts := input["texts"].([]string)
					vectors := make([][]float32, len(texts))
					for i := range vectors {
						vectors[i] = []float32{1, .5}
					}
					return map[string]any{"model_version_id": "embedding", "invocation_id": "fixture-governed-call", "vectors": vectors}, nil
				}
				driver.Embedding.Models = models
			}
			result, err := driver.Run(ctx, actor, scope, config, false)
			count := func(table string) int {
				t.Helper()
				var n int
				if err := admin.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE tenant_id=$1`, id).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			if mode != "allowed" {
				if err == nil || result != (knowledge.IndexTaskResult{}) || count("knowledge.active_generations") != 0 {
					t.Fatal("failed task published", mode, result, err)
				}
				if mode == "batch-source-changed" && !errors.Is(err, knowledge.ErrSourceConflict) {
					t.Fatal("changed source not fenced", err)
				}
				if mode == "manager-revoked" || mode == "model-denied" || mode == "model-no-rows" || mode == "canceled" || mode == "audit-fault" {
					if calls != 0 {
						t.Fatal("denied task called model", mode, calls)
					}
				}
				if mode == "audit-fault" && (count("platform_knowledge_task_checkpoint") != 0 || count("platform_audit_event") != 1 || count("platform_notification_outbox") != 1) {
					t.Fatal("checkpoint fault did not roll back audit/outbox")
				}
				if mode == "publication-fault" {
					fault.fail = false
					var n int
					if err := admin.QueryRow(`SELECT COUNT(*) FROM platform_audit_event WHERE tenant_id=$1 AND action='knowledge.index.published'`, id).Scan(&n); err != nil || n != 0 {
						t.Fatal("failed publication audit committed", n, err)
					}
				}
				return
			}
			if err != nil || result.IndexRevision != 1 || calls != 1 || checks == 0 || count("knowledge.active_generations") != 1 || count("platform_knowledge_task_checkpoint") != 1 || count("platform_audit_event") != 4 || count("platform_notification_outbox") != 4 {
				t.Fatal("production ports not composed", result, calls, checks, err)
			}
			before := count("platform_audit_event")
			// Recreate the composition closure and load its CAS from actual SQL.
			restarted, err := p.indexTask(actor, scope, run.LeaseToken, run.Revision, models)
			if err != nil {
				t.Fatal(err)
			}
			if again, err := restarted.Run(ctx, actor, scope, config, false); err != nil || again.IndexRevision != 1 || calls != 1 || count("platform_audit_event") != before {
				t.Fatal("restart duplicated model/audit", again, calls, err)
			}
			binding.Status = "revoked"
			setBinding()
			if _, err := restarted.Run(ctx, actor, scope, config, false); !errors.Is(err, identity.ErrPermissionDenied) {
				t.Fatal("revoked completed task replay", err)
			}
			var leaked int
			if err := admin.QueryRow(`SELECT COUNT(*) FROM platform_audit_event WHERE tenant_id=$1 AND (summary LIKE '%private-index-body%' OR summary LIKE '%private-lease-owner%')`, id).Scan(&leaked); err != nil || leaked != 0 {
				t.Fatal("index audit leaks body/lease", err)
			}
		})
	}
}

// Target metadata fixture only; service IAM and execution/audit are actual SQL.
type indexAdmissionCatalogFixture []catalog.AvailableAgent

func assertIndexCancelEvents(t *testing.T, db *sql.DB, id string) {
	t.Helper()
	var intents, audits int
	if err := db.QueryRow(`SELECT COUNT(*) FROM platform_execution_event WHERE run_id=$1 AND event_type='cancel_requested'`, id).Scan(&intents); err != nil || intents != 1 {
		t.Fatal("cancel intent not exactly once", err, intents)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM platform_audit_event WHERE action='knowledge.index.cancel_requested' AND summary LIKE '%'||$1||'%'`, id).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("cancel audit not exactly once", err, audits)
	}
}

func (f indexAdmissionCatalogFixture) ListAvailableAgents(context.Context, string, string, string) ([]catalog.AvailableAgent, error) {
	return f, nil
}

func (f indexAdmissionCatalogFixture) ResolveEvaluationAgentTarget(_ context.Context, _ sharedkernel.Scope, agent, version string) (catalog.EvaluationAgentTarget, error) {
	for _, v := range f {
		if v.AgentID == agent && v.VersionID == version {
			return catalog.EvaluationAgentTarget{AgentID: agent, AgentVersionID: version, InstallationID: v.InstallationID}, nil
		}
	}
	return catalog.EvaluationAgentTarget{}, catalog.ErrEvaluationTargetUnavailable
}
