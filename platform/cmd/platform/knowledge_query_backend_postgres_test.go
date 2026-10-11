package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/bootstrap"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestPostgresKnowledgeQueryBackend(t *testing.T) {
	dsn := os.Getenv("KNOWLEDGE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL fixture required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	for _, mode := range []string{"success", "delete-during-rerank", "invalid-rerank", "sql-success", "sql-machine-revoked-during-rerank", "sql-caller-revoked-during-rerank", "sql-machine-expired-during-rerank", "sql-caller-expired-during-rerank", "sql-machine-denied-before-model", "sql-cache-hit", "sql-cache-rewritten-query-reuse", "sql-cache-caller-model-revoked", "sql-cache-machine-model-revoked", "sql-cache-cold", "sql-cache-bypass", "sql-cache-invalid", "sql-answer-cache-hit", "sql-answer-cache-cold", "sql-answer-cache-bypass", "sql-answer-cache-model-revoked", "sql-answer-cache-generation-change", "sql-answer-invalid-citation", "sql-answer-source-deleted-during-model"} {
		t.Run(mode, func(t *testing.T) {
			answerCase := strings.HasPrefix(mode, "sql-answer-")
			id := fmt.Sprintf("query-backend-%d", time.Now().UnixNano())
			humanID, machineID := id+"-user", id+"-executor"
			scope := sharedkernel.Scope{TenantID: id, DepartmentID: id, ApplicationID: id, PrincipalID: humanID, PrincipalType: "user", AgentInstanceID: "i", InstallationID: "i", AgentID: "agent", AgentVersionID: "v", SessionID: "session", RunID: "run", TraceID: "trace", AuthorizationEpoch: 1}
			app := identity.ManagementScope{Type: "application", TenantID: id, DepartmentID: id, ApplicationID: id}
			grant := identity.Grant{ID: "user-grant", SubjectID: "u", SubjectType: identity.PrincipalUser, TenantID: id, DepartmentID: id, ApplicationID: id, AgentInstanceID: "i", ResourceType: "knowledge", ResourceID: "docs", Action: "knowledge.search", Status: "active", Effect: "allow", DataScope: identity.DataScope{Type: "owner"}}
			caller := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalUser, ID: "u", TenantID: id, IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{ID: "member", SubjectID: "u", Scope: app, Status: "active"}}, Bindings: []identity.RoleBinding{{ID: "role", SubjectID: "u", RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active"}}, Grants: []identity.Grant{grant}}
			grant.ID, grant.SubjectID, grant.SubjectType, grant.DataScope = "machine-grant", "executor", identity.PrincipalServicePrincipal, identity.DataScope{Type: "approved_organization"}
			machine := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalServicePrincipal, ID: "executor", TenantID: id, IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Grants: []identity.Grant{grant}}
			binding := identity.WorkloadBinding{TenantID: id, DepartmentID: id, ApplicationID: id, InstallationID: "i", AgentID: "agent", AgentVersionID: "v", PrincipalID: "executor", Status: "active", Revision: 1}
			caller.Principal.ID = humanID
			caller.Memberships[0].SubjectID = humanID
			caller.Bindings[0].SubjectID = humanID
			caller.Grants[0].SubjectID = humanID
			caller.Grants[0].ID = id + "-user-knowledge"
			machine.Principal.ID = machineID
			machine.Grants[0].SubjectID = machineID
			machine.Grants[0].ID = id + "-machine-knowledge"
			binding.PrincipalID = machineID
			if strings.HasPrefix(mode, "sql-cache-") || answerCase {
				for _, action := range []string{"model.generate", "model.embed"} {
					grant := caller.Grants[0]
					grant.ID, grant.Action, grant.ResourceType, grant.ResourceID = id+"-caller-"+action, action, "model", "models"
					caller.Grants = append(caller.Grants, grant)
					grant.SubjectID, grant.SubjectType, grant.ID, grant.DataScope = machineID, identity.PrincipalServicePrincipal, id+"-machine-"+action, identity.DataScope{Type: "approved_organization"}
					machine.Grants = append(machine.Grants, grant)
				}
			}
			authority := capabilityExecutionAuthority{identity: capabilitySnapshotFixture{snapshot: caller, executor: &machine, binding: &binding}}
			if strings.HasPrefix(mode, "sql-") {
				store := seedKnowledgeQuerySQLIdentity(t, db, scope, caller, machine, binding)
				epoch, err := store.CurrentAuthorizationEpoch(ctx, scope, "run")
				if err != nil {
					t.Fatal("SQL runtime epoch unavailable", err)
				}
				scope.AuthorizationEpoch = epoch
				authority.identity = store
				if mode == "sql-machine-denied-before-model" {
					if _, err := db.Exec(`UPDATE platform_identity_grant SET status='revoked',revision=revision+1 WHERE id=$1`, machine.Grants[0].ID); err != nil {
						t.Fatal(err)
					}
				}
			}
			source := knowledge.PostgresSource{DB: db, RecordChange: func(context.Context, *sql.Tx, knowledge.ProjectionScope, knowledge.SourceReceipt) error { return nil }}
			ps := knowledge.ProjectionScope{TenantID: id, DepartmentID: id, ApplicationID: id, KnowledgeID: "docs"}
			documents := []policyasset.KnowledgeDocumentBinding{}
			for index, doc := range []string{"visible", "private"} {
				owner, body := humanID, "recovery procedure"
				if index == 1 {
					owner, body = "other", "PRIVATE-CONTENT recovery"
				}
				if _, err := source.Change(ctx, ps, knowledge.SourceChange{DocumentID: doc, ActorPrincipalID: "fixture", IdempotencyKey: doc, ExpectedSourceRevision: int64(index), Body: body, ACL: knowledge.DocumentACL{OwnerPrincipalID: owner, Readers: []string{machineID}}}); err != nil {
					t.Fatal(err)
				}
				documents = append(documents, policyasset.KnowledgeDocumentBinding{KnowledgeScope: "docs", ProviderID: "platform-knowledge", KnowledgeBaseID: "docs", ProviderDocumentID: doc, OwnerID: owner, OwnershipSource: "source:docs/" + doc, DocumentVersion: "1", Status: "active"})
			}
			coordinator := knowledge.IndexCoordinator{Source: source, Projection: knowledge.PostgresProjection{DB: db}, RecordPublish: func(context.Context, *sql.Tx, knowledge.ProjectionScope, string, int64, int64) error { return nil }}
			plan, err := coordinator.Prepare(ctx, ps, knowledge.IndexConfig{EmbeddingModelVersion: "embedding-v1", Dimensions: 2, WindowRunes: 512, MaximumDocuments: 10, MaximumChunks: 10}, false)
			if err != nil {
				t.Fatal(err)
			}
			vectors := map[string][]float32{}
			for _, chunk := range plan.RequiredChunks() {
				vectors[chunk.ID] = []float32{1, 0}
			}
			if err := coordinator.Build(ctx, plan, "generation-v1", vectors); err != nil {
				t.Fatal(err)
			}
			if _, err := coordinator.Publish(ctx, plan, "generation-v1"); err != nil {
				t.Fatal(err)
			}
			provider, pool, err := knowledgeProviderFromConfig(ctx, bootstrap.RuntimeConfig{KnowledgeDatabaseDSN: dsn}, db, authority)
			if err != nil || provider == nil || pool == nil {
				t.Fatal("configured provider cannot initialize", err)
			}
			defer pool.Close()
			policy := policyasset.Snapshot{ModelProfileID: "models", PromptVersionID: "prompts", KnowledgePolicyID: "knowledge", ToolPolicyID: "tools", MemoryPolicyID: "memory", RuntimePolicyID: "runtime", Revision: 1, Hash: strings.Repeat("b", 64), Model: policyasset.ModelPolicy{Provider: "chat", Model: "chat", ModelVersionID: "chat-v1", EmbeddingProvider: "vectors", EmbeddingModel: "vectors", EmbeddingModelVersionID: "embedding-v1", MaxTokens: 4096}, Prompt: policyasset.PromptPolicy{Template: "Published instruction", TemplateHash: "prompt-hash"}, Tool: policyasset.ToolPolicy{AllowedTools: []string{"json.validate"}}, Memory: policyasset.MemoryPolicy{MaxEntries: 10}, Knowledge: policyasset.KnowledgePolicy{AllowedScopes: []string{"docs"}, DocumentBindings: documents}, Runtime: policyasset.RuntimePolicy{MaxAttempts: 1, TaskTimeoutSeconds: 60, LeaseSeconds: 30}}
			calls := 0
			modelCall := func(_ context.Context, operation string, input map[string]any) (map[string]any, error) {
				calls++
				if operation == "embed" {
					return map[string]any{"model_version_id": "embedding-v1", "invocation_id": "embed-call", "vectors": [][]float32{{1, 0}}}, nil
				}
				messages, ok := input["messages"].([]map[string]string)
				if !ok || messages[0]["content"] != policy.Prompt.Template {
					t.Fatal("published Prompt omitted")
				}
				if strings.HasPrefix(messages[1]["content"], "Rewrite the following question") {
					return map[string]any{"model_version_id": "chat-v1", "invocation_id": "rewrite-call", "text": "recovery"}, nil
				}
				if strings.HasPrefix(messages[1]["content"], "Answer the question using only") {
					var data struct {
						Evidence []struct {
							ID   string `json:"chunk_id"`
							Text string `json:"text"`
						} `json:"evidence"`
					}
					parts := strings.SplitN(messages[1]["content"], "Data:\n", 2)
					if len(parts) != 2 || json.Unmarshal([]byte(parts[1]), &data) != nil || len(data.Evidence) != 1 || data.Evidence[0].Text != "recovery procedure" {
						t.Fatal("answer received unauthorized evidence")
					}
					id := data.Evidence[0].ID
					if mode == "sql-answer-invalid-citation" {
						id = "private-chunk"
					}
					if mode == "sql-answer-source-deleted-during-model" {
						if _, err := source.Change(ctx, ps, knowledge.SourceChange{DocumentID: "visible", ActorPrincipalID: "fixture", IdempotencyKey: "answer-delete", ExpectedSourceRevision: 2, ExpectedDocumentVersion: 1, Deleted: true}); err != nil {
							t.Fatal(err)
						}
					}
					text, _ := json.Marshal(map[string]any{"answer": "recovery procedure", "citation_ids": []string{id}})
					return map[string]any{"model_version_id": "chat-v1", "invocation_id": "answer-call", "text": string(text), "usage": map[string]int{"input_tokens": 42, "output_tokens": 17}, "billing": map[string]any{"price_version_id": "fixture-price-v1", "currency": "USD", "cost_micros": 59}}, nil
				}
				instruction := messages[1]["content"]
				if strings.Contains(instruction, "PRIVATE-CONTENT") {
					t.Fatal("private source reached model")
				}
				var data struct {
					Passages []struct {
						ID string `json:"chunk_id"`
					} `json:"passages"`
				}
				parts := strings.SplitN(instruction, "Data:\n", 2)
				if len(parts) != 2 || json.Unmarshal([]byte(parts[1]), &data) != nil || len(data.Passages) != 1 {
					t.Fatal("unexpected authorized passages")
				}
				if mode == "delete-during-rerank" {
					if _, err := source.Change(ctx, ps, knowledge.SourceChange{DocumentID: "visible", ActorPrincipalID: "fixture", IdempotencyKey: "delete", ExpectedSourceRevision: 2, ExpectedDocumentVersion: 1, Deleted: true}); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "sql-machine-revoked-during-rerank" || mode == "sql-caller-revoked-during-rerank" {
					grantID := machine.Grants[0].ID
					if mode == "sql-caller-revoked-during-rerank" {
						grantID = caller.Grants[0].ID
					}
					if _, err := db.Exec(`UPDATE platform_identity_grant SET status='revoked',revision=revision+1 WHERE id=$1`, grantID); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "sql-machine-expired-during-rerank" || mode == "sql-caller-expired-during-rerank" {
					grant := machine.Grants[0]
					if mode == "sql-caller-expired-during-rerank" {
						grant = caller.Grants[0]
					}
					expires := time.Now().UTC().Add(-time.Second)
					grant.ExpiresAt = &expires
					raw, _ := json.Marshal(grant)
					if _, err := db.Exec(`UPDATE platform_identity_grant SET permission_json=$1 WHERE id=$2`, string(raw), grant.ID); err != nil {
						t.Fatal(err)
					}
				}
				text := fmt.Sprintf(`{"scores":[{"chunk_id":%q,"score":0.9}]}`, data.Passages[0].ID)
				if mode == "invalid-rerank" {
					text = `{"scores":[{"chunk_id":"invented","score":0.9}]}`
				}
				return map[string]any{"model_version_id": "chat-v1", "invocation_id": "rerank-call", "text": text}, nil
			}
			backend := postgresKnowledgeBackend{source: db, projection: pool, authority: authority}
			request := capability.KnowledgeSearchRequest{Query: "how do I recover?", KnowledgeScope: "docs", TopK: 1, Policy: policy, Documents: documents, ModelCall: modelCall}
			if answerCase {
				request.Answer = true
				backend.cache = knowledge.NewStageCache(32, 1<<20, time.Minute)
				request.ModelCheck = func(ctx context.Context, operation string) error {
					return authority.AuthorizeCapabilityResource(ctx, scope, capability.CapabilityResourceAccess{Action: "model." + operation, ResourceType: "model", ResourceID: policy.ModelProfileID})
				}
				if strings.HasPrefix(mode, "sql-answer-cache-") {
					warm, err := backend.SearchKnowledge(ctx, scope, request)
					if err != nil || warm["answer_cache_hit"] != false || calls != 4 {
						t.Fatal("cold answer failed", err, calls)
					}
					switch mode {
					case "sql-answer-cache-cold":
						request.CacheMode = "cold"
					case "sql-answer-cache-bypass":
						request.CacheMode = "bypass"
					case "sql-answer-cache-model-revoked":
						if _, err := db.Exec(`UPDATE platform_identity_grant SET status='revoked',revision=revision+1 WHERE id=$1`, id+"-machine-model.generate"); err != nil {
							t.Fatal(err)
						}
					case "sql-answer-cache-generation-change":
						newPlan, err := coordinator.Prepare(ctx, ps, knowledge.IndexConfig{EmbeddingModelVersion: "embedding-v1", Dimensions: 2, WindowRunes: 512, MaximumDocuments: 10, MaximumChunks: 10}, false)
						if err != nil {
							t.Fatal(err)
						}
						if err := coordinator.Build(ctx, newPlan, "generation-v2", vectors); err != nil {
							t.Fatal(err)
						}
						if _, err := coordinator.Publish(ctx, newPlan, "generation-v2"); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if strings.HasPrefix(mode, "sql-cache-") {
				backend.cache = knowledge.NewStageCache(16, 1<<20, time.Minute)
				request.ModelCheck = func(ctx context.Context, operation string) error {
					return authority.AuthorizeCapabilityResource(ctx, scope, capability.CapabilityResourceAccess{Action: "model." + operation, ResourceType: "model", ResourceID: policy.ModelProfileID})
				}
				warm, err := backend.SearchKnowledge(ctx, scope, request)
				if err != nil || warm == nil || calls != 3 {
					t.Fatal("cache cold query failed", err, calls)
				}
				if mode == "sql-cache-rewritten-query-reuse" {
					request.Query = "What steps recover this service?"
				} else if strings.HasSuffix(mode, "model-revoked") {
					grantID := id + "-caller-model.generate"
					if mode == "sql-cache-machine-model-revoked" {
						grantID = id + "-machine-model.generate"
					}
					if _, err := db.Exec(`UPDATE platform_identity_grant SET status='revoked',revision=revision+1 WHERE id=$1`, grantID); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "sql-cache-cold" {
					request.CacheMode = "cold"
				}
				if mode == "sql-cache-bypass" {
					request.CacheMode = "bypass"
				}
				if mode == "sql-cache-invalid" {
					request.CacheMode = "invalid"
				}
			}
			result, err := backend.SearchKnowledge(ctx, scope, request)
			if answerCase {
				denied := mode == "sql-answer-cache-model-revoked" || mode == "sql-answer-invalid-citation" || mode == "sql-answer-source-deleted-during-model"
				if denied {
					if err == nil || result != nil {
						t.Fatal("rejected answer escaped", mode, err)
					}
					if mode == "sql-answer-cache-model-revoked" && calls != 4 {
						t.Fatal("revoked cache hit reached model", calls)
					}
					return
				}
				if err != nil || result["text"] != "recovery procedure" || result["answer_cache_hit"] != (mode == "sql-answer-cache-hit") {
					t.Fatal("answer cache result mismatch", mode, err, result)
				}
				usage, ok := result["usage"].(knowledgeAnswerUsage)
				billing, billingOK := result["billing"].(knowledgeAnswerBilling)
				if !ok || !billingOK {
					t.Fatal("answer usage/cost receipt missing")
				}
				if mode == "sql-answer-cache-hit" {
					saved := result["saved_usage"].(knowledgeAnswerUsage)
					if calls != 4 || usage.InputTokens != 0 || usage.OutputTokens != 0 || billing.CostMicros != 0 || saved.InputTokens != 42 || saved.OutputTokens != 17 {
						t.Fatal("cached answer consumed model usage", calls, usage, billing)
					}
				} else if calls != 8 || usage.InputTokens != 42 || usage.OutputTokens != 17 || billing.CostMicros != 59 {
					t.Fatal("cold/bypass/version-change did not generate", calls, usage, billing)
				}
				return
			}
			if mode == "success" || mode == "sql-success" || mode == "sql-cache-hit" || mode == "sql-cache-rewritten-query-reuse" || mode == "sql-cache-cold" || mode == "sql-cache-bypass" {
				refs, _ := result["references"].([]map[string]any)
				expectedCalls := 3
				if mode == "sql-cache-hit" {
					expectedCalls = 3
				}
				if mode == "sql-cache-rewritten-query-reuse" {
					expectedCalls = 4
				}
				if mode == "sql-cache-cold" || mode == "sql-cache-bypass" {
					expectedCalls = 6
				}
				if err != nil || len(refs) != 1 || refs[0]["content"] != "recovery procedure" || refs[0]["kb_version"] != "generation-v1" || refs[0]["reranking_score"] != 0.9 || refs[0]["embedding_invocation_id"] != "embed-call" || calls != expectedCalls {
					t.Fatal("backend result/provenance missing", err, result)
				}
				if mode == "sql-cache-hit" && (refs[0]["rewrite_cache_hit"] != true || refs[0]["embedding_cache_hit"] != true || refs[0]["reranking_cache_hit"] != true || refs[0]["retrieval_cache_hit"] != true) {
					t.Fatal("cache receipt missing")
				}
				if mode == "sql-cache-rewritten-query-reuse" && (refs[0]["rewrite_cache_hit"] != false || refs[0]["embedding_cache_hit"] != true || refs[0]["reranking_cache_hit"] != true) {
					t.Fatal("different question did not reuse rewritten-query embedding")
				}
				if mode == "sql-cache-cold" || mode == "sql-cache-bypass" {
					if refs[0]["rewrite_cache_hit"] != false || refs[0]["embedding_cache_hit"] != false || refs[0]["reranking_cache_hit"] != false || refs[0]["retrieval_cache_hit"] != false {
						t.Fatal("cold/bypass read shared cache")
					}
					request.CacheMode = "use"
					if hot, err := backend.SearchKnowledge(ctx, scope, request); err != nil || hot == nil || calls != 6 {
						t.Fatal("cold/bypass evicted shared cache", err, calls)
					}
				}
			} else if err == nil || result != nil {
				t.Fatal("invalid/revoked result exposed", result, err)
			}
			if mode == "sql-machine-denied-before-model" && calls != 0 {
				t.Fatal("SQL-denied machine reached model")
			}
			if strings.HasPrefix(mode, "sql-") && strings.HasSuffix(mode, "during-rerank") && calls != 3 {
				t.Fatal("SQL revocation scenario did not reach reranking", calls)
			}
			if strings.HasPrefix(mode, "sql-cache-") && strings.HasSuffix(mode, "model-revoked") && calls != 3 {
				t.Fatal("revoked cache query reached provider", calls)
			}
			if mode == "sql-cache-invalid" && calls != 3 {
				t.Fatal("invalid mode reached model")
			}
		})
	}
}
