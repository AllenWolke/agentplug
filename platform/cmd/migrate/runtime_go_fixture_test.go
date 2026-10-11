package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type runtimeGoFixture struct {
	scope                                               sharedkernel.Scope
	session, machine, secret, binary, address, internal string
	public                                              ed25519.PublicKey
	calls                                               *atomic.Int32
	live                                                bool
	dimensions                                          int
	chatVersion, embeddingVersion, capabilityURL        string
	cache                                               *runtimeKnowledgeReplay
	answerCache                                         bool
	python                                              bool
}

func processFreeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func prepareRuntimeGoFixture(t *testing.T, ctx context.Context, db *sql.DB, base runtimeIndexFixture, workloadRoot, modelSecretRoot string) ([]string, map[string]string, func(*testing.T, *http.Client, string)) {
	t.Helper()
	f := runtimeGoFixture{scope: base.scope, address: processFreeAddress(t), internal: processFreeAddress(t), calls: &atomic.Int32{}}
	f.answerCache = os.Getenv("PLATFORM_TEST_PUBLIC_ANSWER_CACHE") == "1"
	f.scope.AgentID = "example-go-operations"
	f.python = os.Getenv("PLATFORM_TEST_PYTHON_RUNTIME_CONFIG") != ""
	if f.python {
		f.scope.AgentID = "example-python-documents"
	}
	f.scope.AgentVersionID = "go-process-version"
	f.scope.InstallationID = "go-process-install"
	f.scope.AgentInstanceID = f.scope.InstallationID
	f.scope.PrincipalID = "go-process-user"
	f.machine, f.secret, f.session = seedRuntimeGoIdentity(t, ctx, db, f.scope, base.scope.PrincipalID)
	key, _ := json.Marshal([]string{f.scope.TenantID, f.scope.DepartmentID, f.scope.ApplicationID, f.scope.InstallationID})
	keyHash := sha256.Sum256(key)
	credential, _ := json.Marshal(map[string]string{"client_id": f.machine, "client_secret": f.secret})
	if err := os.WriteFile(filepath.Join(workloadRoot, hex.EncodeToString(keyHash[:])+".json"), credential, 0600); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join("..", "..", "..", "examples", "go-operations")
	if f.python {
		directory = filepath.Join("..", "..", "..", "examples", "python-documents")
	}
	f.binary = filepath.Join(t.TempDir(), "go-operations")
	artifact := os.Getenv("PLATFORM_TEST_PYTHON_ARTIFACT")
	if !f.python {
		command := exec.CommandContext(ctx, "go", "build", "-race", "-o", f.binary, ".")
		command.Dir = directory
		if raw, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build actual Go example: %v %s", err, raw)
		}
		binary, err := os.ReadFile(f.binary)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(binary)
		artifact = "sha256:" + hex.EncodeToString(digest[:])
	} else if !strings.HasPrefix(artifact, "sha256:") || len(artifact) != 71 {
		t.Fatal("formal Python image digest required")
	}
	read := func(name string) json.RawMessage {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	seedRuntimeCatalog(t, ctx, db, f.scope, read("manifest.json"), read("input.schema.json"), read("output.schema.json"), artifact, "http://"+f.address)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer isolated-process-provider-key" {
			http.Error(w, "invalid provider credential", 403)
			return
		}
		var input struct {
			Input    []string                         `json:"input"`
			Messages []struct{ Role, Content string } `json:"messages"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			http.Error(w, "invalid provider request", 400)
			return
		}
		f.calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/embeddings" {
			vectors := make([]map[string]any, len(input.Input))
			for i := range vectors {
				vectors[i] = map[string]any{"index": i, "embedding": []float32{1, .5}}
			}
			json.NewEncoder(w).Encode(map[string]any{"data": vectors, "usage": map[string]int{"prompt_tokens": 20, "total_tokens": 20}})
			return
		}
		if r.URL.Path != "/v1/chat/completions" || len(input.Messages) < 2 {
			http.Error(w, "invalid chat request", 400)
			return
		}
		text := "Check request tracing and latency baselines before changing configuration."
		instruction := input.Messages[len(input.Messages)-1].Content
		if strings.HasPrefix(instruction, "Rewrite the following question") {
			text = "latency diagnosis"
		} else if strings.HasPrefix(instruction, "Answer the question using only") {
			var data struct {
				Evidence []struct {
					ID string `json:"chunk_id"`
				} `json:"evidence"`
			}
			parts := strings.SplitN(instruction, "Data:\n", 2)
			if len(parts) != 2 || json.Unmarshal([]byte(parts[1]), &data) != nil || len(data.Evidence) != 1 {
				http.Error(w, "invalid cited answer", 400)
				return
			}
			raw, _ := json.Marshal(map[string]any{"answer": "Check request tracing and latency baselines.", "citation_ids": []string{data.Evidence[0].ID}})
			text = string(raw)
		} else if strings.Contains(instruction, " Data:\n") {
			var data struct {
				Passages []struct {
					ID string `json:"chunk_id"`
				} `json:"passages"`
			}
			parts := strings.SplitN(instruction, "Data:\n", 2)
			if len(parts) != 2 || json.Unmarshal([]byte(parts[1]), &data) != nil {
				http.Error(w, "invalid rerank", 400)
				return
			}
			scores := make([]map[string]any, len(data.Passages))
			for i, p := range data.Passages {
				scores[i] = map[string]any{"chunk_id": p.ID, "score": .9}
			}
			raw, _ := json.Marshal(map[string]any{"scores": scores})
			text = string(raw)
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]string{"role": "assistant", "content": text}}}, "usage": map[string]int{"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30}})
	}))
	t.Cleanup(provider.Close)
	chatTarget := runtimeModelTarget{Model: "go-process-chat-model", SecretFile: "provider.key", BaseURL: provider.URL + "/v1"}
	embeddingTarget := runtimeModelTarget{Model: "go-process-embedding-model", SecretFile: "provider.key", BaseURL: provider.URL + "/v1"}
	f.dimensions = 2
	if os.Getenv("PLATFORM_TEST_LIVE_MODELS") == "1" {
		chatTarget, embeddingTarget = runtimeLiveModelTargets(t, modelSecretRoot)
		f.live, f.dimensions = true, 1024
	}
	chat := seedRuntimeApprovedModel(t, ctx, db, f.scope, "go-process-chat", modelgovernance.ModelKindChat, nil, chatTarget)
	embedding := seedRuntimeApprovedModel(t, ctx, db, f.scope, "go-process-embedding", modelgovernance.ModelKindEmbedding, nil, embeddingTarget)
	f.chatVersion, f.embeddingVersion = chat, embedding
	// Model access policies intersect. A single approved policy explicitly
	// allows both targets; two disjoint per-model policies would deny both.
	models := modelgovernance.NewSQLStore(db)
	chatFacts, err := models.GetResolvedVersion(ctx, chat)
	if err != nil {
		t.Fatal(err)
	}
	embeddingFacts, err := models.GetResolvedVersion(ctx, embedding)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(-time.Minute)
	access := modelgovernance.AccessPolicy{ID: indexProcessUUID(t), TenantID: f.scope.TenantID, DepartmentID: f.scope.DepartmentID, ApplicationID: f.scope.ApplicationID, InstallationID: f.scope.InstallationID, AgentVersionID: f.scope.AgentVersionID, AllowLocal: true, AllowedProviders: []string{chatFacts.ProviderID, embeddingFacts.ProviderID}, AllowedModels: []string{chatFacts.DefinitionID, embeddingFacts.DefinitionID}, EffectiveFrom: &start, Status: modelgovernance.PolicyDraft, Revision: 1}
	access.AllowExternal = f.live
	if err := models.CreateAccessPolicy(ctx, &access); err != nil {
		t.Fatal(err)
	}
	if err := models.UpdateAccessPolicyStatus(ctx, modelgovernance.Scope{TenantID: f.scope.TenantID, DepartmentID: f.scope.DepartmentID, ApplicationID: f.scope.ApplicationID}, access.ID, 1, modelgovernance.PolicyApproved); err != nil {
		t.Fatal(err)
	}
	skillID := "example.operations.guidance"
	if f.python {
		skillID = "example.documents.guidance"
	}
	skillPath := filepath.Join(directory, "skills", "guidance.v1.json")
	skillJSON, err := os.ReadFile(skillPath)
	if err != nil {
		t.Fatal("read exact published example skill fixture", err)
	}
	var skillBundle capability.SkillBundle
	if json.Unmarshal(skillJSON, &skillBundle) != nil || skillBundle.SkillID != skillID {
		t.Fatal("example skill fixture identity mismatch")
	}
	seedRuntimeGoSkill(t, ctx, db, f.scope, skillBundle)
	snapshot := policyasset.Snapshot{
		ModelProfileID: "go-process-models", PromptVersionID: "go-process-prompt", ToolPolicyID: "go-process-tools",
		MemoryPolicyID: "go-process-memory", KnowledgePolicyID: "go-process-knowledge", RuntimePolicyID: "go-process-runtime",
		Revision: 1, Hash: strings.Repeat("b", 64),
		Model: policyasset.ModelPolicy{
			ModelVersionID: chat, Provider: "go-process-chat-provider", Model: "go-process-chat-model",
			EmbeddingModelVersionID: embedding, EmbeddingProvider: "go-process-embedding-provider", EmbeddingModel: "go-process-embedding-model",
			MaxTokens: 4096, BudgetCents: 1000,
		},
		Prompt: policyasset.PromptPolicy{Template: "Read-only operations diagnosis; cite known evidence.", TemplateHash: "go-process-prompt-hash"},
		Tool: policyasset.ToolPolicy{
			AllowedTools: []string{"runtime.inspect"},
			Functions: []policyasset.FunctionDefinition{{
				Name: "inspect", ToolName: "runtime.inspect", Description: "Read verified execution context; does not inspect host health",
				Parameters: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
			}},
		},
		Memory: policyasset.MemoryPolicy{WorkingTTLSeconds: 600, MaxEntries: 10},
		Knowledge: policyasset.KnowledgePolicy{
			AllowedScopes: []string{"go-operations"}, RequireReferences: true,
			DocumentBindings: []policyasset.KnowledgeDocumentBinding{{
				KnowledgeScope: "go-operations", ProviderID: "platform-knowledge", KnowledgeBaseID: "go-operations",
				ProviderDocumentID: "runbook", OwnerID: base.scope.PrincipalID, OwnershipSource: "source:go-operations/runbook",
				DocumentVersion: "1", Status: "active",
			}},
		},
		Runtime: policyasset.RuntimePolicy{MaxAttempts: 1, TaskTimeoutSeconds: 60, LeaseSeconds: 30},
	}
	snapshot.Runtime.AllowedSkills = []string{skillID}
	snapshot.Model.Model, snapshot.Model.EmbeddingModel = chatTarget.Model, embeddingTarget.Model
	if f.python {
		snapshot.Knowledge.AllowedScopes = []string{"python-documents"}
		snapshot.Knowledge.DocumentBindings[0].KnowledgeScope = "python-documents"
		snapshot.Knowledge.DocumentBindings[0].KnowledgeBaseID = "python-documents"
		snapshot.Knowledge.DocumentBindings[0].OwnershipSource = "source:python-documents/runbook"
	}
	if f.live {
		snapshot.Model.AllowExternal = true
		snapshot.Model.ReasoningMode = "disabled"
		snapshot.Model.InputMicrosPer1KTokens, snapshot.Model.OutputMicrosPer1KTokens = 100000, 100000
		snapshot.Model.MaxTokens, snapshot.Runtime.TaskTimeoutSeconds = 1024, 300
	}
	if snapshot.ValidateDetails() != nil || len(snapshot.Tool.Functions) != 1 || snapshot.Tool.Functions[0].Name != "inspect" || snapshot.Tool.Functions[0].ToolName != "runtime.inspect" || modelgateway.ValidateFunctionRequest(snapshot.Tool, []string{"inspect"}, []modelgateway.Message{{Role: "user", Content: "fixture input"}}) != nil {
		t.Fatal("published runtime fixture does not satisfy the example's exact Harness function contract")
	}
	if err := policyasset.NewSQLResolver(db).Upsert(ctx, f.scope, snapshot); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.public = public
	f.cache = newRuntimeKnowledgeReplay(t, db, f.internal, chat, embedding)
	f.capabilityURL = f.cache.server.URL
	env := []string{"PLATFORM_INTERNAL_ADDR=" + f.internal, "PLATFORM_CONTEXT_PUBLIC_KEY=" + base64.StdEncoding.EncodeToString(public), "PLATFORM_CONTEXT_PRIVATE_KEY=" + base64.StdEncoding.EncodeToString(private)}
	return env, map[string]string{"service://go-process-chat-model": chatTarget.BaseURL, "service://go-process-embedding-model": embeddingTarget.BaseURL}, func(child *testing.T, client *http.Client, address string) {
		if f.python {
			verifyRuntimePythonExample(child, ctx, db, client, address, f, base)
			return
		}
		verifyRuntimeGoExample(child, ctx, db, client, address, f, base)
	}
}

// seedRuntimeGoSkill writes only the exact immutable, reviewed example bundle
// used by this disposable process fixture. Runtime disclosure still passes
// the normal published-policy, caller/machine Grant, Run lease, pin and bundle
// digest checks; this is not a skill-management API or permission bypass.
func seedRuntimeGoSkill(t *testing.T, ctx context.Context, db *sql.DB, scope sharedkernel.Scope, bundle capability.SkillBundle) {
	t.Helper()
	encoded, err := json.Marshal(bundle)
	if err != nil || len(encoded) == 0 || len(encoded) > 64<<10 {
		t.Fatal("invalid bounded skill fixture")
	}
	contentHash := sha256.Sum256(encoded)
	namespaceBytes, err := json.Marshal([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID})
	if err != nil {
		t.Fatal("encode exact skill namespace")
	}
	namespaceHash := sha256.Sum256(namespaceBytes)
	namespace := hex.EncodeToString(namespaceHash[:])
	author, reviewer := scope.PrincipalID+"-fixture-author", scope.PrincipalID+"-fixture-reviewer"
	if author == reviewer {
		t.Fatal("skill fixture reviewer must be independent")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_skill_version(namespace_key,skill_id,version_id,bundle_json,content_hash,author_id,reviewer_id,status,revision,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,'approved',1,clock_timestamp())`, namespace, bundle.SkillID, bundle.VersionID, string(encoded), hex.EncodeToString(contentHash[:]), author, reviewer); err != nil {
		t.Fatal("seed immutable approved example skill", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_skill_release(namespace_key,skill_id,stable_version,candidate_version,candidate_basis_points,revision) VALUES($1,$2,$3,NULL,0,1)`, namespace, bundle.SkillID, bundle.VersionID); err != nil {
		t.Fatal("seed exact stable example skill release", err)
	}
}
