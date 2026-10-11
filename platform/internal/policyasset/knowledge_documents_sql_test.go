package policyasset

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSQLKnowledgeDocumentBindingsRoundTripAndIsolation(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture required")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resolver := NewSQLResolver(db)
	if err := resolver.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	scope := sharedkernel.Scope{TenantID: "document-fixture", DepartmentID: "department", ApplicationID: "application", AgentID: "qa", AgentVersionID: "qa-v1", PrincipalID: "admin"}
	expires := time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)
	snapshot := Snapshot{
		ModelProfileID: "model-v1", PromptVersionID: "prompt-v1", ToolPolicyID: "tool-v1", MemoryPolicyID: "memory-v1", KnowledgePolicyID: "knowledge-v1", RuntimePolicyID: "runtime-v1",
		Revision: 1, Hash: strings.Repeat("a", 64),
		Model: ModelPolicy{Provider: "local", Model: "qa", MaxTokens: 512}, Prompt: PromptPolicy{TemplateHash: "prompt-hash", Template: "approved"},
		Tool: ToolPolicy{AllowedTools: []string{"report"}}, Memory: MemoryPolicy{MaxEntries: 10},
		Knowledge: KnowledgePolicy{AllowedScopes: []string{"platform-knowledge"}, DocumentBindings: []KnowledgeDocumentBinding{{KnowledgeScope: "platform-knowledge", ProviderID: "platform-knowledge", KnowledgeBaseID: "7", ProviderDocumentID: "9007199254740993", OwnerID: "user-a", OwnershipSource: "reviewed-inventory:fixture", DocumentVersion: "v1", Status: "active", ValidUntil: &expires}}},
		Runtime:   RuntimePolicy{MaxAttempts: 1, TaskTimeoutSeconds: 10, LeaseSeconds: 30},
	}
	if err := resolver.Upsert(ctx, scope, snapshot); err != nil {
		t.Fatal(err)
	}
	read, err := resolver.Resolve(ctx, scope, scope.AgentVersionID)
	if err != nil || !reflect.DeepEqual(read.Knowledge, snapshot.Knowledge) {
		t.Fatalf("published document facts did not round-trip: %v", err)
	}
	other := scope
	other.ApplicationID = "other-application"
	if _, err := resolver.Resolve(ctx, other, scope.AgentVersionID); !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("cross-application snapshot resolved: %v", err)
	}
	snapshot.Revision, snapshot.Hash = 2, strings.Repeat("b", 64)
	snapshot.Knowledge.DocumentBindings[0].Status = "deleted"
	snapshot.Knowledge.DocumentBindings[0].DocumentVersion = "v2"
	if err := resolver.Upsert(ctx, scope, snapshot); err != nil {
		t.Fatal(err)
	}
	read, err = resolver.Resolve(ctx, scope, scope.AgentVersionID)
	if err != nil || read.Revision != 2 || read.Hash != snapshot.Hash || read.Knowledge.DocumentBindings[0].Effective(time.Now()) || read.Knowledge.DocumentBindings[0].DocumentVersion != "v2" {
		t.Fatalf("new published revision did not invalidate document: %v", err)
	}
}
