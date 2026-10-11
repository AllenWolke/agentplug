package policyasset

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type schemaExec struct {
	statements []string
	err        error
}

func (s *schemaExec) ExecContext(_ context.Context, query string, _ ...any) (sql.Result, error) {
	s.statements = append(s.statements, query)
	return nil, s.err
}

func (s *schemaExec) QueryRowContext(context.Context, string, ...any) *sql.Row { return nil }

func TestEnsureSchemaCreatesOnlyCanonicalPolicySnapshot(t *testing.T) {
	db := &schemaExec{}
	resolver := NewSQLResolver(db)
	if err := resolver.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema() error = %v", err)
	}
	if len(db.statements) != 1 {
		t.Fatalf("EnsureSchema() executed %d statements, want one canonical CREATE TABLE", len(db.statements))
	}
	ddl := strings.ToLower(db.statements[0])
	for _, required := range []string{
		"create table if not exists platform_policy_snapshot",
		"model_policy_json json not null",
		"prompt_policy_json json not null",
		"tool_policy_json json not null",
		"memory_policy_json json not null",
		"knowledge_policy_json json not null",
		"runtime_policy_json json not null",
		"rule_policy_json json not null",
		"primary key (tenant_id, department_id, application_id, agent_id, agent_version_id)",
	} {
		if !strings.Contains(ddl, required) {
			t.Errorf("canonical schema missing %q", required)
		}
	}
	for _, forbidden := range []string{"alter table", "drop index", "update platform_policy_snapshot", "backfill"} {
		if strings.Contains(ddl, forbidden) {
			t.Errorf("schema creation retained compatibility operation %q", forbidden)
		}
	}
}

func TestEnsureSchemaFailsOnCreateError(t *testing.T) {
	db := &schemaExec{err: errors.New("DDL denied")}
	err := NewSQLResolver(db).EnsureSchema(context.Background())
	if err == nil || !strings.Contains(err.Error(), "create platform policy snapshot schema") {
		t.Fatalf("EnsureSchema() error = %v, want contextual DDL error", err)
	}
}

func TestEnsureSchemaRequiresDatabase(t *testing.T) {
	if err := (*SQLResolver)(nil).EnsureSchema(context.Background()); err == nil {
		t.Fatal("nil resolver must fail")
	}
	if err := NewSQLResolver(nil).EnsureSchema(context.Background()); err == nil {
		t.Fatal("nil database must fail")
	}
}

func TestSQLResolverRetainsTrustedBootstrapSnapshotWrite(t *testing.T) {
	db := &schemaExec{}
	resolver := NewSQLResolver(db)
	scope := sharedkernel.Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentID: "qa", AgentVersionID: "qa-v1", PrincipalID: "admin"}
	snapshot := Snapshot{
		ModelProfileID: "model-v1", PromptVersionID: "prompt-v1", ToolPolicyID: "tool-v1", MemoryPolicyID: "memory-v1", KnowledgePolicyID: "knowledge-v1", RuntimePolicyID: "runtime-v1",
		Revision: 1, Hash: strings.Repeat("a", 64),
		Model: ModelPolicy{Provider: "local", Model: "qa", MaxTokens: 512}, Prompt: PromptPolicy{TemplateHash: "prompt-hash", Template: "approved"},
		Tool: ToolPolicy{AllowedTools: []string{"report"}}, Memory: MemoryPolicy{MaxEntries: 10},
		Knowledge: KnowledgePolicy{AllowedScopes: []string{"platform-knowledge"}}, Runtime: RuntimePolicy{MaxAttempts: 1, TaskTimeoutSeconds: 10, LeaseSeconds: 30},
	}
	if err := resolver.Upsert(context.Background(), scope, snapshot); err != nil {
		t.Fatalf("trusted bootstrap Upsert() error = %v", err)
	}
	if len(db.statements) != 1 || !strings.Contains(strings.ToLower(db.statements[0]), "insert into platform_policy_snapshot") || !strings.Contains(strings.ToLower(db.statements[0]), "on conflict (tenant_id,department_id,application_id,agent_id,agent_version_id) do update set") {
		t.Fatalf("trusted bootstrap upsert was not preserved: %s", strings.Join(db.statements, "\n"))
	}
	var roundTrip Snapshot
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.ModelProfileID != snapshot.ModelProfileID || roundTrip.Prompt.Template != snapshot.Prompt.Template || roundTrip.Hash != snapshot.Hash {
		t.Fatalf("snapshot wire round trip lost fields: %+v", roundTrip)
	}
}

func TestEnsurePromptTemplatesRetainsTrustedBootstrapWrite(t *testing.T) {
	db := &schemaExec{}
	resolver := NewSQLResolver(db)
	if err := resolver.EnsurePromptTemplates(context.Background(), `[{"template_hash":"hash","template":"body"}]`); err != nil {
		t.Fatalf("trusted bootstrap EnsurePromptTemplates() error = %v", err)
	}
	if len(db.statements) != 1 || !strings.Contains(strings.ToLower(db.statements[0]), "update platform_policy_snapshot") {
		t.Fatalf("trusted prompt bootstrap write was not preserved: %s", strings.Join(db.statements, "\n"))
	}
}
