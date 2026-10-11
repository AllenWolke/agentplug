package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func assertRuntimeConversationBinding(t *testing.T, ctx context.Context, client *http.Client, address string, db *sql.DB, sessionID, subject string) {
	t.Helper()
	const tenant, department, application = "session-fixture", "session-fixture-dept", "session-fixture-app"
	const agent, version, installation = "fixture-conversation-agent", "fixture-conversation-version", "fixture-conversation-installation"
	store := catalog.NewSQLStore(db, "pgx")
	definition := catalog.Definition{ID: "fixture-conversation-definition", PublisherID: "fixture-publisher", AgentKey: agent, DisplayName: "Conversation fixture", Description: "Runtime binding fixture", Status: catalog.DefinitionDraft, Revision: 1}
	if err := store.CreateDefinition(ctx, definition); err != nil {
		t.Fatal(err)
	}
	for _, transition := range []struct {
		from, to catalog.DefinitionStatus
		revision uint64
	}{{catalog.DefinitionDraft, catalog.DefinitionEvaluated, 1}, {catalog.DefinitionEvaluated, catalog.DefinitionPublished, 2}} {
		if err := store.TransitionDefinition(ctx, definition.ID, transition.from, transition.to, transition.revision); err != nil {
			t.Fatal(err)
		}
	}
	manifest := json.RawMessage(`{"manifest_version":"agent-manifest/v1","agent_id":"fixture-conversation-agent","version":"1.0.0","execution_protocols":["agent-execution/v2"],"capabilities":["run"],"schemas":{"input":"schema://fixture-conversation-agent/input/v1","output":"schema://fixture-conversation-agent/output/v1","event":"schema://fixture-conversation-agent/event/v1","checkpoint":"schema://fixture-conversation-agent/checkpoint/v1"},"runtime":{"transport":"http","isolation":"container","health_path":"/health"}}`)
	schema := json.RawMessage(`{"type":"object"}`)
	hash, err := catalog.VersionContentHash(manifest, schema, schema)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	if err := store.CreateVersion(ctx, catalog.Version{ID: version, DefinitionID: definition.ID, SemanticVersion: "1.0.0", ManifestHash: hash, Manifest: manifest, ArtifactDigest: digest, InputSchema: schema, OutputSchema: schema, Status: catalog.DefinitionDraft, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	for _, transition := range []struct {
		from, to catalog.DefinitionStatus
		revision uint64
	}{{catalog.DefinitionDraft, catalog.DefinitionEvaluated, 1}, {catalog.DefinitionEvaluated, catalog.DefinitionPublished, 2}} {
		if err := store.TransitionVersion(ctx, version, transition.from, transition.to, transition.revision); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.CreateInstallation(ctx, catalog.Installation{ID: installation, TenantID: tenant, DepartmentID: department, ApplicationID: application, AgentID: agent, VersionID: version, DisplayName: "Conversation fixture", DeploymentMode: "external", DrainPolicy: "wait", RetentionPolicyID: "fixture-retention", Status: catalog.InstallationProvisioning, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	deployment, err := store.CreateDeployment(ctx, catalog.Deployment{ID: "fixture-conversation-deployment", TenantID: tenant, DepartmentID: department, ApplicationID: application, AgentVersionID: version, AgentInstallationID: installation, ArtifactDigest: digest, Transport: "http", EndpointRef: "http://127.0.0.1:1", PlacementPolicy: json.RawMessage(`{}`), ResourcePolicy: json.RawMessage(`{}`), ManifestHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ObserveDeployment(ctx, tenant, department, application, installation, deployment.ID, deployment.DesiredRevision, catalog.DeploymentReady); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionInstallation(ctx, installation, catalog.InstallationProvisioning, catalog.InstallationActive, 1); err != nil {
		t.Fatal(err)
	}
	app := identity.ManagementScope{Type: "application", TenantID: tenant, DepartmentID: department, ApplicationID: application}
	binding := identity.RoleBinding{ID: "fixture-conversation-operator", SubjectID: subject, RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active", Revision: 1, SourceID: "fixture"}
	payload, _ := json.Marshal(binding)
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_role_binding(id,subject_id,role_code,role_version,tenant_id,department_id,application_id,status,revision,payload,source_hash) VALUES(?,?,?,1,?,?,?,'active',1,?,?)`), binding.ID, subject, binding.RoleCode, tenant, department, application, string(payload), strings.Repeat("8", 64)); err != nil {
		t.Fatal(err)
	}
	invoke := func(path string, body any, want int) string {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+address+"/modules/conversation"+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		for key, value := range map[string]string{"X-Internal-Token": "gateway-fixture-0123456789abcdef0123456789abcdef", "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": subject, "X-Tenant-ID": tenant, "X-Department-ID": department, "X-Application-ID": application, "X-Authentication-Revision": "1", "X-Authentication-Session": sessionID, "Content-Type": "application/json"} {
			r.Header.Set(key, value)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		out, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil || response.StatusCode != want {
			t.Fatalf("conversation boundary %s: status=%d want=%d body=%s err=%v", path, response.StatusCode, want, out, err)
		}
		return string(out)
	}
	checkCatalog := func(discover, run bool) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, "GET", "http://"+address+"/modules/catalog/available?tenant_id=forged", nil)
		if err != nil {
			t.Fatal(err)
		}
		for key, value := range map[string]string{"X-Internal-Token": "gateway-fixture-0123456789abcdef0123456789abcdef", "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": subject, "X-Tenant-ID": tenant, "X-Department-ID": department, "X-Application-ID": application, "X-Authentication-Revision": "1", "X-Authentication-Session": sessionID} {
			r.Header.Set(key, value)
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var page struct {
			Items []struct {
				Installation string          `json:"installation_id"`
				AccessStatus string          `json:"access_status"`
				Permissions  map[string]bool `json:"permissions"`
			} `json:"items"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil || resp.StatusCode != 200 {
			t.Fatal("actual catalog projection", resp.StatusCode, err)
		}
		for _, item := range page.Items {
			if item.Installation == installation {
				if item.Permissions["discover"] != discover || item.Permissions["run"] != run || item.Permissions["history.read"] || (item.AccessStatus == "granted") != discover {
					t.Fatal("actual catalog action boundary", item)
				}
				return
			}
		}
		t.Fatal("actual installation missing from catalog")
	}
	checkCatalog(false, false)
	create := conversation.Session{Summary: conversation.Summary{ID: "fixture-bound-conversation", Kind: "qa", AgentID: agent, AgentVersionID: version, Title: "fixture", Status: "active", CanContinue: true, OwnerID: "forged-owner"}, TenantID: "forged-tenant"}
	invoke("/sessions", create, http.StatusForbidden) // A role alone cannot run; permission refusal is not a missing binding.
	var unauthorizedSessions int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_session WHERE id=? AND tenant_id=?`), create.ID, tenant).Scan(&unauthorizedSessions); err != nil || unauthorizedSessions != 0 {
		t.Fatal("role-only creation persisted an unauthorized session", unauthorizedSessions, err)
	}
	grant := identity.Grant{ID: "fixture-conversation-run-grant", SubjectType: identity.PrincipalUser, SubjectID: subject, TenantID: tenant, DepartmentID: department, ApplicationID: application, AgentInstanceID: installation, ResourceType: "agent_installation", ResourceID: installation, Action: "run", Effect: "allow", Status: "active", Revision: 1, SourceID: "fixture", DataScope: identity.DataScope{Type: "owner"}}
	payload, _ = json.Marshal(grant)
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_grant(id,tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id,action,effect,status,revision,grant_key_hash,created_at,permission_json) VALUES(?,?,?,?,?,?,?,?,?,'active',1,?,clock_timestamp(),?)`), grant.ID, tenant, department, application, installation, "user", subject, grant.Action, grant.Effect, strings.Repeat("9", 64), string(payload)); err != nil {
		t.Fatal(err)
	}
	checkCatalog(false, true)
	policyScope := sharedkernel.Scope{TenantID: tenant, DepartmentID: department, ApplicationID: application, AgentID: agent, AgentVersionID: version, PrincipalID: subject}
	policy := policyasset.Snapshot{ModelProfileID: "fixture-model", PromptVersionID: "fixture-prompt", ToolPolicyID: "fixture-tool", MemoryPolicyID: "fixture-memory", KnowledgePolicyID: "fixture-knowledge", RuntimePolicyID: "fixture-runtime", Revision: 1, Hash: strings.Repeat("b", 64), Model: policyasset.ModelPolicy{Provider: "fixture", Model: "fixture", MaxTokens: 512}, Prompt: policyasset.PromptPolicy{TemplateHash: "fixture-prompt-hash", Template: "Fixture prompt"}, Tool: policyasset.ToolPolicy{AllowedTools: []string{"fixture-tool"}}, Memory: policyasset.MemoryPolicy{MaxEntries: 10}, Knowledge: policyasset.KnowledgePolicy{AllowedScopes: []string{"fixture-knowledge"}}, Runtime: policyasset.RuntimePolicy{MaxAttempts: 1, TaskTimeoutSeconds: 10, LeaseSeconds: 30}}
	if err := policyasset.NewSQLResolver(db).Upsert(ctx, policyScope, policy); err != nil {
		t.Fatal("fixture policy snapshot", err)
	}
	discovery := grant
	discovery.ID, discovery.Action = "fixture-conversation-discover-grant", "discover"
	discoveryPayload, _ := json.Marshal(discovery)
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_grant(id,tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id,action,effect,status,revision,grant_key_hash,created_at,permission_json) VALUES(?,?,?,?,?,?,?,?,?,'active',1,?,clock_timestamp(),?)`), discovery.ID, tenant, department, application, installation, "user", subject, discovery.Action, discovery.Effect, fmt.Sprintf("%x", sha256.Sum256([]byte(discovery.ID))), string(discoveryPayload)); err != nil {
		t.Fatal(err)
	}
	checkCatalog(true, true)
	create.InstallationID = "forged-installation"
	invoke("/sessions", create, http.StatusBadRequest)
	create.InstallationID = ""
	response := invoke("/sessions", create, http.StatusCreated)
	var created conversation.Session
	if json.Unmarshal([]byte(response), &created) != nil || created.InstallationID != installation || created.OwnerID != subject || created.TenantID != tenant {
		t.Fatal("create did not return trusted binding", response)
	}
	var owner, bound string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT owner_id,installation_id FROM platform_conversation_session WHERE id=? AND tenant_id=?`), create.ID, tenant).Scan(&owner, &bound); err != nil || owner != subject || bound != installation {
		t.Fatal("durable binding disagrees", owner, bound, err)
	}
	firstRequest := map[string]any{"run_id": "fixture-first-conversation-run", "idempotency_key": "fixture-first-conversation-idem", "request": map[string]any{"question": "first run without history grants", "intent_hint": "AUTHORITY_QUERY", "knowledge_scope": "fixture-knowledge"}}
	invoke("/sessions/"+create.ID+"/runs", firstRequest, http.StatusAccepted)
	// Once projected, a receipt retry is not a new history continuation.
	invoke("/sessions/"+create.ID+"/runs", firstRequest, http.StatusAccepted)
	invoke("/sessions/"+create.ID+"/runs", firstRequest, http.StatusAccepted)
	for _, mutation := range []struct {
		key   string
		value any
	}{
		{"request", map[string]any{"question": "altered command"}},
		{"idempotency_key", "altered-idempotency-key"},
		{"message_id", "forged-message"},
		{"agent_endpoint", "http://attacker"},
		{"fingerprint", "forged-fingerprint"},
	} {
		altered := map[string]any{}
		for key, value := range firstRequest {
			altered[key] = value
		}
		altered[mutation.key] = mutation.value
		invoke("/sessions/"+create.ID+"/runs", altered, http.StatusConflict)
	}
	var projected int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_message WHERE session_id=? AND tenant_id=? AND role='user'`), create.ID, tenant).Scan(&projected); err != nil || projected != 1 {
		t.Fatal("first run did not persist its single user message", projected, err)
	}
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_execution_run WHERE run_id='fixture-first-conversation-run'`)).Scan(&projected); err != nil || projected != 1 {
		t.Fatal("receipt retries duplicated execution", projected, err)
	}
	var intent, knowledge string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT intent_code,knowledge_scope FROM platform_conversation_message WHERE session_id=? AND tenant_id=? AND role='user'`), create.ID, tenant).Scan(&intent, &knowledge); err != nil || intent != "AUTHORITY_QUERY" || knowledge != "fixture-knowledge" {
		t.Fatal("accepted first command lost question metadata", intent, knowledge, err)
	}
	invoke("/sessions/"+create.ID+"/runs", map[string]any{"run_id": "fixture-continue-conversation-run", "idempotency_key": "fixture-continue-conversation-idem", "request": map[string]any{"question": "must require history.continue"}}, http.StatusForbidden)
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_execution_run WHERE run_id='fixture-continue-conversation-run'`)).Scan(&projected); err != nil || projected != 0 {
		t.Fatal("run-only grant continued existing history", projected, err)
	}
	for _, existing := range []struct{ installation, code string }{{"foreign-old-installation", "SESSION_INSTALLATION_CHANGED"}, {"", "SESSION_INSTALLATION_UNVERIFIED"}} {
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_session SET installation_id=? WHERE id=? AND tenant_id=?`), existing.installation, create.ID, tenant); err != nil {
			t.Fatal(err)
		}
		response := invoke("/sessions/"+create.ID+"/runs", map[string]any{"run_id": "fixture-forbidden-conversation-run", "idempotency_key": "fixture-forbidden-conversation-idem", "request": map[string]any{}}, http.StatusForbidden)
		if !strings.Contains(response, "FORBIDDEN") {
			t.Fatal("wrong binding conflict", response)
		}
	}
	var count int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_execution_run WHERE run_id='fixture-forbidden-conversation-run'`)).Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected continuation reached execution", count, err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_session SET installation_id=? WHERE id=? AND tenant_id=?`), installation, create.ID, tenant); err != nil {
		t.Fatal(err)
	}
	invoke("/sessions/"+create.ID+"/runs", firstRequest, http.StatusAccepted)
	grant.Status, grant.Revision = "revoked", 2
	payload, _ = json.Marshal(grant)
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET status='revoked',revision=2,permission_json=? WHERE id=?`), string(payload), grant.ID); err != nil {
		t.Fatal(err)
	}
	checkCatalog(true, false)
	invoke("/sessions/"+create.ID+"/runs", firstRequest, http.StatusForbidden)
	// Revocation also blocks changed bodies before any receipt-comparison oracle.
	invoke("/sessions/"+create.ID+"/runs", map[string]any{"run_id": "fixture-first-conversation-run", "idempotency_key": "fixture-first-conversation-idem", "request": map[string]any{"question": "altered after revocation"}}, http.StatusForbidden)
	create.ID = "fixture-conversation-revoked-create"
	invoke("/sessions", create, http.StatusForbidden)
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_session WHERE id=?`), create.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("revoked creation persisted", count, err)
	}
}
