package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type runtimeIndexFixture struct {
	scope        sharedkernel.Scope
	session      string
	machine      string
	calls        *atomic.Int32
	modelVersion string
}

func indexProcessUUID(t *testing.T) string {
	t.Helper()
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	h := hex.EncodeToString(raw[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[:8], h[8:12], h[12:16], h[16:20], h[20:])
}

// The disposable database is migrated explicitly. Catalog, policy, model
// approval/deployment/access, credentials and IAM are SQL records, not mock
// resolvers. The only model supplier is a bounded loopback HTTP fixture.
func prepareRuntimeIndexFixture(t *testing.T, ctx context.Context, db *sql.DB, dsn string) ([]string, func(*http.Client, string)) {
	t.Helper()
	f := runtimeIndexFixture{scope: sharedkernel.Scope{TenantID: "index-process", DepartmentID: "index-process-dept", ApplicationID: "index-process-app", PrincipalID: "index-process-manager", PrincipalType: "user", AgentID: "index-process-agent", AgentInstanceID: "index-process-install", InstallationID: "index-process-install", AgentVersionID: "index-process-version", TraceID: "index-process-trace"}, machine: "index-process-machine", calls: &atomic.Int32{}}
	iam := identity.NewSQLStore(db)
	for _, err := range []error{
		iam.CreateTenant(ctx, identity.Tenant{ID: f.scope.TenantID, Code: f.scope.TenantID, Name: "Isolated index process", Status: "active", Revision: 1}),
		iam.CreateDepartment(ctx, identity.Department{ID: f.scope.DepartmentID, TenantID: f.scope.TenantID, Code: f.scope.DepartmentID, Name: "Index", Status: "active", Revision: 1}),
		iam.CreateApplication(ctx, identity.Application{ID: f.scope.ApplicationID, TenantID: f.scope.TenantID, DepartmentID: f.scope.DepartmentID, Code: f.scope.ApplicationID, Name: "Index", Status: "active", Revision: 1}),
		iam.CreatePrincipal(ctx, identity.Principal{ID: f.scope.PrincipalID, Type: identity.PrincipalUser, TenantID: f.scope.TenantID, IsActive: true}),
		iam.CreatePrincipal(ctx, identity.Principal{ID: f.machine, Type: identity.PrincipalServicePrincipal, TenantID: f.scope.TenantID, IsActive: true}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, subject := range []struct{ id, kind string }{{f.scope.PrincipalID, "user"}, {f.machine, "service_principal"}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES($1,$2,'v2',1,1)`, subject.kind, subject.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_local_credential(principal_id,tenant_id,department_id,application_id,display_name,password_hash,auth_revision,active,created_at,updated_at) VALUES($1,$2,$3,$4,'Index manager','unusable-index-process-fixture',1,TRUE,clock_timestamp(),clock_timestamp())`, f.scope.PrincipalID, f.scope.TenantID, f.scope.DepartmentID, f.scope.ApplicationID); err != nil {
		t.Fatal(err)
	}
	app := identity.ManagementScope{Type: "application", TenantID: f.scope.TenantID, DepartmentID: f.scope.DepartmentID, ApplicationID: f.scope.ApplicationID}
	member := identity.Membership{ID: "index-process-member", SubjectID: f.scope.PrincipalID, Scope: app, Status: "active", Revision: 1}
	raw, _ := json.Marshal(member)
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES($1,$2,$3,$4,$5,'active',1,$6,$1)`, member.ID, member.SubjectID, app.TenantID, app.DepartmentID, app.ApplicationID, string(raw)); err != nil {
		t.Fatal(err)
	}
	for _, binding := range []identity.RoleBinding{
		{ID: "index-process-admin", SubjectID: f.scope.PrincipalID, RoleCode: "super_admin", RoleVersion: 1, Scope: identity.ManagementScope{Type: "global"}, Status: "active", Revision: 1, SourceID: "isolated-process"},
		{ID: "index-process-model-role", SubjectID: f.scope.PrincipalID, RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active", Revision: 1, SourceID: "isolated-process"},
	} {
		raw, _ := json.Marshal(binding)
		if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_role_binding(id,subject_id,role_code,role_version,tenant_id,department_id,application_id,status,revision,payload,source_hash) VALUES($1,$2,$3,1,$4,$5,$6,'active',1,$7,$1)`, binding.ID, binding.SubjectID, binding.RoleCode, binding.Scope.TenantID, binding.Scope.DepartmentID, binding.Scope.ApplicationID, string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	for _, subject := range []struct {
		id   string
		kind identity.PrincipalType
	}{{f.scope.PrincipalID, identity.PrincipalUser}, {f.machine, identity.PrincipalServicePrincipal}} {
		grant := identity.Grant{ID: subject.id + "-embed", SubjectID: subject.id, SubjectType: subject.kind, TenantID: app.TenantID, DepartmentID: app.DepartmentID, ApplicationID: app.ApplicationID, AgentInstanceID: f.scope.InstallationID, ResourceType: "model", ResourceID: "index-process-model-profile", Action: "model.embed", Effect: "allow", Status: "active", Revision: 1, SourceID: "isolated-process", DataScope: identity.DataScope{Type: "approved_organization"}}
		if err := iam.CreateGrant(ctx, grant); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(grant)
		if _, err := db.ExecContext(ctx, `UPDATE platform_identity_grant SET permission_json=$1 WHERE id=$2`, string(raw), grant.ID); err != nil {
			t.Fatal(err)
		}
	}
	secret := "isolated-process-machine-secret-1234567890"
	digest := sha256.Sum256([]byte(secret))
	if err := iam.CreateMachineCredential(ctx, identity.MachineCredential{TenantID: f.scope.TenantID, PrincipalID: f.machine, SecretHash: hex.EncodeToString(digest[:]), NetworkCIDRs: []string{"127.0.0.1/32"}, Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	binding := identity.WorkloadBinding{TenantID: app.TenantID, DepartmentID: app.DepartmentID, ApplicationID: app.ApplicationID, InstallationID: f.scope.InstallationID, AgentID: f.scope.AgentID, AgentVersionID: f.scope.AgentVersionID, PrincipalID: f.machine, Status: "active", Revision: 1}
	raw, _ = json.Marshal(binding)
	key, _ := json.Marshal([]string{app.TenantID, app.DepartmentID, app.ApplicationID, f.scope.InstallationID})
	keyHash := sha256.Sum256(key)
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_identity_workload_binding(scope_hash,tenant_id,department_id,application_id,installation_id,principal_id,status,revision,payload) VALUES($1,$2,$3,$4,$5,$6,'active',1,$7)`, hex.EncodeToString(keyHash[:]), app.TenantID, app.DepartmentID, app.ApplicationID, f.scope.InstallationID, f.machine, string(raw)); err != nil {
		t.Fatal(err)
	}
	iam.SetRefreshSessionRecorder(func(context.Context, *sql.Tx, identity.RefreshSessionEvent) error { return nil })
	session, err := iam.CreateRefreshSession(ctx, f.scope.PrincipalID, identity.EnrollmentScope{TenantID: app.TenantID, DepartmentID: app.DepartmentID, ApplicationID: app.ApplicationID}, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.session = session.SessionID
	if _, err := iam.CurrentAuthorizationEpoch(ctx, f.scope, "run"); err == nil {
		t.Fatal("manager acquired business run permission")
	}
	seedRuntimeIndexCatalog(t, ctx, db, f.scope)
	modelSecretRoot := t.TempDir()
	workloadRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(modelSecretRoot, "provider.key"), []byte("isolated-process-provider-key"), 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(map[string]string{"client_id": f.machine, "client_secret": secret})
	if err := os.WriteFile(filepath.Join(workloadRoot, hex.EncodeToString(keyHash[:])+".json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/embeddings" || r.Header.Get("Authorization") != "Bearer isolated-process-provider-key" {
			http.Error(w, "invalid request", 400)
			return
		}
		var input struct {
			Input []string `json:"input"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&input) != nil || len(input.Input) == 0 || len(input.Input) > 16 {
			http.Error(w, "invalid batch", 400)
			return
		}
		f.calls.Add(1)
		data := make([]map[string]any, len(input.Input))
		for i := range data {
			data[i] = map[string]any{"index": i, "embedding": []float32{1, .5}}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": data, "usage": map[string]int{"prompt_tokens": 50, "total_tokens": 50}})
	}))
	t.Cleanup(server.Close)
	f.modelVersion = seedRuntimeIndexModel(t, ctx, db, f.scope)
	snapshot := policyasset.Snapshot{ModelProfileID: "index-process-model-profile", PromptVersionID: "index-process-prompt", ToolPolicyID: "index-process-tool", MemoryPolicyID: "index-process-memory", KnowledgePolicyID: "index-process-knowledge", RuntimePolicyID: "index-process-runtime", Revision: 1, Hash: strings.Repeat("a", 64), Model: policyasset.ModelPolicy{ModelVersionID: f.modelVersion, Provider: "index-process-provider", Model: "index-process-model", MaxTokens: 64, BudgetCents: 10}, Prompt: policyasset.PromptPolicy{TemplateHash: "index-process-prompt", Template: "approved index policy"}, Tool: policyasset.ToolPolicy{AllowedTools: []string{"json.validate"}}, Memory: policyasset.MemoryPolicy{MaxEntries: 10}, Knowledge: policyasset.KnowledgePolicy{AllowedScopes: []string{"docs"}}, Runtime: policyasset.RuntimePolicy{MaxAttempts: 1, TaskTimeoutSeconds: 60, LeaseSeconds: 30}}
	if err := policyasset.NewSQLResolver(db).Upsert(ctx, f.scope, snapshot); err != nil {
		t.Fatal(err)
	}
	goEnv, goEndpoints, verifyGo := prepareRuntimeGoFixture(t, ctx, db, f, workloadRoot, modelSecretRoot)
	goEndpoints["service://index-process-model"] = server.URL + "/v1"
	endpoints, _ := json.Marshal(goEndpoints)
	env := []string{"KNOWLEDGE_DATABASE_DSN=" + dsn, "PLATFORM_MODEL_ENDPOINTS_JSON=" + string(endpoints), "PLATFORM_MODEL_SECRET_ROOT=" + modelSecretRoot, "PLATFORM_INDEX_WORKLOAD_SECRET_ROOT=" + workloadRoot}
	env = append(env, goEnv...)
	return env, func(client *http.Client, address string) {
		verifyRuntimeIndex(t, ctx, db, client, address, f)
		name := "go-example-platform-flow"
		if os.Getenv("PLATFORM_TEST_PYTHON_RUNTIME_CONFIG") != "" {
			name = "python-example-platform-flow"
		}
		t.Run(name, func(child *testing.T) { verifyGo(child, client, address) })
	}
}

func seedRuntimeIndexCatalog(t *testing.T, ctx context.Context, db *sql.DB, s sharedkernel.Scope) {
	t.Helper()
	manifest := json.RawMessage(`{"manifest_version":"agent-manifest/v1","agent_id":"index-process-agent","version":"1.0.0","execution_protocols":["agent-execution/v2"],"capabilities":["model.embed"],"schemas":{"input":"schema://index-process/input/v1","output":"schema://index-process/output/v1","event":"schema://index-process/event/v1","checkpoint":"schema://index-process/checkpoint/v1"},"runtime":{"transport":"http","isolation":"container","health_path":"/health"}}`)
	schema := json.RawMessage(`{"type":"object"}`)
	seedRuntimeCatalog(t, ctx, db, s, manifest, schema, schema, "sha256:"+strings.Repeat("a", 64), "http://127.0.0.1:9")
}

func seedRuntimeCatalog(t *testing.T, ctx context.Context, db *sql.DB, s sharedkernel.Scope, manifest, input, output json.RawMessage, artifact, endpoint string) {
	t.Helper()
	store := catalog.NewSQLStore(db, "pgx")
	d := catalog.Definition{ID: s.AgentVersionID + "-definition", PublisherID: s.PrincipalID, AgentKey: s.AgentID, DisplayName: s.AgentID, Description: "Owned SDK process fixture", Status: catalog.DefinitionDraft, Revision: 1}
	if err := store.CreateDefinition(ctx, d); err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(manifest, &meta) != nil {
		t.Fatal("invalid runtime manifest")
	}
	hash, err := catalog.VersionContentHash(manifest, input, output)
	if err != nil {
		t.Fatal(err)
	}
	v := catalog.Version{ID: s.AgentVersionID, DefinitionID: d.ID, SemanticVersion: meta.Version, ManifestHash: hash, Manifest: manifest, ArtifactDigest: artifact, InputSchema: input, OutputSchema: output, Status: catalog.DefinitionDraft, Revision: 1}
	for _, err := range []error{store.CreateVersion(ctx, v), store.TransitionDefinition(ctx, d.ID, catalog.DefinitionDraft, catalog.DefinitionEvaluated, 1), store.TransitionDefinition(ctx, d.ID, catalog.DefinitionEvaluated, catalog.DefinitionPublished, 2), store.TransitionVersion(ctx, v.ID, catalog.DefinitionDraft, catalog.DefinitionEvaluated, 1), store.TransitionVersion(ctx, v.ID, catalog.DefinitionEvaluated, catalog.DefinitionPublished, 2)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	i := catalog.Installation{ID: s.InstallationID, TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, AgentID: s.AgentID, VersionID: s.AgentVersionID, DisplayName: "Index", DeploymentMode: "managed", DrainPolicy: "wait", RetentionPolicyID: "retain", Status: catalog.InstallationProvisioning, Revision: 1}
	if err := store.CreateInstallation(ctx, i); err != nil {
		t.Fatal(err)
	}
	dp, err := store.CreateDeployment(ctx, catalog.Deployment{ID: s.InstallationID + "-deployment", TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, AgentVersionID: s.AgentVersionID, AgentInstallationID: s.InstallationID, ArtifactDigest: v.ArtifactDigest, Transport: "http", EndpointRef: endpoint, PlacementPolicy: []byte(`{}`), ResourcePolicy: []byte(`{}`), ManifestHash: v.ManifestHash})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ObserveDeployment(ctx, s.TenantID, s.DepartmentID, s.ApplicationID, s.InstallationID, dp.ID, dp.DesiredRevision, catalog.DeploymentReady); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionInstallation(ctx, i.ID, catalog.InstallationProvisioning, catalog.InstallationActive, 1); err != nil {
		t.Fatal(err)
	}
}
