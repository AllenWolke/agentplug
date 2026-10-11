package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"crypto/rand"
	"github.com/lexagent/platform/internal/bootstrap"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sqlutil"
	"net/url"
)

func TestSQLMigrationMappingCLIUsesSelectOnlyAndRejectsChangedSource(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	uri, err := url.Parse(dsn)
	if err != nil || uri.Hostname() != "127.0.0.1" || uri.Path != "/knowledge_test" {
		t.Fatal("dedicated loopback PostgreSQL fixture required")
	}
	root, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	name := fmt.Sprintf("mapping_cli_fixture_%d", time.Now().UnixNano())
	if _, err = root.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := root.Exec(`DROP DATABASE "` + name + `"`); err != nil {
			t.Error(err)
		}
	}()
	uri.Path = "/" + name
	adminDSN := uri.String()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	t.Setenv("PLATFORM_DEV_RUNTIME_PASSWORD", "")
	if err = run(ctx, bootstrap.Config{Runtime: bootstrap.RuntimeConfig{Environment: "development", HTTPAddr: ":8080", InternalAddr: ":8081", DBDriver: "pgx", DBDSN: adminDSN, EventBusMode: "disabled"}}); err != nil {
		t.Fatal(err)
	}
	db, err := sqlutil.OpenPostgres(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := identity.NewSQLStore(db)
	if err := store.CreateTenant(ctx, identity.Tenant{ID: "tenant", Code: "tenant", Name: "fixture", Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateDepartment(ctx, identity.Department{ID: "department", TenantID: "tenant", Code: "department", Name: "fixture", Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateApplication(ctx, identity.Application{ID: "application", TenantID: "tenant", DepartmentID: "department", Code: "application", Name: "fixture", Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreatePrincipal(ctx, identity.Principal{Type: identity.PrincipalUser, ID: "user", TenantID: "tenant", Roles: []string{"platform_admin"}, IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_grant(id,tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id,action,effect,status,revision,grant_key_hash,created_at) VALUES('allow','tenant','department','application','installation','user','user','run','allow','active',1,?,clock_timestamp())`), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	readerName := fmt.Sprintf("map_reader_%d", time.Now().UnixNano())
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	password := fmt.Sprintf("%x", secret)
	if _, err = db.Exec(`CREATE ROLE "` + readerName + `" LOGIN PASSWORD '` + password + `'`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := db.Exec(`DROP OWNED BY "` + readerName + `"`); err != nil {
			t.Error(err)
		}
		if _, err := root.Exec(`DROP ROLE "` + readerName + `"`); err != nil {
			t.Error(err)
		}
	}()
	if _, err = db.Exec(`GRANT USAGE ON SCHEMA public,knowledge TO "` + readerName + `"; GRANT SELECT ON ALL TABLES IN SCHEMA public,knowledge TO "` + readerName + `"`); err != nil {
		t.Fatal(err)
	}
	uri.User = url.UserPassword(readerName, password)
	readDSN := uri.String()
	readDB, err := sqlutil.OpenPostgres(ctx, readDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer readDB.Close()
	if _, err := readDB.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE WHERE id='user'`)); err == nil {
		t.Fatal("fixture unexpectedly permits writes")
	}
	work := t.TempDir()
	binary := filepath.Join(work, "identity-inspect")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if output, err := exec.CommandContext(ctx, "go", "build", "-race", "-o", binary, "../identity-inspect").CombinedOutput(); err != nil {
		t.Fatalf("build maintenance CLI: %v %s", err, output)
	}
	subjects := filepath.Join(work, "subjects.json")
	if err := os.WriteFile(subjects, []byte(`[{"principal_type":"user","subject_id":"user"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	invoke := func(extra ...string) ([]byte, error) {
		args := append([]string{"--migration-subjects", subjects, "--tenant", "tenant"}, extra...)
		command := exec.CommandContext(ctx, binary, args...)
		command.Env = append(os.Environ(), "DB_DRIVER=pgx", "DB_DSN="+readDSN)
		return command.Output()
	}
	output, err := invoke()
	if err != nil {
		t.Fatal("SELECT-only snapshot command failed", err)
	}
	var baseline identity.MigrationSourceBatch
	if err := json.Unmarshal(output, &baseline); err != nil || len(baseline.Sources) != 1 {
		t.Fatal("invalid source JSON", err)
	}
	source := baseline.Sources[0]
	var target identity.PermissionSnapshot
	raw, _ := json.Marshal(source.Snapshot)
	if err := json.Unmarshal(raw, &target); err != nil {
		t.Fatal(err)
	}
	target.Mode = "v2"
	app := identity.ManagementScope{Type: "application", TenantID: "tenant", DepartmentID: "department", ApplicationID: "application"}
	target.Memberships = []identity.Membership{{ID: "member", SubjectID: "user", Scope: app, Status: "active", Revision: 1}}
	target.Bindings = []identity.RoleBinding{{ID: "operator", SubjectID: "user", RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active", Revision: 1, SourceID: "reviewed-fixture"}}
	target.Grants[0].ResourceType, target.Grants[0].ResourceID, target.Grants[0].DataScope = "agent_installation", "installation", identity.DataScope{Type: "owner"}
	selection := []struct {
		Subject identity.MigrationSubject  `json:"subject"`
		Mapping identity.MigrationMapping  `json:"mapping"`
		Queries []identity.PermissionQuery `json:"query_samples"`
	}{{identity.MigrationSubject{Type: identity.PrincipalUser, ID: "user"}, identity.MigrationMapping{ExpectedSourceDigest: source.SourceDigest, Basis: "verified fixture job", Target: target}, []identity.PermissionQuery{{Action: "run", Scope: identity.ManagementScope{Type: "agent_installation", TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", ResourceID: "installation"}, ResourceType: "agent_installation", ResourceID: "installation"}}}}
	mapping := filepath.Join(work, "mapping.json")
	raw, _ = json.Marshal(selection)
	if err := os.WriteFile(mapping, raw, 0600); err != nil {
		t.Fatal(err)
	}
	output, err = invoke("--migration-mapping", mapping)
	if err != nil {
		t.Fatal("SELECT-only mapping command failed", err)
	}
	var plans []identity.MigrationMappingPreview
	if err := json.Unmarshal(output, &plans); err != nil || len(plans) != 1 || len(plans[0].Differences) != 3 || len(plans[0].Samples) != 1 || plans[0].Samples[0].Classification != "allowed_both_compare_ranges" || !plans[0].PreviewOnly || plans[0].ResourceOwnershipVerified {
		t.Fatal("invalid mapping report", err)
	}
	output, err = invoke("--migration-mapping", mapping, "--verify-resources")
	if err == nil || len(bytes.TrimSpace(output)) != 0 {
		t.Fatal("unknown installation passed resource verification")
	}
	catalogStore := seedMigrationCatalogFixture(t, ctx, db)
	output, err = invoke("--migration-mapping", mapping, "--verify-resources")
	if err != nil {
		t.Fatal("published installation verification failed", err)
	}
	if err := json.Unmarshal(output, &plans); err != nil || len(plans) != 1 || !plans[0].ResourceOwnershipVerified || !plans[0].PreviewOnly {
		t.Fatal("verification flag missing", err)
	}
	if err := catalogStore.TransitionInstallation(ctx, "installation", catalog.InstallationActive, catalog.InstallationSuspended, 2); err != nil {
		t.Fatal(err)
	}
	output, err = invoke("--migration-mapping", mapping, "--verify-resources")
	if err == nil || len(bytes.TrimSpace(output)) != 0 {
		t.Fatal("suspended installation accepted")
	}
	if err := catalogStore.TransitionInstallation(ctx, "installation", catalog.InstallationSuspended, catalog.InstallationActive, 3); err != nil {
		t.Fatal(err)
	}
	if err := catalogStore.TransitionDefinition(ctx, "fixture-definition", catalog.DefinitionPublished, catalog.DefinitionDisabled, 3); err != nil {
		t.Fatal(err)
	}
	output, err = invoke("--migration-mapping", mapping, "--verify-resources")
	if err == nil || len(bytes.TrimSpace(output)) != 0 {
		t.Fatal("disabled definition accepted")
	}
	// A fact mutation without revision change must fail before any report is
	// emitted; SELECT-only credentials independently prove no migration write.
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET action='discover' WHERE id='allow'`)); err != nil {
		t.Fatal(err)
	}
	output, err = invoke("--migration-mapping", mapping)
	if err == nil || len(bytes.TrimSpace(output)) != 0 {
		t.Fatal("stale mapping accepted or partial output emitted")
	}
	var count int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_role_binding WHERE subject_id='user'`)).Scan(&count); err != nil || count != 0 {
		t.Fatal("mapping wrote roles", count, err)
	}
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_policy_migration WHERE subject_id='user'`)).Scan(&count); err != nil || count != 0 {
		t.Fatal("mapping switched policy mode", count, err)
	}
}

func seedMigrationCatalogFixture(t *testing.T, ctx context.Context, db *sql.DB) *catalog.SQLStore {
	t.Helper()
	store := catalog.NewSQLStore(db, "pgx")
	manifest := json.RawMessage(`{"manifest_version":"agent-manifest/v1","agent_id":"fixture","version":"1.0.0","execution_protocols":["agent-execution/v2"],"capabilities":["invoke"],"schemas":{"input":"schema://input","output":"schema://output","event":"schema://event","checkpoint":"schema://checkpoint"},"runtime":{"transport":"http","isolation":"container","health_path":"/health/ready"}}`)
	schema := json.RawMessage(`{"type":"object"}`)
	hash, err := catalog.VersionContentHash(manifest, schema, schema)
	if err != nil {
		t.Fatal(err)
	}
	artifact := "sha256:" + strings.Repeat("a", 64)
	if err := store.CreateDefinition(ctx, catalog.Definition{ID: "fixture-definition", PublisherID: "fixture-publisher", AgentKey: "fixture", DisplayName: "Fixture", Description: "Verified catalog fixture", Status: catalog.DefinitionDraft, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateVersion(ctx, catalog.Version{ID: "fixture-version", DefinitionID: "fixture-definition", SemanticVersion: "1.0.0", ManifestHash: hash, Manifest: manifest, ArtifactDigest: artifact, InputSchema: schema, OutputSchema: schema, Status: catalog.DefinitionDraft, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	for _, transition := range []struct {
		from, to catalog.DefinitionStatus
		revision uint64
	}{{catalog.DefinitionDraft, catalog.DefinitionEvaluated, 1}, {catalog.DefinitionEvaluated, catalog.DefinitionPublished, 2}} {
		if err := store.TransitionDefinition(ctx, "fixture-definition", transition.from, transition.to, transition.revision); err != nil {
			t.Fatal(err)
		}
		if err := store.TransitionVersion(ctx, "fixture-version", transition.from, transition.to, transition.revision); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.CreateInstallation(ctx, catalog.Installation{ID: "installation", TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentID: "fixture", VersionID: "fixture-version", DisplayName: "Fixture", DeploymentMode: "external", DrainPolicy: "wait", RetentionPolicyID: "fixture-retention", Status: catalog.InstallationProvisioning, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	deployment, err := store.CreateDeployment(ctx, catalog.Deployment{ID: "fixture-deployment", TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentVersionID: "fixture-version", AgentInstallationID: "installation", ArtifactDigest: artifact, Transport: "http", EndpointRef: "http://127.0.0.1:1", PlacementPolicy: json.RawMessage(`{}`), ResourcePolicy: json.RawMessage(`{}`), Status: catalog.DeploymentPending, ManifestHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ObserveDeployment(ctx, "tenant", "department", "application", "installation", deployment.ID, deployment.DesiredRevision, catalog.DeploymentReady); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionInstallation(ctx, "installation", catalog.InstallationProvisioning, catalog.InstallationActive, 1); err != nil {
		t.Fatal(err)
	}
	return store
}
