package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/bootstrap"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/schemaversion"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestPostgresMigrationCommandCompleteBundleAndReplay(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	ctx := context.Background()
	admin, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated admin: %T", err)
	}
	defer admin.Close()
	name := fmt.Sprintf("pg_command_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(`DROP DATABASE "` + name + `"`); err != nil {
			t.Error(err)
		}
	}()
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Scheme != "postgres" {
		t.Fatal("fixture requires PostgreSQL URL DSN")
	}
	parsed.Path = "/" + name
	db, err := sqlutil.OpenPostgres(ctx, parsed.String())
	if err != nil {
		t.Fatalf("open isolated database: %T", err)
	}
	defer db.Close()
	config := bootstrap.Config{Runtime: bootstrap.RuntimeConfig{Environment: "test", DBDriver: "pgx", DBDSN: parsed.String()}}
	// A malformed pre-existing final module makes its index DDL fail after
	// every earlier module has run. All earlier DDL and seeded roles must roll
	// back; externally supplied objects remain untouched.
	if _, err := db.Exec(`CREATE TABLE platform_tool_invocation(fixture_id INT)`); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, config); sqlutil.SQLState(err) != "42703" {
		t.Fatalf("expected late module undefined-column failure, got %v", err)
	}
	for _, table := range []string{"platform_schema_version", "platform_execution_run", "platform_identity_role_definition", "platform_memory_entry", "platform_model_invocation", "knowledge.generations", "platform_knowledge_source_head", "platform_knowledge_document_version"} {
		var present bool
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT to_regclass(?) IS NOT NULL`), table).Scan(&present); err != nil || present {
			t.Fatalf("partial schema survived failed complete bundle: %s %v", table, err)
		}
	}
	if _, err := db.Exec(`DROP TABLE platform_tool_invocation`); err != nil {
		t.Fatal(err)
	}

	if err := run(ctx, config); err != nil {
		t.Fatal(err)
	}
	if err := schemaversion.Check(ctx, db); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{
		"platform_execution_run", "platform_catalog_installation", "platform_identity_refresh_family",
		"platform_identity_role_definition", "platform_identity_workload_binding", "platform_agent_template",
		"platform_evaluation_product_head", "platform_model_deployment", "platform_model_capacity_pool",
		"platform_notification_outbox", "platform_conversation_session", "platform_conversation_erasure",
		"platform_usage_event", "platform_audit_event", "platform_policy_snapshot",
		"platform_memory_entry", "platform_model_invocation", "platform_tool_invocation", "knowledge.generations", "platform_knowledge_source_head", "platform_knowledge_document_head", "platform_knowledge_document_version", "platform_knowledge_source_event",
	} {
		var present bool
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT to_regclass(?) IS NOT NULL`), table).Scan(&present); err != nil || !present {
			t.Fatalf("missing module table %s: %v", table, err)
		}
	}
	var before, after int
	if err := db.QueryRow(`SELECT COUNT(*) FROM platform_identity_role_definition`).Scan(&before); err != nil || before == 0 {
		t.Fatalf("immutable roles not seeded: %d %v", before, err)
	}
	if err := run(ctx, config); err != nil {
		t.Fatal(err)
	}
	completedPredecessors := 0
	if err := db.QueryRow(`SELECT COUNT(*) FROM platform_identity_role_definition`).Scan(&after); err != nil || after != before {
		t.Fatalf("replay changed definitions: %d %d %v", before, after, err)
	}
	t.Run("company administration catalog upgrade preserves assignments", func(t *testing.T) {
		var oldRole, oldPreset string
		if err := db.QueryRow(`SELECT payload::text FROM platform_identity_role_definition WHERE role_code='tenant_admin' AND role_version=1`).Scan(&oldRole); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT payload::text FROM platform_identity_preset_definition WHERE preset_code='tenant_admin' AND preset_version=1`).Scan(&oldPreset); err != nil {
			t.Fatal(err)
		}
		binding := identity.RoleBinding{ID: "company-upgrade-legacy-binding", SubjectID: "company-upgrade-legacy-principal", RoleCode: "tenant_admin", RoleVersion: 1, Scope: identity.ManagementScope{Type: "tenant", TenantID: "company-upgrade-fixture"}, Status: "active", Revision: 1, SourceID: "company-upgrade-legacy-source"}
		iam := identity.NewSQLStore(db)
		if err := iam.CreateTenant(ctx, identity.Tenant{ID: binding.Scope.TenantID, Code: binding.Scope.TenantID, Name: "company upgrade fixture", Status: "active", Revision: 1}); err != nil {
			t.Fatal(err)
		}
		if err := iam.CreatePrincipal(ctx, identity.Principal{Type: identity.PrincipalUser, ID: binding.SubjectID, TenantID: binding.Scope.TenantID, IsActive: true, Revision: 1}); err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(binding)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_role_binding(id,subject_id,role_code,role_version,tenant_id,department_id,application_id,status,revision,payload,source_hash) VALUES(?,?,?,1,?,'','','active',1,?,?)`), binding.ID, binding.SubjectID, binding.RoleCode, binding.Scope.TenantID, string(payload), "company-upgrade-legacy-source-hash"); err != nil {
			t.Fatal(err)
		}
		var oldBinding string
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload::text FROM platform_identity_role_binding WHERE id=?`), binding.ID).Scan(&oldBinding); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`DELETE FROM platform_identity_role_definition WHERE role_code='tenant_admin' AND role_version=2`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`DELETE FROM platform_identity_preset_definition WHERE preset_code='tenant_admin' AND preset_version=2`); err != nil {
			t.Fatal(err)
		}
		departmentChecksum := fmt.Sprintf("%x", sha256.Sum256([]byte(schemaversion.DepartmentAdministrationManifest)))
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_schema_version SET version=?,checksum=? WHERE version=?`), schemaversion.DepartmentAdministrationVersion, departmentChecksum, schemaversion.CurrentVersion); err != nil {
			t.Fatal(err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal("apply explicit company role catalog upgrade", err)
		}
		var currentRole, currentPreset, currentBinding, newPreset string
		if err := db.QueryRow(`SELECT payload::text FROM platform_identity_role_definition WHERE role_code='tenant_admin' AND role_version=1`).Scan(&currentRole); err != nil || currentRole != oldRole {
			t.Fatal("company upgrade changed published v1 role", err)
		}
		if err := db.QueryRow(`SELECT payload::text FROM platform_identity_preset_definition WHERE preset_code='tenant_admin' AND preset_version=1`).Scan(&currentPreset); err != nil || currentPreset != oldPreset {
			t.Fatal("company upgrade changed published v1 preset", err)
		}
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload::text FROM platform_identity_role_binding WHERE id=?`), binding.ID).Scan(&currentBinding); err != nil || currentBinding != oldBinding {
			t.Fatal("company upgrade silently changed an existing assignment", err)
		}
		if principal, err := iam.GetPrincipal(ctx, identity.PrincipalUser, binding.SubjectID); err != nil || principal.Revision != 1 || !principal.IsActive {
			t.Fatal("company upgrade changed the existing account", err)
		}
		if err := db.QueryRow(`SELECT payload::text FROM platform_identity_preset_definition WHERE preset_code='tenant_admin' AND preset_version=2`).Scan(&newPreset); err != nil {
			t.Fatal(err)
		}
		var preset identity.IdentityPreset
		if err := json.Unmarshal([]byte(newPreset), &preset); err != nil || !preset.AppointmentOnly || preset.RoleVersion != 2 {
			t.Fatal("new company preset is not protected", err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal("company catalog upgrade replay", err)
		}
		if err := schemaversion.Check(ctx, db); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_identity_role_binding WHERE id=?`), binding.ID); err != nil {
			t.Fatal(err)
		}
		completedPredecessors++
	})
	t.Run("department Agent ceiling upgrade preserves existing authority", func(t *testing.T) {
		iam := identity.NewSQLStore(db)
		tenant, department, application, user := "ceiling-upgrade-company", "ceiling-upgrade-dept", "ceiling-upgrade-app", "ceiling-upgrade-user"
		for _, err := range []error{
			iam.CreateTenant(ctx, identity.Tenant{ID: tenant, Code: tenant, Name: "fixture", Status: "active", Revision: 1}),
			iam.CreateDepartment(ctx, identity.Department{ID: department, TenantID: tenant, Code: department, Name: "fixture", Status: "active", Revision: 1}),
			iam.CreateApplication(ctx, identity.Application{ID: application, TenantID: tenant, DepartmentID: department, Code: application, Name: "fixture", Status: "active", Revision: 1}),
			iam.CreatePrincipal(ctx, identity.Principal{Type: identity.PrincipalUser, ID: user, TenantID: tenant, IsActive: true, Revision: 1}),
		} {
			if err != nil {
				t.Fatal(err)
			}
		}
		grant := identity.Grant{ID: "ceiling-upgrade-grant", TenantID: tenant, DepartmentID: department, ApplicationID: application, AgentInstanceID: "ceiling-upgrade-agent", SubjectType: identity.PrincipalUser, SubjectID: user, Action: "run", Effect: "allow", Status: identity.GrantActive, Revision: 1}
		if err := iam.CreateGrant(ctx, grant); err != nil {
			t.Fatal(err)
		}
		var beforePermission sql.NullString
		var beforeRole string
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT permission_json::text FROM platform_identity_grant WHERE id=?`), grant.ID).Scan(&beforePermission); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT payload::text FROM platform_identity_role_definition WHERE role_code='tenant_admin' AND role_version=2`).Scan(&beforeRole); err != nil {
			t.Fatal(err)
		}
		// This database is created by the parent fixture. Reproduce the exact
		// predecessor's absence of the three new tables, then run the real bundle.
		if _, err := db.Exec(`DROP TABLE platform_identity_department_agent_change; DROP TABLE platform_identity_department_agent_entry; DROP TABLE platform_identity_department_agent_policy`); err != nil {
			t.Fatal(err)
		}
		companyChecksum := fmt.Sprintf("%x", sha256.Sum256([]byte(schemaversion.CompanyAdministrationManifest)))
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_schema_version SET version=?,checksum=? WHERE version=?`), schemaversion.CompanyAdministrationVersion, companyChecksum, schemaversion.CurrentVersion); err != nil {
			t.Fatal(err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal("upgrade company schema to department Agent ceiling", err)
		}
		var currentPermission sql.NullString
		var currentRole string
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT permission_json::text FROM platform_identity_grant WHERE id=?`), grant.ID).Scan(&currentPermission); err != nil || currentPermission != beforePermission {
			t.Fatal("schema upgrade rewrote existing business grant", err)
		}
		if err := db.QueryRow(`SELECT payload::text FROM platform_identity_role_definition WHERE role_code='tenant_admin' AND role_version=2`).Scan(&currentRole); err != nil || currentRole != beforeRole {
			t.Fatal("schema upgrade rewrote the company role", err)
		}
		var heads int
		if err := db.QueryRow(`SELECT COUNT(*) FROM platform_identity_department_agent_policy`).Scan(&heads); err != nil || heads != 0 {
			t.Fatal("schema upgrade silently constrained existing departments", err)
		}
		if err := iam.CreateDepartmentWithAdministrationContext(ctx, identity.Department{ID: department + "-new", TenantID: tenant, Code: "new", Name: "New department", Status: "active", Revision: 1}); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_department_agent_policy WHERE tenant_id=? AND department_id=? AND revision=1`), tenant, department+"-new").Scan(&heads); err != nil || heads != 1 {
			t.Fatal("new department missing default managed ceiling", err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal("ceiling migration replay", err)
		}
		if err := schemaversion.Check(ctx, db); err != nil {
			t.Fatal(err)
		}
		completedPredecessors++
	})
	t.Run("permission batch upgrade preserves department ceilings", func(t *testing.T) {
		var before, after string
		if err := db.QueryRow(`SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY tenant_id,department_id),'[]'::jsonb)::text FROM platform_identity_department_agent_policy p`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`DROP TABLE platform_identity_permission_batch`); err != nil {
			t.Fatal(err)
		}
		predecessorChecksum := fmt.Sprintf("%x", sha256.Sum256([]byte(schemaversion.DepartmentAgentAccessManifest)))
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_schema_version SET version=?,checksum=? WHERE version=?`), schemaversion.DepartmentAgentAccessVersion, predecessorChecksum, schemaversion.CurrentVersion); err != nil {
			t.Fatal(err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal("upgrade department Agent schema to permission batches", err)
		}
		if err := db.QueryRow(`SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY tenant_id,department_id),'[]'::jsonb)::text FROM platform_identity_department_agent_policy p`).Scan(&after); err != nil || after != before {
			t.Fatal("permission batch upgrade rewrote company-approved department ceilings", err)
		}
		var batches int
		if err := db.QueryRow(`SELECT COUNT(*) FROM platform_identity_permission_batch`).Scan(&batches); err != nil || batches != 0 {
			t.Fatal("batch table was missing or manufactured historical decisions", err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal("permission batch migration replay", err)
		}
		if err := schemaversion.Check(ctx, db); err != nil {
			t.Fatal(err)
		}
		completedPredecessors++
	})
	t.Run("0408 usage step ID migration preserves unlinked history", func(t *testing.T) {
		legacyID := fmt.Sprintf("migration-legacy-usage-%d", time.Now().UnixNano())
		if _, err := db.Exec(sqlutil.Bind(`INSERT INTO platform_usage_event(event_id,tenant_id,department_id,application_id,agent_id,agent_version_id,run_id,provider,model,input_tokens,output_tokens,cost_micros,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,clock_timestamp())`), legacyID, "migration-tenant", "migration-department", "migration-application", "migration-agent", "v1", "migration-run", "fixture", "fixture", 1, 1, 1); err != nil {
			t.Fatal("seed legacy usage event", err)
		}
		if _, err := db.Exec(`ALTER TABLE platform_usage_event DROP COLUMN step_id`); err != nil {
			t.Fatal("simulate 0408 usage schema", err)
		}
		if _, err := db.Exec(sqlutil.Bind(`UPDATE platform_schema_version SET version=?,checksum=? WHERE version=?`), schemaversion.GenerationJournalVersion, schemaversion.GenerationJournalChecksum(), schemaversion.CurrentVersion); err != nil {
			t.Fatal("simulate 0408 schema marker", err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal("apply 0409 usage step migration", err)
		}
		var stepID sql.NullString
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT step_id FROM platform_usage_event WHERE event_id=?`), legacyID).Scan(&stepID); err != nil || stepID.Valid {
			t.Fatalf("migration must leave legacy step ID NULL: value=%+v err=%v", stepID, err)
		}
		if err := schemaversion.Check(ctx, db); err != nil {
			t.Fatal("0409 schema marker is not current", err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal("replay 0409 usage migration", err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_usage_event WHERE event_id=?`), legacyID); err != nil {
			t.Fatal("cleanup legacy usage fixture", err)
		}
		completedPredecessors++
	})
	t.Run("native predecessor directory index upgrade", func(t *testing.T) {
		// Simulate the exact preceding native schema, then execute the real bundle.
		if _, err := db.Exec(`DROP INDEX idx_membership_directory; CREATE INDEX idx_membership_scope ON platform_identity_membership(tenant_id,department_id,application_id,status)`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(sqlutil.Bind(`UPDATE platform_schema_version SET version=?,checksum=? WHERE version=?`), schemaversion.PostgresInitialVersion, schemaversion.PostgresInitialChecksum(), schemaversion.CurrentVersion); err != nil {
			t.Fatal(err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal(err)
		}
		var indexPresent bool
		if err := db.QueryRow(`SELECT to_regclass('idx_membership_directory') IS NOT NULL`).Scan(&indexPresent); err != nil || !indexPresent {
			t.Fatal("directory upgrade index missing", err)
		}
		if err := db.QueryRow(`SELECT to_regclass('idx_membership_scope') IS NOT NULL`).Scan(&indexPresent); err != nil || indexPresent {
			t.Fatal("obsolete partial directory index retained", err)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM platform_identity_role_definition`).Scan(&after); err != nil || after != before {
			t.Fatal("upgrade changed seeded roles", err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal("native upgrade replay", err)
		}
		completedPredecessors++
	})
	t.Run("native directory predecessor source upgrade", func(t *testing.T) {
		if _, err := db.Exec(`DROP TABLE platform_knowledge_source_event; DROP TABLE platform_knowledge_document_head; DROP TABLE platform_knowledge_document_version; DROP TABLE platform_knowledge_source_head`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(sqlutil.Bind(`UPDATE platform_schema_version SET version=?,checksum=? WHERE version=?`), schemaversion.PostgresDirectoryVersion, schemaversion.PostgresDirectoryChecksum(), schemaversion.CurrentVersion); err != nil {
			t.Fatal(err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"platform_knowledge_source_head", "platform_knowledge_document_head", "platform_knowledge_document_version", "platform_knowledge_source_event"} {
			var present bool
			if err := db.QueryRow(sqlutil.Bind(`SELECT to_regclass(?) IS NOT NULL`), table).Scan(&present); err != nil || !present {
				t.Fatal("native source upgrade missing table", table, err)
			}
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM platform_identity_role_definition`).Scan(&after); err != nil || after != before {
			t.Fatal("source upgrade changed roles", err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal("native source upgrade replay", err)
		}
		completedPredecessors++
	})
	t.Run("native source predecessor index receipt upgrade", func(t *testing.T) {
		if _, err := db.Exec(`DROP TABLE knowledge.index_receipts`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(sqlutil.Bind(`UPDATE platform_schema_version SET version=?,checksum=? WHERE version=?`), schemaversion.PostgresSourceVersion, schemaversion.PostgresSourceChecksum(), schemaversion.CurrentVersion); err != nil {
			t.Fatal(err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal(err)
		}
		var present bool
		if err := db.QueryRow(`SELECT to_regclass('knowledge.index_receipts') IS NOT NULL`).Scan(&present); err != nil || !present {
			t.Fatal("index receipt upgrade missing", err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal("index receipt upgrade replay", err)
		}
		completedPredecessors++
	})
	t.Run("native index predecessor checkpoint upgrade", func(t *testing.T) {
		if _, err := db.Exec(`DROP TABLE platform_knowledge_task_checkpoint`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(sqlutil.Bind(`UPDATE platform_schema_version SET version=?,checksum=? WHERE version=?`), schemaversion.PostgresIndexVersion, schemaversion.PostgresIndexChecksum(), schemaversion.CurrentVersion); err != nil {
			t.Fatal(err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal(err)
		}
		var present bool
		if err := db.QueryRow(`SELECT to_regclass('platform_knowledge_task_checkpoint') IS NOT NULL`).Scan(&present); err != nil || !present {
			t.Fatal("checkpoint upgrade missing", err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal("checkpoint upgrade replay", err)
		}
		completedPredecessors++
	})
	t.Run("business state predecessor tool approval upgrade", func(t *testing.T) {
		if _, err := db.Exec(`DROP TABLE platform_tool_approval`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(sqlutil.Bind(`UPDATE platform_schema_version SET version=?,checksum=? WHERE version=?`), schemaversion.BusinessStateVersion, schemaversion.BusinessStateChecksum(), schemaversion.CurrentVersion); err != nil {
			t.Fatal(err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal("0401 predecessor upgrade failed", err)
		}
		var present bool
		if err := db.QueryRow(`SELECT to_regclass('platform_tool_approval') IS NOT NULL`).Scan(&present); err != nil || !present {
			t.Fatal("tool approval upgrade table missing", err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal("tool approval upgrade replay", err)
		}
		completedPredecessors++
	})
	t.Run("0409 permission directory migration preserves v1 definitions", func(t *testing.T) {
		type definitionRecord struct {
			payload []byte
			hash    string
		}
		encode := func(value any) definitionRecord {
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(raw)
			return definitionRecord{payload: raw, hash: hex.EncodeToString(digest[:])}
		}
		read := func(kind, code string, version uint64) definitionRecord {
			t.Helper()
			var query string
			switch kind {
			case "role":
				query = `SELECT payload,content_hash FROM platform_identity_role_definition WHERE role_code=? AND role_version=?`
			case "preset":
				query = `SELECT payload,content_hash FROM platform_identity_preset_definition WHERE preset_code=? AND preset_version=?`
			default:
				t.Fatalf("unsupported permission directory kind %q", kind)
			}
			var record definitionRecord
			if err := db.QueryRowContext(ctx, sqlutil.Bind(query), code, version).Scan(&record.payload, &record.hash); err != nil {
				t.Fatalf("read %s %s/v%d: %v", kind, code, version, err)
			}
			return record
		}
		insert := func(kind, code string, version uint64, record definitionRecord) {
			t.Helper()
			var query string
			switch kind {
			case "role":
				query = `INSERT INTO platform_identity_role_definition(role_code,role_version,payload,content_hash) VALUES(?,?,?,?)`
			case "preset":
				query = `INSERT INTO platform_identity_preset_definition(preset_code,preset_version,payload,content_hash) VALUES(?,?,?,?)`
			default:
				t.Fatalf("unsupported permission directory kind %q", kind)
			}
			if _, err := db.ExecContext(ctx, sqlutil.Bind(query), code, version, string(record.payload), record.hash); err != nil {
				t.Fatalf("insert legacy %s %s/v%d: %v", kind, code, version, err)
			}
		}
		assertRecord := func(kind, code string, version uint64, expected definitionRecord) {
			t.Helper()
			actual := read(kind, code, version)
			if string(actual.payload) != string(expected.payload) || actual.hash != expected.hash {
				t.Fatalf("%s %s/v%d changed: payload_equal=%t hash_equal=%t", kind, code, version, string(actual.payload) == string(expected.payload), actual.hash == expected.hash)
			}
		}

		roleCodes := []string{"skill_user", "agent_delegate"}
		presetCodes := []string{"skill_user", "agent_delegate"}
		roleV1 := make(map[string]definitionRecord, len(roleCodes))
		roleV2 := make(map[string]definitionRecord, len(roleCodes))
		presetV1 := make(map[string]definitionRecord, len(presetCodes))
		presetV2 := make(map[string]definitionRecord, len(presetCodes))
		for _, code := range roleCodes {
			found := false
			for _, role := range identity.BuiltinRoleDefinitions() {
				if role.Code != code || role.Version != 2 {
					continue
				}
				found = true
				roleV2[code] = encode(role)
				role.Version = 1
				roleV1[code] = encode(role)
			}
			if !found {
				t.Fatalf("current v2 role %s is missing from the built-in catalog", code)
			}
		}
		for _, code := range presetCodes {
			found := false
			for _, preset := range identity.BuiltinIdentityPresets() {
				if preset.Code != code || preset.Version != 2 || preset.RoleVersion != 2 {
					continue
				}
				found = true
				presetV2[code] = encode(preset)
				preset.Version = 1
				preset.RoleVersion = 1
				presetV1[code] = encode(preset)
			}
			if !found {
				t.Fatalf("current v2 preset %s is missing from the built-in catalog", code)
			}
		}

		var existing int
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_schema_version WHERE version=?`), schemaversion.ModelUsageStepVersion).Scan(&existing); err != nil || existing != 0 {
			t.Fatalf("0409 marker already exists; refusing to alter another history row: count=%d err=%v", existing, err)
		}
		for _, code := range roleCodes {
			var count int
			if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_role_definition WHERE role_code=? AND role_version IN (1,2)`), code).Scan(&count); err != nil || count != 1 {
				t.Fatalf("unexpected pre-migration role history for %s: count=%d err=%v", code, count, err)
			}
			if _, err := db.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_identity_role_definition WHERE role_code=? AND role_version=2`), code); err != nil {
				t.Fatal("remove simulated current role catalog row", err)
			}
			insert("role", code, 1, roleV1[code])
		}
		for _, code := range presetCodes {
			var count int
			if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_preset_definition WHERE preset_code=? AND preset_version IN (1,2)`), code).Scan(&count); err != nil || count != 1 {
				t.Fatalf("unexpected pre-migration preset history for %s: count=%d err=%v", code, count, err)
			}
			if _, err := db.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_identity_preset_definition WHERE preset_code=? AND preset_version=2`), code); err != nil {
				t.Fatal("remove simulated current preset catalog row", err)
			}
			insert("preset", code, 1, presetV1[code])
		}
		result, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_schema_version SET version=?,checksum=? WHERE version=?`), schemaversion.ModelUsageStepVersion, schemaversion.ModelUsageStepChecksum(), schemaversion.CurrentVersion)
		if err != nil {
			t.Fatal("simulate 0409 permission catalog predecessor marker", err)
		}
		if rows, err := result.RowsAffected(); err != nil || rows != 1 {
			t.Fatalf("expected to downgrade only the current marker: rows=%d err=%v", rows, err)
		}

		if err := run(ctx, config); err != nil {
			t.Fatal("apply 0501 permission catalog migration", err)
		}
		for _, code := range roleCodes {
			assertRecord("role", code, 1, roleV1[code])
			assertRecord("role", code, 2, roleV2[code])
		}
		for _, code := range presetCodes {
			assertRecord("preset", code, 1, presetV1[code])
			assertRecord("preset", code, 2, presetV2[code])
		}
		for _, check := range []struct{ table, codeColumn, versionColumn string }{
			{"platform_identity_role_definition", "role_code", "role_version"},
			{"platform_identity_preset_definition", "preset_code", "preset_version"},
		} {
			for _, version := range []uint64{1, 2} {
				var count int
				query := fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE %s IN ('skill_user','agent_delegate') AND %s=?`, check.table, check.codeColumn, check.versionColumn)
				if err := db.QueryRowContext(ctx, sqlutil.Bind(query), version).Scan(&count); err != nil || count != 2 {
					t.Fatalf("expected exactly two %s definitions at v%d: count=%d err=%v", check.table, version, count, err)
				}
			}
		}
		if err := schemaversion.Check(ctx, db); err != nil {
			t.Fatal("0501 permission directory marker is not current", err)
		}
		if err := run(ctx, config); err != nil {
			t.Fatal("replay 0501 permission catalog migration", err)
		}
		for _, code := range roleCodes {
			assertRecord("role", code, 1, roleV1[code])
			assertRecord("role", code, 2, roleV2[code])
		}
		for _, code := range presetCodes {
			assertRecord("preset", code, 1, presetV1[code])
			assertRecord("preset", code, 2, presetV2[code])
		}
		completedPredecessors++
	})
	t.Run("development runtime role", func(t *testing.T) {
		password := "synthetic_runtime_fixture_20261002_password"
		for _, entry := range []struct{ environment, password string }{{"production", password}, {"development", "bad'password"}} {
			if err := provisionDevRuntimeAccount(ctx, db, entry.environment, parsed.String(), entry.password); err == nil {
				t.Fatal("unsafe development provisioning accepted")
			}
		}
		// A PUBLIC security-definer function makes the proposed role unsafe. The
		// role, grants, provenance and PUBLIC permission changes must roll back.
		if _, err := db.Exec(`CREATE FUNCTION public.provision_failure_fixture() RETURNS INT LANGUAGE SQL SECURITY DEFINER AS 'SELECT 1'`); err != nil {
			t.Fatal(err)
		}
		if err := provisionDevRuntimeAccount(ctx, db, "development", parsed.String(), password); err == nil {
			t.Fatal("unsafe runtime role committed")
		}
		var roleExists bool
		if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='platform_runtime')`).Scan(&roleExists); err != nil || roleExists {
			t.Fatalf("failed provisioning left role: %v %v", roleExists, err)
		}
		if _, err := db.Exec(`DROP FUNCTION public.provision_failure_fixture()`); err != nil {
			t.Fatal(err)
		}
		if err := provisionDevRuntimeAccount(ctx, db, "development", parsed.String(), password); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := db.Exec(`DROP OWNED BY platform_runtime`); err != nil {
				t.Error(err)
			}
			if _, err := db.Exec(`DROP ROLE platform_runtime`); err != nil {
				t.Error(err)
			}
		}()
		if err := provisionDevRuntimeAccount(ctx, db, "development", parsed.String(), password); err != nil {
			t.Fatal("provisioning replay", err)
		}
		if err := provisionDevRuntimeAccount(ctx, db, "development", parsed.String(), "different_synthetic_runtime_password"); err == nil {
			t.Fatal("existing password changed")
		}
		runtimeURL := *parsed
		runtimeURL.User = url.UserPassword(devRuntimeUser, password)
		runtime, err := sqlutil.OpenPostgres(ctx, runtimeURL.String())
		if err != nil {
			t.Fatalf("runtime connect: %T", err)
		}
		defer runtime.Close()
		if err := schemaversion.Check(ctx, runtime); err != nil {
			t.Fatal(err)
		}
		if err := schemaversion.CheckRuntimePrivileges(ctx, runtime); err != nil {
			t.Fatal(err)
		}

		t.Run("new metadata upgrade preserves authentication and rejects unrelated privilege drift", func(t *testing.T) {
			// An earlier bundle grants DML by default. Newly installed owner
			// metadata inherits writes before the explicit upgrade.
			for _, statement := range []string{
				`GRANT INSERT,UPDATE,DELETE ON platform_compensation_schema_version,platform_notification_control_version,platform_kafka_dead_letter_schema_version TO platform_runtime`,
				`GRANT UPDATE,DELETE ON platform_compensation_event,platform_cancellation_effect,platform_kafka_dead_letter_action TO platform_runtime`,
				`GRANT DELETE ON platform_compensation_step,platform_cancellation_operation,platform_compensation_local_effect,platform_notification_inbox,platform_kafka_dead_letter TO platform_runtime`,
			} {
				if _, err := db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			if err := schemaversion.CheckRuntimePrivileges(ctx, runtime); !errors.Is(err, schemaversion.ErrRuntimePrivileges) {
				t.Fatal("new metadata default DML must fail the runtime boundary", err)
			}
			// Wrong credentials must not narrow even the newly installed tables.
			if err := provisionDevRuntimeAccount(ctx, db, "development", parsed.String(), "different_synthetic_runtime_password"); err == nil {
				t.Fatal("metadata upgrade accepted different credentials")
			}
			var writable bool
			if err := runtime.QueryRow(`SELECT has_table_privilege('platform_compensation_schema_version','UPDATE')`).Scan(&writable); err != nil || !writable {
				t.Fatal("wrong credentials changed grants", writable, err)
			}
			if _, err := db.Exec(`GRANT CREATE ON SCHEMA public TO platform_runtime`); err != nil {
				t.Fatal(err)
			}
			if err := provisionDevRuntimeAccount(ctx, db, "development", parsed.String(), password); err == nil {
				t.Fatal("unrelated DDL drift must not be repaired or admitted")
			}
			if err := runtime.QueryRow(`SELECT has_table_privilege('platform_compensation_schema_version','UPDATE')`).Scan(&writable); err != nil || !writable {
				t.Fatal("failed upgrade did not roll back metadata restriction", writable, err)
			}
			if _, err := db.Exec(`REVOKE CREATE ON SCHEMA public FROM platform_runtime`); err != nil {
				t.Fatal(err)
			}
			if err := provisionDevRuntimeAccount(ctx, db, "development", parsed.String(), password); err != nil {
				t.Fatal("explicit metadata upgrade rejected the original valid runtime role", err)
			}
			if err := runtime.PingContext(ctx); err != nil {
				t.Fatal("upgrade changed the original password", err)
			}
			if err := schemaversion.CheckRuntimePrivileges(ctx, runtime); err != nil {
				t.Fatal("metadata upgrade retained unsafe writes", err)
			}
			if err := provisionDevRuntimeAccount(ctx, db, "development", parsed.String(), password); err != nil {
				t.Fatal("metadata upgrade replay", err)
			}
		})

		var seq int64
		if err := runtime.QueryRow(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES('provision-fixture','accepted','{}',clock_timestamp()) RETURNING seq`).Scan(&seq); err != nil {
			t.Fatalf("runtime identity sequence: %v", err)
		}
		for _, statement := range []string{`CREATE TABLE forbidden_role_ddl(id INT)`, `CREATE TEMP TABLE forbidden_role_temp(id INT)`, `UPDATE platform_schema_version SET checksum='changed'`} {
			if _, err := runtime.Exec(statement); err == nil {
				t.Fatal("runtime DDL/version mutation accepted")
			}
		}
		var databaseOwner string
		if err := db.QueryRow(`SELECT current_user`).Scan(&databaseOwner); err != nil || databaseOwner == devRuntimeUser {
			t.Fatal("provisioner leaked session authorization")
		}
	})

	var markers int
	// Go's -run may execute only one selected child while still entering this
	// parent. Keep the marker assertion tied to the predecessor upgrades that
	// actually ran; a full parent run requires all predecessors plus current.
	wantMarkers := 1 + completedPredecessors
	if err := db.QueryRow(`SELECT COUNT(*) FROM platform_schema_version`).Scan(&markers); err != nil || markers != wantMarkers {
		t.Fatalf("version markers=%d want=%d completed_predecessors=%d err=%v", markers, wantMarkers, completedPredecessors, err)
	}
	if _, err := db.Exec(`UPDATE platform_schema_version SET checksum='drifted'`); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, config); !errors.Is(err, schemaversion.ErrIncompatible) {
		t.Fatalf("drifted migration accepted: %v", err)
	}
}
