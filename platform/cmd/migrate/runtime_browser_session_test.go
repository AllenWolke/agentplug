package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/identity"
)

func assertRuntimeBrowserSessionRevocation(t *testing.T, ctx context.Context, client *http.Client, address, dsn string) {
	t.Helper()
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := identity.NewSQLStore(db)
	s.SetRefreshSessionRecorder(func(context.Context, *sql.Tx, identity.RefreshSessionEvent) error { return nil })
	const tenant, department, application, subject = "session-fixture", "session-fixture-dept", "session-fixture-app", "session-fixture-user"
	for _, err := range []error{
		s.CreateTenant(ctx, identity.Tenant{ID: tenant, Code: tenant, Name: "Browser fixture", Status: "active", Revision: 1}),
		s.CreateDepartment(ctx, identity.Department{ID: department, TenantID: tenant, Code: department, Name: "Browser fixture", Status: "active", Revision: 1}),
		s.CreateApplication(ctx, identity.Application{ID: application, TenantID: tenant, DepartmentID: department, Code: application, Name: "Browser fixture", Status: "active", Revision: 1}),
		s.CreatePrincipal(ctx, identity.Principal{Type: identity.PrincipalUser, ID: subject, TenantID: tenant, IsActive: true}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	// This fixture does not test password verification; no usable password is
	// stored. The separate credential endpoint test covers its authentication.
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_local_credential(principal_id,tenant_id,department_id,application_id,display_name,password_hash,auth_revision,active,created_at,updated_at) VALUES(?,?,?,?,?,'unusable-process-fixture',1,TRUE,clock_timestamp(),clock_timestamp())`), subject, tenant, department, application, "Browser fixture"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('user',?,'v2',1,1)`), subject); err != nil {
		t.Fatal(err)
	}
	member := identity.Membership{ID: "session-fixture-member", SubjectID: subject, Scope: identity.ManagementScope{Type: "application", TenantID: tenant, DepartmentID: department, ApplicationID: application}, Status: "active", Revision: 1}
	payload, err := json.Marshal(member)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES(?,?,?,?,?,'active',1,?,?)`), member.ID, subject, tenant, department, application, string(payload), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	session, err := s.CreateRefreshSession(ctx, subject, identity.EnrollmentScope{TenantID: tenant, DepartmentID: department, ApplicationID: application}, 1)
	if err != nil {
		t.Fatal(err)
	}
	boundaryClient := *client
	boundaryClient.Timeout = 15 * time.Second
	invoke := func(path string, want int) string {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for key, value := range map[string]string{"X-Internal-Token": "gateway-fixture-0123456789abcdef0123456789abcdef", "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": subject, "X-Tenant-ID": tenant, "X-Department-ID": department, "X-Application-ID": application, "X-Authentication-Revision": "1", "X-Authentication-Session": session.SessionID} {
			r.Header.Set(key, value)
		}
		resp, err := boundaryClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want || (resp.Header.Get("X-Authentication-Error") == "access_token_invalid") != (want == 401) {
			t.Fatalf("actual runtime session boundary path=%s status=%d want=%d", path, resp.StatusCode, want)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	paths := []string{"/modules/identity/me/permissions", "/modules/catalog/available"}
	for _, path := range paths {
		invoke(path, http.StatusOK)
	}
	// The authenticated SQL-backed directories are the same fixed catalogs
	// consumed by the UI and the authorization planner, not a second projection.
	for _, directory := range []struct {
		path  string
		items any
	}{
		{"permission-actions", identity.BuiltinPermissionActions()},
		{"role-definitions", identity.BuiltinRoleDefinitions()},
		{"identity-presets", identity.BuiltinIdentityPresets()},
	} {
		body := invoke("/modules/identity/"+directory.path, http.StatusOK)
		var response struct {
			Items json.RawMessage `json:"items"`
		}
		want, err := json.Marshal(directory.items)
		if err != nil || json.Unmarshal([]byte(body), &response) != nil || string(response.Items) != string(want) {
			t.Fatal("actual process directory differs from server catalog", directory.path, body, err)
		}
	}
	invoke("/modules/audit/events", http.StatusForbidden)
	auditStore := audit.NewSQLStore(db)
	for i, eventTenant := range []string{tenant, "foreign-fixture-tenant"} {
		if err := auditStore.Record(ctx, audit.Event{ID: fmt.Sprintf("runtime-metadata-%d", i), TenantID: eventTenant, DepartmentID: department, ApplicationID: application, ActorID: subject, AggregateType: "run", AggregateID: "fixture-task", TraceID: "fixture-trace", Action: "run.completed", Outcome: "success", Summary: "private runtime fixture content", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	binding := identity.RoleBinding{ID: "runtime-auditor-binding", SubjectID: subject, RoleCode: "auditor", RoleVersion: 1, Scope: identity.ManagementScope{Type: "application", TenantID: tenant, DepartmentID: department, ApplicationID: application}, Status: "active", Revision: 1, SourceID: "fixture"}
	raw, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_role_binding(id,subject_id,role_code,role_version,tenant_id,department_id,application_id,status,revision,payload,source_hash) VALUES(?,?,?,1,?,?,?,'active',1,?,?)`), binding.ID, subject, "auditor", tenant, department, application, string(raw), strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	assertMetadata := func(path string, total int64) {
		t.Helper()
		body := invoke(path, http.StatusOK)
		var page audit.Page
		if json.Unmarshal([]byte(body), &page) != nil || page.Total != total || !page.MetadataOnly || strings.Contains(body, "private runtime fixture content") {
			t.Fatal("actual audit metadata qualification/scope/content boundary failed", body)
		}
	}
	assertMetadata("/modules/audit/events?trace_id=fixture-trace", 1)
	invoke("/modules/audit/events?scope_type=global", http.StatusForbidden)
	invoke("/modules/audit/events?scope_type=tenant&tenant_id="+tenant, http.StatusForbidden)
	binding.Scope = identity.ManagementScope{Type: "global"}
	raw, _ = json.Marshal(binding)
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_role_binding SET tenant_id='',department_id='',application_id='',payload=? WHERE id=?`), string(raw), binding.ID); err != nil {
		t.Fatal(err)
	}
	assertMetadata("/modules/audit/events?scope_type=global&trace_id=fixture-trace", 2)
	binding.Status, binding.Revision = "revoked", 2
	raw, _ = json.Marshal(binding)
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_role_binding SET status='revoked',revision=2,payload=? WHERE id=?`), string(raw), binding.ID); err != nil {
		t.Fatal(err)
	}
	invoke("/modules/audit/events?scope_type=global", http.StatusForbidden)
	invoke("/modules/audit/events", http.StatusForbidden)
	assertRuntimeVersionedBusinessReview(t, ctx, &boundaryClient, address, dsn, db, session.SessionID, subject)
	assertRuntimeConversationBinding(t, ctx, &boundaryClient, address, db, session.SessionID, subject)
	assertRuntimeConversationAccess(t, ctx, &boundaryClient, address, db, session.SessionID, subject)
	assertRuntimeBrowserRunAccess(t, ctx, &boundaryClient, address, dsn, db, session.SessionID, subject)
	assertRuntimeOIDCStepUp(t, ctx, &boundaryClient, address, db)
	command, err := json.Marshal(map[string]string{"refresh_token": session.RefreshToken})
	if err != nil {
		t.Fatal(err)
	}
	revoke, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+address+"/modules/identity/internal/refresh-sessions:revoke", bytes.NewReader(command))
	if err != nil {
		t.Fatal(err)
	}
	revoke.Header.Set("X-Internal-Token", "gateway-fixture-0123456789abcdef0123456789abcdef")
	revoke.Header.Set("Content-Type", "application/json")
	resp, err := boundaryClient.Do(revoke)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal("actual runtime session revoke failed", resp.StatusCode)
	}
	for _, path := range paths {
		invoke(path, http.StatusUnauthorized)
	}
}
