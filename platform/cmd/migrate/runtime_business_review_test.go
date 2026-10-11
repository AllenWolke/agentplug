package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"github.com/lexagent/platform/internal/sqlutil"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func assertRuntimeVersionedBusinessReview(t *testing.T, ctx context.Context, client *http.Client, address, dsn string, db *sql.DB, sessionID, reviewerID string) {
	t.Helper()
	const tenant, department, application = "session-fixture", "session-fixture-dept", "session-fixture-app"
	scope := sharedkernel.Scope{TenantID: tenant, DepartmentID: department, ApplicationID: application, AgentInstanceID: "fixture-review-installation", InstallationID: "fixture-review-installation", AgentID: "document-assistant", AgentVersionID: "fixture-review-version", PrincipalType: "user", PrincipalID: "fixture-run-initiator", RunID: "fixture-business-review-run", SessionID: "fixture-business-session", AuthorizationEpoch: 1, TraceID: strings.Repeat("f", 32)}
	store, err := execution.ConnectSQLStore(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: "fixture-review-create", Fingerprint: "fixture-review-create-fingerprint", RequestJSON: []byte(`{"operation":"run","input":{"question":"fixture question"}}`), AgentEndpoint: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(scope.RunID, platformruntime.StatusAccepted, platformruntime.StatusRunning, created.Run.Revision); err != nil {
		t.Fatal(err)
	}
	lease, err := store.AcquireLease(scope.RunID, "fixture-review-lease", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinalizeLeased(scope.RunID, platformruntime.StatusWaiting, lease.Revision, lease.LeaseToken, map[string]any{"stage": "waiting_review", "review": map[string]any{"schema_version": "agent-review/v1", "title": "Fixture review", "summary": "fixture protected review draft"}, "references": []map[string]string{{"doc_id": "fixture-document", "title": "fixture title", "content": "private citation body"}}}, map[string]any{"source": "fixture"}); err != nil {
		t.Fatal(err)
	}
	// Deliberately preserve the old roles: they must never qualify v2 review.
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET roles_json='["admin","reviewer"]' WHERE principal_type='user' AND id=?`), reviewerID); err != nil {
		t.Fatal(err)
	}
	invoke := func(method, operation, body string, want int) string {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, "http://"+address+"/modules/execution/platform/runs/"+scope.RunID+"/"+operation, bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		for key, value := range map[string]string{"X-Internal-Token": "gateway-fixture-0123456789abcdef0123456789abcdef", "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": reviewerID, "X-Tenant-ID": tenant, "X-Department-ID": department, "X-Application-ID": application, "X-Authentication-Revision": "1", "X-Authentication-Session": sessionID, "Content-Type": "application/json"} {
			r.Header.Set(key, value)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		out, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil || response.StatusCode != want {
			t.Fatalf("actual business review method=%s operation=%s status=%d want=%d body=%s error=%v", method, operation, response.StatusCode, want, out, err)
		}
		return string(out)
	}
	invoke(http.MethodGet, "review", "", http.StatusForbidden)
	app := identity.ManagementScope{Type: "application", TenantID: tenant, DepartmentID: department, ApplicationID: application}
	binding := identity.RoleBinding{ID: "runtime-business-reviewer", SubjectID: reviewerID, RoleCode: "reviewer", RoleVersion: 1, Scope: app, Status: "active", Revision: 1, SourceID: "fixture"}
	raw, _ := json.Marshal(binding)
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_role_binding(id,subject_id,role_code,role_version,tenant_id,department_id,application_id,status,revision,payload,source_hash) VALUES(?,?,?,1,?,?,?,'active',1,?,?)`), binding.ID, reviewerID, binding.RoleCode, tenant, department, application, string(raw), strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
	invoke(http.MethodGet, "review", "", http.StatusForbidden)
	grant := identity.Grant{ID: "runtime-review-content", SubjectType: identity.PrincipalUser, SubjectID: reviewerID, TenantID: tenant, DepartmentID: department, ApplicationID: application, AgentInstanceID: scope.AgentInstanceID, ResourceType: "agent_installation", ResourceID: scope.AgentInstanceID, Action: "business.content.read", Effect: "allow", Status: "active", Revision: 1, SourceID: "fixture", DataScope: identity.DataScope{Type: "explicit_set", IDs: []string{scope.RunID}}}
	insertGrant := func(g identity.Grant, key string) {
		t.Helper()
		payload, err := json.Marshal(g)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_grant(id,tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id,action,effect,status,revision,grant_key_hash,created_at,permission_json) VALUES(?,?,?,?,?,?,?,?,?,'active',1,?,clock_timestamp(),?)`), g.ID, tenant, department, application, scope.AgentInstanceID, "user", reviewerID, g.Action, g.Effect, key, string(payload)); err != nil {
			t.Fatal(err)
		}
	}
	insertGrant(grant, strings.Repeat("c", 64))
	if body := invoke(http.MethodGet, "review", "", http.StatusOK); !strings.Contains(body, "fixture protected review draft") || strings.Contains(body, "private citation body") {
		t.Fatal("actual review content or citation redaction failed", body)
	}
	decision := `{"decision":"approve","comment":"fixture explicit review"}`
	invoke(http.MethodPost, "resume", decision, http.StatusForbidden)
	if current, err := store.Get(scope.RunID); err != nil || current.Status != platformruntime.StatusWaiting || len(current.ResumeInputJSON) != 0 {
		t.Fatal("content-only permission changed actual Run", current, err)
	}
	grant.ID, grant.Action = "runtime-review-decision", "business.review"
	insertGrant(grant, strings.Repeat("e", 64))
	invoke(http.MethodPost, "resume", decision, http.StatusOK)
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET status='revoked',revision=revision+1 WHERE id=?`), grant.ID); err != nil {
		t.Fatal(err)
	}
	invoke(http.MethodPost, "resume", decision, http.StatusForbidden)
	binding.Status, binding.Revision = "revoked", 2
	raw, _ = json.Marshal(binding)
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_role_binding SET status='revoked',revision=2,payload=? WHERE id=?`), string(raw), binding.ID); err != nil {
		t.Fatal(err)
	}
	invoke(http.MethodGet, "review", "", http.StatusForbidden)
}
