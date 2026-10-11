package main

import (
	"bufio"
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

func assertRuntimeBrowserRunAccess(t *testing.T, ctx context.Context, client *http.Client, address, dsn string, db *sql.DB, sessionID, subject string) {
	t.Helper()
	const tenant, department, application = "session-fixture", "session-fixture-dept", "session-fixture-app"
	owner := sharedkernel.Scope{TenantID: tenant, DepartmentID: department, ApplicationID: application, AgentInstanceID: "fixture-history-installation", InstallationID: "fixture-history-installation", AgentID: "fixture-history-agent", AgentVersionID: "fixture-history-version", PrincipalType: "user", PrincipalID: subject, RunID: "fixture-owned-history-run", SessionID: "fixture-owned-history-session", AuthorizationEpoch: 1, TraceID: strings.Repeat("9", 32)}
	store, err := execution.ConnectSQLStore(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	created, err := store.Create(platformruntime.CreateRequest{ID: owner.RunID, Scope: owner, AgentVersionID: owner.AgentVersionID, IdempotencyKey: owner.RunID, Fingerprint: owner.RunID, RequestJSON: []byte(`{"input":{}}`), AgentEndpoint: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(owner.RunID, platformruntime.StatusAccepted, platformruntime.StatusRunning, created.Run.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireLease(owner.RunID, "fixture-owned-history-lease", time.Now().UTC(), time.Minute); err != nil {
		t.Fatal(err)
	}
	request := func(method, suffix, body string) *http.Request {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, "http://"+address+"/modules/execution/platform/runs/"+owner.RunID+suffix, bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		for key, value := range map[string]string{"X-Internal-Token": "gateway-fixture-0123456789abcdef0123456789abcdef", "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": subject, "X-Tenant-ID": tenant, "X-Department-ID": department, "X-Application-ID": application, "X-Authentication-Revision": "1", "X-Authentication-Session": sessionID, "Content-Type": "application/json"} {
			r.Header.Set(key, value)
		}
		return r
	}
	invoke := func(method, suffix, body string, want int) {
		t.Helper()
		resp, err := client.Do(request(method, suffix, body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			t.Fatalf("actual Run access %s %s: status=%d want=%d body=%s", method, suffix, resp.StatusCode, want, data)
		}
	}
	invoke(http.MethodGet, "", "", http.StatusForbidden)
	app := identity.ManagementScope{Type: "application", TenantID: tenant, DepartmentID: department, ApplicationID: application}
	binding := identity.RoleBinding{ID: "runtime-history-operator", SubjectID: subject, RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active", Revision: 1, SourceID: "fixture"}
	raw, _ := json.Marshal(binding)
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_role_binding(id,subject_id,role_code,role_version,tenant_id,department_id,application_id,status,revision,payload,source_hash) VALUES(?,?,?,1,?,?,?,'active',1,?,?)`), binding.ID, subject, binding.RoleCode, tenant, department, application, string(raw), strings.Repeat("6", 64)); err != nil {
		t.Fatal(err)
	}
	invoke(http.MethodGet, "", "", http.StatusForbidden)
	grant := identity.Grant{ID: "runtime-history-read", SubjectType: identity.PrincipalUser, SubjectID: subject, TenantID: tenant, DepartmentID: department, ApplicationID: application, AgentInstanceID: owner.AgentInstanceID, ResourceType: "agent_installation", ResourceID: owner.AgentInstanceID, Action: "history.read", Effect: "allow", Status: "active", Revision: 1, SourceID: "fixture", DataScope: identity.DataScope{Type: "owner"}}
	insertGrant := func(g identity.Grant, key string) {
		t.Helper()
		payload, err := json.Marshal(g)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_grant(id,tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id,action,effect,status,revision,grant_key_hash,created_at,permission_json) VALUES(?,?,?,?,?,?,?,?,?,'active',1,?,clock_timestamp(),?)`), g.ID, tenant, department, application, owner.AgentInstanceID, "user", subject, g.Action, g.Effect, key, string(payload)); err != nil {
			t.Fatal(err)
		}
	}
	insertGrant(grant, strings.Repeat("7", 64))
	// No run Grant exists: retaining history must remain independent of run.
	invoke(http.MethodGet, "", "", http.StatusOK)
	invoke(http.MethodPost, "/cancel", "{}", http.StatusForbidden)
	openStream := func() (*http.Response, *bufio.Scanner) {
		t.Helper()
		resp, err := client.Do(request(http.MethodGet, "/events", ""))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		if resp.StatusCode != http.StatusOK {
			t.Fatal("actual authorized stream rejected", resp.StatusCode)
		}
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			if scanner.Text() == "event: accepted" {
				return resp, scanner
			}
		}
		t.Fatal("actual stream did not deliver accepted event", scanner.Err())
		return nil, nil
	}
	assertStreamError := func(scanner *bufio.Scanner, code string) {
		t.Helper()
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), `"code":"`+code+`"`) {
				return
			}
		}
		t.Fatal("actual stream did not stop on current authorization", code, scanner.Err())
	}
	first, stream := openStream()
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET status='revoked',revision=revision+1 WHERE id=?`), grant.ID); err != nil {
		t.Fatal(err)
	}
	assertStreamError(stream, "PERMISSION_DENIED")
	first.Body.Close()
	invoke(http.MethodGet, "", "", http.StatusForbidden)
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET status='active',revision=revision+1 WHERE id=?`), grant.ID); err != nil {
		t.Fatal(err)
	}
	grant.ID, grant.Action = "runtime-history-cancel", "cancel"
	insertGrant(grant, strings.Repeat("8", 64))
	invoke(http.MethodPost, "/cancel", "{}", http.StatusAccepted)
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET status='revoked',revision=revision+1 WHERE id=?`), grant.ID); err != nil {
		t.Fatal(err)
	}
	invoke(http.MethodPost, "/cancel", "{}", http.StatusForbidden)
	second, stream := openStream()
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_refresh_family SET revoked=TRUE WHERE id=?`), sessionID); err != nil {
		t.Fatal(err)
	}
	assertStreamError(stream, "SESSION_INVALID")
	second.Body.Close()
	invoke(http.MethodGet, "", "", http.StatusUnauthorized)
}
