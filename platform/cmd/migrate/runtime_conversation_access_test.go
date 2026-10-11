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
	"time"

	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/identity"
)

func assertRuntimeConversationAccess(t *testing.T, ctx context.Context, client *http.Client, address string, db *sql.DB, sessionID, subject string) {
	t.Helper()
	const tenant, department, application, installation = "session-fixture", "session-fixture-dept", "session-fixture-app", "fixture-conversation-installation"
	store := conversation.NewSQLStore(db)
	scope := conversation.Scope{TenantID: tenant, DepartmentID: department, ApplicationID: application, PrincipalType: "user", PrincipalID: subject}
	for i, owner := range []string{subject, subject, "fixture-other-owner", subject, subject} {
		actor := scope
		actor.PrincipalID = owner
		instance := installation
		if i == 3 {
			instance = "fixture-other-installation"
		}
		if i == 4 {
			instance = ""
		}
		id := fmt.Sprintf("fixture-readable-session-%d", i)
		if err := store.CreateSession(ctx, actor, conversation.Session{Summary: conversation.Summary{ID: id, Kind: "qa", AgentID: "fixture-conversation-agent", AgentVersionID: "fixture-conversation-version", InstallationID: instance, Title: fmt.Sprintf("fixture history %d", i), Status: "active", CanContinue: true}}); err != nil {
			t.Fatal(err)
		}
		if err := store.AppendMessage(ctx, actor, conversation.Message{ID: id + "-message", SessionID: id, Role: "assistant", Content: "private history answer " + id}); err != nil {
			t.Fatal(err)
		}
	}
	invoke := func(method, path string, body any, want int) string {
		t.Helper()
		raw, _ := json.Marshal(body)
		r, err := http.NewRequestWithContext(ctx, method, "http://"+address+"/modules/conversation"+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range map[string]string{"X-Internal-Token": "gateway-fixture-0123456789abcdef0123456789abcdef", "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": subject, "X-Tenant-ID": tenant, "X-Department-ID": department, "X-Application-ID": application, "X-Authentication-Revision": "1", "X-Authentication-Session": sessionID, "Content-Type": "application/json"} {
			r.Header.Set(k, v)
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil || resp.StatusCode != want {
			t.Fatalf("conversation grant %s %s: status=%d want=%d body=%s error=%v", method, path, resp.StatusCode, want, out, err)
		}
		return string(out)
	}
	assertPage := func(path string, total int64, size int) {
		t.Helper()
		// Other real-process fixtures also own valid sessions in this application.
		// Narrow this test's source rows with the public query before COUNT/LIMIT.
		separator := "?"
		if strings.Contains(path, "?") {
			separator = "&"
		}
		raw := invoke("GET", path+separator+"text=fixture%20history", nil, 200)
		var page conversation.Page
		if json.Unmarshal([]byte(raw), &page) != nil || page.Total != total || len(page.Items) != size {
			t.Fatal("unauthorized count/pagination", raw)
		}
		for _, item := range page.Items {
			if item.ID == "fixture-readable-session-1" || item.InstallationID != installation || !item.Permissions["history.read"] || item.CanContinue {
				t.Fatal("bad authorization projection", raw)
			}
		}
	}
	assertPage("/sessions?page_size=1", 0, 0)
	invoke("GET", "/sessions/fixture-readable-session-0/messages", nil, 403)
	grant := identity.Grant{ID: "fixture-conversation-owner-read", SubjectType: identity.PrincipalUser, SubjectID: subject, TenantID: tenant, DepartmentID: department, ApplicationID: application, AgentInstanceID: installation, ResourceType: "agent_installation", ResourceID: installation, Action: "history.read", Effect: "allow", Status: "active", Revision: 1, SourceID: "fixture", DataScope: identity.DataScope{Type: "owner"}}
	writeGrant := func(g identity.Grant) {
		t.Helper()
		payload, err := json.Marshal(g)
		if err != nil {
			t.Fatal(err)
		}
		key := fmt.Sprintf("%x", sha256.Sum256([]byte(g.ID)))
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_grant(id,tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id,action,effect,status,revision,grant_key_hash,created_at,permission_json) VALUES(?,?,?,?,?,?,?,?,?,?,1,?,clock_timestamp(),?) ON CONFLICT(id) DO UPDATE SET status=EXCLUDED.status,revision=platform_identity_grant.revision+1,permission_json=EXCLUDED.permission_json`), g.ID, tenant, department, application, installation, "user", subject, g.Action, g.Effect, g.Status, key, string(payload)); err != nil {
			t.Fatal(err)
		}
	}
	writeGrant(grant)
	deny := grant
	deny.ID = "fixture-conversation-deny-read"
	deny.Effect = "deny"
	deny.DataScope = identity.DataScope{Type: "explicit_set", IDs: []string{"fixture-readable-session-1"}}
	writeGrant(deny)
	assertPage("/sessions?page_size=1", 1, 1)
	invoke("GET", "/sessions/fixture-readable-session-0/messages", nil, 200)
	invoke("GET", "/sessions/fixture-readable-session-1/messages", nil, 403)
	invoke("GET", "/sessions/fixture-readable-session-2/messages", nil, 403)
	invoke("GET", "/sessions/fixture-readable-session-4/messages", nil, 403)
	invoke("POST", "/sessions/fixture-readable-session-0/resume", map[string]any{}, 403)
	invoke("POST", "/sessions/fixture-readable-session-0/shares", map[string]any{"ttl_seconds": 60}, 403)
	invoke("POST", "/exports", map[string]any{"session_ids": []string{"fixture-readable-session-0"}}, 403)
	foreign := grant
	foreign.ID = "fixture-conversation-explicit-read"
	foreign.DataScope = identity.DataScope{Type: "explicit_set", IDs: []string{"fixture-readable-session-2"}}
	writeGrant(foreign)
	assertPage("/sessions?view=managed&page_size=1", 2, 1)
	assertPage("/sessions?view=mine&page_size=1", 1, 1)
	if body := invoke("GET", "/sessions/fixture-readable-session-2/messages", nil, 200); !strings.Contains(body, "private history answer") {
		t.Fatal("authorized foreign content missing", body)
	}
	invoke("GET", "/managed-search?tenant_id=foreign", nil, 403)
	invoke("GET", "/sessions/fixture-readable-session-0?tenant_id=foreign", nil, 200) // Header scope remains authoritative.
	shareGrant := grant
	shareGrant.ID = "fixture-conversation-share"
	shareGrant.Action = "history.share"
	writeGrant(shareGrant)
	var share conversation.Share
	if body := invoke("POST", "/sessions/fixture-readable-session-0/shares", map[string]any{"ttl_seconds": 60}, 201); json.Unmarshal([]byte(body), &share) != nil || share.Token == "" {
		t.Fatal("valid share rejected", body)
	}
	publicRead := func(want int) {
		t.Helper()
		// Anonymous browser reads still pass through the independently authenticated
		// gateway; the opaque share token replaces human session context, not the
		// gateway's transport credential.
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/modules/conversation/shares/"+share.Token, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("X-Internal-Token", "gateway-fixture-0123456789abcdef0123456789abcdef")
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if readErr != nil || resp.StatusCode != want {
			t.Fatalf("public share current grant: status=%d want=%d body=%s error=%v", resp.StatusCode, want, out, readErr)
		}
	}
	publicRead(200)
	shareGrant.Status = "revoked"
	writeGrant(shareGrant)
	publicRead(404)
	exportGrant := grant
	exportGrant.ID = "fixture-conversation-export"
	exportGrant.Action = "history.export"
	writeGrant(exportGrant)
	var export conversation.Export
	if body := invoke("POST", "/exports", map[string]any{"session_ids": []string{"fixture-readable-session-0"}}, 201); json.Unmarshal([]byte(body), &export) != nil || export.ID == "" {
		t.Fatal("valid export rejected", body)
	}
	invoke("GET", "/exports/"+export.ID, nil, 200)
	exportGrant.Status = "revoked"
	writeGrant(exportGrant)
	invoke("GET", "/exports/"+export.ID, nil, 403)
	grant.Status = "revoked"
	writeGrant(grant)
	assertPage("/sessions?view=mine", 0, 0)
	invoke("GET", "/sessions/fixture-readable-session-0/messages", nil, 403)
	foreign.ExpiresAt = func() *time.Time { expired := time.Now().Add(-time.Second); return &expired }()
	writeGrant(foreign)
	assertPage("/sessions?view=managed", 0, 0)
}
