package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/bootstrap"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/notification"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestPostgresIndexKnowledgeManagementControl(t *testing.T) {
	migrationDSN := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if migrationDSN == "" {
		t.Skip("isolated PostgreSQL required")
	}
	uri, err := url.Parse(migrationDSN)
	if err != nil || uri.Hostname() != "127.0.0.1" || uri.Path != "/knowledge_test" {
		t.Fatal("owned loopback fixture required")
	}
	ctx := context.Background()
	admin, err := sql.Open("pgx", migrationDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	runtimeDSN := os.Getenv("KNOWLEDGE_TEST_POSTGRES_DSN")
	db, err := sql.Open("pgx", runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	iamAdmin := identity.NewSQLStore(admin)
	for _, ensure := range []func(context.Context) error{iamAdmin.EnsureSchema, notification.NewSQLStore(admin).EnsureSchema, audit.NewSQLStore(admin).EnsureSchema, func(ctx context.Context) error { return execution.MigrateSchema(ctx, admin) }} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	id := fmt.Sprintf("knowledge-control-%d", time.Now().UnixNano())
	for _, err := range []error{
		iamAdmin.CreateTenant(ctx, identity.Tenant{ID: id, Code: id, Name: "fixture", Status: "active", Revision: 1}),
		iamAdmin.CreateDepartment(ctx, identity.Department{ID: id, TenantID: id, Code: id, Name: "fixture", Status: "active", Revision: 1}),
		iamAdmin.CreateApplication(ctx, identity.Application{ID: id, TenantID: id, DepartmentID: id, Code: id, Name: "fixture", Status: "active", Revision: 1}),
		iamAdmin.CreatePrincipal(ctx, identity.Principal{ID: id, Type: identity.PrincipalUser, TenantID: id, IsActive: true}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('user',$1,'v2',1,1)`, id); err != nil {
		t.Fatal(err)
	}
	binding := identity.RoleBinding{ID: id, SubjectID: id, RoleCode: "super_admin", RoleVersion: 1, Scope: identity.ManagementScope{Type: "global"}, Status: "active", Revision: 1, SourceID: "isolated-fixture"}
	setBinding := func() {
		t.Helper()
		raw, err := json.Marshal(binding)
		if err != nil {
			t.Fatal(err)
		}
		_, err = admin.Exec(`INSERT INTO platform_identity_role_binding(id,subject_id,role_code,role_version,tenant_id,department_id,application_id,status,revision,payload,source_hash) VALUES($1,$1,'super_admin',1,'','','',$2,1,$3,'fixture') ON CONFLICT(id) DO UPDATE SET status=EXCLUDED.status,payload=EXCLUDED.payload`, id, binding.Status, string(raw))
		if err != nil {
			t.Fatal(err)
		}
	}
	setBinding()
	outbox := notification.NewSQLStore(db)
	fault := &releaseAuditFault{recorder: audit.NewSQLStoreWithOutbox(db, outbox)}
	ex, err := execution.OpenSQLStore(ctx, "pgx", runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer ex.Close()
	p := knowledgePersistence{db: db, iam: identity.NewSQLStore(db), execution: ex, audit: fault}
	actor := sharedkernel.Scope{TenantID: id, DepartmentID: id, ApplicationID: id, PrincipalID: id, PrincipalType: "user", TraceID: "management-trace", AgentID: "indexer", AgentInstanceID: "indexer", AgentVersionID: "v1", InstallationID: "indexer", SessionID: id, RunID: id, AuthorizationEpoch: 1}
	scope := knowledge.ProjectionScope{TenantID: id, DepartmentID: id, ApplicationID: id, KnowledgeID: "docs"}
	source := p.source(actor)
	// Authorization retains the common IAM lock throughout the business tx.
	protected, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.authorize(ctx, protected, actor, scope); err != nil {
		protected.Rollback()
		t.Fatal(err)
	}
	contender, err := admin.BeginTx(ctx, nil)
	if err != nil {
		protected.Rollback()
		t.Fatal(err)
	}
	var guardRevision uint64
	err = contender.QueryRowContext(ctx, `SELECT revision FROM platform_identity_continuity_guard WHERE id=1 FOR UPDATE NOWAIT`).Scan(&guardRevision)
	contender.Rollback()
	var state interface{ SQLState() string }
	if !errors.As(err, &state) || state.SQLState() != "55P03" {
		protected.Rollback()
		t.Fatal("IAM mutation not fenced", err)
	}
	protected.Rollback()
	command := knowledge.SourceChange{DocumentID: "doc", ActorPrincipalID: id, IdempotencyKey: "create", Body: "private-source-contents", ACL: knowledge.DocumentACL{OwnerPrincipalID: id}}
	receipt, err := source.Change(ctx, scope, command)
	if err != nil || receipt.SourceRevision != 1 {
		t.Fatal("authorized source", err)
	}
	count := func(table string) int {
		t.Helper()
		var n int
		if err := admin.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE tenant_id=$1`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count("platform_audit_event") != 1 || count("platform_notification_outbox") != 1 {
		t.Fatal("source audit/outbox missing")
	}
	if _, err := source.Change(ctx, scope, command); err != nil {
		t.Fatal("authorized retry", err)
	}
	if count("platform_audit_event") != 1 {
		t.Fatal("retry audited twice")
	}
	binding.Status = "revoked"
	setBinding()
	if _, err := source.Change(ctx, scope, command); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatal("revoked replay accepted", err)
	}
	binding.Status = "active"
	expires := time.Now().Add(-time.Second)
	binding.ExpiresAt = &expires
	setBinding()
	if _, err := source.Change(ctx, scope, command); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatal("expired management accepted", err)
	}
	binding.ExpiresAt = nil
	setBinding()
	if _, err := admin.Exec(`UPDATE platform_identity_principal SET active=FALSE WHERE id=$1 AND principal_type='user'`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Change(ctx, scope, command); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatal("disabled manager accepted", err)
	}
	if _, err := admin.Exec(`UPDATE platform_identity_principal SET active=TRUE WHERE id=$1 AND principal_type='user'`, id); err != nil {
		t.Fatal(err)
	}
	wrongActor := command
	wrongActor.ActorPrincipalID = "other-user"
	if _, err := source.Change(ctx, scope, wrongActor); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatal("forged source actor accepted", err)
	}
	next := command
	next.IdempotencyKey = "update"
	next.ExpectedSourceRevision = 1
	next.ExpectedDocumentVersion = 1
	next.Body = "private-update-contents"
	fault.fail = true
	if _, err := source.Change(ctx, scope, next); err == nil {
		t.Fatal("audit/outbox fault committed source")
	}
	fault.fail = false
	snapshot, err := source.Snapshot(ctx, scope, 10)
	if err != nil || snapshot.Revision != 1 || count("platform_audit_event") != 1 || count("platform_notification_outbox") != 1 {
		t.Fatal("source audit rollback", err)
	}
	index := p.index(actor)
	plan, err := index.Prepare(ctx, scope, knowledge.IndexConfig{EmbeddingModelVersion: "fixture-v1", Dimensions: 2, WindowRunes: 8, OverlapRunes: 2, MaximumDocuments: 10, MaximumChunks: 100}, false)
	if err != nil {
		t.Fatal(err)
	}
	vectors := map[string][]float32{}
	for _, chunk := range plan.RequiredChunks() {
		vectors[chunk.ID] = []float32{1, .5}
	}
	if err := index.Build(ctx, plan, "generation", vectors); err != nil {
		t.Fatal(err)
	}
	binding.Status = "revoked"
	setBinding()
	if _, err := index.Publish(ctx, plan, "generation"); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatal("revoked publish accepted", err)
	}
	binding.Status = "active"
	setBinding()
	if _, err := index.Publish(ctx, plan, "generation"); err != nil {
		t.Fatal("authorized publish", err)
	}
	if _, err := ex.Create(platformruntime.CreateRequest{ID: id, Scope: actor, AgentVersionID: "v1", IdempotencyKey: "index", Fingerprint: "fixture"}); err != nil {
		t.Fatal(err)
	}
	claimed, err := ex.AcquireLease(id, "owner-token", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	run, err := ex.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := plan.Checkpoint(vectors)
	if err != nil {
		t.Fatal(err)
	}
	checkpoints := p.checkpoints(scope)
	if _, err := checkpoints.Save(ctx, actor, "docs", run.LeaseToken, run.Revision, 0, raw); err != nil {
		t.Fatal("authorized checkpoint", err)
	}
	if count("platform_audit_event") != 3 || count("platform_notification_outbox") != 3 {
		t.Fatal("publish/checkpoint audit missing")
	}
	binding.Status = "revoked"
	setBinding()
	if _, err := checkpoints.Load(ctx, actor, "docs", run.LeaseToken, run.Revision); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatal("revoked checkpoint read", err)
	}
	if _, err := checkpoints.Save(ctx, actor, "docs", run.LeaseToken, run.Revision, 0, raw); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatal("revoked checkpoint replay", err)
	}
	var leaked int
	if err := admin.QueryRow(`SELECT COUNT(*) FROM platform_audit_event WHERE tenant_id=$1 AND (summary LIKE '%private-source-contents%' OR summary LIKE '%private-update-contents%' OR summary LIKE '%owner-token%')`, id).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal("audit leaked source or token", err)
	}
	// Real HTTP transport and current SQL browser-session validation. Session
	// facts are seeded here; this is not a password-login/refresh-rotation test.
	binding.Status = "active"
	setBinding()
	member := identity.Membership{ID: id, SubjectID: id, Scope: identity.ManagementScope{Type: "application", TenantID: id, DepartmentID: id, ApplicationID: id}, Status: "active", Revision: 1}
	memberJSON, err := json.Marshal(member)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES($1,$1,$1,$1,$1,'active',1,$2,$1)`, id, string(memberJSON)); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(`INSERT INTO platform_identity_local_credential(principal_id,tenant_id,department_id,application_id,display_name,password_hash,auth_revision,active,created_at,updated_at) VALUES($1,$1,$1,$1,'HTTP fixture','not-a-login-password',1,TRUE,clock_timestamp(),clock_timestamp())`, id); err != nil {
		t.Fatal(err)
	}
	family := fmt.Sprintf("%064x", time.Now().UnixNano())
	if _, err := admin.Exec(`INSERT INTO platform_identity_refresh_family(id,principal_id,tenant_id,department_id,application_id,auth_revision,created_at,expires_at,revoked) VALUES($1,$2,$2,$2,$2,1,clock_timestamp(),clock_timestamp()+INTERVAL '1 hour',FALSE)`, family, id); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(`INSERT INTO platform_identity_refresh_token(token_hash,family_id,used,created_at) VALUES($1,$1,FALSE,clock_timestamp())`, family); err != nil {
		t.Fatal(err)
	}
	const runtimeToken = "runtime-knowledge-fixture-0123456789abcdef"
	const gatewayToken = "gateway-knowledge-fixture-0123456789abcdef"
	registry := bootstrap.NewModuleRegistry()
	if err := registry.Register(knowledge.NewControlModule(runtimeToken, knowledgeControl{persistence: p})); err != nil {
		t.Fatal(err)
	}
	handler := bootstrap.BrowserBoundary(bootstrap.BrowserSessionBoundary(registry.Handler(), identityBrowserSessionCheck(p.iam)), gatewayToken, runtimeToken)
	server := httptest.NewServer(handler)
	defer server.Close()
	request := func(method, path string, body []byte, token string) (int, []byte) {
		t.Helper()
		r, err := http.NewRequest(method, server.URL+"/modules/knowledge"+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		for key, value := range map[string]string{"X-Internal-Token": token, "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": id, "X-Tenant-ID": id, "X-Department-ID": id, "X-Application-ID": id, "X-Trace-ID": "HTTP-knowledge-trace", "X-Authentication-Session": family, "X-Authentication-Revision": "1"} {
			r.Header.Set(key, value)
		}
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("source response browser cache enabled")
		}
		return response.StatusCode, raw
	}
	if status, _ := request("GET", "/sources/docs", nil, runtimeToken); status != 403 {
		t.Fatal("runtime secret authenticated human", status)
	}
	if status, raw := request("GET", "/sources/docs", nil, gatewayToken); status != 200 || !bytes.Contains(raw, []byte(`"schema_version":"knowledge-source-snapshot/v1"`)) {
		t.Fatal("authorized HTTP snapshot", status)
	}
	httpBody := []byte(`{"expected_source_revision":1,"expected_document_version":0,"idempotency_key":"http-create","body":"HTTP teaching document","acl":{"owner_principal_id":"` + id + `"}}`)
	if status, _ := request("PUT", "/sources/docs/documents/http-doc", httpBody, gatewayToken); status != 200 {
		t.Fatal("HTTP source mutation", status)
	}
	if status, _ := request("PUT", "/sources/docs/documents/http-doc", httpBody, gatewayToken); status != 200 {
		t.Fatal("HTTP retry", status)
	}
	if count("platform_audit_event") != 4 || count("platform_notification_outbox") != 4 {
		t.Fatal("HTTP atomic records/replay")
	}
	if status, _ := request("PUT", "/sources/docs/documents/http-doc", []byte(`{"actor_principal_id":"forged"}`), gatewayToken); status != 400 {
		t.Fatal("HTTP caller identity field accepted", status)
	}
	if status, _ := request("PUT", "/sources/docs/documents/http-doc", append(httpBody, []byte(` {}`)...), gatewayToken); status != 400 {
		t.Fatal("trailing HTTP body accepted", status)
	}
	if status, _ := request("GET", "/sources/docs?limit=0", nil, gatewayToken); status != 400 {
		t.Fatal("invalid snapshot limit accepted", status)
	}
	binding.Status = "revoked"
	setBinding()
	if status, _ := request("GET", "/sources/docs", nil, gatewayToken); status != 403 {
		t.Fatal("revoked HTTP snapshot", status)
	}
	if status, _ := request("PUT", "/sources/docs/documents/http-doc", httpBody, gatewayToken); status != 403 {
		t.Fatal("revoked HTTP replay", status)
	}
	if _, err := admin.Exec(`UPDATE platform_identity_refresh_family SET revoked=TRUE WHERE id=$1`, family); err != nil {
		t.Fatal(err)
	}
	if status, _ := request("GET", "/sources/docs", nil, gatewayToken); status != 401 {
		t.Fatal("revoked authentication session accepted", status)
	}
}
