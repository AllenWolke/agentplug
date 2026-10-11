package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Opt-in scale acceptance uses a newly created fixture database; normal unit
// runs do not seed large datasets or connect to a development database.
func TestSQLPermissionScaleAcceptance(t *testing.T) {
	if os.Getenv("PERMISSION_SCALE_TEST") != "1" {
		t.Skip("explicit scale fixture opt-in required")
	}
	f := newAdministratorFixture(t)
	f.db.SetMaxOpenConns(24)
	f.db.SetMaxIdleConns(24)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	f.ctx = ctx
	appointment := f.authenticate(t, 0, f.command(2, "scale-permission-admin"))
	if _, err := f.store.AppointAdministrator(ctx, f.actors[0], appointment); err != nil {
		t.Fatal(err)
	}
	scope := appointment.Scope
	const users = 10000
	t.Log("seeding 10,000 additional users and 100,000 bindings/grants")
	seedStart := time.Now()
	for start := 0; start < users; start += 250 {
		principals, modes, members, bindings, grants := [][]any{}, [][]any{}, [][]any{}, [][]any{}, [][]any{}
		for i := start; i < start+250; i++ {
			id := fmt.Sprintf("scale-user-%05d", i)
			principals = append(principals, []any{id, "user", scope.TenantID, "[]", "[]", true, 1, f.now})
			modes = append(modes, []any{"user", id, "v2", 1, 1})
			member := Membership{ID: id + "-member", SubjectID: id, Scope: scope, Status: "active", Revision: 1}
			raw, _ := json.Marshal(member)
			members = append(members, []any{member.ID, id, scope.TenantID, scope.DepartmentID, scope.ApplicationID, "active", 1, string(raw), permissionHash([]byte(member.ID))})
			for j := 0; j < 9; j++ {
				b := RoleBinding{ID: fmt.Sprintf("%s-binding-%d", id, j), SubjectID: id, RoleCode: "operator", RoleVersion: 1, Scope: scope, Status: "active", Revision: 1, SourceID: fmt.Sprintf("source-%d", j)}
				raw, _ := json.Marshal(b)
				source, _ := json.Marshal([]any{b.SubjectID, b.RoleCode, b.RoleVersion, b.Scope, b.SourceID})
				bindings = append(bindings, []any{b.ID, id, b.RoleCode, 1, scope.TenantID, scope.DepartmentID, scope.ApplicationID, "active", 1, string(raw), permissionHash(source)})
			}
			g := Grant{ID: id + "-grant", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentInstanceID: "installation-test", SubjectType: PrincipalUser, SubjectID: id, Action: "run", Effect: "allow", Status: "active", Revision: 1, ResourceType: "agent_installation", ResourceID: "installation-test", DataScope: DataScope{Type: "owner"}, SourceID: "scale"}
			raw, _ = json.Marshal(g)
			grants = append(grants, []any{g.ID, g.TenantID, g.DepartmentID, g.ApplicationID, g.AgentInstanceID, g.SubjectType, g.SubjectID, g.Action, g.Effect, g.Status, 1, grantKeyHash(g), f.now, string(raw)})
		}
		seedPermissionScaleBatch(t, ctx, f.db, "INSERT INTO platform_identity_principal(id,principal_type,tenant_id,roles_json,groups_json,active,revision,created_at) VALUES ", principals)
		seedPermissionScaleBatch(t, ctx, f.db, "INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES ", modes)
		seedPermissionScaleBatch(t, ctx, f.db, "INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES ", members)
		seedPermissionScaleBatch(t, ctx, f.db, "INSERT INTO platform_identity_role_binding(id,subject_id,role_code,role_version,tenant_id,department_id,application_id,status,revision,payload,source_hash) VALUES ", bindings)
		seedPermissionScaleBatch(t, ctx, f.db, "INSERT INTO platform_identity_grant(id,tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id,action,effect,status,revision,grant_key_hash,created_at,permission_json) VALUES ", grants)
	}
	t.Logf("seed finished in %s", time.Since(seedStart))
	// Save cold planner evidence without ANALYZE, warmup, or changing thresholds.
	oldArgs := []any{scope.TenantID, "", "", scope.DepartmentID, scope.DepartmentID, scope.ApplicationID, scope.ApplicationID, f.now, f.now}
	oldCount := `SELECT COUNT(*) FROM platform_identity_principal p WHERE p.principal_type='user' AND p.tenant_id=? AND (?='' OR p.id=?) AND (?='' OR EXISTS (SELECT 1 FROM platform_identity_membership m WHERE m.subject_id=p.id AND m.tenant_id=p.tenant_id AND m.department_id=? AND (?='' OR m.application_id=?) AND m.status='active' AND (m.starts_at IS NULL OR m.starts_at<=?) AND (m.expires_at IS NULL OR m.expires_at>?)))`
	where, countArgs := permissionPrincipalWhere(scope, "", f.now)
	plans := map[string]json.RawMessage{}
	for name, query := range map[string]struct {
		sql  string
		args []any
	}{
		"previous_optional_scope_disjunction": {oldCount, oldArgs},
		"current_fixed_scope_predicates":      {`SELECT COUNT(*) FROM platform_identity_principal p WHERE ` + where, countArgs},
	} {
		var raw []byte
		if err := f.db.QueryRowContext(ctx, sqlutil.Bind(`EXPLAIN (FORMAT JSON) `+query.sql), query.args...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		plans[name] = json.RawMessage(raw)
	}
	f.store.SetPermissionResourceResolver(permissionTestResourceResolver{})
	server := httptest.NewServer(NewModule(f.store, "scale-fixture-internal-token").Handler())
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	const concurrency = 20
	const perWorker = 25
	listSamples, decisionSamples := make([]time.Duration, 0, concurrency*perWorker), make([]time.Duration, 0, concurrency*perWorker)
	var mu sync.Mutex
	var wg sync.WaitGroup
	failures := []string{}
	start := make(chan struct{})
	for worker := 0; worker < concurrency; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start
			for sample := 0; sample < perWorker; sample++ {
				r, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/principals?principal_type=user&page=1&page_size=20", nil)
				r.Header.Set("X-Internal-Token", "scale-fixture-internal-token")
				r.Header.Set("X-Browser-Module", "1")
				r.Header.Set("X-Tenant-ID", scope.TenantID)
				r.Header.Set("X-Department-ID", scope.DepartmentID)
				r.Header.Set("X-Application-ID", scope.ApplicationID)
				r.Header.Set("X-Principal-Type", "user")
				r.Header.Set("X-Principal-ID", f.actors[2].PrincipalID)
				begin := time.Now()
				response, err := client.Do(r)
				if err == nil {
					_, err = io.Copy(io.Discard, response.Body)
					response.Body.Close()
					if response.StatusCode != http.StatusOK {
						err = fmt.Errorf("list HTTP %d", response.StatusCode)
					}
				}
				elapsed := time.Since(begin)
				mu.Lock()
				listSamples = append(listSamples, elapsed)
				if err != nil {
					failures = append(failures, err.Error())
				}
				mu.Unlock()
				id := fmt.Sprintf("scale-user-%05d", (worker*perWorker+sample)%users)
				begin = time.Now()
				decision, err := f.store.ResolvePermission(ctx, PrincipalUser, id, PermissionQuery{Action: "run", Scope: scope, ResourceType: "agent_installation", ResourceID: "installation-test"})
				elapsed = time.Since(begin)
				mu.Lock()
				decisionSamples = append(decisionSamples, elapsed)
				if err != nil {
					failures = append(failures, err.Error())
				} else if !decision.Allowed {
					failures = append(failures, "permission unexpectedly denied: "+decision.Reason)
				}
				mu.Unlock()
			}
		}(worker)
	}
	close(start)
	wg.Wait()
	var principalCount, bindingCount, grantCount int
	for _, query := range []struct {
		sql   string
		count *int
	}{{`SELECT COUNT(*) FROM platform_identity_principal`, &principalCount}, {`SELECT COUNT(*) FROM platform_identity_role_binding`, &bindingCount}, {`SELECT COUNT(*) FROM platform_identity_grant`, &grantCount}} {
		if err := f.db.QueryRowContext(ctx, sqlutil.Bind(query.sql)).Scan(query.count); err != nil {
			t.Fatal(err)
		}
	}
	listP95, decisionP95 := scalePercentile(listSamples, 95), scalePercentile(decisionSamples, 95)
	evidence := map[string]any{"cold_count_plans": plans, "users": principalCount, "role_bindings": bindingCount, "resource_grants": grantCount, "concurrency": concurrency, "samples_per_operation": len(listSamples), "list_p95_ms": float64(listP95) / float64(time.Millisecond), "decision_p95_ms": float64(decisionP95) / float64(time.Millisecond), "list_samples_ms": scaleMilliseconds(listSamples), "decision_samples_ms": scaleMilliseconds(decisionSamples), "errors": failures, "recorded_at": time.Now().UTC(), "list_measurement": "Identity HTTP handler, including trusted-context auth, live SQL policy, scoped count/page and response body", "decision_measurement": "local SQL repository with repeatable-read snapshot and live organization validation; installation resolver uses deterministic fixture", "limitations": "isolated PostgreSQL fixture; production deployment, browser and cross-module acceptance remain separate", "passed": len(failures) == 0 && listP95 <= time.Second && decisionP95 <= 100*time.Millisecond}
	raw, _ := json.MarshalIndent(evidence, "", "  ")
	if path := os.Getenv("PERMISSION_SCALE_EVIDENCE_PATH"); path != "" {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("users=%d bindings=%d grants=%d concurrent=%d samples=%d list P95=%s local decision P95=%s errors=%d", principalCount, bindingCount, grantCount, concurrency, len(listSamples), listP95, decisionP95, len(failures))
	if len(failures) > 0 {
		t.Fatalf("scale requests failed (%d total); first error: %s", len(failures), failures[0])
	}
	if listP95 > time.Second || decisionP95 > 100*time.Millisecond {
		t.Fatal("permission scale latency threshold failed")
	}
}

func seedPermissionScaleBatch(t *testing.T, ctx context.Context, db *sql.DB, prefix string, rows [][]any) {
	t.Helper()
	width := len(rows[0])
	placeholder := "(" + strings.TrimSuffix(strings.Repeat("?,", width), ",") + ")"
	parts := make([]string, len(rows))
	args := make([]any, 0, len(rows)*width)
	for i, row := range rows {
		parts[i] = placeholder
		args = append(args, row...)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(prefix+strings.Join(parts, ",")), args...); err != nil {
		t.Fatal(err)
	}
}

func scalePercentile(samples []time.Duration, percent int) time.Duration {
	copy := append([]time.Duration(nil), samples...)
	sort.Slice(copy, func(i, j int) bool { return copy[i] < copy[j] })
	return copy[(len(copy)*percent+99)/100-1]
}
func scaleMilliseconds(samples []time.Duration) []float64 {
	values := make([]float64, len(samples))
	for i, value := range samples {
		values[i] = float64(value) / float64(time.Millisecond)
	}
	return values
}
