package modelcapacity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// TestSQLProviderPostgresIntegration is enabled only by the isolated Compose E2E.
// It exercises the actual PostgreSQL lock/CAS boundary rather than replacing it
// with a process-local fake.
func TestSQLProviderPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("PUBLIC_TEST_POSTGRES_MIGRATION_DSN is only set by the isolated Compose E2E")
	}

	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(16)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		t.Fatalf("connect isolated PostgreSQL: %v", err)
	}
	provider := NewSQLProvider(db)
	if err = provider.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure model capacity schema: %v", err)
	}

	deploymentID, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	deployment := Deployment{
		ID: deploymentID, TenantID: "capacity-e2e-tenant", DepartmentID: "capacity-e2e-department",
		ApplicationID: "capacity-e2e-application", ModelVersionID: "capacity-e2e-version", CapacityUnits: 3,
	}
	if _, err = db.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_model_capacity_lease WHERE deployment_id=?`), deploymentID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_model_capacity_pool WHERE deployment_id=?`), deploymentID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := db.ExecContext(context.Background(), sqlutil.Bind(`DELETE FROM platform_model_capacity_lease WHERE deployment_id=?`), deploymentID); err != nil {
			t.Errorf("cleanup leases: %v", err)
		}
		if _, err := db.ExecContext(context.Background(), sqlutil.Bind(`DELETE FROM platform_model_capacity_pool WHERE deployment_id=?`), deploymentID); err != nil {
			t.Errorf("cleanup pool: %v", err)
		}
	})

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = RegisterPoolTx(tx, deployment, time.Now().UTC()); err != nil {
		_ = tx.Rollback()
		t.Fatalf("register capacity pool: %v", err)
	}
	if err = UpdatePoolStateTx(tx, capacityScope(), deploymentID, "ready", "ready", time.Now().UTC()); err != nil {
		_ = tx.Rollback()
		t.Fatalf("set capacity pool ready: %v", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}

	const callers = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	leases := make([]Lease, 0, callers)
	exceeded, unexpected := 0, 0
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			request := Request{Scope: capacityScope(), DeploymentID: deploymentID, Units: 1, Owner: fmt.Sprintf("worker-%d", index), RequestID: fmt.Sprintf("request-%d", index), TTL: time.Minute}
			lease, acquireErr := provider.AcquireCapacity(ctx, request)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case acquireErr == nil:
				leases = append(leases, lease)
			case errors.Is(acquireErr, ErrExceeded):
				exceeded++
			default:
				unexpected++
				t.Errorf("AcquireCapacity(%d): %v", index, acquireErr)
			}
		}(i)
	}
	wg.Wait()
	if len(leases) != 3 || exceeded != callers-3 || unexpected != 0 {
		t.Fatalf("capacity was oversold or unexpectedly unavailable: acquired=%d exceeded=%d unexpected=%d", len(leases), exceeded, unexpected)
	}
	seenFences := map[int64]bool{}
	for _, lease := range leases {
		if seenFences[lease.FencingToken] {
			t.Fatalf("duplicate fencing token %d", lease.FencingToken)
		}
		seenFences[lease.FencingToken] = true
		if err = provider.ReleaseCapacity(ctx, lease); err != nil {
			t.Fatalf("release %s: %v", lease.ID, err)
		}
		if err = provider.ReleaseCapacity(ctx, lease); err != nil {
			t.Fatalf("idempotent release %s: %v", lease.ID, err)
		}
	}

	first, err := provider.AcquireCapacity(ctx, Request{Scope: capacityScope(), DeploymentID: deploymentID, Units: 1, Owner: "expiry-worker", RequestID: "expiry-request", TTL: time.Second})
	if err != nil {
		t.Fatalf("acquire expiry fixture: %v", err)
	}
	provider.now = func() time.Time { return first.ExpiresAt.Add(time.Second) }
	reaped, err := provider.ReapExpired(ctx, first.ExpiresAt.Add(time.Second), 10)
	if err != nil || reaped != 1 {
		t.Fatalf("expired lease recovery: reaped=%d err=%v", reaped, err)
	}
	second, err := provider.AcquireCapacity(ctx, Request{Scope: capacityScope(), DeploymentID: deploymentID, Units: 1, Owner: "replacement-worker", RequestID: "replacement-request", TTL: time.Minute})
	if err != nil {
		t.Fatalf("capacity not recovered after lease expiry: %v", err)
	}
	if second.FencingToken <= first.FencingToken {
		t.Fatalf("fencing token did not advance across expiry recovery: first=%d second=%d", first.FencingToken, second.FencingToken)
	}
	if err = provider.ReleaseCapacity(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err = updatePoolStateTx(ctx, db, capacityScope(), deploymentID, "draining", "draining"); err != nil {
		t.Fatal(err)
	}
	_, err = provider.AcquireCapacity(ctx, Request{Scope: capacityScope(), DeploymentID: deploymentID, Units: 1, Owner: "draining-worker", RequestID: "draining-request", TTL: time.Minute})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("draining deployment admitted a request: %v", err)
	}
	foreignScope := capacityScope()
	foreignScope.ApplicationID = "foreign-application"
	_, err = provider.AcquireCapacity(ctx, Request{Scope: foreignScope, DeploymentID: deploymentID, Units: 1, Owner: "foreign-worker", RequestID: "foreign-request", TTL: time.Minute})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cross-application capacity lookup was not hidden: %v", err)
	}
}

func capacityScope() sharedkernel.Scope {
	return sharedkernel.Scope{
		TenantID: "capacity-e2e-tenant", DepartmentID: "capacity-e2e-department", ApplicationID: "capacity-e2e-application",
		AgentInstanceID: "capacity-e2e-instance", AgentID: "capacity-e2e-agent", PrincipalID: "capacity-e2e-user",
		PrincipalType: "user", InstallationID: "capacity-e2e-installation", AgentVersionID: "capacity-e2e-agent-version",
		SessionID: "capacity-e2e-session", RunID: "capacity-e2e-run", AuthorizationEpoch: 1, TraceID: "capacity-e2e-trace",
	}
}

func updatePoolStateTx(ctx context.Context, db *sql.DB, scope sharedkernel.Scope, deploymentID, health, status string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = UpdatePoolStateTx(tx, scope, deploymentID, health, status, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}
