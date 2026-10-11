package bootstrap_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/bootstrap"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
)

type healthConnector struct {
	unavailable atomic.Bool
	active      atomic.Int32
}

type healthDriver struct{ connector *healthConnector }
type healthConnection struct{ connector *healthConnector }

func (d healthDriver) Open(string) (driver.Conn, error) {
	return d.connector.Connect(context.Background())
}
func (c *healthConnector) Driver() driver.Driver { return healthDriver{c} }
func (c *healthConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &healthConnection{c}, nil
}
func (*healthConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("health fixture forbids SQL")
}
func (*healthConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("health fixture forbids transactions")
}
func (*healthConnection) Close() error { return nil }
func (c *healthConnection) Ping(ctx context.Context) error {
	c.connector.active.Add(1)
	defer c.connector.active.Add(-1)
	if !c.connector.unavailable.Load() {
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

// Use the real stores and database/sql cancellation, without claiming live PostgreSQL.
// 使用实际仓储及 database/sql 取消机制；驱动为故障夹具，不声称真实 PostgreSQL 验收。
func TestCatalogIdentitySQLReadinessBlackHoleAndRecovery(t *testing.T) {
	connector := &healthConnector{}
	db := sql.OpenDB(connector)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	registry := bootstrap.NewModuleRegistry()
	if err := registry.Register(catalog.NewModule(catalog.NewSQLStore(db, "pgx"), "fixture-token")); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(identity.NewModule(identity.NewSQLStore(db), "fixture-token")); err != nil {
		t.Fatal(err)
	}
	if err := registry.ReadyContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	connector.unavailable.Store(true)
	start := time.Now()
	if err := registry.ReadyContext(context.Background()); err == nil {
		t.Fatal("database black hole reported ready")
	}
	if elapsed := time.Since(start); elapsed < 1900*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("SQL timeout not bounded: %s", elapsed)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if err := registry.ReadyContext(ctx); err == nil {
				t.Error("cancelled SQL probe reported ready")
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SQL probes did not release on cancellation")
	}
	if connector.active.Load() != 0 {
		t.Fatal("SQL driver probes leaked")
	}
	connector.unavailable.Store(false)
	if err := registry.ReadyContext(context.Background()); err != nil {
		t.Fatalf("SQL recovery not detected: %v", err)
	}
	if db.Stats().InUse != 0 {
		t.Fatal("SQL health checks leaked pooled connections")
	}
}
