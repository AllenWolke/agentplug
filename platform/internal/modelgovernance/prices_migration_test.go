package modelgovernance

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"
	"testing"
)

type ddlRecorder struct {
	mu         sync.Mutex
	statements []string
}

type ddlConnector struct{ recorder *ddlRecorder }

func (c ddlConnector) Connect(context.Context) (driver.Conn, error) {
	return ddlConn{recorder: c.recorder}, nil
}
func (ddlConnector) Driver() driver.Driver { return ddlDriver{} }

type ddlDriver struct{}

func (ddlDriver) Open(string) (driver.Conn, error) { return nil, errors.New("connector required") }

type ddlConn struct{ recorder *ddlRecorder }

func (ddlConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not supported")
}
func (ddlConn) Close() error              { return nil }
func (ddlConn) Begin() (driver.Tx, error) { return nil, errors.New("transactions are not supported") }
func (c ddlConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.recorder.mu.Lock()
	defer c.recorder.mu.Unlock()
	c.recorder.statements = append(c.recorder.statements, query)
	return driver.RowsAffected(0), nil
}

func TestEnsureSchemaCreatesPriceVersionTableWithoutCredentialColumns(t *testing.T) {
	recorder := &ddlRecorder{}
	db := sql.OpenDB(ddlConnector{recorder: recorder})
	t.Cleanup(func() { _ = db.Close() })
	if err := NewSQLStore(db).EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	var priceDDL string
	for _, statement := range recorder.statements {
		if strings.Contains(statement, "CREATE TABLE IF NOT EXISTS platform_model_price_version") {
			priceDDL = statement
			break
		}
	}
	if priceDDL == "" {
		t.Fatal("price version table migration was not emitted")
	}
	for _, required := range []string{
		"model_version_id VARCHAR(36) NOT NULL",
		"currency VARCHAR(3) NOT NULL",
		"input_micros_per_1k_tokens BIGINT NOT NULL",
		"output_micros_per_1k_tokens BIGINT NOT NULL",
		"effective_from TIMESTAMPTZ(6) NOT NULL",
		"effective_until TIMESTAMPTZ(6) NULL",
		"content_hash VARCHAR(71) NOT NULL",
		"revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL",
		"uq_platform_model_price_hash",
		"idx_platform_model_price_effective",
	} {
		if !strings.Contains(priceDDL, required) {
			t.Errorf("price migration missing %q: %s", required, priceDDL)
		}
	}
	for _, forbidden := range []string{"secret_ref", "api_key", "credential"} {
		if strings.Contains(strings.ToLower(priceDDL), forbidden) {
			t.Errorf("price table must not persist credential material (%q): %s", forbidden, priceDDL)
		}
	}
}
