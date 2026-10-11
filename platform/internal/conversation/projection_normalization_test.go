package conversation

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
	"unicode/utf8"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// Return the normalized content persisted by the first delivery.
// 返回首次投递已持久化的规范化正文，验证重试不产生伪冲突。
type projectionReplayDriver struct{}
type projectionReplayConn struct{}
type projectionReplayRows struct {
	done    bool
	session bool
}

func (projectionReplayDriver) Open(string) (driver.Conn, error) { return projectionReplayConn{}, nil }
func (projectionReplayConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (projectionReplayConn) Close() error { return nil }
func (projectionReplayConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected transaction")
}
func (projectionReplayConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	return &projectionReplayRows{session: strings.Contains(query, "SELECT id,kind,agent_id")}, nil
}
func (r *projectionReplayRows) Columns() []string {
	if r.session {
		return []string{"id", "kind", "agent_id", "agent_version_id", "installation_id", "title", "preview", "owner_id", "status", "message_count", "can_continue"}
	}
	return []string{"content"}
}
func (*projectionReplayRows) Close() error { return nil }
func (r *projectionReplayRows) Next(values []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	if r.session {
		copy(values, []driver.Value{"session", "qa", "qa", "v1", "installation", "test", "", "user", "active", int64(1), true})
		return nil
	}
	values[0] = truncate(strings.Repeat("a", 32769), 32768)
	return nil
}
func init() { sql.Register("projection-long-answer", projectionReplayDriver{}) }
func TestProjectionLongAnswerReplay(t *testing.T) {
	db, err := sql.Open("projection-long-answer", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scope := sharedkernel.Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "app", PrincipalType: "user", PrincipalID: "user", SessionID: "session", AgentID: "qa", AgentVersionID: "v1", InstallationID: "installation"}
	err = NewSQLStore(db).RecordRunResult(context.Background(), scope, "run", map[string]any{"answer": strings.Repeat("a", 32769)})
	if err != nil {
		t.Fatalf("same durable result must replay idempotently: %v", err)
	}
	// A genuinely different persisted prefix still must conflict.
	// 真正不同的持久化正文仍须拒绝，不能把幂等冲突吞掉。
	err = NewSQLStore(db).RecordRunResult(context.Background(), scope, "run", map[string]any{"answer": "different answer"})
	if err == nil {
		t.Fatal("different answer replay was accepted")
	}
}

func TestProjectionUTF8ByteBoundaries(t *testing.T) {
	for _, value := range []string{"", "ascii", strings.Repeat("中", 12000), strings.Repeat("😀", 9000), "abc中文😀"} {
		for _, limit := range []int{-1, 0, 1, 2, 3, 4, 5, 512, 2048, 32768, 40000} {
			got := truncate(value, limit)
			if !utf8.ValidString(got) || !strings.HasPrefix(value, got) || len(got) > max(limit, 0) {
				t.Fatalf("invalid UTF8/limit result at budget %d", limit)
			}
			if limit >= len(value) && got != value {
				t.Fatal("short content changed")
			}
		}
	}
}

// Run only against the disposable schema created by the official Docker E2E.
// 仅使用官方Docker验收创建的隔离库，验证真实utf8mb4写入和重复投影。
func TestSQLProjectionUTF8AndLongReplay(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal("cannot open isolated PostgreSQL fixture")
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store := NewSQLStore(db)
	if err = store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("unicode-%d", time.Now().UnixNano())
	scope := Scope{TenantID: id, DepartmentID: "dept", ApplicationID: "app", PrincipalType: "user", PrincipalID: "actor"}
	if err = store.CreateSession(ctx, scope, Session{Summary: Summary{ID: id, Kind: "qa", AgentID: "qa", AgentVersionID: "v1", Title: "UTF-8 test", Status: "active"}}); err != nil {
		t.Fatal(err)
	}
	runScope := sharedkernel.Scope{TenantID: id, DepartmentID: "dept", ApplicationID: "app", PrincipalType: "user", PrincipalID: "actor", SessionID: id, AgentID: "qa", AgentVersionID: "v1"}
	for index, answer := range []string{strings.Repeat("中", 1000), strings.Repeat("中文😀", 4000)} {
		runID := fmt.Sprintf("%s-%d", id, index)
		for attempt := 0; attempt < 2; attempt++ {
			if err = store.RecordRunResult(ctx, runScope, runID, map[string]any{"answer": answer}); err != nil {
				t.Fatalf("projection %d/%d: %v", index, attempt, err)
			}
		}
	}
	var count int
	var preview string
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT message_count,preview FROM platform_conversation_session WHERE id=?`), id).Scan(&count, &preview); err != nil {
		t.Fatal(err)
	}
	if count != 2 || !utf8.ValidString(preview) {
		t.Fatalf("non-idempotent or invalid result: count=%d", count)
	}
}
