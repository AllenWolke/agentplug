package notification

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestInboxHTTPRecipientRevocationAndContinuityLockPostgres(t *testing.T) {
	ctx, channel, event, scope := ownedInboxFixture(t)
	if err := channel.Send(ctx, event); err != nil {
		t.Fatal(err)
	}
	if _, err := channel.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS inbox_http_guard_fixture(id INTEGER PRIMARY KEY);INSERT INTO inbox_http_guard_fixture VALUES(1) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	m := NewModule(NewSQLStore(channel.db), channel, "internal-fixture")
	active := true
	if err := m.SetRecipientInbox(channel, func(r *http.Request) (sharedkernel.Scope, error) {
		if r.Header.Get("X-Fixture-Actor") != scope.PrincipalID {
			return sharedkernel.Scope{}, errors.New("not authenticated")
		}
		return scope, nil
	}, func(ctx context.Context, tx *sql.Tx, s sharedkernel.Scope) error {
		if !active || s != scope {
			return errors.New("revoked")
		}
		var id int
		return tx.QueryRowContext(ctx, `SELECT id FROM inbox_http_guard_fixture WHERE id=1 FOR SHARE`).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	request := func(path, actor string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
		r.Header.Set("X-Internal-Token", "internal-fixture")
		r.Header.Set("X-Fixture-Actor", actor)
		w := httptest.NewRecorder()
		m.Handler().ServeHTTP(w, r)
		return w
	}
	if w := request("/inbox", scope.PrincipalID); w.Code != 200 || !strings.Contains(w.Body.String(), event.ID) {
		t.Fatal("own feed denied", w.Code)
	}
	if w := request("/inbox?recipient_id=other", scope.PrincipalID); w.Code != 400 {
		t.Fatal("caller selected recipient", w.Code)
	}
	if w := request("/inbox", "other"); w.Code != 403 || strings.Contains(w.Body.String(), event.ID) {
		t.Fatal("feed crossed user", w.Code)
	}
	active = false
	if w := request("/inbox", scope.PrincipalID); w.Code != 403 || strings.Contains(w.Body.String(), event.ID) {
		t.Fatal("revoked feed disclosed messages", w.Code)
	}
	active = true
	binding, _ := AgentReversalBinding(event)
	if _, err := channel.Revoke(ctx, ReversalRequest{Version: "notification-reversal/v1", Binding: binding, Key: reversalDigest(event.ID + "-withdraw"), Action: "withdraw"}); err != nil {
		t.Fatal(err)
	}
	if w := request("/inbox", scope.PrincipalID); w.Code != 200 || strings.Contains(w.Body.String(), event.ID) {
		t.Fatal("withdrawn message visible", w.Code)
	}
}
