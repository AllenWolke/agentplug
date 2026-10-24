package execution

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLCapabilityReadsJoinOwnerConnection(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL migration fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	store, err := openMigratedSQLFixture(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id := fmt.Sprintf("continuity-read-%d", time.Now().UnixNano())
	scope := testScope(id).domain()
	scope.SessionID = id
	body, policy := strings.Repeat("b", 64), strings.Repeat("c", 64)
	_, err = store.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: "fixture", RequestJSON: []byte(`{"operation":"invoke","input_schema":"schema://fixture/input/v1"}`), AgentEndpoint: "http://agent.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.AcquireLease(id, "worker", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	run, err := store.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordDispatchCommand(platformruntime.DispatchCommand{RunID: id, Revision: run.Revision, Operation: "invoke", BodyHash: body, PolicyHash: policy}, run.LeaseToken); err != nil {
		t.Fatal(err)
	}
	store.db.SetMaxOpenConns(1)
	checks := []struct {
		name string
		read func(context.Context) error
	}{
		{"budget", func(c context.Context) error {
			v, e := store.BudgetRunContext(c, id)
			if e == nil && v.Scope != scope {
				return errors.New("wrong budget scope")
			}
			return e
		}},
		{"command", func(c context.Context) error {
			v, e := store.ReadLiveCapabilityCommand(c, scope, "invoke", body, policy)
			if e == nil && v.Scope != scope {
				return errors.New("wrong command scope")
			}
			return e
		}},
		{"epoch", func(c context.Context) error {
			v, e := store.ExpectedAuthorizationEpoch(c, scope)
			if e == nil && v != scope.AuthorizationEpoch {
				return errors.New("wrong epoch")
			}
			return e
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			owner, e := store.db.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer owner.Rollback()
			bounded, stop := context.WithTimeout(ctx, time.Second)
			defer stop()
			bound := sqlutil.WithContinuityTransaction(bounded, store.db, owner)
			waits := store.db.Stats().WaitCount
			if e := check.read(bound); e != nil || store.db.Stats().WaitCount != waits {
				t.Fatalf("nested pool read wait_delta=%d err=%v", store.db.Stats().WaitCount-waits, e)
			}
			foreign := sqlutil.WithContinuityTransaction(ctx, new(sql.DB), owner)
			if e := check.read(foreign); e == nil {
				t.Fatal("foreign owner escaped into pool")
			}
			if e := owner.Rollback(); e != nil {
				t.Fatal(e)
			}
			closed := sqlutil.WithContinuityTransaction(ctx, store.db, owner)
			if e := check.read(closed); !errors.Is(e, sql.ErrTxDone) {
				t.Fatal("closed owner escaped into pool", e)
			}
			if e := check.read(ctx); e != nil {
				t.Fatal("standalone read changed", e)
			}
		})
	}
}
