package agentcoordination

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLRootAuthorityRenewalDeniesDelegatedAndChangedWorkload(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL fixture required")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLRouteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err = store.EnsureDelegationAuthoritySchema(ctx); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"renewed", "old epoch", "changed scope epoch", "new workload", "delegated", "rolled back"} {
		t.Run(variant, func(t *testing.T) {
			id := fmt.Sprintf("root-renew-%d", time.Now().UnixNano())
			old := RootMachineAuthorityStamp{RootRunID: id, RootInstallationID: "installation", RootPrincipalType: "user", RootPrincipalID: "owner", RootAuthorizationEpoch: 1, MachinePrincipalID: "original-executor", MachineRunEpoch: 1}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = store.PinRootMachineAuthorityTx(ctx, tx, old); err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if variant == "delegated" {
				_, err = db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_agent_route(parent_key,operation_key,parent_run_id,fingerprint,policy_hash,task_type,child_depth,reserved_children,plan_json,evidence_digest) VALUES(?,?,?,?,?,?,1,1,'{}',?)`), strings.Repeat("a", 64), id, id, strings.Repeat("b", 64), strings.Repeat("c", 64), "generic-task", strings.Repeat("d", 64))
				if err != nil {
					t.Fatal(err)
				}
			}
			next := old
			next.MachineRunEpoch = 2
			previous := uint64(1)
			if variant == "old epoch" {
				previous = 3
			}
			if variant == "changed scope epoch" {
				next.RootAuthorizationEpoch = 2
			}
			if variant == "new workload" {
				next.MachinePrincipalID = "foreign-executor"
			}
			tx, err = db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = store.RenewUndelegatedRootAuthorityTx(ctx, tx, previous, next)
			allowed := variant == "renewed" || variant == "rolled back"
			if allowed && err != nil {
				t.Fatal("valid explicit renewal rejected", err)
			}
			if !allowed && err == nil {
				t.Fatal("unsafe renewal admitted")
			}
			if variant == "renewed" {
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
			} else {
				_ = tx.Rollback()
			}
			tx, err = db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := store.RootMachineAuthorityTx(ctx, tx, id)
			_ = tx.Rollback()
			if err != nil {
				t.Fatal(err)
			}
			expected := old
			if variant == "renewed" {
				expected = next
			}
			if actual != expected {
				t.Fatal("authority renewal/rollback not atomic")
			}
			tx, err = db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if variant == "renewed" {
				if err = store.PinRootMachineAuthorityTx(ctx, tx, old); err == nil {
					t.Fatal("normal dispatch accepted obsolete immutable authority")
				}
			}
			_ = tx.Rollback()
		})
	}
}
