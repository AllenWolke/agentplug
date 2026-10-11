package capability

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLMemoryWriteContinuityWithPrincipalRevocation(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated Postgres fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	iam := identity.NewSQLStore(db)
	if err := iam.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLMemoryStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	store.SetAuthorizationContinuityGuard(iam.AcquirePermissionReadContinuity)
	tenantID := fmt.Sprintf("memory-continuity-%d", time.Now().UnixNano())
	if err := iam.CreateTenant(ctx, identity.Tenant{ID: tenantID, Code: tenantID, Name: "isolated memory fixture", Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	actor := sharedkernel.Scope{TenantID: tenantID, DepartmentID: "department", ApplicationID: "application", PrincipalType: "user", PrincipalID: "memory-admin"}
	waitForLock := func(done <-chan error) {
		t.Helper()
		for {
			var waiting int
			err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM pg_stat_activity a WHERE a.datname=current_database() AND cardinality(pg_blocking_pids(a.pid))>0 AND a.query LIKE '%platform_identity_continuity_guard%'`)).Scan(&waiting)
			if err != nil {
				t.Fatal(err)
			}
			if waiting > 0 {
				return
			}
			select {
			case err := <-done:
				t.Fatalf("operation completed without expected lock wait: %v", err)
			case <-ctx.Done():
				t.Fatal("continuity lock wait timeout")
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	for _, revokeFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("revoke-first-%t", revokeFirst), func(t *testing.T) {
			id := fmt.Sprintf("memory-continuity-%d", time.Now().UnixNano())
			if err := iam.CreatePrincipal(ctx, identity.Principal{Type: identity.PrincipalUser, ID: id, TenantID: actor.TenantID, IsActive: true, Revision: 1}); err != nil {
				t.Fatal(err)
			}
			check := func(ctx context.Context) error {
				p, err := iam.GetPrincipal(ctx, identity.PrincipalUser, id)
				if err != nil {
					return err
				}
				if !p.IsActive {
					return identity.ErrPermissionDenied
				}
				return nil
			}
			entered, release := make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			writes, revokes := make(chan error, 1), make(chan error, 1)
			write := func(check func(context.Context) error) {
				writes <- store.SaveAuthorized(ctx, id, memoryEntry{Value: map[string]any{"text": "protected"}, ExpiresAt: time.Now().Add(time.Hour)}, 5, check)
			}
			revoke := func() { _, err := iam.DisablePrincipal(ctx, actor, id, 1); revokes <- err }
			if revokeFirst {
				iam.SetPrincipalLifecycleRecorder(func(ctx context.Context, _ *sql.Tx, _ sharedkernel.Scope, _ identity.PrincipalLifecycleDecision) error {
					close(entered)
					select {
					case <-release:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				})
				go revoke()
			} else {
				iam.SetPrincipalLifecycleRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, identity.PrincipalLifecycleDecision) error {
					return nil
				})
				calls := 0
				go write(func(ctx context.Context) error {
					calls++
					if calls == 1 {
						close(entered)
						select {
						case <-release:
						case <-ctx.Done():
							return ctx.Err()
						}
					}
					return check(ctx)
				})
			}
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("first transaction failed to acquire fence")
			}
			if revokeFirst {
				go write(check)
				waitForLock(writes)
			} else {
				go revoke()
				waitForLock(revokes)
			}
			close(release)
			writeErr, revokeErr := <-writes, <-revokes
			if revokeErr != nil {
				t.Fatal(revokeErr)
			}
			if revokeFirst && !errors.Is(writeErr, errMemoryWriteDenied) {
				t.Fatal("write after revocation accepted", writeErr)
			}
			if !revokeFirst && writeErr != nil {
				t.Fatal("earlier authorized transaction failed", writeErr)
			}
			_, exists, err := store.Load(ctx, id)
			if err != nil || exists == revokeFirst {
				t.Fatal("durable write disagrees with transaction order", exists, err)
			}
		})
	}
	t.Run("denied-before-commit-rolls-back", func(t *testing.T) {
		key := fmt.Sprintf("memory-check-failure-%d", time.Now().UnixNano())
		old := memoryEntry{Value: map[string]any{"generation": "original"}, ExpiresAt: time.Now().Add(time.Hour)}
		if err := store.Save(ctx, key, old, 5); err != nil {
			t.Fatal(err)
		}
		calls := 0
		err := store.SaveAuthorized(ctx, key, memoryEntry{Value: map[string]any{"generation": "forbidden"}, ExpiresAt: old.ExpiresAt}, 5, func(context.Context) error {
			calls++
			if calls == 2 {
				return identity.ErrPermissionDenied
			}
			return nil
		})
		if !errors.Is(err, errMemoryWriteDenied) || calls != 2 {
			t.Fatal("final authority check missing", err, calls)
		}
		entry, exists, err := store.Load(ctx, key)
		if err != nil || !exists || entry.Value["generation"] != "original" {
			t.Fatal("denied transaction leaked overwrite", entry, err)
		}
	})
	t.Run("missing-fence-refuses-write", func(t *testing.T) {
		unconfigured, err := NewSQLMemoryStore(db)
		if err != nil {
			t.Fatal(err)
		}
		err = unconfigured.SaveAuthorized(ctx, "unconfigured", memoryEntry{Value: map[string]any{"x": true}, ExpiresAt: time.Now().Add(time.Hour)}, 5, func(context.Context) error { return nil })
		if !errors.Is(err, errMemoryContinuityUnavailable) {
			t.Fatal("missing fence accepted", err)
		}
	})
}
