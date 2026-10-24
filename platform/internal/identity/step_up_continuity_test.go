package identity

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSQLStepUpIssuanceSharesReadsAndFencesRevocation(t *testing.T) {
	f := newAdministratorFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	released := false
	defer func() {
		if !released {
			close(release)
		}
		select {
		case <-result:
		case <-time.After(3 * time.Second):
			t.Error("step-up worker did not stop")
		}
	}()
	go func() {
		_, err := f.store.CreateToolStepUp(f.ctx, f.actors[2], StepUpRequest{CurrentPassword: "fixture-administrator-password", Action: "tool.approval.approve", RequestDigest: strings.Repeat("e", 64)},
			func(ctx context.Context, _ *sql.Tx, _ sharedkernel.Scope, _, _ string) error {
				close(entered)
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
		result <- err
	}()
	select {
	case <-entered:
	case <-f.ctx.Done():
		t.Fatal("step-up callback not reached")
	}
	readCtx, cancel := context.WithTimeout(f.ctx, time.Second)
	defer cancel()
	reader, err := f.db.BeginTx(readCtx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.AcquirePermissionReadContinuity(readCtx, reader); err != nil {
		reader.Rollback()
		t.Fatal("step-up blocked independent IAM read", err)
	}
	if err = reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	writeCtx, stop := context.WithTimeout(f.ctx, 150*time.Millisecond)
	defer stop()
	writer, err := f.db.BeginTx(writeCtx, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = lockPermissionContinuity(writeCtx, writer)
	writer.Rollback()
	if err == nil {
		t.Fatal("revocation crossed live issuance fence")
	}
	close(release)
	released = true
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
		result <- nil
	case <-f.ctx.Done():
		t.Fatal("step-up did not finish")
	}
	writer, err = f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	if err = lockPermissionContinuity(f.ctx, writer); err != nil {
		t.Fatal("revocation fence not released", err)
	}
}
