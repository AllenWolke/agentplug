package identity

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func newToolConsumptionProof(t *testing.T, f administratorFixture) StepUpProof {
	t.Helper()
	proof, err := f.store.CreateToolStepUp(f.ctx, f.actors[2], StepUpRequest{
		CurrentPassword: "fixture-administrator-password", Action: "tool.approval.approve",
		RequestDigest: strings.Repeat("d", 64),
	}, func(context.Context, *sql.Tx, sharedkernel.Scope, string, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestSQLToolStepUpConsumptionSharesReadsAndFencesRevocation(t *testing.T) {
	f := newAdministratorFixture(t)
	proof := newToolConsumptionProof(t, f)
	reader, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	if err = f.store.AcquirePermissionReadContinuity(f.ctx, reader); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, time.Second)
	defer cancel()
	consumer, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Rollback()
	if err = f.store.ConsumeToolStepUpTx(ctx, consumer, f.actors[2], strings.Repeat("a", 64), 1, proof.Token,
		"tool.approval.approve", strings.Repeat("d", 64)); err != nil {
		t.Fatal("unrelated protected business read blocked proof consumption", err)
	}
	// The consumer, independently of the original reader, must fence a real
	// authorization mutation until its approval/audit transaction finishes.
	if err = reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	writerCtx, stop := context.WithTimeout(f.ctx, 150*time.Millisecond)
	defer stop()
	writer, err := f.db.BeginTx(writerCtx, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = lockPermissionContinuity(writerCtx, writer)
	writer.Rollback()
	if err == nil {
		t.Fatal("revocation crossed unfinished proof consumption")
	}
	if err = consumer.Commit(); err != nil {
		t.Fatal(err)
	}
	writer, err = f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	if err = lockPermissionContinuity(f.ctx, writer); err != nil {
		t.Fatal("completed consumer retained global authorization fence", err)
	}
}

func TestSQLToolStepUpConcurrentConsumptionStillSingleUse(t *testing.T) {
	f := newAdministratorFixture(t)
	proof := newToolConsumptionProof(t, f)
	first, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback()
	if err = f.store.ConsumeToolStepUpTx(f.ctx, first, f.actors[2], strings.Repeat("a", 64), 1, proof.Token,
		"tool.approval.approve", strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		tx, err := f.db.BeginTx(f.ctx, nil)
		if err != nil {
			result <- err
			return
		}
		defer tx.Rollback()
		result <- f.store.ConsumeToolStepUpTx(f.ctx, tx, f.actors[2], strings.Repeat("a", 64), 1, proof.Token,
			"tool.approval.approve", strings.Repeat("d", 64))
	}()
	select {
	case err = <-result:
		t.Fatal("same proof did not wait for first transaction", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err = first.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-result:
		if !errors.Is(err, ErrStepUpRequired) {
			t.Fatal("same proof could be committed twice", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proof contender did not stop after owner committed")
	}
}
