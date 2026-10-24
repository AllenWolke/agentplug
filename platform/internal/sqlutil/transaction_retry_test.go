package sqlutil

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestRetryRolledBackRestartsWholeOperationAndDiscardsAbortedResult(t *testing.T) {
	calls := 0
	value, report, err := RetryRolledBack(context.Background(), func() (string, error) {
		calls++
		if calls == 1 {
			return "uncommitted", &pgconn.PgError{Code: "40001"}
		}
		return "committed", nil
	})
	if err != nil || value != "committed" || calls != 2 || report.Attempts != 2 || len(report.Aborts) != 1 || report.Aborts[0] != "40001" {
		t.Fatalf("complete transaction retry lost its boundary: value=%q attempts=%d err=%v", value, report.Attempts, err)
	}
}

func TestRetryRolledBackExhaustionIsKnownNoCommit(t *testing.T) {
	for _, state := range []string{"40001", "40P01"} {
		calls := 0
		value, report, err := RetryRolledBack(context.Background(), func() (string, error) { calls++; return "partial", &pgconn.PgError{Code: state} })
		if value != "" || !IsKnownRollback(err) || SQLState(err) != state || calls != 3 || report.Attempts != 3 {
			t.Fatalf("unsafe exhausted result: state=%s calls=%d err=%v", state, calls, err)
		}
	}
}

func TestRetryRolledBackNeverReplaysUnknownCommitOrOtherFailures(t *testing.T) {
	for _, failure := range []error{io.EOF, context.DeadlineExceeded, &pgconn.PgError{Code: "40003"}, &pgconn.PgError{Code: "23505"}, errors.New("permission denied")} {
		calls := 0
		_, report, err := RetryRolledBack(context.Background(), func() (string, error) { calls++; return "possibly committed", failure })
		if !errors.Is(err, failure) || IsKnownRollback(err) || calls != 1 || report.Attempts != 1 {
			t.Fatalf("unproven failure was replayed/classified no-effect: %T attempts=%d", failure, calls)
		}
	}
}

func TestRetryRolledBackCancellationAfterAbortStopsBeforeNextAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	_, report, err := RetryRolledBack(ctx, func() (int, error) { calls++; cancel(); return 9, &pgconn.PgError{Code: "40001"} })
	if calls != 1 || report.Attempts != 1 || !errors.Is(err, context.Canceled) || !IsKnownRollback(err) {
		t.Fatalf("cancelled transaction was retried: %v", err)
	}
	_, report, err = RetryRolledBack(ctx, func() (int, error) { t.Fatal("cancelled operation entered SQL"); return 0, nil })
	if report.Attempts != 0 || !IsKnownRollback(err) {
		t.Fatal("unstarted cancellation lost no-effect proof")
	}
}

func TestRetryRolledBackPreservesConfirmedSuccessAtCancellationBoundary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	value, report, err := RetryRolledBack(ctx, func() (int, error) { cancel(); return 7, nil })
	if err != nil || value != 7 || report.Attempts != 1 {
		t.Fatal("confirmed commit was turned into an unknown")
	}
}
