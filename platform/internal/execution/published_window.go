package execution

import (
	"context"
	"errors"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// PublishedExecutionWindow reads an immutable start already committed by lease
// admission. Re-signing, retries, restarts and Agent checkpoint replay do not
// grant another processing window. Human approval waiting is not new diagnosis.
func (m *Module) PublishedExecutionWindow(ctx context.Context, scope sharedkernel.Scope, operation, bodyHash, policyHash string, seconds int) (time.Time, time.Time, error) {
	if seconds < 1 || seconds > 3600 {
		return time.Time{}, time.Time{}, platformruntime.ErrInvalidRequest
	}
	run, err := m.validatedLiveLease(ctx, scope, operation, bodyHash, policyHash)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	store, ok := m.store.(interface {
		OriginalGenerationStart(context.Context, platformruntime.Run) (time.Time, error)
	})
	if !ok {
		return time.Time{}, time.Time{}, errors.New("original generation journal unavailable")
	}
	start, err := store.OriginalGenerationStart(ctx, run)
	if err != nil || start.IsZero() {
		return time.Time{}, time.Time{}, errors.New("original generation journal unavailable")
	}
	return start, start.Add(time.Duration(seconds) * time.Second), nil
}

func (s *SQLStore) OriginalGenerationStart(ctx context.Context, run platformruntime.Run) (time.Time, error) {
	if run.ID == "" || run.Scope.ValidateTrusted() != nil {
		return time.Time{}, platformruntime.ErrInvalidRequest
	}
	var start time.Time
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT recorded_at
 FROM platform_execution_generation_claim_journal WHERE run_id=? AND request_hash=?
 AND protocol_epoch=? AND protocol_version=? ORDER BY claim_revision LIMIT 1`),
		run.ID, generationJournalHash(run.RequestJSON), generationJournalProtocolEpoch, generationJournalProtocolVersion).Scan(&start)
	return start, err
}
