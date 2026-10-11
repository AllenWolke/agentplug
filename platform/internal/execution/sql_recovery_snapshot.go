package execution

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"time"
)

// RecoverySnapshot reads persisted cancellation and stop-recovery intents.
// It never exposes Run, tenant or principal identifiers to monitoring.
type RecoverySnapshot struct {
	Cancelling         int64
	Recovering         int64
	OldestCancellingAt time.Time
	OldestRecoveringAt time.Time
}

func (s *SQLStore) RecoverySnapshot(ctx context.Context) (RecoverySnapshot, error) {
	var snapshot RecoverySnapshot
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT status,COUNT(*),MIN(updated_at)
		FROM platform_execution_run WHERE status IN ('cancelling','recovering') GROUP BY status`))
	if err != nil {
		return snapshot, fmt.Errorf("query execution recovery backlog: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int64
		var oldest sql.NullTime
		if err := rows.Scan(&status, &count, &oldest); err != nil {
			return RecoverySnapshot{}, fmt.Errorf("scan execution recovery backlog: %w", err)
		}
		if count < 0 || (count > 0 && !oldest.Valid) {
			return RecoverySnapshot{}, fmt.Errorf("invalid execution recovery backlog")
		}
		switch status {
		case "cancelling":
			snapshot.Cancelling, snapshot.OldestCancellingAt = count, oldest.Time
		case "recovering":
			snapshot.Recovering, snapshot.OldestRecoveringAt = count, oldest.Time
		default:
			return RecoverySnapshot{}, fmt.Errorf("unexpected execution recovery state")
		}
	}
	if err := rows.Err(); err != nil {
		return RecoverySnapshot{}, fmt.Errorf("read execution recovery backlog: %w", err)
	}
	return snapshot, nil
}
