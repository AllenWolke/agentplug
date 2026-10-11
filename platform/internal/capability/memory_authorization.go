package capability

import (
	"context"
	"database/sql"
	"errors"
)

var errMemoryWriteDenied = errors.New("memory write authorization denied")
var errMemoryContinuityUnavailable = errors.New("memory write continuity unavailable")

// AuthorizedMemoryStore keeps the supplied current-authority check inside its
// commit boundary. Remote adapters must supply an equivalent durable fence.
type AuthorizedMemoryStore interface {
	SaveAuthorized(context.Context, string, memoryEntry, int, func(context.Context) error) error
}

// Configure only during composition, before accepting requests. The SQL store
// and the guard must use the same modular-monolith database transaction.
func (s *SQLMemoryStore) SetAuthorizationContinuityGuard(guard func(context.Context, *sql.Tx) error) {
	s.authorityGuard = guard
}

func (s *SQLMemoryStore) SaveAuthorized(ctx context.Context, key string, entry memoryEntry, maxEntries int, check func(context.Context) error) error {
	if s.authorityGuard == nil || check == nil {
		return errMemoryContinuityUnavailable
	}
	return s.save(ctx, key, entry, maxEntries, check)
}
