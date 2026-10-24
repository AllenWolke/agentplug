package capability

import (
	"context"
	"database/sql"
	"errors"

	"github.com/lexagent/platform/internal/sharedkernel"
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

// Startup composition may supply the execution-parent/IAM lock protocol.
// Scope is taken only from the gateway's private mutation binding. Existing
// standalone stores keep their IAM-only guard and wire contract unchanged.
func (s *SQLMemoryStore) SetExecutionContinuityGuard(guard func(context.Context, *sql.Tx, sharedkernel.Scope) error) {
	s.executionGuard = guard
}

func (s *SQLMemoryStore) lockAuthorizationContinuity(ctx context.Context, tx *sql.Tx) error {
	if s.executionGuard != nil {
		mutation, ok := ctx.Value(memoryMutationKey{}).(memoryMutation)
		if !ok || mutation.Scope.ValidateTrusted() != nil {
			return errMemoryContinuityUnavailable
		}
		if err := s.executionGuard(ctx, tx, mutation.Scope); err != nil {
			return err
		}
	}
	return s.authorityGuard(ctx, tx)
}

func (s *SQLMemoryStore) SaveAuthorized(ctx context.Context, key string, entry memoryEntry, maxEntries int, check func(context.Context) error) error {
	if s.authorityGuard == nil || check == nil {
		return errMemoryContinuityUnavailable
	}
	return s.save(ctx, key, entry, maxEntries, check)
}
