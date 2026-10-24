package execution

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func waitingAuthorityRequestHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func waitingAuthorityScopeHash(scope sharedkernel.Scope) string {
	raw, _ := json.Marshal(scope)
	return waitingAuthorityRequestHash(raw)
}

func validWaitingAuthorityReceipt(r WaitingAuthorizationReceipt, facts BudgetRunFacts) bool {
	digest, err := hex.DecodeString(r.RequestDigest)
	return r.Version == WaitingAuthorizationVersion && facts.Scope.ParentRunID == "" &&
		r.RunID == facts.Scope.RunID && waitingAuthorizationID.MatchString(r.RequestID) &&
		err == nil && len(digest) == 32 && r.RequestDigest == strings.ToLower(r.RequestDigest) && !r.OccurredAt.IsZero() && !r.Replayed &&
		r.ExecutionRevision >= 2 && r.ExecutionRevision <= facts.Revision &&
		r.OriginalAuthorizationEpoch == facts.Scope.AuthorizationEpoch &&
		r.PreviousAuthorizationEpoch >= r.OriginalAuthorizationEpoch &&
		r.AuthorizationEpoch >= r.PreviousAuthorizationEpoch && r.AuthorizationEpoch < 1<<53 &&
		r.ScopeHash == waitingAuthorityScopeHash(facts.Scope) &&
		r.RequestHash == waitingAuthorityRequestHash(facts.RequestJSON)
}

// ExpectedAuthorizationEpoch returns a server-owned expected current IAM epoch.
// It grants no permission: callers still check fresh IAM, workload and live lease.
// Original Scope remains the key of every checkpoint, receipt and execution token.
func (s *SQLStore) ExpectedAuthorizationEpoch(ctx context.Context, scope sharedkernel.Scope) (uint64, error) {
	if s == nil || s.db == nil {
		return 0, ErrRunPermissionDenied
	}
	if tx, joined, err := sqlutil.ContinuityTransaction(ctx, s.db); joined {
		if err != nil {
			return 0, err
		}
		return s.ExpectedAuthorizationEpochTx(ctx, tx, scope)
	}
	facts, err := s.BudgetRunContext(ctx, scope.RunID)
	if err != nil {
		return 0, err
	}
	return s.expectedAuthorizationEpoch(ctx, s.db, facts, scope)
}

func (s *SQLStore) ExpectedAuthorizationEpochTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) (uint64, error) {
	if tx == nil {
		return 0, ErrRunPermissionDenied
	}
	facts, err := s.BudgetRunReadTx(ctx, tx, scope.RunID)
	if err != nil {
		return 0, err
	}
	return s.expectedAuthorizationEpoch(ctx, tx, facts, scope)
}

func (s *SQLStore) expectedAuthorizationEpoch(ctx context.Context, q budgetRunQueryer, facts BudgetRunFacts, scope sharedkernel.Scope) (uint64, error) {
	if scope.ValidateTrusted() != nil || facts.Scope != scope {
		return 0, ErrRunPermissionDenied
	}
	var raw []byte
	err := q.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_execution_event WHERE run_id=? AND event_type=? ORDER BY seq DESC LIMIT 1`), scope.RunID, waitingAuthorizationEvent).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return scope.AuthorizationEpoch, nil
	}
	if err != nil {
		return 0, err
	}
	var receipt WaitingAuthorizationReceipt
	if len(raw) > 2048 || json.Unmarshal(raw, &receipt) != nil || !validWaitingAuthorityReceipt(receipt, facts) {
		return 0, ErrRunPermissionDenied
	}
	return receipt.AuthorizationEpoch, nil
}

func (m *Module) ExpectedAuthorizationEpoch(ctx context.Context, scope sharedkernel.Scope) (uint64, error) {
	if m == nil {
		return 0, ErrRunPermissionDenied
	}
	if reader, ok := m.store.(interface {
		ExpectedAuthorizationEpoch(context.Context, sharedkernel.Scope) (uint64, error)
	}); ok {
		return reader.ExpectedAuthorizationEpoch(ctx, scope)
	}
	run, err := m.store.Get(scope.RunID)
	if err != nil || run.Scope != scope {
		return 0, ErrRunPermissionDenied
	}
	return scope.AuthorizationEpoch, nil
}
