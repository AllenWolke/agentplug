package capability

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Startup-only port. The owner installs the immutable provider/version binding
// before BeginTool commits or submits any business/API/code operation.
type CancellationToolRegistrar func(context.Context, *sql.Tx, ToolReceiptQuery) error

func (s *SQLToolInvocationStore) SetCancellationRegistrar(register CancellationToolRegistrar) error {
	if s == nil || register == nil || s.cancellationRegistrar != nil || s.admitExecution == nil {
		return compensation.ErrInvalid
	}
	s.cancellationRegistrar = register
	return nil
}

func (s *SQLToolInvocationStore) registerCancellationToolTx(ctx context.Context, tx *sql.Tx, l ToolExecutionLease) error {
	if s.cancellationRegistrar == nil {
		return nil
	}
	q, err := receiptQueryFromContext(ctx, l.ScopeHash, l.CallID, l.Fingerprint)
	if err != nil || q == nil || q.Scope.ValidateTrusted() != nil || q.RuntimeAudit == nil ||
		q.RuntimeAudit.Descriptor.Validate() != nil || !auditRuntimeDigest(q.RuntimeAudit.PolicyHash) {
		return ErrToolInvocationConflict
	}
	return s.cancellationRegistrar(ctx, tx, *q)
}

// Facts contain immutable metadata only. Original command/results, credentials
// and arbitrary output are excluded. Unknown remains unknown: this read does
// not repair/replay a tool or claim that a side effect was reversed.
type CancellationToolFact struct {
	Query        ToolReceiptQuery
	Status       string
	Phase        string
	LeaseExpired bool
}

// A receipt-only owner reads one exact invocation under the cancellation
// transaction. No command body or returned business content is disclosed.
func (s *SQLToolInvocationStore) ReadCancellationToolTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, id string) (CancellationToolFact, error) {
	if s == nil || ctx == nil || tx == nil || scope.ValidateTrusted() != nil || id == "" {
		return CancellationToolFact{}, compensation.ErrInvalid
	}
	row := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT call_id,fingerprint,status,phase,lease_until,recovery_query,clock_timestamp() FROM platform_tool_invocation WHERE scope_hash=? AND call_id=? FOR SHARE`), ToolReceiptScopeHash(scope), id)
	return readCancellationToolFact(row, scope)
}

type cancellationFactScanner interface{ Scan(...any) error }

func readCancellationToolFact(row cancellationFactScanner, scope sharedkernel.Scope) (CancellationToolFact, error) {
	var id, fp, raw string
	var fact CancellationToolFact
	var until sql.NullTime
	var now time.Time
	if err := row.Scan(&id, &fp, &fact.Status, &fact.Phase, &until, &raw, &now); err != nil {
		return fact, err
	}
	if len(raw) > 65536 || json.Unmarshal([]byte(raw), &fact.Query) != nil || fact.Query.Scope != scope || fact.Query.CallID != id || fact.Query.Fingerprint != fp || !auditRuntimeDigest(fp) || fact.Query.Name == "" || fact.Query.RuntimeAudit == nil || fact.Query.RuntimeAudit.Descriptor.Validate() != nil || !auditRuntimeDigest(fact.Query.RuntimeAudit.PolicyHash) {
		return fact, compensation.ErrConflict
	}
	if fact.Status != "running" && fact.Status != "unknown" && fact.Status != "completed" && fact.Status != "failed" {
		return fact, compensation.ErrConflict
	}
	if fact.Phase != "preparing" && fact.Phase != "executing" {
		return fact, compensation.ErrConflict
	}
	fact.LeaseExpired = until.Valid && !now.Before(until.Time)
	return fact, nil
}

// Called under the owning execution/ancestry cancellation fence. Exact Scope,
// call, fingerprint and platform-installed runtime metadata are revalidated.
// Missing historical metadata fails closed instead of treating it as a read.
func (s *SQLToolInvocationStore) ReadCancellationToolsTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) ([]CancellationToolFact, error) {
	if s == nil || ctx == nil || tx == nil || scope.ValidateTrusted() != nil {
		return nil, compensation.ErrInvalid
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT call_id,fingerprint,status,phase,lease_until,recovery_query,clock_timestamp() FROM platform_tool_invocation WHERE scope_hash=? ORDER BY call_id LIMIT ? FOR SHARE`), ToolReceiptScopeHash(scope), compensation.MaxSteps+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	facts := make([]CancellationToolFact, 0)
	for rows.Next() {
		if len(facts) >= compensation.MaxSteps {
			return nil, compensation.ErrConflict
		}
		fact, err := readCancellationToolFact(rows, scope)
		if err != nil {
			return nil, err
		}
		facts = append(facts, fact)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return facts, nil
}
