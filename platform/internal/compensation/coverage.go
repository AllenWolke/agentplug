package compensation

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// RecordedEffectsTx exposes immutable effect bindings to the composition root.
// It never exposes before-images, tool output, credentials or inverse leases.
// The caller must first fence the exact Run through its execution owner.
func (s *SQLStore) RecordedEffectsTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) ([]Step, error) {
	if s == nil || ctx == nil || tx == nil || scope.ValidateTrusted() != nil {
		return nil, ErrInvalid
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT step_id,spec_digest,spec_json FROM platform_compensation_step WHERE run_id=? ORDER BY ordinal LIMIT ? FOR SHARE`), scope.RunID, MaxSteps+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	effects := []Step{}
	for rows.Next() {
		var id, saved string
		var raw []byte
		var step Step
		if err := rows.Scan(&id, &saved, &raw); err != nil {
			return nil, err
		}
		if len(effects) >= MaxSteps || len(raw) > 16384 || json.Unmarshal(raw, &step) != nil || step.Validate() != nil || step.ID != id || step.Digest() != saved || step.Scope != scope {
			return nil, ErrConflict
		}
		effects = append(effects, step)
	}
	return effects, rows.Err()
}

func coverageSet(control sharedkernel.Scope, scopes []sharedkernel.Scope) (map[string]sharedkernel.Scope, error) {
	if control.ValidateTrusted() != nil || len(scopes) == 0 || len(scopes) > 69905 {
		return nil, ErrInvalid
	}
	set := make(map[string]sharedkernel.Scope, len(scopes))
	for _, scope := range scopes {
		if scope.ValidateTrusted() != nil || scope.TenantID != control.TenantID || scope.DepartmentID != control.DepartmentID || scope.ApplicationID != control.ApplicationID {
			return nil, ErrConflict
		}
		if _, found := set[scope.RunID]; found {
			return nil, ErrConflict
		}
		set[scope.RunID] = scope
	}
	if set[control.RunID] != control {
		return nil, ErrConflict
	}
	return set, nil
}

// EnrollStoppedTreeTx accepts only scopes proven by the routing owner. The
// authority rechecks every cross-Run enrollment. It is called after BeginTx
// and before the stop proof commits; replay after confirmation is read-only.
func (s *SQLStore) EnrollStoppedTreeTx(ctx context.Context, tx *sql.Tx, control sharedkernel.Scope, scopes []sharedkernel.Scope) error {
	if _, err := coverageSet(control, scopes); err != nil {
		return err
	}
	phase, _, err := s.lockJob(ctx, tx, control)
	if err != nil {
		return err
	}
	if phase != "stopping" {
		return s.VerifyStoppedTreeCoverageTx(ctx, tx, control, scopes)
	}
	count := 0
	for _, scope := range scopes {
		effects, err := s.RecordedEffectsTx(ctx, tx, scope)
		if err != nil {
			return err
		}
		count += len(effects)
		if count > MaxSteps {
			return ErrInvalid
		}
		for _, step := range effects {
			if err := s.EnrollRecordedTx(ctx, tx, control, step.ID); err != nil {
				return err
			}
		}
	}
	return s.VerifyStoppedTreeCoverageTx(ctx, tx, control, scopes)
}

// VerifyStoppedTreeCoverageTx requires exact equality: missing descendants,
// extra effects, altered bindings or a new write cannot be hidden by counts.
func (s *SQLStore) VerifyStoppedTreeCoverageTx(ctx context.Context, tx *sql.Tx, control sharedkernel.Scope, scopes []sharedkernel.Scope) error {
	if _, err := coverageSet(control, scopes); err != nil {
		return err
	}
	expected := map[string]string{}
	for _, scope := range scopes {
		effects, err := s.RecordedEffectsTx(ctx, tx, scope)
		if err != nil {
			return err
		}
		for _, step := range effects {
			if _, duplicate := expected[step.ID]; duplicate || len(expected) >= MaxSteps {
				return ErrConflict
			}
			expected[step.ID] = step.Digest()
		}
	}
	// Enrollment rows are append-only and their UPDATE grant is deliberately
	// revoked. PostgreSQL row-lock clauses require UPDATE even for FOR SHARE.
	// The caller's Run/job lock fences new enrollment; compare immutable rows
	// without requesting a mutation privilege on the history table.
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT e.step_id,e.spec_digest,x.spec_digest FROM platform_cancellation_effect e LEFT JOIN platform_compensation_step x ON x.step_id=e.step_id WHERE e.root_run_id=? ORDER BY e.step_id LIMIT ?`), control.RunID, MaxSteps+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, saved string
		var original sql.NullString
		if err := rows.Scan(&id, &saved, &original); err != nil {
			return err
		}
		if !original.Valid || expected[id] != saved || saved != original.String {
			return ErrConflict
		}
		delete(expected, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(expected) != 0 {
		return ErrConflict
	}
	return nil
}
