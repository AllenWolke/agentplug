package execution

import (
	"context"
	"database/sql"
	"errors"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type ChildResultFacts struct {
	Scope              sharedkernel.Scope
	Status             platformruntime.Status
	Revision           uint64
	RequestFingerprint string
	OutputJSON         []byte
	OutputAvailable    bool
	OutputBytes        int64
	OutputOmitted      bool
}

// ChildResultTx is a read-only composition Port, not a history endpoint. It
// enforces exact immediate parent, owner, session and workspace before reading
// output. The coordinator must also verify its own lineage and current rights.
// It cannot invoke, cancel, resume or acknowledge a projection.
func (s *SQLStore) ChildResultTx(ctx context.Context, tx *sql.Tx, parent sharedkernel.Scope, childID string) (ChildResultFacts, error) {
	if tx == nil || parent.ValidateTrusted() != nil || childID == parent.RunID {
		return ChildResultFacts{}, platformruntime.ErrInvalidRequest
	}
	run, err := s.BudgetRunTx(ctx, tx, childID)
	if err != nil {
		return ChildResultFacts{}, err
	}
	child := run.Scope
	if child.ParentRunID != parent.RunID || child.TenantID != parent.TenantID || child.DepartmentID != parent.DepartmentID || child.ApplicationID != parent.ApplicationID || child.PrincipalType != parent.PrincipalType || child.PrincipalID != parent.PrincipalID || child.SessionID != parent.SessionID {
		return ChildResultFacts{}, platformruntime.ErrInvalidRequest
	}
	result := ChildResultFacts{Scope: child, Status: run.Status, Revision: run.Revision, RequestFingerprint: run.RequestFingerprint}
	if run.Status != platformruntime.StatusSucceeded {
		return result, nil
	}
	var revision uint64
	var eventType string
	var output sql.NullString
	// PostgreSQL stores the outcome as JSON. Measure its exact stored UTF-8
	// representation explicitly; octet_length(json) is not a PostgreSQL overload.
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,event_type,CASE WHEN octet_length(output_json::text)<=16384 THEN output_json::text ELSE NULL END,octet_length(output_json::text) FROM platform_execution_outcome WHERE run_id=? FOR SHARE`), childID).Scan(&revision, &eventType, &output, &result.OutputBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return result, nil
	}
	if err != nil {
		return ChildResultFacts{}, err
	}
	if revision != run.Revision || eventType != "task_completed" {
		return ChildResultFacts{}, platformruntime.ErrRevisionConflict
	}
	result.OutputAvailable = output.Valid
	result.OutputOmitted = !output.Valid
	if output.Valid {
		result.OutputJSON = []byte(output.String)
	}
	return result, nil
}
