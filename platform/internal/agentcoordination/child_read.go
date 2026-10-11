package agentcoordination

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type ChildReadRequest struct {
	OperationKey string `json:"operation_key"`
	Ordinal      int    `json:"ordinal"`
}

type ChildResult struct {
	Version           string         `json:"version"`
	ParentRunID       string         `json:"parent_run_id"`
	ChildRunID        string         `json:"child_run_id"`
	ChildKey          string         `json:"child_key"`
	InputFingerprint  string         `json:"input_fingerprint"`
	OperationKey      string         `json:"operation_key"`
	Ordinal           int            `json:"ordinal"`
	Status            string         `json:"status"`
	ExecutionRevision uint64         `json:"execution_revision"`
	OutputSchema      string         `json:"output_schema"`
	Output            map[string]any `json:"output"`
	OutputBytes       int64          `json:"output_bytes"`
	OutputOmitted     bool           `json:"output_omitted"`
	OutputDigest      string         `json:"output_digest,omitempty"`
	InstructionTrust  string         `json:"instruction_trust"`
}

type ChildExecutionRead struct {
	Parent ParentFacts
	Target Target
	Depth  int
	RunID  string
}

type ChildExecutionResult struct {
	RequestFingerprint string
	Scope              sharedkernel.Scope
	Status             string
	Revision           uint64
	Output             map[string]any
	OutputBytes        int64
	OutputOmitted      bool
	OutputDigest       string
}

type ChildExecutionReader interface {
	ReadChild(context.Context, *sql.Tx, ChildExecutionRead) (ChildExecutionResult, error)
}
type ChildResultStore interface {
	ReadChild(context.Context, sharedkernel.Scope, ChildReadRequest) (ChildResult, error)
}

type ChildResultDisclosureStore interface {
	CheckChildResult(context.Context, sharedkernel.Scope, ChildReadRequest, ChildResult) error
}

// CheckChildResult repeats target/owner authority at the final disclosure
// boundary. It grants no execution and never repairs a missing result.
func (r *Router) CheckChildResult(ctx context.Context, scope sharedkernel.Scope, request ChildReadRequest, result ChildResult) error {
	if r == nil || scope.ValidateTrusted() != nil {
		return ErrDenied
	}
	store, ok := r.store.(ChildResultDisclosureStore)
	if !ok {
		return ErrUnavailable
	}
	return store.CheckChildResult(ctx, scope, request, result)
}

func (s *SQLRouteStore) CheckChildResult(ctx context.Context, scope sharedkernel.Scope, request ChildReadRequest, result ChildResult) error {
	if s == nil || s.db == nil || s.authority == nil || scope.ValidateTrusted() != nil || !identifier(request.OperationKey) || request.Ordinal < 0 || request.Ordinal > 15 {
		return ErrDenied
	}
	reader, ok := s.children.(ChildExecutionReader)
	if !ok {
		return ErrUnavailable
	}
	if result.Version != "agent-child-result/v1" || result.ParentRunID != scope.RunID || result.OperationKey != request.OperationKey || result.Ordinal != request.Ordinal || !hashValue(result.ChildKey) || result.ChildRunID != "child-"+result.ChildKey[:48] || result.InstructionTrust != "untrusted_data" {
		return ErrDenied
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	unit := &sqlRouteTransaction{ctx: ctx, tx: tx, store: s, scope: scope, key: routeScopeKey(scope)}
	parent, err := unit.Parent(ctx, scope)
	if err != nil {
		return err
	}
	plan, found, err := unit.Existing(request.OperationKey)
	if err != nil {
		return err
	}
	if !found || !parent.Active || parent.Policy == nil || plan.Version != "agent-route/v1" || plan.ParentRunID != scope.RunID || plan.PolicyHash != parent.PolicyHash || plan.ChildDepth != parent.Depth+1 || plan.EvidenceDigest != digest(plan.Targets) || request.Ordinal >= len(plan.Targets) || result.ChildKey != digest([]any{unit.key, plan.OperationKey, request.Ordinal, plan.Fingerprint}) {
		return ErrDenied
	}
	target := plan.Targets[request.Ordinal]
	if result.OutputSchema != target.OutputSchema || !eligible(parent, target, plan.TaskType) || unit.AuthorizeTarget(ctx, parent, target) != nil {
		return ErrDenied
	}
	var childID, fingerprint sql.NullString
	var key, status string
	var revision uint64
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT child_key,status,revision,child_run_id,request_fingerprint FROM platform_agent_child_reservation WHERE parent_key=? AND operation_key=? AND ordinal=? FOR SHARE`), unit.key, request.OperationKey, request.Ordinal).Scan(&key, &status, &revision, &childID, &fingerprint)
	if err != nil {
		return err
	}
	if key != result.ChildKey || !childID.Valid || childID.String != result.ChildRunID || !fingerprint.Valid || !hashValue(fingerprint.String) || revision < 3 {
		return ErrDenied
	}
	switch status {
	case "accepted", "running", "completed", "failed", "cancelled", "uncertain":
	default:
		return ErrDenied
	}
	current, err := reader.ReadChild(ctx, tx, ChildExecutionRead{Parent: parent, Target: target, Depth: plan.ChildDepth, RunID: childID.String})
	if err != nil {
		return err
	}
	child := current.Scope
	if child.ValidateTrusted() != nil || child.RunID != result.ChildRunID || child.ParentRunID != scope.RunID || child.TenantID != scope.TenantID || child.DepartmentID != scope.DepartmentID || child.ApplicationID != scope.ApplicationID || child.PrincipalType != scope.PrincipalType || child.PrincipalID != scope.PrincipalID || child.SessionID != scope.SessionID || child.AgentID != target.AgentID || child.InstallationID != target.InstallationID || child.AgentInstanceID != target.InstallationID || child.AgentVersionID != target.VersionID {
		return ErrDenied
	}
	if current.RequestFingerprint != fingerprint.String || result.InputFingerprint != current.RequestFingerprint || current.Status != result.Status || current.Revision != result.ExecutionRevision || current.OutputDigest != result.OutputDigest || current.OutputBytes != result.OutputBytes || current.OutputOmitted != result.OutputOmitted || (current.Output == nil) != (result.Output == nil) {
		return ErrConflict
	}
	// The authority holds permission-read continuity and execution locks in this
	// transaction. Repeat the selected target immediately before completing it.
	if s.authority.AuthorizeTarget(ctx, tx, parent, target) != nil {
		return ErrDenied
	}
	return tx.Commit()
}

func (r *Router) ReadChild(ctx context.Context, scope sharedkernel.Scope, request ChildReadRequest) (ChildResult, error) {
	if r == nil || scope.ValidateTrusted() != nil {
		return ChildResult{}, ErrDenied
	}
	store, ok := r.store.(ChildResultStore)
	if !ok {
		return ChildResult{}, ErrUnavailable
	}
	return store.ReadChild(ctx, scope, request)
}

func (s *SQLRouteStore) ReadChild(ctx context.Context, scope sharedkernel.Scope, request ChildReadRequest) (ChildResult, error) {
	if s == nil {
		return ChildResult{}, ErrUnavailable
	}
	reader, ok := s.children.(ChildExecutionReader)
	if !ok {
		return ChildResult{}, ErrUnavailable
	}
	if !identifier(request.OperationKey) || request.Ordinal < 0 || request.Ordinal > 15 {
		return ChildResult{}, ErrDenied
	}
	var result ChildResult
	err := s.Transact(ctx, scope, func(port RouteTransaction) error {
		unit, ok := port.(*sqlRouteTransaction)
		if !ok {
			return ErrUnavailable
		}
		parent, err := unit.Parent(ctx, scope)
		if err != nil {
			return err
		}
		plan, found, err := unit.Existing(request.OperationKey)
		if err != nil {
			return err
		}
		if !found || parent.Policy == nil || !parent.Active || plan.Version != "agent-route/v1" || plan.ParentRunID != scope.RunID || plan.PolicyHash != parent.PolicyHash || plan.ChildDepth != parent.Depth+1 || plan.EvidenceDigest != digest(plan.Targets) || request.Ordinal >= len(plan.Targets) {
			return ErrDenied
		}
		result, err = unit.readChildResult(ctx, parent, plan, request.Ordinal, reader)
		if err != nil {
			return err
		}
		unit.auditAction = "agent.child_read"
		return unit.Audit(plan)
	})
	if err != nil {
		return ChildResult{}, err
	}
	return result, nil
}

// Shared bounded child read for individual and whole-plan snapshots. The
// caller owns the parent fence/plan transaction and records its audit once.
func (unit *sqlRouteTransaction) readChildResult(ctx context.Context, parent ParentFacts, plan RoutePlan, ordinal int, reader ChildExecutionReader) (ChildResult, error) {
	empty := ChildResult{}
	scope := unit.scope
	if parent.Scope != scope || ordinal < 0 || ordinal >= len(plan.Targets) || !parent.Active || parent.Policy == nil || plan.Version != "agent-route/v1" || plan.ParentRunID != scope.RunID || plan.PolicyHash != parent.PolicyHash || plan.ChildDepth != parent.Depth+1 || plan.EvidenceDigest != digest(plan.Targets) {
		return empty, ErrDenied
	}
	target := plan.Targets[ordinal]
	if !eligible(parent, target, plan.TaskType) || unit.AuthorizeTarget(ctx, parent, target) != nil {
		return empty, ErrDenied
	}
	var key, status string
	var childID, fingerprint sql.NullString
	var revision uint64
	err := unit.tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT child_key,status,revision,child_run_id,request_fingerprint FROM platform_agent_child_reservation WHERE parent_key=? AND operation_key=? AND ordinal=? FOR SHARE`), unit.key, plan.OperationKey, ordinal).Scan(&key, &status, &revision, &childID, &fingerprint)
	if err != nil {
		return empty, err
	}
	if key != digest([]any{unit.key, plan.OperationKey, ordinal, plan.Fingerprint}) || !childID.Valid || childID.String != "child-"+key[:48] || !fingerprint.Valid || !hashValue(fingerprint.String) || revision < 3 {
		return empty, ErrConflict
	}
	switch status {
	case "accepted", "running", "completed", "failed", "cancelled", "uncertain":
	default:
		return empty, ErrConflict
	}
	read, err := reader.ReadChild(ctx, unit.tx, ChildExecutionRead{Parent: parent, Target: target, Depth: plan.ChildDepth, RunID: childID.String})
	if err != nil {
		return empty, err
	}
	child := read.Scope
	if child.ValidateTrusted() != nil || child.RunID != childID.String || child.ParentRunID != scope.RunID || child.PrincipalID != scope.PrincipalID || child.PrincipalType != scope.PrincipalType || child.SessionID != scope.SessionID || child.TenantID != scope.TenantID || child.DepartmentID != scope.DepartmentID || child.ApplicationID != scope.ApplicationID || child.AgentID != target.AgentID || child.InstallationID != target.InstallationID || child.AgentInstanceID != target.InstallationID || child.AgentVersionID != target.VersionID || read.RequestFingerprint != fingerprint.String || read.Revision == 0 || read.OutputBytes < 0 {
		return empty, ErrDenied
	}
	switch read.Status {
	case "accepted", "running", "waiting", "completed", "failed", "cancelled", "cancelling", "recovering", "uncertain":
	default:
		return empty, ErrConflict
	}
	if read.Output != nil {
		encoded, err := json.Marshal(read.Output)
		if err != nil || len(encoded) > 16384 || read.Status != "completed" || read.OutputOmitted || read.OutputBytes == 0 || read.OutputBytes > 16384 || !hashValue(read.OutputDigest) {
			return empty, ErrConflict
		}
	} else if read.OutputDigest != "" || (read.OutputOmitted && (read.Status != "completed" || read.OutputBytes <= 16384)) || (!read.OutputOmitted && (read.Status == "completed" || read.OutputBytes != 0)) {
		return empty, ErrConflict
	}
	// Expose the already verified admission fingerprint so consumers can bind
	// cited output to the frozen child input, rather than infer it from text.
	return ChildResult{Version: "agent-child-result/v1", ParentRunID: scope.RunID, ChildRunID: child.RunID, ChildKey: key, InputFingerprint: read.RequestFingerprint, OperationKey: plan.OperationKey, Ordinal: ordinal, Status: read.Status, ExecutionRevision: read.Revision, OutputSchema: target.OutputSchema, Output: read.Output, OutputBytes: read.OutputBytes, OutputOmitted: read.OutputOmitted, OutputDigest: read.OutputDigest, InstructionTrust: "untrusted_data"}, nil
}
