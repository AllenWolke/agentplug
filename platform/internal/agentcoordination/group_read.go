package agentcoordination

import (
	"context"
	"encoding/json"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type GroupReadRequest struct {
	OperationKey string `json:"operation_key"`
}

type GroupResult struct {
	Version          string        `json:"version"`
	ParentRunID      string        `json:"parent_run_id"`
	OperationKey     string        `json:"operation_key"`
	Status           string        `json:"status"`
	Terminal         bool          `json:"terminal"`
	OutputsComplete  bool          `json:"outputs_complete"`
	Completed        int           `json:"completed"`
	Failed           int           `json:"failed"`
	Cancelled        int           `json:"cancelled"`
	Pending          int           `json:"pending"`
	OutputsOmitted   int           `json:"outputs_omitted"`
	Children         []ChildResult `json:"children"`
	InstructionTrust string        `json:"instruction_trust"`
}

type GroupResultStore interface {
	ReadGroup(context.Context, sharedkernel.Scope, GroupReadRequest) (GroupResult, error)
	CheckGroupResult(context.Context, sharedkernel.Scope, GroupReadRequest, GroupResult) error
}

func (r *Router) ReadGroup(ctx context.Context, scope sharedkernel.Scope, request GroupReadRequest) (GroupResult, error) {
	if r == nil || scope.ValidateTrusted() != nil {
		return GroupResult{}, ErrDenied
	}
	store, ok := r.store.(GroupResultStore)
	if !ok {
		return GroupResult{}, ErrUnavailable
	}
	return store.ReadGroup(ctx, scope, request)
}

func (r *Router) CheckGroupResult(ctx context.Context, scope sharedkernel.Scope, request GroupReadRequest, result GroupResult) error {
	if r == nil || scope.ValidateTrusted() != nil {
		return ErrDenied
	}
	store, ok := r.store.(GroupResultStore)
	if !ok {
		return ErrUnavailable
	}
	return store.CheckGroupResult(ctx, scope, request, result)
}

// Group reads require all planned slots to have been admitted. Missing or
// uncertain admission is reconciled through individual reads, never created here.
func (s *SQLRouteStore) ReadGroup(ctx context.Context, scope sharedkernel.Scope, request GroupReadRequest) (GroupResult, error) {
	if s == nil || !identifier(request.OperationKey) {
		return GroupResult{}, ErrDenied
	}
	reader, ok := s.children.(ChildExecutionReader)
	if !ok {
		return GroupResult{}, ErrUnavailable
	}
	var result GroupResult
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
		if !found {
			return ErrConflict
		}
		result, err = unit.readGroupResult(ctx, parent, plan, reader)
		if err != nil {
			return err
		}
		unit.auditAction = "agent.group_read"
		return unit.Audit(plan)
	})
	if err != nil {
		return GroupResult{}, err
	}
	return result, nil
}

func (unit *sqlRouteTransaction) readGroupResult(ctx context.Context, parent ParentFacts, plan RoutePlan, reader ChildExecutionReader) (GroupResult, error) {
	empty := GroupResult{}
	if len(plan.Targets) < 1 || len(plan.Targets) > 16 {
		return empty, ErrConflict
	}
	result := GroupResult{Version: "agent-group-result/v1", ParentRunID: unit.scope.RunID, OperationKey: plan.OperationKey, InstructionTrust: "untrusted_data", Children: make([]ChildResult, 0, len(plan.Targets))}
	uncertain := false
	for ordinal := range plan.Targets {
		child, err := unit.readChildResult(ctx, parent, plan, ordinal, reader)
		if err != nil {
			return empty, err
		}
		result.Children = append(result.Children, child)
		switch child.Status {
		case "completed":
			result.Completed++
		case "failed":
			result.Failed++
		case "cancelled":
			result.Cancelled++
		default:
			result.Pending++
		}
		uncertain = uncertain || child.Status == "uncertain"
		if child.OutputOmitted {
			result.OutputsOmitted++
		}
	}
	result.Terminal = result.Pending == 0
	result.OutputsComplete = result.Terminal && result.Completed == len(result.Children) && result.OutputsOmitted == 0
	switch {
	case uncertain:
		result.Status = "uncertain"
	case !result.Terminal:
		result.Status = "in_progress"
	case result.Failed > 0:
		result.Status = "failed"
	case result.Cancelled > 0:
		result.Status = "cancelled"
	default:
		result.Status = "completed"
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 524288 {
		return empty, ErrConflict
	}
	return result, nil
}

// Final whole-plan disclosure check re-reads all children in one transaction,
// rejects a changed snapshot/authority and neither re-dispatches nor audits twice.
func (s *SQLRouteStore) CheckGroupResult(ctx context.Context, scope sharedkernel.Scope, request GroupReadRequest, result GroupResult) error {
	if s == nil || s.db == nil || s.authority == nil || scope.ValidateTrusted() != nil || !identifier(request.OperationKey) || result.Version != "agent-group-result/v1" || result.ParentRunID != scope.RunID || result.OperationKey != request.OperationKey {
		return ErrDenied
	}
	reader, ok := s.children.(ChildExecutionReader)
	if !ok {
		return ErrUnavailable
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
	if !found {
		return ErrDenied
	}
	current, err := unit.readGroupResult(ctx, parent, plan, reader)
	if err != nil {
		return err
	}
	if digest(current) != digest(result) {
		return ErrConflict
	}
	for _, target := range unit.targetChecks {
		if s.authority.AuthorizeTarget(ctx, tx, parent, target) != nil {
			return ErrDenied
		}
	}
	return tx.Commit()
}
