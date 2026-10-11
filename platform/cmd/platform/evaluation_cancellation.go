package main

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/evaluationproduct"
	"github.com/lexagent/platform/internal/execution"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

type evaluationCancellationCoordinator struct {
	authority    *evaluationExecutionAuthority
	runs         *execution.SQLStore
	products     *evaluationproduct.SQLStore
	execution    *execution.Module
	capabilities *capability.Module
}

// Read only recorded depth-zero children and verify their frozen case
// provenance. Product head locking shares the new-admission fence. Browser
// input, fresh run grants and guessed child IDs confer no control authority.
func (c evaluationCancellationCoordinator) children(ctx context.Context, expected evaluationproduct.Resource) ([]execution.BudgetRunFacts, error) {
	if c.authority == nil || c.runs == nil || c.products == nil || expected.Kind != evaluationproduct.KindRun || expected.CreatedBy == "" || (expected.Status != "cancelling" && expected.Status != "cancelled") {
		return nil, evaluationproduct.ErrUnavailable
	}
	tx, err := c.runs.DB().BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	parent, err := c.products.GetTx(ctx, tx, expected.Scope, evaluationproduct.KindRun, expected.ID, true)
	if err != nil || parent.Revision != expected.Revision || parent.Status != expected.Status || parent.CreatedBy != expected.CreatedBy {
		return nil, evaluationproduct.ErrConflict
	}
	snapshot, err := evaluationproduct.ResolveHistoricalExecutionSnapshot(ctx, c.products, parent.Scope, parent)
	if err != nil {
		return nil, err
	}
	var data evaluationproduct.RunData
	if json.Unmarshal(parent.Data, &data) != nil {
		return nil, evaluationproduct.ErrInvalid
	}
	ids, err := c.runs.EvaluationBatchChildIDsTx(ctx, tx, execution.EvaluationBatchParent{
		TenantID: parent.Scope.TenantID, DepartmentID: parent.Scope.DepartmentID,
		ApplicationID: parent.Scope.ApplicationID, EvaluationID: parent.ID,
	})
	if err != nil {
		return nil, err
	}
	children := make([]execution.BudgetRunFacts, 0, len(ids))
	caseIndices := make(map[string]int, len(ids))
	for _, id := range ids {
		facts, err := c.runs.BudgetRunReadTx(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		var request contract.ExecuteRequest
		if json.Unmarshal(facts.RequestJSON, &request) != nil || request.Validate() != nil || request.Operation != "invoke" || request.ResumeInput != nil || !evaluationCreatorMatches(parent, facts.Scope) || request.Scope != evaluationContractScope(facts.Scope) || !evaluationScopeMatchesSnapshot(facts.Scope, snapshot.AgentID(), snapshot.AgentVersionID()) {
			return nil, evaluationproduct.ErrForbidden
		}
		fingerprint, err := contract.CanonicalExecuteBodyHash(request)
		index, valid := evaluationInvocationIndex(parent.ID, data.IdempotencyKey, facts.Scope, request, len(snapshot.Dataset().Cases))
		if err != nil || fingerprint != facts.RequestFingerprint || !valid || facts.Scope.TraceID != evaluationTraceID(parent.ID, index) || !evaluationCaseRequestMatches(snapshot.Dataset().Cases[index], request.Input) {
			return nil, evaluationproduct.ErrForbidden
		}
		children = append(children, facts)
		caseIndices[id] = index
	}
	// Cases execute serially. Undo the newest verified case first, rather
	// than sorting hashed Run IDs, which have no causal ordering.
	sort.Slice(children, func(i, j int) bool {
		return caseIndices[children[i].Scope.RunID] > caseIndices[children[j].Scope.RunID]
	})
	return children, tx.Commit()
}

type evaluationCaseCancellationControls struct {
	stop        func(context.Context, execution.BudgetRunFacts) error
	stopped     func(context.Context, execution.BudgetRunFacts) (bool, error)
	compensate  func(context.Context, execution.BudgetRunFacts) error
	compensated func(context.Context, execution.BudgetRunFacts) (bool, error)
}

// Stop all active cases first. Then admit only one completed-case inverse
// at a time in reverse case order. This preserves the causal stamps of
// resources written by more than one case, including external API values.
// A pending or ambiguous inverse must never be bypassed by an earlier case.
func requestEvaluationCaseCancellation(ctx context.Context, children []execution.BudgetRunFacts, controls evaluationCaseCancellationControls) error {
	if controls.stop == nil || controls.stopped == nil || controls.compensate == nil || controls.compensated == nil {
		return evaluationproduct.ErrUnavailable
	}
	for _, child := range children {
		if child.Status == platformruntime.StatusSucceeded || child.Status == platformruntime.StatusFailed || child.Status == platformruntime.StatusCancelled {
			continue
		}
		if err := controls.stop(ctx, child); err != nil {
			return err
		}
	}
	for _, child := range children {
		if child.Status == platformruntime.StatusSucceeded || child.Status == platformruntime.StatusFailed {
			continue
		}
		stopped, err := controls.stopped(ctx, child)
		if err != nil {
			return err
		}
		if !stopped {
			return nil
		}
	}
	for _, child := range children {
		if child.Status != platformruntime.StatusSucceeded && child.Status != platformruntime.StatusFailed {
			continue
		}
		if err := controls.compensate(ctx, child); err != nil {
			return err
		}
		complete, err := controls.compensated(ctx, child)
		if err != nil {
			return err
		}
		if !complete {
			return nil
		}
	}
	return nil
}

func (c evaluationCancellationCoordinator) RequestChildStops(ctx context.Context, parent evaluationproduct.Resource) error {
	if c.execution == nil {
		return evaluationproduct.ErrUnavailable
	}
	children, err := c.children(ctx, parent)
	if err != nil {
		return err
	}
	return requestEvaluationCaseCancellation(ctx, children, evaluationCaseCancellationControls{
		stop: func(ctx context.Context, child execution.BudgetRunFacts) error {
			return c.execution.RequestSynchronousStop(ctx, child.Scope)
		},
		stopped: func(ctx context.Context, child execution.BudgetRunFacts) (bool, error) {
			_, proof, err := c.runs.ReadCancellationProjection(ctx, child.Scope)
			return err == nil && proof != nil && proof.Disposition == "verified", err
		},
		compensate: func(ctx context.Context, child execution.BudgetRunFacts) error {
			return c.runs.RequestCompletedEvaluationCompensation(ctx, child.Scope)
		},
		compensated: func(ctx context.Context, child execution.BudgetRunFacts) (bool, error) {
			return c.runs.CompletedEvaluationCompensationComplete(ctx, child.Scope)
		},
	})
}

func (c evaluationCancellationCoordinator) CancellationComplete(ctx context.Context, parent evaluationproduct.Resource) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	children, err := c.children(ctx, parent)
	if err != nil {
		return false, err
	}
	for _, child := range children {
		switch child.Status {
		case platformruntime.StatusCancelled:
			_, proof, err := c.runs.ReadCancellationProjection(ctx, child.Scope)
			if err != nil {
				return false, err
			}
			if proof == nil || proof.Disposition != "verified" {
				return false, nil
			}
		case platformruntime.StatusSucceeded, platformruntime.StatusFailed:
			// Completed cases retain their historical outcomes. The separate
			// durable control job proves every registered inverse before the
			// product batch can publish a cancelled terminal state.
			complete, err := c.runs.CompletedEvaluationCompensationComplete(ctx, child.Scope)
			if err != nil {
				return false, err
			}
			if !complete {
				return false, nil
			}
		default:
			return false, nil
		}
	}
	return true, nil
}

var _ evaluationproduct.CancellationCoordinator = evaluationCancellationCoordinator{}
