package main

import (
	"context"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/knowledge"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func (p knowledgePersistence) executeIndexWithStopReceipt(ctx context.Context, run platformruntime.Run, execute func(context.Context) error) error {
	if p.execution == nil || execute == nil {
		return knowledge.ErrInvalidProjection
	}
	err := execute(ctx)
	// Execute is synchronous and must finish all local work/model cleanup before
	// returning. Cleanup still records the exit if shutdown cancelled its context.
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	stopErr := p.execution.RecordInternalTaskStopped(stopCtx, run.Scope, run.LeaseToken, run.Revision)
	return errors.Join(err, stopErr)
}

func (p knowledgePersistence) reconcileIndexStops(ctx context.Context, module *capability.Module) error {
	_, err := p.reconcileIndexStopsPage(ctx, module, "")
	return err
}

func (p knowledgePersistence) reconcileIndexStopsPage(ctx context.Context, module *capability.Module, after string) (string, error) {
	if p.execution == nil || module == nil {
		return after, knowledge.ErrCheckpointUnavailable
	}
	ids, err := p.execution.ListInternalStopping(ctx, after, 16)
	if err != nil {
		return after, err
	}
	if len(ids) == 0 {
		return "", nil
	}
	var failures []error
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return after, err
		}
		run, err := p.execution.GetContext(ctx, id)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if _, _, _, err := indexRunParameters(run); err != nil {
			failures = append(failures, err)
			continue
		}
		if run.Status == platformruntime.StatusRunning {
			// Fence expired owners, but never infer process/graph exit from time.
			run, err = p.execution.BeginRecovery(run.ID, run.Revision, time.Now().UTC())
			if err != nil {
				failures = append(failures, err)
				continue
			}
		}
		if run.Status != platformruntime.StatusCancelling && run.Status != platformruntime.StatusRecovering {
			continue
		}
		if run.LeaseToken != "" {
			stopped, err := p.execution.InternalTaskStopped(ctx, run)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			if !stopped {
				continue
			}
			if err := module.CheckTaskModelQuiescence(ctx, run.Scope); err != nil {
				failures = append(failures, err)
				continue
			}
		}
		if run.Status == platformruntime.StatusRecovering {
			_, err = p.execution.CompleteRecovery(run.ID, run.Revision)
		} else {
			_, err = p.execution.Cancel(run.ID, run.Revision)
		}
		if err != nil && !errors.Is(err, platformruntime.ErrRevisionConflict) {
			failures = append(failures, err)
		}
	}
	return ids[len(ids)-1], errors.Join(failures...)
}
