package execution

import (
	"context"
	"log"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/telemetry"
)

// projectCreation is shared by HTTP, browser, machine and recovery paths.
// projectCreation 由 HTTP、浏览器、机器身份和恢复共用，成功的消费者独立确认。
func projectCreation(ctx context.Context, repository Repository, p platformruntime.CreationProjection, conversation ConversationRecorder, task TaskRecorder) {
	run, err := repository.Get(p.RunID)
	if err != nil {
		telemetry.RecordExecutionReconciliationFailure("creation")
		log.Printf("creation projection pending code=RUN_READ_FAILED")
		return
	}
	if p.ConversationPending && conversation != nil {
		projectionCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if recorder, ok := conversation.(ConversationMessageRecorder); ok && p.MessageID != "" {
			err = recorder.RecordRunWithMessage(projectionCtx, run.Scope, run.RequestJSON, p.MessageID)
		} else {
			err = conversation.RecordRun(projectionCtx, run.Scope, run.RequestJSON)
		}
		cancel()
		if err == nil {
			err = repository.AcknowledgeCreation(run.ID, "conversation")
		}
		if err != nil {
			telemetry.RecordExecutionReconciliationFailure("creation")
			log.Printf("creation projection pending run_id=%s code=CONVERSATION_PROJECTION_FAILED", run.ID)
		}
	}
	if p.TaskPending && task != nil {
		projectionCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if recorder, ok := task.(TaskRecorderWithRequest); ok {
			err = recorder.RecordRunTaskWithRequest(projectionCtx, run.Scope, run.RequestJSON)
		} else {
			err = task.RecordRunTask(projectionCtx, run.Scope)
		}
		cancel()
		if err == nil {
			err = repository.AcknowledgeCreation(run.ID, "task")
		}
		if err != nil {
			telemetry.RecordExecutionReconciliationFailure("creation")
			log.Printf("creation projection pending run_id=%s code=TASK_PROJECTION_FAILED", run.ID)
		}
	}
}

func (m *Module) projectCreated(ctx context.Context, id string) {
	p, err := m.store.GetCreation(id)
	if err != nil {
		telemetry.RecordExecutionReconciliationFailure("creation")
		log.Printf("creation projection pending code=CREATION_READ_FAILED")
		return
	}
	projectCreation(ctx, m.store, p, m.conversation, m.taskRecorder)
}

func (d *Dispatcher) reconcileCreations(ctx context.Context) {
	if d.conversation == nil && d.taskRecorder == nil {
		return
	}
	// Bound each sweep and continue after poison rows without acknowledging them.
	// 有界扫描并越过失败项，但绝不把失败项误确认或删除。
	if !d.creationScanMu.TryLock() {
		return
	}
	defer d.creationScanMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	pending, err := d.repository.PendingCreationsAfter(d.creationCursor, 64)
	if err != nil {
		telemetry.RecordExecutionReconciliationFailure("creation")
		log.Printf("creation reconciliation failed code=CREATION_READ_FAILED")
		return
	}
	if len(pending) == 0 {
		d.creationCursor = ""
		return
	}
	for _, p := range pending {
		if ctx.Err() != nil {
			return
		}
		d.creationCursor = p.RunID
		projectCreation(ctx, d.repository, p, d.conversation, d.taskRecorder)
	}
	if len(pending) < 64 {
		d.creationCursor = ""
	}
}
