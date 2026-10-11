package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/knowledge"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func knowledgeIndexWorkerFailureCode(err error) string {
	if err == nil {
		return "INDEX_TASK_NO_ERROR"
	}
	// Initial admission can fail before the execution supervisor starts. Only
	// publish known protocol codes; provider messages and SQL stay private.
	var modelErr *capability.KnowledgeModelError
	if errors.As(err, &modelErr) {
		switch modelErr.Code {
		case "TASK_MODEL_CONTEXT_DENIED", "CAPABILITY_DENIED", "POLICY_DENIED", "WORKLOAD_AUTHENTICATION_DENIED", "MODEL_ACCESS_DENIED", "MODEL_SELECTION_MISMATCH", "MODEL_GOVERNANCE_UNAVAILABLE", "EXTERNAL_MODEL_DENIED", "INVALID_REQUEST", "UNAUTHENTICATED", "INVALID_SIGNATURE":
			return "INDEX_TASK_" + modelErr.Code
		case "MODEL_LIMIT_EXCEEDED", "CONTEXT_LIMIT_EXCEEDED", "MODEL_BILLING_UNAVAILABLE", "MODEL_IDEMPOTENCY_CONFLICT", "MODEL_RECONCILIATION_REQUIRED", "MODEL_INVOCATION_IN_PROGRESS", "MODEL_BUDGET_EXCEEDED", "MODEL_LEDGER_UNAVAILABLE", "USAGE_LEDGER_UNAVAILABLE", "MODEL_PRICE_UNAVAILABLE", "MODEL_BUDGET_ADMISSION_DEFERRED", "MODEL_BUDGET_UNAVAILABLE", "MODEL_CAPACITY_UNAVAILABLE", "MODEL_CAPACITY_EXCEEDED", "MODEL_SEND_PERSISTENCE_FAILED", "MODEL_CALL_CANCELLED", "MODEL_PROVIDER_FAILED", "KNOWLEDGE_RECONCILIATION_REQUIRED":
			return "INDEX_TASK_" + modelErr.Code
		default:
			return "INDEX_TASK_MODEL_ADMISSION_FAILED"
		}
	}
	if errors.Is(err, errIndexSecretUnavailable) {
		return "INDEX_TASK_WORKLOAD_SECRET_UNAVAILABLE"
	}
	var phased interface{ InternalTaskPhase() string }
	if errors.As(err, &phased) {
		switch phased.InternalTaskPhase() {
		case "authorize":
			return "INDEX_TASK_AUTHORIZATION_FAILED"
		case "execute":
			if errors.Is(err, context.DeadlineExceeded) {
				return "INDEX_TASK_EXECUTION_TIMEOUT"
			}
			if errors.Is(err, context.Canceled) {
				return "INDEX_TASK_EXECUTION_STOPPED"
			}
			return "INDEX_TASK_EXECUTION_FAILED"
		case "finalize":
			if errors.Is(err, execution.ErrExecutionOutcomeUnconfirmed) {
				return "INDEX_TASK_OUTCOME_FENCE_UNCONFIRMED"
			}
			return "INDEX_TASK_FINALIZATION_FAILED"
		case "load":
			return "INDEX_TASK_RUN_LOAD_FAILED"
		case "session_lease":
			return "INDEX_TASK_SESSION_LEASE_FAILED"
		}
	}
	if errors.Is(err, context.Canceled) {
		return "INDEX_TASK_WORKER_STOPPING"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "INDEX_TASK_SCHEDULER_TIMEOUT"
	}
	if errors.Is(err, platformruntime.ErrLeaseConflict) {
		return "INDEX_TASK_LEASE_CONFLICT"
	}
	if errors.Is(err, platformruntime.ErrRevisionConflict) {
		return "INDEX_TASK_REVISION_CONFLICT"
	}
	return "INDEX_TASK_PENDING_RECONCILIATION"
}

type indexWorkloadCredentialResolver interface {
	Resolve(context.Context, sharedkernel.Scope) (capability.TaskWorkloadCredential, error)
}

func indexRunParameters(run platformruntime.Run) (knowledge.ProjectionScope, knowledge.IndexConfig, bool, error) {
	var command contract.ExecuteRequest
	var config knowledge.IndexConfig
	empty := knowledge.ProjectionScope{}
	if json.Unmarshal(run.RequestJSON, &command) != nil || command.InputSchema != execution.KnowledgeIndexInputSchema || run.Scope.ValidateTrusted() != nil {
		return empty, config, false, knowledge.ErrInvalidProjection
	}
	id, _ := command.Input["knowledge_id"].(string)
	mode, _ := command.Input["index_mode"].(string)
	raw, err := json.Marshal(command.Input["index_config"])
	if err != nil || json.Unmarshal(raw, &config) != nil || id == "" || len(id) > 256 {
		return empty, config, false, knowledge.ErrInvalidProjection
	}
	request := knowledge.IndexTaskRequest{InstallationID: run.Scope.InstallationID, IdempotencyKey: command.IdempotencyKey, Mode: mode, Config: knowledge.IndexSettings{Dimensions: config.Dimensions, WindowRunes: config.WindowRunes, OverlapRunes: config.OverlapRunes, MaximumDocuments: config.MaximumDocuments, MaximumChunks: config.MaximumChunks}}
	if _, err := request.IndexConfig(config.EmbeddingModelVersion); err != nil {
		return empty, config, false, err
	}
	return knowledge.ProjectionScope{TenantID: run.Scope.TenantID, DepartmentID: run.Scope.DepartmentID, ApplicationID: run.Scope.ApplicationID, KnowledgeID: id}, config, mode == "incremental", nil
}

func (p knowledgePersistence) indexWorker(signer execution.MachineRunContextSigner, module *capability.Module, secrets indexWorkloadCredentialResolver) func(context.Context) error {
	return func(ctx context.Context) error {
		if p.execution == nil || p.db == nil || signer == nil || module == nil || secrets == nil {
			return knowledge.ErrCheckpointUnavailable
		}
		const ttl = 30 * time.Second
		stopCursor := ""
		scheduler := execution.InternalTaskScheduler{Repository: p.execution, InputSchema: execution.KnowledgeIndexInputSchema, LeaseTTL: ttl, BeforeSweep: func(ctx context.Context) error {
			var err error
			stopCursor, err = p.reconcileIndexStopsPage(ctx, module, stopCursor)
			return err
		}, Authorize: func(ctx context.Context, owner sharedkernel.Scope) error {
			run, err := p.execution.GetContext(ctx, owner.RunID)
			if err != nil {
				return err
			}
			if run.Scope != owner {
				return knowledge.ErrManagementDenied
			}
			if _, err := secrets.Resolve(ctx, owner); err != nil {
				return err
			}
			scope, _, _, err := indexRunParameters(run)
			if err != nil {
				return err
			}
			tx, err := p.db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			if err := p.authorize(ctx, tx, owner, scope); err != nil {
				return err
			}
			return tx.Commit()
		}, Execute: func(ctx context.Context, run platformruntime.Run) error {
			return p.executeIndexWithStopReceipt(ctx, run, func(ctx context.Context) error {
				scope, config, incremental, err := indexRunParameters(run)
				if err != nil {
					return err
				}
				credential, err := secrets.Resolve(ctx, run.Scope)
				if err != nil {
					return err
				}
				return p.executeIssuedIndexTask(ctx, run, scope, config, incremental, signer, module, credential, ttl)
			})
		}}
		return scheduler.Run(ctx, time.Second, func(err error) {
			if !errors.Is(err, context.Canceled) {
				log.Printf("knowledge index worker code=%s", knowledgeIndexWorkerFailureCode(err))
			}
		})
	}
}
