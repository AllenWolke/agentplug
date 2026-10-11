package execution

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// InvokeSynchronous is the shared governed Run Port for evaluation callers.
// The caller gets a durable terminal response. A waiting review is exposed by
// the normal Run APIs and can only be resumed by the authorized review flow.
// InvokeSynchronous 是评测共用的受控 Run 端口，返回持久化结果而非无记录直连结果。
func (m *Module) InvokeSynchronous(ctx context.Context, scope sharedkernel.Scope, endpoint string, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	if m.dispatcher == nil || m.dispatcher.gateway == nil || m.dispatcher.signer == nil || m.dispatcher.authorize == nil {
		return contract.ExecuteResponse{}, errors.New("governed synchronous execution unavailable")
	}
	if err := scope.ValidateTrusted(); err != nil {
		return contract.ExecuteResponse{}, err
	}
	if err := request.Validate(); err != nil {
		return contract.ExecuteResponse{}, err
	}
	expected := contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, SessionID: scope.SessionID, RunID: scope.RunID, ParentRunID: scope.ParentRunID, InstallationID: scope.InstallationID, AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID}
	if request.Operation != "invoke" || request.ResumeInput != nil || request.Scope != expected {
		return contract.ExecuteResponse{}, platformruntime.ErrInvalidRequest
	}
	if ctx.Err() != nil {
		return contract.ExecuteResponse{}, ctx.Err()
	}
	// Evaluation children are admitted by the product-specific verifier before
	// persistence. A client-selected parent ID cannot opt into this path: the
	// verifier must match the exact live product Run and immutable case input.
	// Ordinary root Runs retain the dispatcher authorizer and machine root pin.
	authorize := func() error { return m.dispatcher.authorize(ctx, scope) }
	if scope.ParentRunID != "" {
		if request.Scope.DelegationDepth != 0 || m.synchronousRunAuthorizer == nil {
			return contract.ExecuteResponse{}, contract.ErrPermissionDenied
		}
		authorize = func() error { return m.synchronousRunAuthorizer(ctx, scope, endpoint, request) }
	}
	// Replay remains an authorized read; a previously saved response must not
	// bypass a revoked IAM grant. / 回放也是受控读取，不能绕过已撤销授权。
	if authorize() != nil {
		return contract.ExecuteResponse{}, contract.ErrPermissionDenied
	}
	fingerprint, err := contract.CanonicalExecuteBodyHash(request)
	if err != nil {
		return contract.ExecuteResponse{}, err
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return contract.ExecuteResponse{}, err
	}
	created, err := m.store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: request.IdempotencyKey, Fingerprint: fingerprint, RequestJSON: raw, AgentEndpoint: endpoint})
	if err != nil {
		return contract.ExecuteResponse{}, err
	}
	m.projectCreated(ctx, created.Run.ID)
	// The same Dispatcher checks IAM, claims/renews its lease and commits the
	// result. A concurrent owner is awaited; it is never forcefully replaced.
	// 同一 Dispatcher 重验 IAM、领取/续租并保存结果；并发 owner 只能等待，不能抢占。
	if err := m.dispatcher.dispatch(ctx, created.Run); err != nil && !errors.Is(err, platformruntime.ErrLeaseConflict) {
		if ctx.Err() != nil {
			return contract.ExecuteResponse{}, m.synchronousInterrupted(ctx, scope)
		}
		return contract.ExecuteResponse{}, err
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	nextAuthorization := time.Now()
	for {
		if ctx.Err() != nil {
			return contract.ExecuteResponse{}, m.synchronousInterrupted(ctx, scope)
		}
		run, err := m.store.Get(created.Run.ID)
		if err != nil {
			return contract.ExecuteResponse{}, err
		}
		if run.ID != scope.RunID || run.Scope != scope || run.AgentEndpoint != endpoint || run.IdempotencyKey != request.IdempotencyKey {
			return contract.ExecuteResponse{}, platformruntime.ErrInvalidRequest
		}
		terminal := run.Status == platformruntime.StatusSucceeded || run.Status == platformruntime.StatusFailed || run.Status == platformruntime.StatusCancelled
		// Recheck live parent/IAM/target authority while waiting, and always
		// before returning a result. Never resume a review or redispatch here.
		// 等待时重查实时授权，结果返回前再查一次；不自动审核、恢复或重放。
		if terminal || !time.Now().Before(nextAuthorization) {
			if authorize() != nil {
				if ctx.Err() != nil {
					return contract.ExecuteResponse{}, m.synchronousInterrupted(ctx, scope)
				}
				m.stopSynchronousRun(scope)
				return contract.ExecuteResponse{}, contract.ErrPermissionDenied
			}
			nextAuthorization = time.Now().Add(500 * time.Millisecond)
		}
		if terminal {
			outcome, err := m.store.GetOutcome(run.ID)
			if err != nil {
				return contract.ExecuteResponse{}, err
			}
			if outcome.Revision != run.Revision {
				return contract.ExecuteResponse{}, platformruntime.ErrRevisionConflict
			}
			var output map[string]any
			if err := json.Unmarshal(outcome.OutputJSON, &output); err != nil {
				return contract.ExecuteResponse{}, err
			}
			response := contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: run.ID, Status: string(run.Status), Output: output}
			if run.Status == platformruntime.StatusFailed {
				code, _ := outcome.EventPayload["code"].(string)
				if code == "" {
					code = "AGENT_EXECUTION_FAILED"
				}
				response.Error = &contract.AppError{Code: code, Message: "Agent execution failed", Retryable: false}
			}
			return response, nil
		}
		select {
		case <-ctx.Done():
			return contract.ExecuteResponse{}, m.synchronousInterrupted(ctx, scope)
		case <-ticker.C:
		}
	}
}

// A case deadline requests a governed stop. Worker shutdown/transport loss is
// different: preserve the same durable child for recovery unless the product
// parent itself has been explicitly aborted. No unknown effect is replayed.
// 用例超时请求受控停止；Worker退出保留原子Run，父评测明确终止时才取消。
func (m *Module) synchronousInterrupted(ctx context.Context, scope sharedkernel.Scope) error {
	err := ctx.Err()
	stop := errors.Is(err, context.DeadlineExceeded)
	if errors.Is(err, context.Canceled) && m.synchronousRunAbortCheck != nil {
		control, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		aborted, checkErr := m.synchronousRunAbortCheck(control, scope)
		cancel()
		stop = checkErr == nil && aborted
	}
	if stop {
		m.stopSynchronousRun(scope)
	}
	return err
}

func (m *Module) stopSynchronousRun(scope sharedkernel.Scope) {
	control, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for attempt := 0; attempt < 3; attempt++ {
		run, err := m.store.Get(scope.RunID)
		if err != nil || run.Scope != scope {
			break
		}
		if run.Status == platformruntime.StatusSucceeded || run.Status == platformruntime.StatusFailed || run.Status == platformruntime.StatusCancelled {
			return
		}
		if _, err = m.requestCancellation(control, run, run.Revision); err == nil {
			return
		} else if !errors.Is(err, platformruntime.ErrRevisionConflict) {
			break
		}
	}
	// Do not replace missing stop evidence with a fabricated terminal state.
	log.Printf("synchronous stop pending run_id=%q code=STOP_INTENT_UNCONFIRMED", scope.RunID)
}

// Trusted composition-only stop for an already recorded Evaluation child.
// The persisted parent must be explicitly aborted; this grants no execution.
func (m *Module) RequestSynchronousStop(ctx context.Context, scope sharedkernel.Scope) error {
	if m == nil || m.synchronousRunAbortCheck == nil || scope.ValidateTrusted() != nil || scope.ParentRunID == "" {
		return platformruntime.ErrInvalidRequest
	}
	aborted, err := m.synchronousRunAbortCheck(ctx, scope)
	if err != nil {
		return err
	}
	if !aborted {
		return platformruntime.ErrInvalidTransition
	}
	run, err := m.store.Get(scope.RunID)
	if err != nil {
		return err
	}
	if run.Scope != scope {
		return platformruntime.ErrInvalidRequest
	}
	if run.Status == platformruntime.StatusCancelled || run.Status == platformruntime.StatusSucceeded || run.Status == platformruntime.StatusFailed || run.Status == platformruntime.StatusCancelling {
		return nil
	}
	_, err = m.requestCancellation(ctx, run, run.Revision)
	return err
}
