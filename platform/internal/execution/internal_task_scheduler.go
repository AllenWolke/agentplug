package execution

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

const KnowledgeIndexInputSchema = "schema://platform/knowledge-index/v1"

type InternalTaskQueue interface {
	Repository
	ListInternalPending(context.Context, string, int) ([]string, error)
}

// InternalTaskScheduler consumes persisted platform-owned commands. Empty
// AgentEndpoint keeps these commands out of ordinary remote Agent dispatch.
// Execute owns heartbeat and outcome via InternalTaskSupervisor. Expired
// owners are not reclaimed without an explicit stop/reconciliation barrier.
type InternalTaskScheduler struct {
	Repository  InternalTaskQueue
	InputSchema string
	LeaseTTL    time.Duration
	Authorize   func(context.Context, sharedkernel.Scope) error
	Execute     func(context.Context, platformruntime.Run) error
	BeforeSweep func(context.Context) error
}

func (s InternalTaskScheduler) Dispatch(ctx context.Context, id string) error {
	if s.Repository == nil || s.InputSchema != KnowledgeIndexInputSchema || s.Authorize == nil || s.Execute == nil || s.LeaseTTL < 30*time.Millisecond || s.LeaseTTL > 10*time.Minute {
		return platformruntime.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	run, err := s.Repository.Get(id)
	if err != nil {
		return err
	}
	var request contract.ExecuteRequest
	if run.AgentEndpoint != "" || run.Scope.ValidateTrusted() != nil || json.Unmarshal(run.RequestJSON, &request) != nil || request.InputSchema != s.InputSchema || request.ContextToken != "" || (request.Operation != "run" && request.Operation != "invoke") || request.Scope.DelegationDepth != 0 {
		return platformruntime.ErrInvalidRequest
	}
	r := request.Scope
	owner := sharedkernel.Scope{TenantID: r.TenantID, DepartmentID: r.DepartmentID, ApplicationID: r.ApplicationID, AgentID: r.AgentID, AgentInstanceID: r.AgentInstanceID, InstallationID: r.InstallationID, AgentVersionID: r.AgentVersionID, PrincipalID: r.PrincipalID, PrincipalType: r.PrincipalType, SessionID: r.SessionID, RunID: r.RunID, ParentRunID: r.ParentRunID, TraceID: r.TraceID, AuthorizationEpoch: r.AuthorizationEpoch}
	if owner != run.Scope || run.ID != owner.RunID {
		return platformruntime.ErrInvalidRequest
	}
	if run.Status != platformruntime.StatusAccepted && !(run.Status == platformruntime.StatusRunning && run.LeaseToken == "") {
		return platformruntime.ErrLeaseConflict
	}
	if err := s.Authorize(ctx, run.Scope); err != nil {
		return err
	}
	claimed, err := s.Repository.AcquireLease(id, newLeaseToken(id), time.Now().UTC(), s.LeaseTTL)
	if err != nil {
		return err
	}
	if claimed.Status == platformruntime.StatusAccepted {
		claimed, err = s.Repository.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
		if err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.Authorize(ctx, claimed.Scope); err != nil {
		return err
	}
	return s.Execute(ctx, claimed)
}

func (s InternalTaskScheduler) Sweep(ctx context.Context) error {
	if s.Repository == nil {
		return platformruntime.ErrInvalidRequest
	}
	var failures []error
	if s.BeforeSweep != nil {
		if err := s.BeforeSweep(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	ids, err := s.Repository.ListInternalPending(ctx, s.InputSchema, 16)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.Dispatch(ctx, id); err != nil && !errors.Is(err, platformruntime.ErrLeaseConflict) && !errors.Is(err, platformruntime.ErrRevisionConflict) {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (s InternalTaskScheduler) Run(ctx context.Context, poll time.Duration, report func(error)) error {
	if poll < 250*time.Millisecond || poll > 10*time.Second {
		return platformruntime.ErrInvalidRequest
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.Sweep(ctx); err != nil && report != nil {
			report(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
