package execution

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

// prepareResumeRenewal rebuilds the exact transient resume envelope in the
// same priority order as dispatch: committed runtime recovery, committed
// agent-group wait, then a committed Harness tool approval. Durable Run JSON
// remains token-free; the caller hashes and signs only this local request.
func (d *Dispatcher) prepareResumeRenewal(ctx context.Context, running platformruntime.Run, request *contract.ExecuteRequest) error {
	if request == nil || request.Operation != "resume" {
		return ErrStopEvidenceInvalid
	}
	if len(running.ResumeInputJSON) > 0 {
		var durable map[string]any
		if contract.DecodeJSONPreservingNumbers(running.ResumeInputJSON, &durable) != nil || durable == nil {
			return errors.New("execution resume contract unavailable")
		}
		request.ResumeInput = durable
	}

	recovered, err := d.prepareRecoveryRenewal(ctx, running, request)
	if err != nil {
		return ErrStopEvidenceInvalid
	}
	if recovered {
		return nil
	}
	groupResume, err := d.prepareAgentGroupRenewal(ctx, running, request)
	if err != nil {
		return ErrStopEvidenceInvalid
	}
	if groupResume {
		return nil
	}
	if len(running.ResumeInputJSON) == 0 {
		return nil
	}
	var durable struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(running.ResumeInputJSON, &durable); err != nil {
		return ErrStopEvidenceInvalid
	}
	if durable.Version == "harness-tool-resume/v1" {
		if d.approvedResumeRenewal == nil {
			return errors.New("approved execution renewal unavailable")
		}
		resolved, resolveErr := d.approvedResumeRenewal(ctx, running.Scope, running.ResumeInputJSON)
		if resolveErr != nil || resolved == nil {
			return errors.New("approved execution renewal denied")
		}
		request.ResumeInput = resolved
	}
	return nil
}
