package execution

import (
	"encoding/json"
	"errors"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

const maximumDelegationDepth = 4
const maximumDispatchWorkers = 128

// ConfigureDelegationCapacity is startup-only. Each depth has reserved bounded
// workers; a waiting parent cannot consume its descendants' execution capacity.
// Ordinary deployments retain their original root pool until explicitly enabled.
func (d *Dispatcher) ConfigureDelegationCapacity(childWorkers int) error {
	if d == nil {
		return errors.New("invalid delegation dispatch capacity")
	}
	d.capacityMu.Lock()
	defer d.capacityMu.Unlock()
	if d.started || childWorkers < 1 || childWorkers > 32 || d.workers+maximumDelegationDepth*childWorkers > maximumDispatchWorkers || len(d.childQueues) != 0 {
		return errors.New("invalid delegation dispatch capacity")
	}
	d.childWorkers = childWorkers
	d.childQueues = make([]chan string, maximumDelegationDepth)
	for depth := range d.childQueues {
		d.childQueues[depth] = make(chan string, childWorkers*4)
	}
	return nil
}

func scheduledDelegationDepth(run platformruntime.Run) (int, error) {
	var command struct {
		ProtocolVersion string `json:"protocol_version"`
		Scope           struct {
			RunID       string `json:"run_id"`
			ParentRunID string `json:"parent_run_id"`
			Depth       uint32 `json:"delegation_depth"`
		} `json:"scope"`
	}
	// Empty/legacy root hints continue through the existing durable dispatch
	// validation. Positive business depth is never inferred from ParentRunID.
	if len(run.RequestJSON) == 0 || json.Unmarshal(run.RequestJSON, &command) != nil {
		return 0, nil
	}
	if command.Scope.Depth == 0 {
		return 0, nil
	}
	if command.ProtocolVersion != contract.ProtocolVersion || command.Scope.Depth > maximumDelegationDepth || command.Scope.RunID != run.ID || command.Scope.ParentRunID == "" || command.Scope.ParentRunID != run.Scope.ParentRunID {
		return 0, platformruntime.ErrInvalidRequest
	}
	return int(command.Scope.Depth), nil
}
