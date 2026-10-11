package capability

import (
	"context"
	"time"

	"github.com/lexagent/platform/internal/modelcapacity"
)

type captureModelCapacity struct {
	requests []modelcapacity.Request
	released []modelcapacity.Lease
	err      error
}

func (p *captureModelCapacity) AcquireCapacity(_ context.Context, request modelcapacity.Request) (modelcapacity.Lease, error) {
	p.requests = append(p.requests, request)
	if p.err != nil {
		return modelcapacity.Lease{}, p.err
	}
	return modelcapacity.Lease{ID: "capacity-lease-1", DeploymentID: request.DeploymentID, TenantID: request.Scope.TenantID, DepartmentID: request.Scope.DepartmentID, ApplicationID: request.Scope.ApplicationID, Units: request.Units, FencingToken: int64(len(p.requests)), Owner: request.Owner, RequestID: request.RequestID, ExpiresAt: time.Now().UTC().Add(request.TTL)}, nil
}

func (p *captureModelCapacity) ReleaseCapacity(_ context.Context, lease modelcapacity.Lease) error {
	p.released = append(p.released, lease)
	return nil
}

func (p *captureModelCapacity) ReapExpired(context.Context, time.Time, int) (int, error) {
	return 0, nil
}
