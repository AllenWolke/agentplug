// Package modelcapacity provides the Platform-owned admission boundary for
// managed model deployments. The SQL implementation is authoritative across
// Platform processes; a later Redis/Kubernetes implementation can satisfy the
// same Port without changing Capability callers.
//
// modelcapacity 为受管模型部署提供 Platform 所有的容量准入边界。SQL 实现可在
// 多个 Platform 进程间共享权威状态；后续 Redis/Kubernetes 实现可以满足相同 Port，
// 不需要修改 Capability 调用方。
package modelcapacity

import (
	"context"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

var (
	ErrUnavailable = errors.New("model deployment capacity is unavailable")
	ErrExceeded    = errors.New("model deployment capacity exceeded")
	ErrStaleLease  = errors.New("model deployment capacity lease is stale")
	ErrInvalid     = errors.New("invalid model deployment capacity request")
)

// CapacityProvider is the stable admission boundary used by Model Capability. Implementors
// must make leases atomic across processes; a process-local semaphore is not a
// production implementation.
// Port 是 Model Capability 使用的稳定准入边界。实现必须确保跨进程租约原子性；
// 进程内信号量不能作为生产权威实现。
type CapacityProvider interface {
	AcquireCapacity(context.Context, Request) (Lease, error)
	ReleaseCapacity(context.Context, Lease) error
	ReapExpired(context.Context, time.Time, int) (int, error)
}

type Request struct {
	Scope        sharedkernel.Scope
	DeploymentID string
	Units        int64
	Owner        string
	RequestID    string
	TTL          time.Duration
}

type Lease struct {
	ID            string
	DeploymentID  string
	TenantID      string
	DepartmentID  string
	ApplicationID string
	Units         int64
	FencingToken  int64
	Owner         string
	RequestID     string
	ExpiresAt     time.Time
}

// Deployment is the immutable scope binding required to register a capacity
// pool when a Model Deployment is created.
// Deployment 是创建模型部署时注册容量池所需的不可变作用域绑定。
type Deployment struct {
	ID             string
	TenantID       string
	DepartmentID   string
	ApplicationID  string
	ModelVersionID string
	CapacityUnits  int64
}

type RuntimeDeployment struct {
	ID             string
	ModelVersionID string
	EndpointRef    string
	CapacityUnits  int64
	HealthStatus   string
	Status         string
}

// DeploymentReader is supplied by the catalog owner, not its SQL repository.
// 部署元数据经所属模块 Port 获取，容量模块不得 JOIN 外模块表。
type DeploymentReader interface {
	GetRuntimeDeployment(context.Context, sharedkernel.Scope, string) (RuntimeDeployment, error)
}

// Validate checks trusted scope and lease invariants before touching storage.
func (r Request) Validate() error {
	if r.Scope.ValidateTrusted() != nil || r.DeploymentID == "" || r.Units <= 0 || r.Owner == "" || r.RequestID == "" {
		return ErrInvalid
	}
	if r.TTL <= 0 || r.TTL > 10*time.Minute {
		return ErrInvalid
	}
	return nil
}
