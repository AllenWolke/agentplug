package bootstrap

import (
	"context"
	"errors"
	"github.com/lexagent/platform/internal/telemetry"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Module is the only composition seam for a trusted platform business module.
// 业务模块只能通过该组合边界参与平台进程，不得反向读取其他模块的数据库。
type Module interface {
	Name() string
	Start(context.Context) error
	Handler() http.Handler
	Close(context.Context) error
}

// ReadyModule is an optional module readiness contract. A module that is
// registered but whose durable dependency is unavailable must keep the
// process alive for diagnostics while remaining out of service.
// ReadyModule 是可选的模块就绪契约：模块仍可保留进程用于诊断，但持久化依赖
// 不可用时必须保持未就绪，不能让流量进入。
type ReadyModule interface {
	Ready() error
}

// ContextReadyModule propagates cancellation to dependency probes.
// ContextReadyModule 将请求取消传递至依赖探测，避免故障探测无限等待。
type ContextReadyModule interface {
	ReadyContext(context.Context) error
}

// ProbeDependency applies the shared two-second readiness budget.
// ProbeDependency 使用统一的两秒预算，且不延长调用方已有的截止时间。
func ProbeDependency(ctx context.Context, probe func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return probe(ctx)
}

// ModuleRegistry owns deterministic registration and reverse-order shutdown.
// ModuleRegistry 负责确定性注册和逆序关闭，便于未来按模块拆成微服务。
type ModuleRegistry struct {
	mu      sync.RWMutex
	modules map[string]Module
	started []string
}

func NewModuleRegistry() *ModuleRegistry {
	return &ModuleRegistry{modules: make(map[string]Module)}
}

func (r *ModuleRegistry) Register(module Module) error {
	if module == nil || module.Name() == "" || module.Handler() == nil {
		return errors.New("module name, module and handler are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.modules[module.Name()]; exists {
		return errors.New("module already registered")
	}
	r.modules[module.Name()] = module
	return nil
}

func (r *ModuleRegistry) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	r.mu.Lock()
	names := make([]string, 0, len(r.modules))
	for name := range r.modules {
		names = append(names, name)
	}
	sort.Strings(names)
	r.mu.Unlock()
	for _, name := range names {
		r.mu.RLock()
		module := r.modules[name]
		r.mu.RUnlock()
		if err := module.Start(ctx); err != nil {
			_ = r.Close(context.Background())
			return err
		}
		r.mu.Lock()
		r.started = append(r.started, name)
		r.mu.Unlock()
	}
	return nil
}

func (r *ModuleRegistry) Handler() http.Handler {
	mux := http.NewServeMux()
	r.mu.RLock()
	defer r.mu.RUnlock()
	for name, module := range r.modules {
		mux.Handle("/modules/"+name+"/", telemetry.Module(name, http.StripPrefix("/modules/"+name, module.Handler())))
	}
	return mux
}

// Ready reports the first deterministic module readiness failure. Modules that
// do not implement ReadyModule are treated as ready because their Start hook
// has already completed successfully.
// Ready 返回确定性的第一个模块就绪错误；未实现 ReadyModule 的模块视为已就绪，
// 因为其 Start 已成功完成。
func (r *ModuleRegistry) Ready() error {
	return r.ReadyContext(context.Background())
}

func (r *ModuleRegistry) ReadyContext(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	r.mu.RLock()
	names := make([]string, 0, len(r.modules))
	for name := range r.modules {
		names = append(names, name)
	}
	sort.Strings(names)
	modules := make([]Module, 0, len(names))
	for _, name := range names {
		modules = append(modules, r.modules[name])
	}
	r.mu.RUnlock()
	for i, module := range modules {
		if err := ctx.Err(); err != nil {
			return err
		}
		if ready, ok := module.(ContextReadyModule); ok {
			if err := ready.ReadyContext(ctx); err != nil {
				return errors.New(names[i] + ": " + err.Error())
			}
			continue
		}
		if ready, ok := module.(ReadyModule); ok {
			if err := ready.Ready(); err != nil {
				return errors.New(names[i] + ": " + err.Error())
			}
		}
	}
	return nil
}

// InternalHandler returns only capability routes intended for Agent-to-platform
// calls. Modules opt in explicitly; ordinary module routes stay under
// /modules/<name> and are never accidentally exposed on the internal listener.
// InternalHandler 只返回显式声明的 Agent→平台能力路由，普通模块仍挂在
// /modules/<name> 下，避免内部监听器意外暴露全部业务路由。
func (r *ModuleRegistry) InternalHandler() http.Handler {
	mux := http.NewServeMux()
	r.mu.RLock()
	names := make([]string, 0, len(r.modules))
	for name := range r.modules {
		names = append(names, name)
	}
	sort.Strings(names)
	providers := make([]interface{ InternalHandler() http.Handler }, 0, 1)
	for _, name := range names {
		if provider, ok := r.modules[name].(interface{ InternalHandler() http.Handler }); ok {
			providers = append(providers, provider)
		}
	}
	r.mu.RUnlock()
	// The private listener currently has one capability owner. Keep that
	// invariant deterministic until the registry grows an explicit route
	// ownership contract; ranging over the module map would otherwise make the
	// exposed internal API depend on Go's randomized map iteration order.
	if len(providers) > 0 {
		mux.Handle("/internal/", providers[0].InternalHandler())
	}
	return mux
}

func (r *ModuleRegistry) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	r.mu.Lock()
	started := append([]string(nil), r.started...)
	r.started = nil
	r.mu.Unlock()
	var firstErr error
	for i := len(started) - 1; i >= 0; i-- {
		r.mu.RLock()
		module := r.modules[started[i]]
		r.mu.RUnlock()
		if err := module.Close(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
