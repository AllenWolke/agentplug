// Package bootstrap owns process composition for the modular platform.
// bootstrap 负责模块化平台进程的组合，不承载业务逻辑。
package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/telemetry"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var ErrClosed = errors.New("platform bootstrap is closed")

// Config is intentionally small in MM-P-01; later cards add validated ports,
// secrets and dependency factories without changing the process contract.
// Config 在 MM-P-01 保持最小，后续任务再增加端口、Secret 和依赖工厂。
type Config struct {
	HTTPAddr     string
	InternalAddr string
	Runtime      RuntimeConfig
	// LoadError is retained until Run so invalid configuration cannot silently
	// start a process with development fallbacks. / LoadError 保留到 Run 阶段，
	// 防止非法配置静默降级为开发默认值并启动。
	LoadError error
	// Bootstrap owns process-wide dependency readiness and shutdown. Modules
	// remain responsible for their own schema, but never own the shared pool.
	// Bootstrap 负责进程级依赖就绪与关闭；模块只负责自己的 schema，不重复拥有连接池。
	Bootstrap       *Bootstrap
	Modules         *ModuleRegistry
	PublicHandler   http.Handler
	InternalHandler http.Handler
}

// SQLDependency is the local adapter for the one SQL pool shared by all
// platform modules. Keeping this adapter in bootstrap makes the ownership
// seam explicit and allows a future remote dependency adapter without
// changing module contracts.
type SQLDependency struct {
	db *sql.DB
}

func NewSQLDependency(db *sql.DB) *SQLDependency { return &SQLDependency{db: db} }

func (d *SQLDependency) Name() string { return "sql" }

func (d *SQLDependency) Check(ctx context.Context) error {
	if d == nil || d.db == nil {
		return errors.New("sql database is required")
	}
	return d.db.PingContext(ctx)
}

func (d *SQLDependency) Close(context.Context) error {
	if d == nil || d.db == nil {
		return nil
	}
	return d.db.Close()
}

func LoadConfig() Config {
	httpAddr := os.Getenv("PLATFORM_HTTP_ADDR")
	if httpAddr == "" {
		httpAddr = ":8080"
	}
	internalAddr := os.Getenv("PLATFORM_INTERNAL_ADDR")
	if internalAddr == "" {
		internalAddr = ":8081"
	}
	runtime, err := LoadRuntimeConfig()
	if err == nil {
		return Config{HTTPAddr: httpAddr, InternalAddr: internalAddr, Runtime: runtime}
	}
	// Preserve the error instead of silently replacing production (or malformed
	// development) configuration with unsafe defaults. Tests and embedders can
	// still construct Config{} explicitly when they need an in-memory app.
	// 保留错误，不再把生产配置或非法开发配置静默替换成不安全默认值；测试和
	// 嵌入者如需内存应用仍可显式构造 Config{}。
	return Config{
		HTTPAddr:     httpAddr,
		InternalAddr: internalAddr,
		Runtime: RuntimeConfig{
			Environment:  envOrDefault("APP_ENV", "development"),
			HTTPAddr:     httpAddr,
			InternalAddr: internalAddr,
			DBDriver:     strings.ToLower(envOrDefault("DB_DRIVER", "pgx")),
		},
		LoadError: err,
	}
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

// App is the lifecycle boundary for the future single platform process.
// App 是未来单平台进程的生命周期边界。
type App struct {
	config  Config
	mu      sync.Mutex
	closed  bool
	servers []*http.Server
}

func New(config Config) *App { return &App{config: config} }

func (a *App) Config() Config { return a.config }

// Run starts the two platform listener boundaries and blocks until the context
// is cancelled. Business routes are injected by module composition; the
// default handlers expose only liveness/readiness, never a fake business API.
// Run 启动公开/内部两个监听边界并等待退出；业务路由由模块组合注入，默认只暴露
// 存活/就绪探针，不伪造业务接口。
func (a *App) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	if a.config.LoadError != nil {
		return fmt.Errorf("invalid platform configuration: %w", a.config.LoadError)
	}
	if a.config.HTTPAddr == "" && a.config.InternalAddr == "" {
		<-ctx.Done()
		a.mu.Lock()
		a.closed = true
		a.mu.Unlock()
		return nil
	}
	runtime := a.config.Runtime
	if runtime.HTTPAddr == "" {
		runtime.HTTPAddr = a.config.HTTPAddr
	}
	if runtime.InternalAddr == "" {
		runtime.InternalAddr = a.config.InternalAddr
	}
	if runtime.Environment == "" {
		runtime.Environment = "development"
	}
	if runtime.DBDriver == "" {
		runtime.DBDriver = "pgx"
	}
	if runtime.EventBusMode == "" {
		runtime.EventBusMode = "disabled"
	}
	if err := runtime.Validate(); err != nil {
		return fmt.Errorf("invalid platform runtime configuration: %w", err)
	}
	if a.config.Bootstrap != nil {
		if err := a.config.Bootstrap.Start(ctx); err != nil {
			return fmt.Errorf("platform bootstrap: %w", err)
		}
	}
	if a.config.Modules != nil {
		if err := a.config.Modules.Start(ctx); err != nil {
			if a.config.Bootstrap != nil {
				_ = a.config.Bootstrap.Close(context.Background())
			}
			return err
		}
	}
	publicHandler := a.config.PublicHandler
	internalHandler := a.config.InternalHandler
	if a.config.Modules != nil {
		if publicHandler == nil {
			publicHandler = a.config.Modules.Handler()
		}
		if internalHandler == nil {
			internalHandler = a.config.Modules.InternalHandler()
		}
	}
	public := &http.Server{Addr: a.config.HTTPAddr, Handler: a.handler(publicHandler, false), ReadHeaderTimeout: 5 * time.Second}
	internal := &http.Server{Addr: a.config.InternalAddr, Handler: a.handler(internalHandler, true), ReadHeaderTimeout: 5 * time.Second}
	a.mu.Lock()
	a.servers = []*http.Server{public, internal}
	a.mu.Unlock()
	errCh := make(chan error, 2)
	for _, server := range []*http.Server{public, internal} {
		go func(s *http.Server) {
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}(server)
	}
	select {
	case <-ctx.Done():
		a.shutdownServers()
	case err := <-errCh:
		a.shutdownServers()
		a.mu.Lock()
		a.closed = true
		a.mu.Unlock()
		return err
	}
	a.mu.Lock()
	a.closed = true
	a.mu.Unlock()
	return nil
}

// shutdownServers closes both listeners and then the modules that own their
// routes. It is shared by normal cancellation and listener-start failures so
// a bind error cannot leave the other listener or a worker goroutine running.
// shutdownServers 同时处理正常退出和监听启动失败，避免一个端口绑定失败后
// 另一个监听器或模块 Worker 继续孤立运行。
func (a *App) shutdownServers() {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a.mu.Lock()
	servers := append([]*http.Server(nil), a.servers...)
	a.mu.Unlock()
	for _, server := range servers {
		_ = server.Shutdown(shutdownCtx)
	}
	if a.config.Modules != nil {
		_ = a.config.Modules.Close(shutdownCtx)
	}
	if a.config.Bootstrap != nil {
		_ = a.config.Bootstrap.Close(shutdownCtx)
	}
}

func (a *App) handler(next http.Handler, internal bool) http.Handler {
	mux := http.NewServeMux()
	if internal {
		mux.Handle("/metrics", telemetry.MetricsHandler())
	}
	mux.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		ready := a.config.LoadError == nil && (a.config.Modules == nil || a.config.Modules.ReadyContext(r.Context()) == nil)
		telemetry.SetReadiness(ready)
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	if next != nil {
		mux.Handle("/", next)
	} else if internal {
		mux.HandleFunc("/internal/", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "platform module route not wired", http.StatusNotImplemented)
		})
	}
	return telemetry.HTTP(mux)
}

func (a *App) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	for _, server := range a.servers {
		_ = server.Close()
	}
	if a.config.Modules != nil {
		_ = a.config.Modules.Close(context.Background())
	}
	if a.config.Bootstrap != nil {
		_ = a.config.Bootstrap.Close(context.Background())
	}
	a.closed = true
	return nil
}
