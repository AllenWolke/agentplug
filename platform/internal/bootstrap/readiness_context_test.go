package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type contextProbeModule struct{ fakeModule }

func (m *contextProbeModule) ReadyContext(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

type recoveringProbeModule struct {
	fakeModule
	unavailable atomic.Bool
	active      atomic.Int32
}

func (m *recoveringProbeModule) ReadyContext(ctx context.Context) error {
	return ProbeDependency(ctx, func(ctx context.Context) error {
		m.active.Add(1)
		defer m.active.Add(-1)
		if !m.unavailable.Load() {
			return nil
		}
		<-ctx.Done()
		return ctx.Err()
	})
}

// Exercise the actual readiness route through a cooperative black-hole port.
// 通过真实健康路由验证黑洞依赖、并发取消和恢复；不是 MySQL 集成测试。
func TestReadinessHTTPBlackHoleIsBoundedAndRecovers(t *testing.T) {
	registry := NewModuleRegistry()
	module := &recoveringProbeModule{fakeModule: fakeModule{name: "database"}}
	module.unavailable.Store(true)
	if err := registry.Register(module); err != nil {
		t.Fatal(err)
	}
	app := New(Config{Modules: registry})
	handler := app.handler(nil, false)
	start := time.Now()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("black hole returned %d", response.Code)
	}
	metrics := httptest.NewRecorder()
	app.handler(nil, true).ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), "agent_platform_ready 0\n") {
		t.Fatal("failed readiness probe was not exported")
	}
	if elapsed := time.Since(start); elapsed < 1900*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("default probe budget not enforced: %s", elapsed)
	}
	var requests sync.WaitGroup
	for i := 0; i < 32; i++ {
		requests.Add(1)
		go func() {
			defer requests.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health/ready", nil).WithContext(ctx))
			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("cancelled probe returned %d", w.Code)
			}
		}()
	}
	done := make(chan struct{})
	go func() { requests.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled probes accumulated")
	}
	if module.active.Load() != 0 {
		t.Fatal("dependency probes leaked after requests ended")
	}
	module.unavailable.Store(false)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if response.Code != http.StatusOK || module.active.Load() != 0 {
		t.Fatal("dependency recovery did not restore readiness")
	}
	metrics = httptest.NewRecorder()
	app.handler(nil, true).ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), "agent_platform_ready 1\n") {
		t.Fatal("readiness recovery was not exported")
	}
}

func TestReadinessPropagatesRequestDeadline(t *testing.T) {
	r := NewModuleRegistry()
	if err := r.Register(&contextProbeModule{fakeModule{name: "database"}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := r.ReadyContext(ctx); err == nil {
		t.Fatal("unavailable dependency reported ready")
	}
	if time.Since(start) > time.Second {
		t.Fatal("request cancellation not propagated")
	}
}

func TestSharedReadinessBudget(t *testing.T) {
	err := ProbeDependency(context.Background(), func(ctx context.Context) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 2*time.Second {
			t.Fatal("missing bounded probe deadline")
		}
		return context.DeadlineExceeded
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("probe error lost: %v", err)
	}
}
