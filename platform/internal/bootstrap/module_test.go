package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type fakeModule struct {
	name  string
	mu    sync.Mutex
	state []string
}

type readinessModule struct {
	fakeModule
	err error
}

type internalModule struct {
	fakeModule
	response string
}

func (m *readinessModule) Ready() error { return m.err }

func (m *internalModule) InternalHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(m.response))
	})
}

func (m *fakeModule) Name() string { return m.name }
func (m *fakeModule) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
}
func (m *fakeModule) Start(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = append(m.state, "start")
	return nil
}
func (m *fakeModule) Close(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = append(m.state, "close")
	return nil
}

func TestModuleRegistryStartsInOrderAndClosesInReverse(t *testing.T) {
	registry := NewModuleRegistry()
	a, b := &fakeModule{name: "a"}, &fakeModule{name: "b"}
	if err := registry.Register(b); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(a); err != nil {
		t.Fatal(err)
	}
	if err := registry.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := registry.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if got := a.state; len(got) != 2 || got[0] != "start" || got[1] != "close" {
		t.Fatalf("unexpected module lifecycle: %#v", got)
	}
}

func TestModuleRegistryRejectsDuplicateAndMountsHandler(t *testing.T) {
	registry := NewModuleRegistry()
	m := &fakeModule{name: "qa"}
	if err := registry.Register(m); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(m); err == nil {
		t.Fatal("expected duplicate rejection")
	}
	req := httptest.NewRequest(http.MethodGet, "/modules/qa/health", nil)
	rec := httptest.NewRecorder()
	registry.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("unexpected module route status: %d", rec.Code)
	}
}

func TestModuleRegistryReadinessFailsClosed(t *testing.T) {
	registry := NewModuleRegistry()
	if err := registry.Register(&readinessModule{fakeModule: fakeModule{name: "database"}, err: context.DeadlineExceeded}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Ready(); err == nil {
		t.Fatal("expected unavailable module to keep registry unready")
	}
}

func TestModuleRegistryInternalHandlerSelectionIsDeterministic(t *testing.T) {
	registry := NewModuleRegistry()
	if err := registry.Register(&internalModule{fakeModule: fakeModule{name: "z-capability"}, response: "z"}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(&internalModule{fakeModule: fakeModule{name: "a-capability"}, response: "a"}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/internal/who", nil)
	rec := httptest.NewRecorder()
	registry.InternalHandler().ServeHTTP(rec, req)
	if got := rec.Body.String(); got != "a" {
		t.Fatalf("internal handler selection must be stable by module name, got %q", got)
	}
}
