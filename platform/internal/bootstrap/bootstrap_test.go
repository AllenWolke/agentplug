package bootstrap

import (
	"context"
	"testing"
	"time"
)

func TestLoadConfigUsesSafeDefaults(t *testing.T) {
	t.Setenv("PLATFORM_HTTP_ADDR", "")
	t.Setenv("PLATFORM_INTERNAL_ADDR", "")
	cfg := LoadConfig()
	if cfg.HTTPAddr != ":8080" || cfg.InternalAddr != ":8081" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadConfigDoesNotSilentlyDowngradeInvalidProduction(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("DB_DSN", "")
	t.Setenv("INTERNAL_TOKEN", "")
	t.Setenv("INTERNAL_SIGNING_SECRET", "")
	t.Setenv("PLATFORM_POLICY_RESOLVER", "disabled")
	cfg := LoadConfig()
	if cfg.LoadError == nil {
		t.Fatal("invalid production configuration must be retained as a startup error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := New(cfg).Run(ctx); err == nil {
		t.Fatal("platform must fail closed before opening listeners")
	}
}

func TestAppRunStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- New(Config{}).Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after context cancellation")
	}
}

func TestAppRunCleansUpModulesWhenListenerFails(t *testing.T) {
	registry := NewModuleRegistry()
	module := &fakeModule{name: "worker"}
	if err := registry.Register(module); err != nil {
		t.Fatal(err)
	}
	// A missing port is rejected by net.Listen before the second listener can
	// become a long-lived orphan.
	err := New(Config{HTTPAddr: "-", InternalAddr: ":0", Modules: registry}).Run(context.Background())
	if err == nil {
		t.Fatal("invalid listener address must fail")
	}
	module.mu.Lock()
	defer module.mu.Unlock()
	if len(module.state) != 2 || module.state[0] != "start" || module.state[1] != "close" {
		t.Fatalf("listener failure leaked module lifecycle: %#v", module.state)
	}
}

func TestAppRunValidatesProgrammaticRuntimeConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := New(Config{HTTPAddr: ":0", InternalAddr: ":0", Runtime: RuntimeConfig{Environment: "development", HTTPAddr: ":0", InternalAddr: ":0", DBDriver: "mysql", EventBusMode: "disabled"}}).Run(ctx)
	if err == nil {
		t.Fatal("programmatic invalid runtime config must fail closed")
	}
}
