package bootstrap

import (
	"context"
	"errors"
	"testing"
)

type fakeDependency struct {
	name   string
	check  error
	closed bool
}

func (d *fakeDependency) Name() string                { return d.name }
func (d *fakeDependency) Check(context.Context) error { return d.check }
func (d *fakeDependency) Close(context.Context) error { d.closed = true; return nil }

func TestBootstrapFailsClosedWhenDependencyIsUnavailable(t *testing.T) {
	cfg := RuntimeConfig{Environment: "development", HTTPAddr: ":8080", InternalAddr: ":8081", DBDriver: "pgx", EventBusMode: "disabled"}
	dep := &fakeDependency{name: "database", check: errors.New("offline")}
	b := NewBootstrap(cfg, dep)
	if err := b.Start(context.Background()); err == nil {
		t.Fatal("expected dependency failure")
	}
	if b.Ready() {
		t.Fatal("bootstrap must remain unready")
	}
}

func TestBootstrapClosesDependenciesInReverseOrder(t *testing.T) {
	cfg := RuntimeConfig{Environment: "development", HTTPAddr: ":8080", InternalAddr: ":8081", DBDriver: "pgx", EventBusMode: "disabled"}
	first := &fakeDependency{name: "database"}
	second := &fakeDependency{name: "telemetry"}
	b := NewBootstrap(cfg, first, second)
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !b.Ready() {
		t.Fatal("bootstrap should be ready")
	}
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if first.closed == false || second.closed == false || b.Ready() {
		t.Fatal("bootstrap did not close all dependencies")
	}
}

func TestBootstrapStartIsIdempotentButClosedBootstrapCannotRestart(t *testing.T) {
	cfg := RuntimeConfig{Environment: "development", HTTPAddr: ":8080", InternalAddr: ":8081", DBDriver: "pgx", EventBusMode: "disabled"}
	dep := &fakeDependency{name: "database"}
	b := NewBootstrap(cfg, dep)
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("repeat Start should be idempotent: %v", err)
	}
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed bootstrap must not restart: %v", err)
	}
}
