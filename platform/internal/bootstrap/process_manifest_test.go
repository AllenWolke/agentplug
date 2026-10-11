package bootstrap

import (
	"context"
	"net/http"
	"testing"
)

func TestDefaultSingleProcessManifestIsValid(t *testing.T) {
	manifest := DefaultSingleProcessManifest()
	if err := manifest.Validate(); err != nil {
		t.Fatalf("default manifest must be valid: %v", err)
	}
}

func TestProcessManifestRejectsLegacyTrustedProcess(t *testing.T) {
	manifest := DefaultSingleProcessManifest()
	manifest.TrustedModules = append(manifest.TrustedModules, "go-harness")
	if err := manifest.Validate(); err == nil {
		t.Fatal("legacy process must not be trusted in-process")
	}
}

func TestModuleRegistryValidateRegistered(t *testing.T) {
	manifest := DefaultSingleProcessManifest()
	registry := NewModuleRegistry()
	for _, name := range manifest.TrustedModules {
		if err := registry.Register(manifestFakeModule{name: name}); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}
	if err := registry.ValidateRegistered(manifest); err != nil {
		t.Fatalf("registered manifest should pass: %v", err)
	}
	if err := registry.Register(manifestFakeModule{name: "go-backend"}); err != nil {
		t.Fatalf("register test legacy module: %v", err)
	}
	if err := registry.ValidateRegistered(manifest); err == nil {
		t.Fatal("legacy registered module must fail closed")
	}
}

func TestModuleRegistryValidateRegisteredRejectsMissingTrustedModule(t *testing.T) {
	manifest := DefaultSingleProcessManifest()
	registry := NewModuleRegistry()
	for _, name := range manifest.TrustedModules[:len(manifest.TrustedModules)-1] {
		if err := registry.Register(manifestFakeModule{name: name}); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}
	if err := registry.ValidateRegistered(manifest); err == nil {
		t.Fatal("missing trusted module must fail closed")
	}
}

func TestModuleRegistryValidateRegisteredRejectsUndeclaredModule(t *testing.T) {
	manifest := DefaultSingleProcessManifest()
	registry := NewModuleRegistry()
	for _, name := range manifest.TrustedModules {
		if err := registry.Register(manifestFakeModule{name: name}); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}
	if err := registry.Register(manifestFakeModule{name: "unreviewed-module"}); err != nil {
		t.Fatalf("register undeclared test module: %v", err)
	}
	if err := registry.ValidateRegistered(manifest); err == nil {
		t.Fatal("module absent from the process manifest must fail closed")
	}
}

// fakeModule is also used by module_test.go; keep the test helper here only
// when that file is not compiled separately in focused package tests.
type manifestFakeModule struct{ name string }

func (m manifestFakeModule) Name() string              { return m.name }
func (manifestFakeModule) Start(context.Context) error { return nil }
func (manifestFakeModule) Handler() http.Handler       { return http.NewServeMux() }
func (manifestFakeModule) Close(context.Context) error { return nil }
