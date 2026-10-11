package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestIndexWorkloadMountIsScopedBoundedAndRotationAware(t *testing.T) {
	for _, mode := range []string{"allowed", "foreign-installation", "unknown-field", "invalid-header", "oversized", "canceled", "relative-root", "rotation"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u", PrincipalType: "user", AgentID: "agent", AgentInstanceID: "i", InstallationID: "i", AgentVersionID: "v", SessionID: "s", RunID: "r", TraceID: "trace", AuthorizationEpoch: 1}
			path := filepath.Join(root, indexWorkloadSecretName(scope))
			body := `{"client_id":"fixture-client","client_secret":"fixture-secret"}`
			if mode == "unknown-field" {
				body = `{"client_id":"fixture-client","client_secret":"fixture-secret","token":"override"}`
			}
			if mode == "invalid-header" {
				body = `{"client_id":"fixture-client","client_secret":"line\r\ninjection"}`
			}
			if mode == "oversized" {
				body = string(make([]byte, 16385))
			}
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			resolver := mountedIndexWorkloadSecrets{Root: root}
			if mode == "relative-root" {
				resolver.Root = "relative"
			}
			if mode == "foreign-installation" {
				scope.InstallationID = "other"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			credential, err := resolver.Resolve(ctx, scope)
			if mode != "allowed" && mode != "rotation" {
				if err == nil || credential.Secret != "" {
					t.Fatal("invalid credential admitted")
				}
				if mode == "canceled" && !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation lost")
				}
				return
			}
			if err != nil || credential.ClientID != "fixture-client" || credential.Secret != "fixture-secret" {
				t.Fatal("mount not resolved")
			}
			if mode == "rotation" {
				if err := os.WriteFile(path, []byte(`{"client_id":"fixture-client","client_secret":"rotated-fixture"}`), 0600); err != nil {
					t.Fatal(err)
				}
				fresh, err := resolver.Resolve(ctx, scope)
				if err != nil || fresh.Secret == credential.Secret {
					t.Fatal("rotation not reloaded")
				}
			}
		})
	}
}
