package main

import (
	"context"
	"github.com/lexagent/platform/internal/bootstrap"
	"strings"
	"testing"
)

func TestRunRequiresDatabaseDSN(t *testing.T) {
	config := bootstrap.Config{Runtime: bootstrap.RuntimeConfig{
		Environment: "development", HTTPAddr: ":8080", InternalAddr: ":8081",
		DBDriver: "pgx", EventBusMode: "disabled",
	}}
	err := run(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "DB_DSN is required") {
		t.Fatalf("expected fail-closed migration error, got %v", err)
	}
}

func TestMigrationConfigDoesNotLoadRuntimeSecrets(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("DB_DRIVER", "pgx")
	t.Setenv("DB_DSN", "postgresql://schema_owner:synthetic-fixture-password-32-bytes@127.0.0.1:5432/fixture?sslmode=verify-full")
	t.Setenv("INTERNAL_TOKEN", "runtime-only-token")
	t.Setenv("INTERNAL_SIGNING_SECRET", "runtime-only-signing-key")
	t.Setenv("KNOWLEDGE_DATABASE_DSN", "runtime-only-knowledge-dsn")
	config := loadMigrationConfig()
	if config.Runtime.Environment != "production" || config.Runtime.DBDriver != "pgx" || config.Runtime.DBDSN == "" {
		t.Fatalf("migration did not load its required database settings: %+v", config.Runtime)
	}
	if config.Runtime.InternalToken != "" || config.Runtime.InternalSigningSecret != "" || config.Runtime.KnowledgeDatabaseDSN != "" {
		t.Fatal("migration loaded unrelated runtime credentials")
	}
}

func TestRunRejectsUnsafeProductionMigrationBeforeConnecting(t *testing.T) {
	for _, tc := range []struct {
		name, environment, driver, dsn, devPassword string
	}{
		{name: "unknown environment", environment: "produciton", driver: "pgx", dsn: "postgresql://schema_owner:synthetic-fixture-password-32-bytes@127.0.0.1:1/db?sslmode=verify-full"},
		{name: "unsupported database", environment: "production", driver: "mysql", dsn: "mysql://fixture"},
		{name: "placeholder credential", environment: "production", driver: "pgx", dsn: "postgresql://schema_owner:root@127.0.0.1:1/db?sslmode=verify-full"},
		{name: "development account", environment: "production", driver: "pgx", dsn: "postgresql://schema_owner:synthetic-fixture-password-32-bytes@127.0.0.1:1/db?sslmode=verify-full", devPassword: "fixture"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PLATFORM_DEV_RUNTIME_PASSWORD", tc.devPassword)
			config := bootstrap.Config{Runtime: bootstrap.RuntimeConfig{Environment: tc.environment, DBDriver: tc.driver, DBDSN: tc.dsn}}
			if err := run(context.Background(), config); err == nil {
				t.Fatal("unsafe migration configuration was accepted")
			}
		})
	}
}

func TestRunPreservesConfigurationLoadError(t *testing.T) {
	config := bootstrap.Config{LoadError: context.Canceled}
	err := run(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "invalid platform configuration") {
		t.Fatalf("expected configuration error, got %v", err)
	}
}
