package main

import (
	"context"
	"database/sql"
	"regexp"
	"testing"

	"github.com/lexagent/platform/internal/schemaversion"
)

// Bootstrap fixtures use the same protected-history restrictions as runtime
// accounts. A blanket DML grant is deliberately rejected by the real verifier.
func restrictBootstrapRuntimeFixture(t *testing.T, ctx context.Context, owner *sql.DB, role string) {
	t.Helper()
	if !regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`).MatchString(role) {
		t.Fatal("invalid owned runtime fixture role")
	}
	for _, statement := range []string{
		`REVOKE INSERT,UPDATE,DELETE ON platform_schema_version FROM `,
		`REVOKE INSERT,UPDATE,DELETE ON platform_compensation_schema_version FROM `,
		`REVOKE UPDATE,DELETE ON platform_compensation_event FROM `,
		`REVOKE DELETE ON platform_compensation_step,platform_compensation_local_effect,platform_cancellation_operation FROM `,
		`REVOKE UPDATE,DELETE ON platform_cancellation_effect FROM `,
		`REVOKE INSERT,UPDATE,DELETE ON platform_notification_control_version FROM `,
		`REVOKE DELETE ON platform_notification_inbox FROM `,
		`REVOKE INSERT,UPDATE,DELETE ON platform_kafka_dead_letter_schema_version FROM `,
		`REVOKE UPDATE,DELETE ON platform_kafka_dead_letter_action FROM `,
		`REVOKE DELETE ON platform_kafka_dead_letter FROM `,
	} {
		if _, err := owner.ExecContext(ctx, statement+`"`+role+`"`); err != nil {
			t.Fatal("restrict owned bootstrap runtime history privileges", err)
		}
	}
}

func verifyBootstrapRuntimeFixture(t *testing.T, ctx context.Context, runtime *sql.DB) {
	t.Helper()
	if err := schemaversion.CheckRuntimePrivileges(ctx, runtime); err != nil {
		t.Fatal("owned bootstrap runtime fixture is not DML-only", err)
	}
}
