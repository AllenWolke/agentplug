package identity

import (
	"context"
	"fmt"

	"github.com/lexagent/platform/internal/sqlutil"
)

func (s *SQLStore) EnsureDepartmentAgentAccessSchema(ctx context.Context) error {
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS platform_identity_department_agent_policy (
			tenant_id VARCHAR(128) NOT NULL, department_id VARCHAR(128) NOT NULL,
			revision NUMERIC(20,0) CHECK (revision>0 AND revision<=18446744073709551615) NOT NULL,
			entries_digest VARCHAR(64) NOT NULL, updated_by VARCHAR(128) NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY(tenant_id,department_id))`,
		`CREATE TABLE IF NOT EXISTS platform_identity_department_agent_entry (
			tenant_id VARCHAR(128) NOT NULL, department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL, installation_id VARCHAR(128) NOT NULL,
			actions_json JSONB NOT NULL, action_versions_json JSONB NOT NULL,
			starts_at TIMESTAMPTZ, expires_at TIMESTAMPTZ,
			PRIMARY KEY(tenant_id,department_id,application_id,installation_id),
			FOREIGN KEY(tenant_id,department_id) REFERENCES platform_identity_department_agent_policy(tenant_id,department_id))`,
		`CREATE TABLE IF NOT EXISTS platform_identity_department_agent_change (
			idempotency_key VARCHAR(128) PRIMARY KEY, request_digest VARCHAR(64) NOT NULL,
			actor_id VARCHAR(128) NOT NULL, tenant_id VARCHAR(128) NOT NULL, department_id VARCHAR(128) NOT NULL,
			receipt_json JSONB NOT NULL, occurred_at TIMESTAMPTZ NOT NULL)`,
	} {
		if _, err := s.db.ExecContext(ctx, sqlutil.Bind(statement)); err != nil {
			return fmt.Errorf("department Agent policy schema: %w", err)
		}
	}
	return nil
}
