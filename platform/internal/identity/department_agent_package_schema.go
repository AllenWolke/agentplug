package identity

import (
	"context"
	"errors"

	"github.com/lexagent/platform/internal/sqlutil"
)

// Owner migration only: add this table without reseeding or changing any IAM facts.
func (s *SQLStore) EnsureDepartmentAgentPackageSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("identity database is required")
	}
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`CREATE TABLE IF NOT EXISTS platform_identity_department_agent_package (
id VARCHAR(128) PRIMARY KEY,tenant_id VARCHAR(128) NOT NULL,department_id VARCHAR(128) NOT NULL,application_id VARCHAR(128) NOT NULL,
installation_id VARCHAR(128) NOT NULL,status VARCHAR(24) NOT NULL,revision NUMERIC(20,0) CHECK (revision>=1 AND revision<=18446744073709551615) NOT NULL,
payload JSON NOT NULL,updated_at TIMESTAMPTZ(6) NOT NULL,CONSTRAINT uq_department_agent_package UNIQUE(tenant_id,department_id,application_id,installation_id));`))
	return err
}
