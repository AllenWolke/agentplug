package capability

import (
	"context"
	"database/sql"
	"fmt"
)

// Only these explicit fixture objects may be removed; never accept a caller's identifier.
func dropPostgresBillingFault(ctx context.Context, db *sql.DB, name string) (sql.Result, error) {
	statements := map[string]string{
		"billing_audit_accept_fault":  `DROP TRIGGER IF EXISTS billing_audit_accept_fault ON platform_model_billing_decision; DROP FUNCTION IF EXISTS billing_audit_accept_fault_fn()`,
		"billing_audit_apply_fault":   `DROP TRIGGER IF EXISTS billing_audit_apply_fault ON platform_model_billing_decision; DROP FUNCTION IF EXISTS billing_audit_apply_fault_fn()`,
		"billing_completion_fault":    `DROP TRIGGER IF EXISTS billing_completion_fault ON platform_model_invocation; DROP FUNCTION IF EXISTS billing_completion_fault_fn()`,
		"billing_settlement_fault":    `DROP TRIGGER IF EXISTS billing_settlement_fault ON platform_usage_event; DROP FUNCTION IF EXISTS billing_settlement_fault_fn()`,
		"billing_unsent_accept_fault": `DROP TRIGGER IF EXISTS billing_unsent_accept_fault ON platform_model_billing_decision; DROP FUNCTION IF EXISTS billing_unsent_accept_fault_fn()`,
		"billing_unsent_finish_fault": `DROP TRIGGER IF EXISTS billing_unsent_finish_fault ON platform_model_billing_decision; DROP FUNCTION IF EXISTS billing_unsent_finish_fault_fn()`,
	}
	statement, ok := statements[name]
	if !ok {
		return nil, fmt.Errorf("unknown billing fault fixture")
	}
	return db.ExecContext(ctx, statement)
}
