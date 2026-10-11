package capability

import (
	"log"

	"github.com/lexagent/platform/internal/sqlutil"
)

// Only stable categories reach logs, never SQL text, bound values or payloads.
func logLedgerFailure(stage string, err error) {
	if state := sqlutil.SQLState(err); state != "" {
		log.Printf("capability_ledger_failed stage=%s sqlstate=%s", stage, state)
		return
	}
	log.Printf("capability_ledger_failed stage=%s error_type=%T", stage, err)
}
