package execution

import (
	"database/sql"
	"github.com/lexagent/platform/internal/sqlutil"
	"time"
)

func (s *SQLStore) dbProofEvent(tx *sql.Tx, id string, payload []byte) (sql.Result, error) {
	return tx.Exec(sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES (?,?,?,?)`), id, "runtime_process_stop_confirmed", payload, time.Now().UTC())
}
