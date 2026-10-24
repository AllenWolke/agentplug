package capability

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"

	"github.com/lexagent/platform/internal/sqlutil"
)

// A transaction lock covers absent rows and scope-wide quota reads. PostgreSQL
// row locks cannot lock a missing key or an aggregate. Namespace-separated
// hashes prevent different ledgers from sharing locks; collisions only serialize.
func lockLedgerScope(ctx context.Context, tx *sql.Tx, namespace, scope string) error {
	digest := sha256.Sum256([]byte(namespace + "\x00" + scope))
	key := int64(binary.BigEndian.Uint64(digest[:8]))
	_, err := tx.ExecContext(ctx, sqlutil.Bind(`SELECT pg_advisory_xact_lock(?)`), key)
	return err
}

func shareLedgerScope(ctx context.Context, tx *sql.Tx, namespace, scope string) error {
	digest := sha256.Sum256([]byte(namespace + "\x00" + scope))
	key := int64(binary.BigEndian.Uint64(digest[:8]))
	_, err := tx.ExecContext(ctx, sqlutil.Bind(`SELECT pg_advisory_xact_lock_shared(?)`), key)
	return err
}
