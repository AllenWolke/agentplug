package compensation

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

type alternateCoordinator struct{ Coordinator }

func TestLocalEffectLedgerRejectsUnboundCoordinator(t *testing.T) {
	db := new(sql.DB)
	var typedNil *SQLStore
	for _, coordinator := range []Coordinator{nil, typedNil, &SQLStore{db: new(sql.DB)}, alternateCoordinator{}} {
		ledger, err := NewLocalEffectLedger(context.Background(), db, coordinator)
		if ledger != nil || !errors.Is(err, ErrInvalid) {
			t.Fatalf("unbound coordinator accepted: ledger=%v err=%v", ledger, err)
		}
	}
}
