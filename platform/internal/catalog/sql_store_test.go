package catalog

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestCatalogPersistenceErrorMapsOnlyDuplicateKeysToConflict(t *testing.T) {
	duplicate := &pgconn.PgError{Code: "23505", Message: "duplicate key"}
	if err := catalogPersistenceError("create installation", errors.Join(errors.New("insert failed"), duplicate)); !errors.Is(err, ErrCatalogConflict) {
		t.Fatalf("duplicate key must map to a stable catalog conflict, got %v", err)
	}
	transient := errors.New("database unavailable")
	if err := catalogPersistenceError("create installation", transient); !errors.Is(err, transient) || errors.Is(err, ErrCatalogConflict) {
		t.Fatalf("non-duplicate database errors must retain their cause, got %v", err)
	}
}
