package sqlutil

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestBindPreservesSQLQuotedDataAndComments(t *testing.T) {
	query := `SELECT '?' AS data, "?" AS quoted_identifier, $$?$$, $body$?$body$ FROM records WHERE tenant_id=? /* ? /* nested ? */ */ AND id=? -- ?
 AND revision=?`
	want := `SELECT '?' AS data, "?" AS quoted_identifier, $$?$$, $body$?$body$ FROM records WHERE tenant_id=$1 /* ? /* nested ? */ */ AND id=$2 -- ?
 AND revision=$3`
	if got := Bind(query); got != want {
		t.Fatalf("quoted data or parameter order corrupted: %s", got)
	}
	if got := Bind(`SELECT $1::jsonb ->> 'key?'`); got != `SELECT $1::jsonb ->> 'key?'` {
		t.Fatal("native PostgreSQL statement changed")
	}
}

func TestPostgresErrorsPreserveDomainConflictAndHideCredentials(t *testing.T) {
	if !IsUniqueViolation(fmt.Errorf("write: %w", &pgconn.PgError{Code: "23505"})) {
		t.Fatal("wrapped unique violation not recognized")
	}
	if IsUniqueViolation(&pgconn.PgError{Code: "40001"}) {
		t.Fatal("serialization failure incorrectly treated as duplicate")
	}
	secret := "must-not-appear-in-error"
	_, err := OpenPostgres(context.Background(), "postgres://bad:"+secret+"@invalid:bad/database")
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("invalid DSN accepted or credential leaked")
	}
}
