package execution

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestRetryableCreateErrorOnlyRetriesTransientPostgresFailures(t *testing.T) {
	for _, test := range []struct {
		name string
		code string
		want bool
	}{
		{name: "serialization", code: "40001", want: true},
		{name: "deadlock", code: "40P01", want: true},
		{name: "lock wait timeout", code: "55P03", want: true},
		{name: "duplicate", code: "23505", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := &pgconn.PgError{Code: test.code, Message: test.name}
			if got := retryableCreateError(errors.Join(errors.New("transaction failed"), err)); got != test.want {
				t.Fatalf("retryableCreateError(%s)=%v, want %v", test.code, got, test.want)
			}
		})
	}
}
