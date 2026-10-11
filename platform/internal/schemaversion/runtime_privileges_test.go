package schemaversion

import (
	"context"
	"errors"
	"testing"
)

func TestRuntimePrivilegesRejectMissingConnection(t *testing.T) {
	if !errors.Is(CheckRuntimePrivileges(context.Background(), nil), ErrRuntimePrivileges) {
		t.Fatal("missing connection accepted")
	}
}
