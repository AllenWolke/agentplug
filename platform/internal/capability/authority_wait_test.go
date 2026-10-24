package capability

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestAuthorityWaitDoesNotBecomeRevocationOrDiscloseState(t *testing.T) {
	m := &Module{}
	for _, cause := range []error{context.DeadlineExceeded, &pgconn.PgError{Code: "55P03", Message: "private database detail"}, &pgconn.PgError{Code: "57014"}} {
		err := errors.Join(ErrStateDenied, &capabilityStageError{stage: "RUN_AUTHORITY", cause: cause})
		response := httptest.NewRecorder()
		m.stateError(response, envelope{}, err)
		if response.Code != 503 || !strings.Contains(response.Body.String(), "STATE_UNAVAILABLE") || strings.Contains(response.Body.String(), "private database detail") {
			t.Fatal("transient state check exposed details or became revocation", response.Code, response.Body.String())
		}
		response = httptest.NewRecorder()
		if !m.capabilityCheckUnavailable(response, envelope{}, err) || response.Code != 503 || !strings.Contains(response.Body.String(), "CAPABILITY_UNAVAILABLE") {
			t.Fatal("unfinished capability check became a grant/denial", response.Code)
		}
	}
	for _, cause := range []error{context.Canceled, ErrStateDenied, ErrToolApprovalDenied, errors.New("revoked")} {
		response := httptest.NewRecorder()
		if m.capabilityCheckUnavailable(response, envelope{}, cause) {
			t.Fatal("actual cancellation/denial treated as a transient database check")
		}
	}
	response := httptest.NewRecorder()
	m.stateError(response, envelope{}, ErrStateDenied)
	if response.Code != 403 || !strings.Contains(response.Body.String(), "STATE_AUTHORITY_DENIED") {
		t.Fatal("actual State denial was weakened")
	}
}
