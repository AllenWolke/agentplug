package capability

import (
	"log"
	"net/http"
)

// An unfinished database check grants no access, but is not proof of revoked
// authority. This says nothing about whether earlier work executed: callers
// must retain receipts and reconcile the same operation, never blindly resend.
func capabilityCheckFailure(err error) (int, string) {
	if budgetAdmissionDeferred(err) {
		return http.StatusServiceUnavailable, "CAPABILITY_UNAVAILABLE"
	}
	return http.StatusForbidden, "CAPABILITY_DENIED"
}

func (m *Module) capabilityCheckUnavailable(w http.ResponseWriter, op envelope, err error) bool {
	status, code := capabilityCheckFailure(err)
	if status != http.StatusServiceUnavailable {
		return false
	}
	retainCapabilityDiagnostic(w, err)
	log.Printf("capability current check unfinished run_id=%q stage=%s reason=%s", op.Context.TaskID, capabilityFailureDiagnostic(err), budgetAdmissionErrorType(err))
	m.error(w, status, code, "current capability check unavailable; reconcile the original operation before further work", op.Context.TraceID)
	return true
}
