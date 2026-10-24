package capability

import (
	"errors"
	"net/http"
)

// Internal diagnostics retain only a fixed admission stage. Error text and the
// public response remain unchanged; credentials and provider messages are never
// copied into this field.
type capabilityStageError struct {
	stage string
	cause error
}

func (e *capabilityStageError) Error() string { return e.cause.Error() }
func (e *capabilityStageError) Unwrap() error { return e.cause }

func capabilityFailureDiagnostic(err error) string {
	if err == nil {
		return ""
	}
	var staged *capabilityStageError
	if errors.As(err, &staged) {
		switch staged.stage {
		case "SIGNED_EXECUTION", "SIGNED_POLICY", "RUN_AUTHORITY", "RESOURCE_AUTHORITY", "WORKLOAD_PROOF":
			return staged.stage
		}
	}
	switch err.Error() {
	case "invalid platform context signature":
		return "CONTEXT_SIGNATURE"
	case "platform context claim mismatch: iss":
		return "CONTEXT_ISSUER"
	case "platform context claim mismatch: aud":
		return "CONTEXT_AUDIENCE"
	case "platform context expired":
		return "CONTEXT_EXPIRED"
	case "platform context mismatch":
		return "CONTEXT_HEADER"
	case "platform context authorization epoch mismatch":
		return "CONTEXT_EPOCH"
	case "current capability policy denied":
		return "CURRENT_POLICY"
	default:
		return "ADMISSION_UNKNOWN"
	}
}

func retainCapabilityDiagnostic(w http.ResponseWriter, err error) {
	if capture, ok := w.(*modelCallResponse); ok {
		capture.diagnostic = capabilityFailureDiagnostic(err)
	}
}
