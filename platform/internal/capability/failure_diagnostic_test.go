package capability

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCapabilityDiagnosticPreservesCauseWithoutDisclosingDetails(t *testing.T) {
	private := errors.New("token=private SQL provider message")
	for _, test := range []struct {
		err  error
		want string
	}{
		{nil, ""},
		{private, "ADMISSION_UNKNOWN"},
		{errors.New("platform context claim mismatch: aud"), "CONTEXT_AUDIENCE"},
		{errors.New("platform context claim mismatch: sub=private"), "ADMISSION_UNKNOWN"},
		{&capabilityStageError{stage: "RUN_AUTHORITY", cause: private}, "RUN_AUTHORITY"},
		{&capabilityStageError{stage: "token=private", cause: private}, "ADMISSION_UNKNOWN"},
	} {
		if got := capabilityFailureDiagnostic(test.err); got != test.want {
			t.Fatalf("unexpected diagnostic %q", got)
		}
	}
	wrapped := &capabilityStageError{stage: "RUN_AUTHORITY", cause: private}
	if !errors.Is(wrapped, private) || wrapped.Error() != private.Error() {
		t.Fatal("error cause changed")
	}
	admission := &KnowledgeModelError{Status: 403, Code: "CAPABILITY_DENIED", DiagnosticCode: "RUN_AUTHORITY"}
	raw, err := json.Marshal(admission)
	if err != nil || strings.Contains(string(raw), "RUN_AUTHORITY") || strings.Contains(string(raw), "Diagnostic") || admission.Error() != "governed knowledge model stage failed: CAPABILITY_DENIED" {
		t.Fatal("internal diagnostic entered serialized error")
	}
}
