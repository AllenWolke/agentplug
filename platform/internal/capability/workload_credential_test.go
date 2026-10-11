package capability

import (
	"context"
	"errors"
	"github.com/lexagent/platform/internal/sharedkernel"
	"net/http/httptest"
	"testing"
)

type credentialProbe struct {
	revoked bool
	calls   int
}

func (p *credentialProbe) AuthorizeCapability(context.Context, sharedkernel.Scope, string, string, string) error {
	return nil
}
func (p *credentialProbe) AuthenticateWorkload(_ context.Context, _ sharedkernel.Scope, id, secret, peer string) error {
	p.calls++
	if p.revoked || id != "worker" || secret != "fixture-workload-secret-value-12345678" || peer != "127.0.0.1:1234" {
		return errors.New("workload credential revoked")
	}
	return nil
}
func TestWorkloadProofRechecksRotationAndRejectsScopeReuse(t *testing.T) {
	r := httptest.NewRequest("POST", "/internal/tool/invoke", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Agent-Client-ID", "worker")
	r.Header.Set("X-Agent-Client-Secret", "fixture-workload-secret-value-12345678")
	op := envelope{Context: capabilityContext()}
	retainWorkloadProof(r, op)
	probe := &credentialProbe{}
	m := newTestModule("internal", "signing", nil, "issuer", "audience")
	m.SetLiveExecutionAuthority(probe)
	scope := workloadScope(op.Context)
	if err := m.recheckWorkloadProof(r.Context(), scope); err != nil {
		t.Fatal(err)
	}
	probe.revoked = true
	if err := m.recheckWorkloadProof(r.Context(), scope); err == nil {
		t.Fatal("rotated/revoked proof admitted")
	}
	probe.revoked = false
	scope.InstallationID = "another"
	if err := m.recheckWorkloadProof(r.Context(), scope); err == nil {
		t.Fatal("proof reused across installations")
	}
	if probe.calls != 2 {
		t.Fatal("scope mismatch reached credential service")
	}
}
