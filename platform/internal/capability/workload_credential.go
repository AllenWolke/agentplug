package capability

import (
	"context"
	"errors"
	"github.com/lexagent/platform/internal/sharedkernel"
	"net/http"
)

type WorkloadCredentialAuthority interface {
	AuthenticateWorkload(context.Context, sharedkernel.Scope, string, string, string) error
}

func (m *Module) authenticateWorkload(r *http.Request, op envelope) error {
	authority, ok := m.liveAuthority.(WorkloadCredentialAuthority)
	if !ok {
		return errors.New("workload credential authority unavailable")
	}
	c := op.Context
	scope := sharedkernel.Scope{TenantID: c.TenantID, DepartmentID: c.DepartmentID, ApplicationID: c.ApplicationID, AgentInstanceID: c.AgentInstanceID, AgentID: c.AgentID, PrincipalType: c.PrincipalType, PrincipalID: c.ActorID, InstallationID: c.InstallationID, AgentVersionID: c.AgentVersionID, SessionID: c.SessionID, RunID: c.TaskID, ParentRunID: c.ParentRunID, AuthorizationEpoch: c.AuthorizationEpoch, TraceID: c.TraceID}
	return authority.AuthenticateWorkload(r.Context(), scope, r.Header.Get("X-Agent-Client-ID"), r.Header.Get("X-Agent-Client-Secret"), r.RemoteAddr)
}

type workloadCredentialKey struct{}
type workloadCredentialProof struct {
	scope                  sharedkernel.Scope
	clientID, secret, peer string
}

// AgentCoordinationStopWorkloadProof is a composition-only reader for the
// authenticated workload credential carried by a stop-only request. Callers
// must reauthenticate it while holding IAM read continuity in the stop
// transaction. The secret is never returned in an HTTP response or log.
func AgentCoordinationStopWorkloadProof(ctx context.Context, scope sharedkernel.Scope) (string, string, string, error) {
	proof, ok := ctx.Value(workloadCredentialKey{}).(workloadCredentialProof)
	if !ok || proof.scope != scope || proof.clientID == "" || proof.secret == "" || proof.peer == "" {
		return "", "", "", errors.New("workload proof missing or mismatched")
	}
	return proof.clientID, proof.secret, proof.peer, nil
}

func workloadScope(c harnessContext) sharedkernel.Scope {
	return sharedkernel.Scope{TenantID: c.TenantID, DepartmentID: c.DepartmentID, ApplicationID: c.ApplicationID, AgentInstanceID: c.AgentInstanceID, AgentID: c.AgentID, PrincipalType: c.PrincipalType, PrincipalID: c.ActorID, InstallationID: c.InstallationID, AgentVersionID: c.AgentVersionID, SessionID: c.SessionID, RunID: c.TaskID, ParentRunID: c.ParentRunID, AuthorizationEpoch: c.AuthorizationEpoch, TraceID: c.TraceID}
}
func retainWorkloadProof(r *http.Request, op envelope) {
	proof := workloadCredentialProof{scope: workloadScope(op.Context), clientID: r.Header.Get("X-Agent-Client-ID"), secret: r.Header.Get("X-Agent-Client-Secret"), peer: r.RemoteAddr}
	*r = *r.WithContext(context.WithValue(r.Context(), workloadCredentialKey{}, proof))
}
func (m *Module) recheckWorkloadProof(ctx context.Context, scope sharedkernel.Scope) error {
	proof, exists := ctx.Value(workloadCredentialKey{}).(workloadCredentialProof)
	if !exists {
		return nil
	}
	if proof.scope != scope {
		return errors.New("workload proof scope mismatch")
	}
	authority, ok := m.liveAuthority.(WorkloadCredentialAuthority)
	if !ok {
		return errors.New("workload credential authority unavailable")
	}
	return authority.AuthenticateWorkload(ctx, scope, proof.clientID, proof.secret, proof.peer)
}
