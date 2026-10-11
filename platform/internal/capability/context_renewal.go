package capability

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type capabilityTokenRenewer interface {
	RenewCapability(context.Context, sharedkernel.Scope, string, string, string) (string, error)
}

func (m *Module) renewContext(w http.ResponseWriter, r *http.Request) {
	// Only this endpoint accepts expired identity proof; capabilities never do.
	// 仅续签入口可读取过期身份签名；仍须实时核对 IAM/Run/租约，能力入口禁止过期。
	if m.publicKey == nil || m.liveAuthority == nil {
		m.error(w, http.StatusServiceUnavailable, "RENEWAL_UNAVAILABLE", "execution renewal unavailable", "")
		return
	}
	op, ok := m.authorizeWithExpiry(w, r, true)
	if !ok {
		return
	}
	renewer, ok := m.liveAuthority.(capabilityTokenRenewer)
	if !ok {
		m.error(w, 503, "RENEWAL_UNAVAILABLE", "execution renewal unavailable", op.Context.TraceID)
		return
	}
	parts := strings.Split(op.Context.PlatformContextToken, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	var proof struct {
		Actions    []string `json:"actions"`
		BodyHash   string   `json:"body_hash"`
		PolicyHash string   `json:"policy_snapshot_hash"`
		Revision   uint64   `json:"execution_revision"`
		LeaseHash  string   `json:"lease_token_hash"`
	}
	if err != nil || json.Unmarshal(raw, &proof) != nil || len(proof.Actions) != 1 {
		m.error(w, 403, "RENEWAL_DENIED", "execution proof denied", op.Context.TraceID)
		return
	}
	c := op.Context
	scope := sharedkernel.Scope{TenantID: c.TenantID, DepartmentID: c.DepartmentID, ApplicationID: c.ApplicationID, InstallationID: c.InstallationID, AgentInstanceID: c.AgentInstanceID, AgentID: c.AgentID, AgentVersionID: c.AgentVersionID, PrincipalType: c.PrincipalType, PrincipalID: c.ActorID, RunID: c.TaskID, ParentRunID: c.ParentRunID, SessionID: c.SessionID, TraceID: c.TraceID, AuthorizationEpoch: c.AuthorizationEpoch}
	ctx := sharedkernel.WithExecutionLease(r.Context(), sharedkernel.ExecutionLeaseBinding{Revision: proof.Revision, TokenHash: proof.LeaseHash})
	token, err := renewer.RenewCapability(ctx, scope, proof.Actions[0], proof.BodyHash, proof.PolicyHash)
	if err != nil || token == "" {
		m.error(w, 403, "RENEWAL_DENIED", "current execution renewal denied", c.TraceID)
		return
	}
	m.ok(w, map[string]string{"context_token": token}, c.TraceID)
}
