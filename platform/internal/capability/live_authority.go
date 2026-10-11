package capability

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// LiveExecutionAuthority binds an already verified JWT to current Run, IAM and
// installation facts. / LiveExecutionAuthority 将已验证 JWT 绑定当前 Run、IAM 和安装事实。
type LiveExecutionAuthority interface {
	AuthorizeCapability(context.Context, sharedkernel.Scope, string, string, string) error
}

// StopOnlyExecutionAuthority authenticates the signed command against its
// current execution generation without consulting live IAM or catalog grants.
// It is reserved for cancelling a previously admitted child edge.
type StopOnlyExecutionAuthority interface {
	AuthorizeStopOnlyExecution(context.Context, sharedkernel.Scope, string, string, string, sharedkernel.ExecutionLeaseBinding) error
}

type executionCapabilityClaims struct {
	Actions    []string `json:"actions"`
	BodyHash   string   `json:"body_hash"`
	PolicyHash string   `json:"policy_snapshot_hash"`
	Revision   uint64   `json:"execution_revision"`
	LeaseHash  string   `json:"lease_token_hash"`
}

func signedExecutionClaims(c harnessContext) (executionCapabilityClaims, error) {
	var claims executionCapabilityClaims
	parts := strings.Split(c.PlatformContextToken, ".")
	if len(parts) != 3 {
		return claims, errors.New("invalid command token")
	}
	encoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(encoded, &claims) != nil || len(claims.Actions) != 1 || (claims.Actions[0] != "run" && claims.Actions[0] != "invoke" && claims.Actions[0] != "resume") {
		return executionCapabilityClaims{}, errors.New("execution operation denied")
	}
	for _, hash := range []string{claims.BodyHash, claims.PolicyHash} {
		decoded, err := hex.DecodeString(hash)
		if err != nil || len(decoded) != 32 || hash != strings.ToLower(hash) {
			return executionCapabilityClaims{}, errors.New("execution digest denied")
		}
	}
	leaseBytes, err := hex.DecodeString(claims.LeaseHash)
	if claims.Revision == 0 || err != nil || len(leaseBytes) != 32 || claims.LeaseHash != strings.ToLower(claims.LeaseHash) {
		return executionCapabilityClaims{}, errors.New("execution lease proof denied")
	}
	return claims, nil
}

func (claims executionCapabilityClaims) lease() sharedkernel.ExecutionLeaseBinding {
	return sharedkernel.ExecutionLeaseBinding{Revision: claims.Revision, TokenHash: claims.LeaseHash}
}

func (m *Module) SetLiveExecutionAuthority(authority LiveExecutionAuthority) {
	m.liveAuthority = authority
}

func (m *Module) validateLiveAuthority(ctx context.Context, op envelope) error {
	if m.liveAuthority == nil {
		return errors.New("live execution authority unavailable")
	}
	// Signature, identity and expiry were checked by validateContext first.
	// 身份、签名和有效期已由 validateContext 检查，此处只读取已验证的绑定字段。
	claims, err := signedExecutionClaims(op.Context)
	if err != nil {
		return err
	}
	ctx = sharedkernel.WithExecutionLease(ctx, claims.lease())
	if m.policy != nil && op.Policy.Hash != claims.PolicyHash {
		return errors.New("signed policy snapshot denied")
	}
	c := op.Context
	scope := sharedkernel.Scope{TenantID: c.TenantID, DepartmentID: c.DepartmentID, ApplicationID: c.ApplicationID, AgentInstanceID: c.AgentInstanceID, AgentID: c.AgentID, PrincipalType: c.PrincipalType, PrincipalID: c.ActorID, InstallationID: c.InstallationID, AgentVersionID: c.AgentVersionID, SessionID: c.SessionID, RunID: c.TaskID, ParentRunID: c.ParentRunID, AuthorizationEpoch: c.AuthorizationEpoch, TraceID: c.TraceID}
	if err := m.liveAuthority.AuthorizeCapability(ctx, scope, claims.Actions[0], claims.BodyHash, claims.PolicyHash); err != nil {
		return err
	}
	if op.ResourceAccess.Action != "" {
		authority, ok := m.liveAuthority.(CapabilityResourceAuthority)
		if !ok {
			return errors.New("capability resource authority unavailable")
		}
		if err := authority.AuthorizeCapabilityResource(ctx, scope, op.ResourceAccess); err != nil {
			return err
		}
	}
	return m.recheckWorkloadProof(ctx, scope)
}

func (m *Module) authorizeStopOnlyExecution(ctx context.Context, op envelope) (sharedkernel.ExecutionLeaseBinding, string, error) {
	if m.liveAuthority == nil {
		return sharedkernel.ExecutionLeaseBinding{}, "", errors.New("live execution authority unavailable")
	}
	claims, err := signedExecutionClaims(op.Context)
	if err != nil {
		return sharedkernel.ExecutionLeaseBinding{}, "", err
	}
	authority, ok := m.liveAuthority.(StopOnlyExecutionAuthority)
	if !ok {
		return sharedkernel.ExecutionLeaseBinding{}, "", errors.New("stop-only execution authority unavailable")
	}
	c := op.Context
	scope := sharedkernel.Scope{TenantID: c.TenantID, DepartmentID: c.DepartmentID, ApplicationID: c.ApplicationID, AgentInstanceID: c.AgentInstanceID, AgentID: c.AgentID, PrincipalType: c.PrincipalType, PrincipalID: c.ActorID, InstallationID: c.InstallationID, AgentVersionID: c.AgentVersionID, SessionID: c.SessionID, RunID: c.TaskID, ParentRunID: c.ParentRunID, AuthorizationEpoch: c.AuthorizationEpoch, TraceID: c.TraceID}
	if err := authority.AuthorizeStopOnlyExecution(ctx, scope, claims.Actions[0], claims.BodyHash, claims.PolicyHash, claims.lease()); err != nil {
		return sharedkernel.ExecutionLeaseBinding{}, "", fmt.Errorf("stop-only execution authority denied: %w", err)
	}
	return claims.lease(), claims.PolicyHash, nil
}
