package conversation

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// SignEvent is an events-only signature seam for trusted platform callers.
// Callers must authorize current history access before signing; receivers still
// use the read-only event authority on every disclosure. No execution lease is
// granted by this token and it cannot invoke business capabilities.
func (s Ed25519ContextTokenSigner) SignEvent(ctx context.Context, scope sharedkernel.Scope, request contract.EventRequest) (string, error) {
	if ctx == nil || ctx.Err() != nil || len(s.PrivateKey) != ed25519.PrivateKeySize || strings.TrimSpace(s.Issuer) == "" || strings.TrimSpace(s.Audience) == "" {
		return "", errors.New("event signer unavailable")
	}
	if scope.ValidateTrusted() != nil || request.ContextToken != "" || request.ProtocolVersion != contract.ProtocolVersion || request.Scope.Validate() != nil {
		return "", errors.New("event envelope invalid")
	}
	r := request.Scope
	bound := sharedkernel.Scope{TenantID: r.TenantID, DepartmentID: r.DepartmentID, ApplicationID: r.ApplicationID,
		InstallationID: r.InstallationID, AgentInstanceID: r.AgentInstanceID, AgentID: r.AgentID,
		AgentVersionID: r.AgentVersionID, PrincipalType: r.PrincipalType, PrincipalID: r.PrincipalID,
		RunID: r.RunID, ParentRunID: r.ParentRunID, SessionID: r.SessionID, TraceID: r.TraceID, AuthorizationEpoch: r.AuthorizationEpoch}
	policy, err := hex.DecodeString(request.PolicySnapshotHash)
	if bound != scope || err != nil || len(policy) != 32 || strings.ToLower(request.PolicySnapshotHash) != request.PolicySnapshotHash {
		return "", errors.New("event scope or policy denied")
	}
	digest, err := contract.CanonicalEventBodyHash(request)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if s.Clock != nil {
		now = s.Clock().UTC()
	}
	ttl := s.TTL
	if ttl <= 0 || ttl > 5*time.Minute {
		ttl = 2 * time.Minute
	}
	claims := map[string]any{"iss": s.Issuer, "aud": s.Audience, "subject_type": scope.PrincipalType,
		"sub": scope.PrincipalID, "tenant_id": scope.TenantID, "department_id": scope.DepartmentID,
		"application_id": scope.ApplicationID, "installation_id": scope.InstallationID,
		"agent_instance_id": scope.AgentInstanceID, "agent_id": scope.AgentID, "agent_version_id": scope.AgentVersionID,
		"run_id": scope.RunID, "session_id": scope.SessionID, "trace_id": scope.TraceID,
		"authorization_epoch": scope.AuthorizationEpoch, "actions": []string{"events"},
		"body_hash": digest, "policy_snapshot_hash": request.PolicySnapshotHash,
		"iat": now.Unix(), "exp": now.Add(ttl).Unix()}
	if scope.ParentRunID != "" {
		claims["parent_run_id"] = scope.ParentRunID
	}
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.PrivateKey, []byte(unsigned))), nil
}
