package capability

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// ToolApprovalSigner belongs to the human control-plane process only.
// Issue signs only after the owner transaction, audit and Outbox commit.
type ToolApprovalSigner struct {
	privateKey ed25519.PrivateKey
	store      *SQLToolApprovalStore
}

func NewToolApprovalSigner(key ed25519.PrivateKey, store *SQLToolApprovalStore) (*ToolApprovalSigner, error) {
	if len(key) != ed25519.PrivateKeySize || store == nil || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])) {
		return nil, errors.New("tool approval signer unavailable")
	}
	return &ToolApprovalSigner{privateKey: append(ed25519.PrivateKey(nil), key...), store: store}, nil
}

func (s *ToolApprovalSigner) String() string   { return "ToolApprovalSigner[redacted]" }
func (s *ToolApprovalSigner) GoString() string { return s.String() }

func (s *ToolApprovalSigner) Issue(ctx context.Context, scope sharedkernel.Scope, claims ToolConfirmationClaims, proof string) (string, error) {
	if s == nil || s.store == nil {
		return "", ErrToolApprovalDenied
	}
	body, err := json.Marshal(claims)
	if err != nil || len(body) > 4096 {
		return "", ErrToolApprovalDenied
	}
	if err := s.store.Approve(ctx, scope, claims, proof); err != nil {
		return "", err
	}
	if err := s.store.CheckApproval(ctx, claims); err != nil {
		return "", err
	}
	signature := ed25519.Sign(s.privateKey, append([]byte(toolConfirmationDomain), body...))
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// ReissueApproved recreates a token for an exact, still-live committed approval.
// It neither creates an approval nor extends its lifetime. Only the platform
// dispatch composition may use it, after current dual-identity authorization;
// tokens must remain transient and must not enter durable Run/event records.
func (s *ToolApprovalSigner) ReissueApproved(ctx context.Context, scope sharedkernel.Scope, claims ToolConfirmationClaims) (string, error) {
	if s == nil || s.store == nil || ctx.Err() != nil || scope.ValidateTrusted() != nil || scope.PrincipalType != "user" || claims.Version != "tool-confirmation/v1" || claims.ActorID != scope.PrincipalID || claims.ScopeHash != ToolReceiptScopeHash(scope) || claims.AuthorizationEpoch != scope.AuthorizationEpoch || claims.PendingKey == "" || !validPendingConfirmationReference(claims) || claims.PolicyHash == "" || claims.ToolName == "" || claims.CallID == "" || claims.Fingerprint == "" {
		return "", ErrToolApprovalDenied
	}
	now := time.Now().UTC().Unix()
	if claims.IssuedAt <= 0 || claims.IssuedAt > now+5 || claims.ExpiresAt <= now || claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > 300 {
		return "", ErrToolApprovalDenied
	}
	body, err := json.Marshal(claims)
	if err != nil || len(body) > 4096 {
		return "", ErrToolApprovalDenied
	}
	if s.store.CheckApproval(ctx, claims) != nil || ctx.Err() != nil {
		return "", ErrToolApprovalDenied
	}
	signature := ed25519.Sign(s.privateKey, append([]byte(toolConfirmationDomain), body...))
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
