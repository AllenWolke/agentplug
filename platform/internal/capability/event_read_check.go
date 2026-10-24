package capability

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type EventReadAuthority interface {
	AuthorizeEventRead(context.Context, sharedkernel.Scope, string) error
}

// Events use their own signed envelope, not the business capability envelope.
// This read-only endpoint validates the exact cursor plus live caller/machine.
func (m *Module) checkEventRead(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	authority, ok := m.liveAuthority.(EventReadAuthority)
	workload, workloadOK := m.liveAuthority.(WorkloadCredentialAuthority)
	if !ok || !workloadOK || len(m.publicKey) != ed25519.PublicKeySize || m.signingSecret == "" || m.internalToken == "" {
		m.error(w, 503, "EVENT_AUTHORIZATION_UNAVAILABLE", "event authority unavailable", "")
		return
	}
	if r.Method != http.MethodPost || !hmac.Equal([]byte(m.internalToken), []byte(r.Header.Get("X-Internal-Token"))) {
		m.error(w, 401, "UNAUTHENTICATED", "invalid internal credential", "")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 32769))
	if err != nil || len(raw) > 32768 {
		m.error(w, 413, "REQUEST_TOO_LARGE", "event request exceeds limit", "")
		return
	}
	mac := hmac.New(sha256.New, []byte(m.signingSecret))
	_, _ = mac.Write(requestSignaturePayload(r.Method, r.URL.RequestURI(), raw))
	supplied := strings.TrimPrefix(r.Header.Get("X-Context-Signature"), "sha256=")
	if !hmac.Equal([]byte(supplied), []byte(fmt.Sprintf("%x", mac.Sum(nil)))) {
		m.error(w, 401, "INVALID_SIGNATURE", "invalid request signature", "")
		return
	}
	var request contract.EventRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || request.Validate() != nil {
		m.error(w, 400, "INVALID_REQUEST", "invalid event envelope", "")
		return
	}
	s := request.Scope
	c := harnessContext{TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID,
		InstallationID: s.InstallationID, AgentInstanceID: s.AgentInstanceID, AgentID: s.AgentID,
		AgentVersionID: s.AgentVersionID, PrincipalType: s.PrincipalType, ActorID: s.PrincipalID,
		TaskID: s.RunID, ParentRunID: s.ParentRunID, SessionID: s.SessionID, TraceID: s.TraceID,
		AuthorizationEpoch: s.AuthorizationEpoch, PlatformContextToken: request.ContextToken}
	if m.validateContext(r, c) != nil {
		m.error(w, 403, "EVENT_AUTHORIZATION_DENIED", "event capability denied", s.TraceID)
		return
	}
	parts := strings.Split(request.ContextToken, ".")
	claimsRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Actions    []string `json:"actions"`
		BodyHash   string   `json:"body_hash"`
		PolicyHash string   `json:"policy_snapshot_hash"`
	}
	digest, hashErr := contract.CanonicalEventBodyHash(request)
	if err != nil || hashErr != nil || json.Unmarshal(claimsRaw, &claims) != nil || len(claims.Actions) != 1 || claims.Actions[0] != "events" || claims.BodyHash != digest || claims.PolicyHash != request.PolicySnapshotHash {
		m.error(w, 403, "EVENT_AUTHORIZATION_DENIED", "event binding denied", s.TraceID)
		return
	}
	scope := sharedkernel.Scope{TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID,
		InstallationID: s.InstallationID, AgentInstanceID: s.AgentInstanceID, AgentID: s.AgentID,
		AgentVersionID: s.AgentVersionID, PrincipalType: s.PrincipalType, PrincipalID: s.PrincipalID,
		RunID: s.RunID, ParentRunID: s.ParentRunID, SessionID: s.SessionID, TraceID: s.TraceID, AuthorizationEpoch: s.AuthorizationEpoch}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := workload.AuthenticateWorkload(ctx, scope, r.Header.Get("X-Agent-Client-ID"), r.Header.Get("X-Agent-Client-Secret"), r.RemoteAddr); err != nil {
		if m.capabilityCheckUnavailable(w, envelope{Context: c}, err) {
			return
		}
		m.error(w, 403, "EVENT_AUTHORIZATION_DENIED", "current event read denied", s.TraceID)
		return
	}
	if err := authority.AuthorizeEventRead(ctx, scope, request.PolicySnapshotHash); err != nil {
		if m.capabilityCheckUnavailable(w, envelope{Context: c}, err) {
			return
		}
		m.error(w, 403, "EVENT_AUTHORIZATION_DENIED", "current event read denied", s.TraceID)
		return
	}
	if m.capabilityCheckUnavailable(w, envelope{Context: c}, ctx.Err()) {
		return
	}
	if ctx.Err() != nil || m.validateContext(r, c) != nil {
		m.error(w, 403, "EVENT_AUTHORIZATION_DENIED", "event capability expired", s.TraceID)
		return
	}
	m.ok(w, map[string]bool{"allowed": true}, s.TraceID)
}
