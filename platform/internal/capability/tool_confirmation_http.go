package capability

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type ToolApprovalOperation struct {
	RunID              string         `json:"run_id"`
	Name               string         `json:"name"`
	CallID             string         `json:"call_id"`
	Payload            map[string]any `json:"payload"`
	PendingKey         string         `json:"pending_key,omitempty"`
	CheckpointRevision uint64         `json:"checkpoint_revision,omitempty"`
}

// Resolve derives the full scope and current approved policy from durable Run,
// session and dual-identity IAM facts, never from request-owned identity fields.
type ToolApprovalControl struct {
	Store          *SQLToolApprovalStore
	Signer         *ToolApprovalSigner
	Resolve        func(*http.Request, ToolApprovalOperation) (sharedkernel.Scope, string, error)
	StepUp         func(context.Context, *http.Request, sharedkernel.Scope, ToolApprovalOperation, string, string, string) (string, time.Time, error)
	ResolvePending func(*http.Request, ToolApprovalOperation, string) (ToolApprovalOperation, error)
	Resume         func(*http.Request, sharedkernel.Scope, ToolApprovalOperation, ToolConfirmationClaims) (any, error)
	ResumeReplay   func(*http.Request, ToolApprovalOperation, ToolConfirmationClaims) (any, bool, error)
}

func (m *Module) SetToolApprovalControl(control *ToolApprovalControl) {
	m.toolApprovalControl = control
}
func ToolApprovalDigest(claims ToolConfirmationClaims) string { return toolApprovalDigest(claims) }

func (m *Module) toolApprovalHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		m.error(w, 405, "METHOD_NOT_ALLOWED", "POST required", "")
		return
	}
	if r.Header.Get("X-Browser-Module") != "1" || r.Header.Get("X-Internal-Token") != m.internalToken || r.Header.Get("X-Principal-Type") != "user" {
		m.error(w, 403, "TRUSTED_USER_CONTEXT_REQUIRED", "human gateway authentication required", "")
		return
	}
	control := m.toolApprovalControl
	if control == nil || control.Resolve == nil || control.Store == nil {
		m.error(w, 503, "TOOL_APPROVAL_UNAVAILABLE", "tool approval control unavailable", "")
		return
	}
	var input struct {
		Operation       ToolApprovalOperation  `json:"operation"`
		Claims          ToolConfirmationClaims `json:"claims"`
		Action          string                 `json:"action"`
		CurrentPassword string                 `json:"current_password"`
		StepUpToken     string                 `json:"step_up_token"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	path := strings.TrimPrefix(r.URL.Path, "/tool-approvals/")
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.Operation.RunID == "" || (path != "pending" && (input.Operation.Name == "" || len(input.Operation.Name) > 128 || input.Operation.CallID == "" || len(input.Operation.CallID) > 128)) {
		m.error(w, 400, "INVALID_REQUEST", "bounded operation required", "")
		return
	}
	if path == "resume" {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		if input.CurrentPassword != "" || input.StepUpToken != "" || input.Operation.Payload != nil || input.Operation.PendingKey == "" || !validPendingConfirmationReference(input.Claims) {
			m.error(w, 400, "INVALID_REQUEST", "approved reference without credentials required", "")
			return
		}
		if control.ResumeReplay != nil {
			receipt, replayed, err := control.ResumeReplay(r, input.Operation, input.Claims)
			if err != nil || ctx.Err() != nil {
				m.error(w, 403, "TOOL_APPROVAL_DENIED", "current replay authorization denied", "")
				return
			}
			if replayed {
				m.ok(w, receipt, "")
				return
			}
		}
	}
	if path == "pending" || input.Operation.PendingKey != "" || input.Operation.CheckpointRevision != 0 {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		if control.ResolvePending == nil || !stateName.MatchString(input.Operation.PendingKey) || input.Operation.Payload != nil || input.Operation.CheckpointRevision > 64 {
			m.error(w, 400, "INVALID_REQUEST", "bounded pending operation reference required", "")
			return
		}
		pendingAction := path
		if path == "step-up" && input.Action == "tool.approval.revoke" {
			pendingAction = "revoke"
		}
		operation, err := control.ResolvePending(r, input.Operation, pendingAction)
		if err != nil || ctx.Err() != nil {
			if path == "resume" && ctx.Err() == nil && control.ResumeReplay != nil {
				receipt, replayed, replayErr := control.ResumeReplay(r, input.Operation, input.Claims)
				if replayErr == nil && replayed && ctx.Err() == nil {
					m.ok(w, receipt, "")
					return
				}
			}
			m.error(w, 403, "TOOL_APPROVAL_DENIED", "pending operation cannot be confirmed", "")
			return
		}
		input.Operation = operation
	}
	scope, policy, err := control.Resolve(r, input.Operation)
	policyBytes, policyErr := hex.DecodeString(policy)
	if err != nil || policyErr != nil || len(policyBytes) != 32 || scope.ValidateTrusted() != nil || scope.PrincipalType != "user" || scope.RunID != input.Operation.RunID || scope.PrincipalID != r.Header.Get("X-Principal-ID") || scope.TenantID != r.Header.Get("X-Tenant-ID") || scope.DepartmentID != r.Header.Get("X-Department-ID") || scope.ApplicationID != r.Header.Get("X-Application-ID") {
		m.error(w, 403, "TOOL_APPROVAL_DENIED", "current operation authorization denied", "")
		return
	}
	fingerprint, err := ToolCommandFingerprint(input.Operation.Name, input.Operation.Payload)
	if err != nil {
		m.error(w, 400, "INVALID_REQUEST", "invalid tool arguments", scope.TraceID)
		return
	}
	if path == "pending" {
		// Only an operation reference reaches the browser. Complete arguments
		// remain in the governed checkpoint and are reloaded on every action.
		input.Operation.Payload = nil
		m.ok(w, map[string]any{"operation": input.Operation}, scope.TraceID)
		return
	}
	if path == "preview" {
		var nonce [24]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			m.error(w, 503, "TOOL_APPROVAL_UNAVAILABLE", "preview unavailable", scope.TraceID)
			return
		}
		now := time.Now().UTC()
		claims := ToolConfirmationClaims{Version: "tool-confirmation/v1", ApprovalID: base64.RawURLEncoding.EncodeToString(nonce[:]), ActorID: scope.PrincipalID, ScopeHash: ToolReceiptScopeHash(scope), AuthorizationEpoch: scope.AuthorizationEpoch, PolicyHash: policy, ToolName: input.Operation.Name, CallID: input.Operation.CallID, Fingerprint: fingerprint, IssuedAt: now.Unix(), ExpiresAt: now.Unix() + 120}
		sanitizer := observationSanitizer{}
		claims.PendingKey, claims.CheckpointRevision = input.Operation.PendingKey, input.Operation.CheckpointRevision
		m.ok(w, map[string]any{"claims": claims, "request_digest": toolApprovalDigest(claims), "display_payload": sanitizer.value(input.Operation.Payload, 0), "display_filtered": sanitizer.filtered, "display_truncated": sanitizer.truncated}, scope.TraceID)
		return
	}
	c := input.Claims
	if !validPendingConfirmationReference(c) || c.PendingKey != input.Operation.PendingKey || c.CheckpointRevision != input.Operation.CheckpointRevision {
		m.error(w, 403, "TOOL_APPROVAL_DENIED", "preview checkpoint reference changed", scope.TraceID)
		return
	}
	if c.Version != "tool-confirmation/v1" || c.ActorID != scope.PrincipalID || c.ScopeHash != ToolReceiptScopeHash(scope) || c.AuthorizationEpoch != scope.AuthorizationEpoch || c.PolicyHash != policy || c.ToolName != input.Operation.Name || c.CallID != input.Operation.CallID || c.Fingerprint != fingerprint || c.ApprovalID == "" || c.IssuedAt <= 0 || c.IssuedAt > time.Now().Unix()+5 || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > 300 {
		m.error(w, 403, "TOOL_APPROVAL_DENIED", "preview operation binding changed", scope.TraceID)
		return
	}
	switch path {
	case "resume":
		if control.Resume == nil || c.PendingKey == "" || input.CurrentPassword != "" || input.StepUpToken != "" {
			m.error(w, 400, "INVALID_REQUEST", "committed pending approval reference required", scope.TraceID)
			return
		}
		receipt, err := control.Resume(r, scope, input.Operation, c)
		if err != nil {
			// Another identical owner request may have committed after this one
			// resolved waiting. Only replay a matching durable command; no retry CAS.
			if control.ResumeReplay != nil {
				reference := input.Operation
				reference.Payload = nil // ResolvePending loaded arguments only for the transaction.
				previous, replayed, replayErr := control.ResumeReplay(r, reference, c)
				if replayErr == nil && replayed && r.Context().Err() == nil {
					m.ok(w, previous, scope.TraceID)
					return
				}
			}
			m.error(w, 403, "TOOL_APPROVAL_DENIED", "approved run continuation denied", scope.TraceID)
			return
		}
		m.ok(w, receipt, scope.TraceID)
	case "step-up":
		if control.StepUp == nil || (input.Action != "tool.approval.approve" && input.Action != "tool.approval.revoke") {
			m.error(w, 400, "INVALID_REQUEST", "bound approval action required", scope.TraceID)
			return
		}
		proof, expires, err := control.StepUp(r.Context(), r, scope, input.Operation, input.Action, toolApprovalDigest(c), input.CurrentPassword)
		if err != nil {
			m.error(w, 403, "STEP_UP_FAILED", "fresh operation authentication denied", scope.TraceID)
			return
		}
		m.ok(w, map[string]any{"step_up_token": proof, "expires_at": expires}, scope.TraceID)
	case "approve":
		if control.Signer == nil {
			m.error(w, 503, "TOOL_APPROVAL_UNAVAILABLE", "approval signing unavailable", scope.TraceID)
			return
		}
		token, err := control.Signer.Issue(r.Context(), scope, c, input.StepUpToken)
		if err != nil {
			m.error(w, 403, "TOOL_APPROVAL_DENIED", "approval transaction denied", scope.TraceID)
			return
		}
		m.ok(w, map[string]any{"confirmation_token": token, "approval_id": c.ApprovalID, "expires_at": time.Unix(c.ExpiresAt, 0)}, scope.TraceID)
	case "revoke":
		if err := control.Store.Revoke(r.Context(), scope, c, input.StepUpToken); err != nil {
			m.error(w, 403, "TOOL_APPROVAL_DENIED", "revocation transaction denied", scope.TraceID)
			return
		}
		m.ok(w, map[string]any{"revoked": true, "approval_id": c.ApprovalID}, scope.TraceID)
	default:
		m.error(w, 404, "NOT_FOUND", "unknown approval action", scope.TraceID)
	}
}
