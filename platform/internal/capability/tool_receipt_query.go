package capability

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

// Lookup is read-only: it must not acquire a lease, retry, repair or execute.
type toolReceiptReadStore interface {
	LookupToolInvocation(context.Context, string, string) (ToolInvocation, bool, error)
}

func (s *memoryToolInvocationStore) LookupToolInvocation(_ context.Context, scope, id string) (ToolInvocation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, found := s.records[scope+"\x00"+id]
	return cloneToolInvocation(record), found, nil
}

func (s *SQLToolInvocationStore) LookupToolInvocation(ctx context.Context, scope, id string) (ToolInvocation, bool, error) {
	record := ToolInvocation{ScopeHash: scope, CallID: id}
	var result sql.NullString
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT fingerprint,status,result_json FROM platform_tool_invocation WHERE scope_hash=? AND call_id=?`), scope, id).Scan(&record.Fingerprint, &record.Status, &result)
	if errors.Is(err, sql.ErrNoRows) {
		return ToolInvocation{}, false, nil
	}
	if err != nil {
		return ToolInvocation{}, false, err
	}
	if record.Status == "completed" && (!result.Valid || decodeToolStoredResult([]byte(result.String), &record.Result) != nil) {
		return ToolInvocation{}, false, errors.New("invalid stored tool receipt")
	}
	return record, true, nil
}

func (m *Module) toolReceipt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		m.error(w, 405, "METHOD_NOT_ALLOWED", "POST required", "")
		return
	}
	op, ok := m.authorize(w, r)
	if !ok {
		return
	}
	var input struct {
		Name              string         `json:"name"`
		CallID            string         `json:"call_id"`
		Payload           map[string]any `json:"payload"`
		ConfirmationToken string         `json:"confirmation_token"`
	}
	decoder := json.NewDecoder(bytes.NewReader(op.Input))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.Name == "" || len(input.Name) > 128 || input.CallID == "" || len(input.CallID) > 128 || input.Payload == nil || len(input.ConfirmationToken) > 8192 {
		m.error(w, 400, "INVALID_REQUEST", "exact tool operation required", op.Context.TraceID)
		return
	}
	if !op.Policy.AllowsTool(input.Name) {
		m.error(w, 403, "CAPABILITY_DENIED", "tool is not allowed", op.Context.TraceID)
		return
	}
	if input.Name == notifySelfToolName {
		if op.Context.PrincipalType != "user" {
			m.error(w, http.StatusForbidden, "NOTIFICATION_RECIPIENT_DENIED", "notify.self requires a human principal", op.Context.TraceID)
			return
		}
		if _, _, err := selfNotificationFields(scopeFromHarness(op.Context), input.Payload); err != nil {
			m.error(w, http.StatusBadRequest, "INVALID_NOTIFICATION", "notify.self accepts only title and text within their size limits", op.Context.TraceID)
			return
		}
	}
	fingerprint, err := ToolCommandFingerprint(input.Name, input.Payload)
	if err != nil {
		m.error(w, 400, "INVALID_REQUEST", "invalid tool arguments", op.Context.TraceID)
		return
	}
	if m.runtimeConfirmationRequired(op.Policy.Tool.RequireConfirmation, input.Name) {
		if m.checkToolConfirmation(r.Context(), input.ConfirmationToken, scopeFromHarness(op.Context), op.Policy.Hash, input.Name, input.CallID, fingerprint) != nil {
			m.error(w, 403, "TOOL_CONFIRMATION_REQUIRED", "valid operation-bound confirmation required", op.Context.TraceID)
			return
		}
		// Retain the verified claims for the same final revocation check as invoke.
		var claims ToolConfirmationClaims
		parts := bytes.Split([]byte(input.ConfirmationToken), []byte("."))
		body, _ := base64.RawURLEncoding.Strict().DecodeString(string(parts[0]))
		if json.Unmarshal(body, &claims) != nil {
			m.error(w, 403, "TOOL_CONFIRMATION_REQUIRED", "invalid confirmation", op.Context.TraceID)
			return
		}
		op.ToolApproval = &claims
	}
	store, available := m.toolStore.(toolReceiptReadStore)
	if !available {
		m.error(w, 503, "TOOL_RECEIPT_UNAVAILABLE", "receipt query unavailable", op.Context.TraceID)
		return
	}
	record, found, err := store.LookupToolInvocation(r.Context(), toolScopeHash(op.Context), input.CallID)
	if err != nil {
		m.error(w, 503, "TOOL_RECEIPT_UNAVAILABLE", "receipt query failed", op.Context.TraceID)
		return
	}
	status := "not_found"
	var receipt map[string]any
	if found {
		if record.Fingerprint != fingerprint {
			m.error(w, 409, "TOOL_IDEMPOTENCY_CONFLICT", "operation binding changed", op.Context.TraceID)
			return
		}
		status = record.Status
		switch status {
		case "completed":
			receipt, err = toolObservationResponse(scopeFromHarness(op.Context), input.Name, input.CallID, record.Result)
			if err != nil {
				m.error(w, 502, "TOOL_RECEIPT_INVALID", "stored receipt rejected", op.Context.TraceID)
				return
			}
		case "running", "failed", "unknown":
		default:
			m.error(w, 502, "TOOL_RECEIPT_INVALID", "stored status rejected", op.Context.TraceID)
			return
		}
	}
	// A Code controller may have finished after the platform response was lost.
	// Fresh approved lookup reads it without executing or repairing any ledger.
	if found && (status == "running" || status == "unknown") {
		descriptor, registered := m.RuntimeToolDescriptor(input.Name)
		if registered && isNotificationTool(input.Name) && op.ToolApproval != nil {
			port, supported := m.notifications.(BusinessToolReceiptPort)
			if !supported {
				m.error(w, 503, "TOOL_RECEIPT_UNAVAILABLE", "notification receipt unavailable", op.Context.TraceID)
				return
			}
			ctx := context.WithValue(r.Context(), runtimeExecutionAuthorizationKey{}, runtimeExecutionAuthorization{PolicyHash: op.Policy.Hash, Approval: *op.ToolApproval})
			ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			result, completed, lookupErr := port.LookupToolReceipt(ctx, ToolReceiptQuery{Scope: scopeFromHarness(op.Context), Name: input.Name, CallID: input.CallID, Fingerprint: fingerprint})
			cancel()
			if lookupErr != nil {
				m.error(w, 503, "TOOL_RECEIPT_UNAVAILABLE", "notification receipt query failed", op.Context.TraceID)
				return
			}
			if completed {
				receipt, err = toolObservationResponse(scopeFromHarness(op.Context), input.Name, input.CallID, result)
				if err != nil {
					m.error(w, 502, "TOOL_RECEIPT_INVALID", "notification receipt rejected", op.Context.TraceID)
					return
				}
				status = "completed"
			}
		} else if registered && descriptor.ExecutionType == "code" && op.ToolApproval != nil {
			port, supported := m.tools.(BusinessToolReceiptPort)
			if !supported {
				m.error(w, 503, "TOOL_RECEIPT_UNAVAILABLE", "controller receipt unavailable", op.Context.TraceID)
				return
			}
			ctx := context.WithValue(r.Context(), runtimeExecutionAuthorizationKey{}, runtimeExecutionAuthorization{PolicyHash: op.Policy.Hash, Approval: *op.ToolApproval})
			ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			result, completed, lookupErr := port.LookupToolReceipt(ctx, ToolReceiptQuery{Scope: scopeFromHarness(op.Context), Name: input.Name, CallID: input.CallID, Fingerprint: fingerprint})
			cancel()
			if lookupErr != nil {
				m.error(w, 503, "TOOL_RECEIPT_UNAVAILABLE", "controller receipt query failed", op.Context.TraceID)
				return
			}
			if completed {
				receipt, err = toolObservationResponse(scopeFromHarness(op.Context), input.Name, input.CallID, result)
				if err != nil {
					m.error(w, 502, "TOOL_RECEIPT_INVALID", "controller receipt rejected", op.Context.TraceID)
					return
				}
				status = "completed"
			}
		}
	}
	m.currentResult(w, r, op, map[string]any{"version": "tool-receipt/v1", "tool_name": input.Name, "call_id": input.CallID, "status": status, "receipt": receipt})
}
