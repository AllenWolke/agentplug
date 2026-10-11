package notification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

var ErrReversalUnconfirmed = errors.New("notification reversal unconfirmed")

// Binding omits names, contact details and message bodies. It pins the exact
// original message, recipient and tenancy; a different message cannot satisfy
// the receipt even when the webhook returns HTTP 200.
type ReversalBinding struct {
	Version         string `json:"version"`
	EventID         string `json:"event_id"`
	TenantID        string `json:"tenant_id"`
	DepartmentID    string `json:"department_id"`
	ApplicationID   string `json:"application_id"`
	RecipientDigest string `json:"recipient_digest"`
	MessageDigest   string `json:"message_digest"`
}

func reversalDigest(value any) string {
	raw, _ := json.Marshal(value)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func reversalHash(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32
}

func AgentReversalBinding(event Event) (ReversalBinding, error) {
	if event.validateFields() != nil || event.Topic != "platform.notification" || event.EventType != "agent.notification.requested.v1" {
		return ReversalBinding{}, ErrInvalidEvent
	}
	recipient, ok := event.Payload["recipient_id"].(string)
	if !ok || recipient == "" || len(recipient) > 255 || strings.TrimSpace(recipient) != recipient {
		return ReversalBinding{}, ErrInvalidEvent
	}
	for _, name := range []string{"tool_name", "tool_call_id", "tool_fingerprint", "run_id", "session_id", "installation_id", "agent_version_id", "principal_id", "principal_type"} {
		value, ok := event.Payload[name].(string)
		if !ok || value == "" {
			return ReversalBinding{}, ErrInvalidEvent
		}
	}
	return ReversalBinding{Version: "notification-message-binding/v1", EventID: event.ID, TenantID: event.TenantID, DepartmentID: event.DepartmentID, ApplicationID: event.ApplicationID, RecipientDigest: reversalDigest([]string{event.TenantID, event.DepartmentID, event.ApplicationID, recipient}), MessageDigest: reversalDigest([]any{event.ID, event.TenantID, event.DepartmentID, event.ApplicationID, event.Topic, event.EventType, event.PartitionKey, event.Payload})}, nil
}

func (b ReversalBinding) Validate() error {
	if b.Version != "notification-message-binding/v1" || b.EventID == "" || len(b.EventID) > 128 || b.TenantID == "" || b.DepartmentID == "" || b.ApplicationID == "" || !reversalHash(b.RecipientDigest) || !reversalHash(b.MessageDigest) {
		return ErrInvalidEvent
	}
	return nil
}

type ReversalRequest struct {
	Version string          `json:"version"`
	Binding ReversalBinding `json:"binding"`
	Key     string          `json:"compensation_key"`
	Action  string          `json:"action"`
}

func (r ReversalRequest) Validate() error {
	if r.Version != "notification-reversal/v1" || r.Binding.Validate() != nil || !reversalHash(r.Key) || (r.Action != "withdraw" && r.Action != "correct") {
		return ErrInvalidEvent
	}
	return nil
}

type ReversalReceipt struct {
	Version        string          `json:"version"`
	Binding        ReversalBinding `json:"binding"`
	Key            string          `json:"compensation_key"`
	Action         string          `json:"action"`
	Disposition    string          `json:"disposition"`
	ForwardClosed  bool            `json:"forward_closed"`
	EvidenceDigest string          `json:"evidence_digest"`
}

func (p ReversalReceipt) Validate(r ReversalRequest) error {
	if r.Validate() != nil || p.Version != "notification-reversal-receipt/v1" || p.Binding != r.Binding || p.Key != r.Key || p.Action != r.Action || !p.ForwardClosed || !reversalHash(p.EvidenceDigest) {
		return ErrReversalUnconfirmed
	}
	if p.Disposition == "no_effect" || (r.Action == "withdraw" && p.Disposition == "withdrawn") || (r.Action == "correct" && p.Disposition == "corrected") {
		return nil
	}
	return ErrReversalUnconfirmed
}

// Implementations MUST atomically fence delayed Send for this binding. Lookup
// is read-only; queued/published/2xx and unconfirmed correction are not proofs.
// A legacy ChannelAdapter intentionally does not implement this contract.
type RevocableChannel interface {
	ChannelAdapter
	LookupReversal(context.Context, ReversalRequest) (ReversalReceipt, bool, error)
	Revoke(context.Context, ReversalRequest) (ReversalReceipt, error)
}
