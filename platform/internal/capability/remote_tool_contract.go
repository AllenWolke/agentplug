package capability

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

// ToolOperationIdentity describes the business intent, never an executor attempt.
// Ownership tokens, lease generations and retries must not enter OperationID.
// RequestSHA256 is compared independently: changed arguments cannot become a
// second intent merely because their hash changed.
type ToolOperationIdentity struct {
	Version       string `json:"version"`
	OperationID   string `json:"operation_id"`
	ScopeSHA256   string `json:"scope_sha256"`
	RunID         string `json:"run_id"`
	CallID        string `json:"call_id"`
	ToolName      string `json:"tool_name"`
	RequestSHA256 string `json:"request_sha256"`
}

func NewToolOperationIdentity(q ToolReceiptQuery) (ToolOperationIdentity, error) {
	if q.Scope.ValidateTrusted() != nil || !remoteIdentifier(q.CallID, 255) || !remoteIdentifier(q.Name, 128) || !remoteIdentifier(q.Scope.RunID, 128) || !auditRuntimeDigest(q.Fingerprint) {
		return ToolOperationIdentity{}, ErrToolInvocationConflict
	}
	scope := ToolReceiptScopeHash(q.Scope)
	hash := sha256.Sum256([]byte(scope + "\x00" + q.CallID))
	return ToolOperationIdentity{Version: "tool-operation-identity/v1", OperationID: fmt.Sprintf("operation-%x", hash), ScopeSHA256: scope, RunID: q.Scope.RunID, CallID: q.CallID, ToolName: q.Name, RequestSHA256: q.Fingerprint}, nil
}

func remoteIdentifier(value string, max int) bool {
	return value != "" && len(value) <= max && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

// RemoteToolContract is operator-owned and frozen with a pending receipt query.
// Declaring a durable key does not enable resending unknown operations. The
// current recovery engine remains query-only, including after key expiry.
type RemoteToolContract struct {
	Version          string `json:"version"`
	Idempotency      string `json:"idempotency"`
	RetentionSeconds int    `json:"retention_seconds"`
	ConflictRule     string `json:"conflict_rule"`
	ReceiptTool      string `json:"receipt_tool,omitempty"`
	ReceiptSchema    string `json:"receipt_schema_sha256,omitempty"`
	ReceiptReadOnly  bool   `json:"receipt_read_only,omitempty"`
	BindingSHA256    string `json:"binding_sha256,omitempty"`
}

func (c RemoteToolContract) Validate() error {
	if c.BindingSHA256 != "" && !auditRuntimeDigest(c.BindingSHA256) {
		return errors.New("invalid remote provider binding")
	}
	if c.Version != "remote-tool-effects/v1" || c.Idempotency != "none" && c.Idempotency != "durable_key" || c.ConflictRule != "reject_mismatch" || c.RetentionSeconds < 0 || c.RetentionSeconds > 31536000 {
		return errors.New("invalid remote effect contract")
	}
	if c.Idempotency == "durable_key" && c.RetentionSeconds == 0 || c.Idempotency == "none" && c.RetentionSeconds != 0 {
		return errors.New("invalid remote idempotency retention")
	}
	if c.ReceiptTool == "" && (c.ReceiptSchema != "" || c.ReceiptReadOnly) || c.ReceiptTool != "" && (!c.ReceiptReadOnly || !remoteIdentifier(c.ReceiptTool, 128) || !auditRuntimeDigest(c.ReceiptSchema)) {
		return errors.New("invalid remote receipt contract")
	}
	return nil
}

func conservativeRemoteContract() RemoteToolContract {
	return RemoteToolContract{Version: "remote-tool-effects/v1", Idempotency: "none", ConflictRule: "reject_mismatch"}
}

type RemoteToolDescriber interface {
	DescribeRemoteTool(string) (RemoteToolContract, bool)
}

// Exact, schema-pinned read-only lookup input. No original command payload is
// sent to the reconciliation tool, and no effect operation is retried here.
const remoteReceiptInputSchema = `{"type":"object","properties":{"version":{"type":"string"},"operation_id":{"type":"string"},"scope_sha256":{"type":"string"},"run_id":{"type":"string"},"call_id":{"type":"string"},"tool_name":{"type":"string"},"request_sha256":{"type":"string"}},"required":["version","operation_id","scope_sha256","run_id","call_id","tool_name","request_sha256"],"additionalProperties":false}`

type remoteToolReceipt struct {
	Version  string                `json:"version"`
	Identity ToolOperationIdentity `json:"identity"`
	Status   string                `json:"status"`
	// Preserve exact result numbers through MCP SDKs whose untyped structured
	// content decoder uses float64. The inner JSON is validated independently.
	ReceiptJSON string `json:"receipt_json,omitempty"`
}
