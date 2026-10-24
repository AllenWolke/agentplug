package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ID is a bounded wire identifier. IDs are opaque; modules must not infer
// tenant or ownership from their textual format.
// ID 是有长度上限的线标识符；模块不得从字符串格式推断租户或所有权。
type ID string

func (id ID) Valid() bool { return len(id) > 0 && len(id) <= 128 }

type ScopeKey struct {
	TenantID           string `json:"tenant_id"`
	DepartmentID       string `json:"department_id"`
	ApplicationID      string `json:"application_id"`
	AgentInstanceID    string `json:"agent_instance_id"`
	AgentID            string `json:"agent_id"`
	AgentVersionID     string `json:"agent_version_id"`
	PrincipalType      string `json:"principal_type"`
	PrincipalID        string `json:"principal_id"`
	SessionID          string `json:"session_id"`
	RunID              string `json:"run_id"`
	AuthorizationEpoch uint64 `json:"authorization_epoch"`
	TraceID            string `json:"trace_id"`
	ParentRunID        string `json:"parent_run_id,omitempty"`
	DelegationDepth    uint32 `json:"delegation_depth,omitempty"`
	// InstallationID binds every execution to the exact published Agent installation.
	// InstallationID 将每次执行绑定到唯一已发布 Agent 安装。
	InstallationID string `json:"installation_id"`
}

var traceIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (s ScopeKey) Validate() error {
	for name, value := range map[string]string{
		"tenant_id": s.TenantID, "department_id": s.DepartmentID,
		"application_id": s.ApplicationID, "agent_instance_id": s.AgentInstanceID,
		"agent_id": s.AgentID, "agent_version_id": s.AgentVersionID,
		"installation_id": s.InstallationID,
		"principal_id":    s.PrincipalID, "session_id": s.SessionID, "run_id": s.RunID,
	} {
		if value == "" || len(value) > 128 {
			return fmt.Errorf("%w: %s", ErrSchemaValidation, name)
		}
	}
	if s.PrincipalType != "user" && s.PrincipalType != "service_principal" {
		return fmt.Errorf("%w: principal_type", ErrSchemaValidation)
	}
	if s.AuthorizationEpoch == 0 {
		return fmt.Errorf("%w: authorization_epoch", ErrSchemaValidation)
	}
	if !traceIDPattern.MatchString(s.TraceID) {
		return fmt.Errorf("%w: trace_id", ErrSchemaValidation)
	}
	if len(s.ParentRunID) > 128 || s.DelegationDepth > 8 {
		return fmt.Errorf("%w: delegation", ErrSchemaValidation)
	}
	return nil
}

type ExecuteRequest struct {
	ProtocolVersion string         `json:"protocol_version"`
	ContextToken    string         `json:"context_token"`
	Scope           ScopeKey       `json:"scope"`
	Operation       string         `json:"operation"`
	IdempotencyKey  string         `json:"idempotency_key"`
	InputSchema     string         `json:"input_schema"`
	Input           map[string]any `json:"input"`
	// ResumeInput is covered by the canonical body signature, never Headers.
	// ResumeInput 属于签名正文，Header 不得升级操作或替换审核决策。
	ResumeInput map[string]any `json:"resume_input,omitempty"`
}

// CanonicalExecuteBodyHash matches the Python/Java SDK canonical form: omit
// the bearer token and optional zero-value fields, sort every object key,
// retain UTF-8, and use compact JSON before hashing.
// CanonicalExecuteBodyHash 与 Python/Java SDK 使用相同规范：排除 Bearer Token
// 和可选零值字段，对象键排序，保留 UTF-8，以紧凑 JSON 求哈希。
func CanonicalExecuteBodyHash(request ExecuteRequest) (string, error) {
	request.ContextToken = ""
	raw, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("marshal execution envelope: %w", err)
	}
	var envelope map[string]any
	if err := DecodeJSONPreservingNumbers(raw, &envelope); err != nil {
		return "", fmt.Errorf("normalize execution envelope: %w", err)
	}
	delete(envelope, "context_token")
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(envelope); err != nil {
		return "", fmt.Errorf("encode canonical execution envelope: %w", err)
	}
	encoded := bytes.TrimSuffix(canonical.Bytes(), []byte("\n"))
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (r ExecuteRequest) Validate() error {
	if r.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: %s", ErrProtocolNotSupported, r.ProtocolVersion)
	}
	if len(r.ContextToken) < 32 || len(r.ContextToken) > 8192 {
		return fmt.Errorf("%w: context_token", ErrSchemaValidation)
	}
	return r.ValidateForSigning()
}

// ValidateForSigning validates a platform-owned durable command before its
// short-lived token is issued. Inbound Agent requests must use Validate.
func (r ExecuteRequest) ValidateForSigning() error {
	if r.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: %s", ErrProtocolNotSupported, r.ProtocolVersion)
	}
	if err := r.Scope.Validate(); err != nil {
		return err
	}
	if r.Operation != "invoke" && r.Operation != "run" && r.Operation != "resume" && r.Operation != "cancel" {
		return fmt.Errorf("%w: operation", ErrSchemaValidation)
	}
	if len(r.IdempotencyKey) < 8 || len(r.IdempotencyKey) > 128 {
		return fmt.Errorf("%w: idempotency_key", ErrSchemaValidation)
	}
	if !strings.HasPrefix(r.InputSchema, "schema://") || r.Input == nil {
		return fmt.Errorf("%w: input", ErrSchemaValidation)
	}
	return nil
}

type ExecuteResponse struct {
	ProtocolVersion   string             `json:"protocol_version"`
	RunID             string             `json:"run_id"`
	Status            string             `json:"status"`
	OutputSchema      string             `json:"output_schema,omitempty"`
	Output            map[string]any     `json:"output,omitempty"`
	Error             *AppError          `json:"error,omitempty"`
	Handoff           *HandlerHandoff    `json:"handoff,omitempty"`
	AgentGroupHandoff *AgentGroupHandoff `json:"agent_group_handoff,omitempty"`
}

// MaxAgentEventSequence is shared by JSON and protobuf Agent event boundaries.
// It does not constrain the platform's independent durable event sequence.
const MaxAgentEventSequence uint64 = (1 << 53) - 1

type EventRequest struct {
	ProtocolVersion    string   `json:"protocol_version"`
	ContextToken       string   `json:"context_token"`
	Scope              ScopeKey `json:"scope"`
	AfterSeq           uint64   `json:"after_seq"`
	PolicySnapshotHash string   `json:"policy_snapshot_hash"`
}

// CanonicalEventBodyHash binds the immutable cursor and scope, excluding JWT.
// Preserve uint64 cursors through normalization instead of rounding float64.
func CanonicalEventBodyHash(request EventRequest) (string, error) {
	if request.AfterSeq > MaxAgentEventSequence {
		return "", fmt.Errorf("%w: after_seq", ErrSchemaValidation)
	}
	request.ContextToken = ""
	raw, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	var envelope map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&envelope); err != nil {
		return "", err
	}
	delete(envelope, "context_token")
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(envelope); err != nil {
		return "", err
	}
	digest := sha256.Sum256(bytes.TrimSuffix(canonical.Bytes(), []byte("\n")))
	return hex.EncodeToString(digest[:]), nil
}

func (r EventRequest) Validate() error {
	if r.AfterSeq > MaxAgentEventSequence {
		return fmt.Errorf("%w: after_seq", ErrSchemaValidation)
	}
	if r.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: %s", ErrProtocolNotSupported, r.ProtocolVersion)
	}
	if len(r.ContextToken) < 32 || len(r.ContextToken) > 8192 {
		return fmt.Errorf("%w: context_token", ErrSchemaValidation)
	}
	if err := r.Scope.Validate(); err != nil {
		return err
	}
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(r.PolicySnapshotHash) {
		return fmt.Errorf("%w: policy_snapshot_hash", ErrSchemaValidation)
	}
	return nil
}

type ExecutionEvent struct {
	RunID      string         `json:"run_id"`
	Seq        uint64         `json:"seq"`
	EventType  string         `json:"event_type"`
	OccurredAt time.Time      `json:"occurred_at"`
	Payload    map[string]any `json:"payload"`
}
