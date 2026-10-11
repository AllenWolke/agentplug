// Package agentplatform implements the language-neutral Agent Execution v2 contract.
// Package agentplatform 实现语言无关的 Agent Execution v2 契约。
package agentplatform

import "time"

const ProtocolVersion = "agent-execution/v2"

const HandlerHandoffVersion = "sdk-handler-exit/v1"

const AgentGroupHandoffVersion = "sdk-agent-group-exit/v1"

type ScopeKey struct {
	TenantID           string `json:"tenant_id"`
	DepartmentID       string `json:"department_id"`
	ApplicationID      string `json:"application_id"`
	AgentInstanceID    string `json:"agent_instance_id"`
	InstallationID     string `json:"installation_id"`
	AgentID            string `json:"agent_id"`
	AgentVersionID     string `json:"agent_version_id"`
	PrincipalType      string `json:"principal_type"`
	PrincipalID        string `json:"principal_id"`
	SessionID          string `json:"session_id"`
	RunID              string `json:"run_id"`
	AuthorizationEpoch uint64 `json:"authorization_epoch"`
	TraceID            string `json:"trace_id"`
	ParentRunID        string `json:"parent_run_id"`
	DelegationDepth    uint32 `json:"delegation_depth"`
}

type ExecuteRequest struct {
	ProtocolVersion string         `json:"protocol_version"`
	ContextToken    string         `json:"context_token"`
	Scope           ScopeKey       `json:"scope"`
	Operation       string         `json:"operation"`
	IdempotencyKey  string         `json:"idempotency_key"`
	InputSchema     string         `json:"input_schema"`
	Input           map[string]any `json:"input"`
	ResumeInput     map[string]any `json:"resume_input,omitempty"`
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

// HandlerHandoff binds a locally supervised Harness pause to the exact
// execution generation that returned. It is evidence of this SDK handler's
// exit only; it does not authorize execution or prove a process stop.
type HandlerHandoff struct {
	Version           string `json:"version"`
	RunID             string `json:"run_id"`
	ExecutionRevision uint64 `json:"execution_revision"`
	BodyHash          string `json:"body_hash"`
	LeaseTokenHash    string `json:"lease_token_hash"`
	InputFingerprint  string `json:"input_fingerprint"`
	OriginOperation   string `json:"origin_operation"`
	HarnessKey        string `json:"harness_key"`
	ToolName          string `json:"tool_name"`
	CallID            string `json:"call_id"`
	LastEventSeq      uint64 `json:"last_event_seq"`
}

// AgentGroupHandoff records the exact SDK execution that exited while waiting
// for an already-admitted AgentGroup. It is lifecycle evidence, not permission
// to resume the parent or any child.
type AgentGroupHandoff struct {
	Version           string                        `json:"version"`
	RunID             string                        `json:"run_id"`
	ExecutionRevision uint64                        `json:"execution_revision"`
	BodyHash          string                        `json:"body_hash"`
	LeaseTokenHash    string                        `json:"lease_token_hash"`
	InputFingerprint  string                        `json:"input_fingerprint"`
	OriginOperation   string                        `json:"origin_operation"`
	GroupKey          string                        `json:"group_key"`
	OperationKey      string                        `json:"operation_key"`
	LastEventSeq      uint64                        `json:"last_event_seq"`
	Checkpoint        AgentGroupCheckpointReference `json:"checkpoint"`
	ChildKeys         []string                      `json:"child_keys"`
}

// AgentGroupCheckpointReference is the public, non-secret identity of the
// current coordination checkpoint captured in an AgentGroup handoff.
type AgentGroupCheckpointReference struct {
	StateKey          string    `json:"state_key"`
	Revision          uint64    `json:"revision"`
	SchemaID          string    `json:"schema_id"`
	ContentHash       string    `json:"content_hash"`
	ExecutionRevision uint64    `json:"execution_revision"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type AppError struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Retryable bool           `json:"retryable"`
	Details   map[string]any `json:"details,omitempty"`
}

// Error lets AppError travel as a Go error through handler seams while keeping
// the wire shape stable. / Error 让 AppError 作为 Go error 穿过处理器接缝，同时
// 保持线上形态稳定。
func (e AppError) Error() string { return e.Code + ": " + e.Message }

type EventRequest struct {
	ProtocolVersion    string   `json:"protocol_version"`
	ContextToken       string   `json:"context_token"`
	Scope              ScopeKey `json:"scope"`
	AfterSeq           uint64   `json:"after_seq"`
	PolicySnapshotHash string   `json:"policy_snapshot_hash"`
}

type ExecutionEvent struct {
	RunID      string         `json:"run_id"`
	Seq        uint64         `json:"seq"`
	EventType  string         `json:"event_type"`
	OccurredAt time.Time      `json:"occurred_at"`
	Payload    map[string]any `json:"payload"`
}
