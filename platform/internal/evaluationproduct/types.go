// Package evaluationproduct owns the product-facing evaluation registry and
// review workflow. Execution remains behind the Runner/Dispatcher ports.
// evaluationproduct 管理面向产品的评测资产与审核流程，执行由 Runner/Dispatcher 端口提供。
package evaluationproduct

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalid     = errors.New("invalid evaluation product request")
	ErrNotFound    = errors.New("evaluation product resource not found")
	ErrConflict    = errors.New("evaluation product revision conflict")
	ErrForbidden   = errors.New("evaluation product operation forbidden")
	ErrUnavailable = errors.New("evaluation execution unavailable")
	ErrImmutable   = errors.New("evaluation product resource is immutable")
)

type Kind string

const (
	KindDataset    Kind = "dataset"
	KindSuite      Kind = "suite"
	KindMetric     Kind = "metric"
	KindRun        Kind = "run"
	KindCaseResult Kind = "case_result"
	KindEvidence   Kind = "evidence"
	KindReview     Kind = "review"
	KindBaseline   Kind = "baseline"
	KindFeedback   Kind = "feedback"
)

type Action string

const (
	ActionRead    Action = "read"
	ActionCreate  Action = "create"
	ActionUpdate  Action = "update"
	ActionPublish Action = "publish"
	ActionExecute Action = "execute"
	ActionReview  Action = "review"
	ActionGate    Action = "gate"
)

type Scope struct {
	TenantID      string `json:"tenant_id"`
	DepartmentID  string `json:"department_id"`
	ApplicationID string `json:"application_id"`
}

func (s Scope) valid() bool {
	for _, v := range []string{s.TenantID, s.DepartmentID, s.ApplicationID} {
		if strings.TrimSpace(v) == "" || strings.TrimSpace(v) != v || len(v) > 128 || strings.ContainsAny(v, "\x00\r\n") {
			return false
		}
	}
	return true
}

// Actor values are taken only from trusted Gateway headers. Scope is the
// authenticated application scope, never decoded from a resource body.
// Actor 仅来自可信 Gateway Header；Scope 是认证后的应用作用域，不从资源 Body 解码。
type Actor struct {
	Scope         Scope
	PrincipalType string
	PrincipalID   string
	Browser       bool
}

type Authorizer interface {
	AuthorizeEvaluation(context.Context, Actor, Action, Scope) error
}

type Resource struct {
	ID        string          `json:"id"`
	Kind      Kind            `json:"kind"`
	Scope     Scope           `json:"scope"`
	Status    string          `json:"status"`
	Revision  uint64          `json:"revision"`
	CreatedBy string          `json:"created_by,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	Data      json.RawMessage `json:"data"`
}

type Store interface {
	EnsureSchema(context.Context) error
	Create(context.Context, Resource) error
	Get(context.Context, Scope, Kind, string) (Resource, error)
	List(context.Context, Scope, Kind, int, int) ([]Resource, int64, error)
	UpdateCAS(context.Context, Scope, Kind, string, uint64, Resource) error
}

type IdempotencyStore interface {
	FindByIdempotency(context.Context, Scope, Kind, string) (Resource, error)
}

// Dispatcher submits a persisted Run to the platform's configured evaluator.
// An implementation must be idempotent by run ID. It may use a local Worker
// today and a remote service later. No synthetic evaluation is performed here.
// Dispatcher 将已持久化 Run 提交给平台配置的评测器；实现必须按 Run ID 幂等。
// 当前可接本地 Worker，未来可接远端服务；本包不伪造评测结果。
type Dispatcher interface {
	Enqueue(context.Context, Scope, Resource) error
	Cancel(context.Context, Scope, string, uint64) error
}

// ExecutionStore is the durable coordination boundary used by the product
// evaluator. ClaimNextRun is global only inside the trusted worker and returns
// the persisted scope with the row; all subsequent reads and writes remain
// explicitly scoped. FinalizeRun commits terminal run state and its evidence
// atomically, fenced by the active lease token.
type ExecutionStore interface {
	Store
	ClaimNextRun(context.Context, string, string, time.Time, time.Duration) (Resource, bool, error)
	RenewRunLease(context.Context, Scope, string, uint64, string, time.Time) (Resource, error)
	CommitRunCase(context.Context, Scope, string, uint64, string, Resource) error
	FinalizeRun(context.Context, Scope, uint64, string, Resource, *Resource) error
	ListRunCases(context.Context, Scope, string, int, int) ([]Resource, int64, error)
}

// DispatcherLifecycle lets a durable dispatcher start recovery polling with
// the owning module and stop cleanly when the module closes.
type DispatcherLifecycle interface {
	Start(context.Context) error
	Close(context.Context) error
}

// AgentInvoker invokes the exact Agent version selected by a frozen Suite.
// Implementations must route through the platform Gateway and deduplicate on
// IdempotencyKey because workers provide at-least-once delivery.
type AgentInvoker interface {
	InvokeEvaluationCase(context.Context, InvocationRequest) (InvocationResult, error)
}

type InvocationRequest struct {
	Scope                Scope
	RunID                string
	IdempotencyKey       string
	AgentID              string
	AgentVersionID       string
	InstallationID       string
	InstallationRevision uint64
	CaseIndex            int
	Input                json.RawMessage
}

type InvocationResult struct {
	Output            json.RawMessage
	ProviderMode      string
	CitationGrounding string
	DomainGrounding   string
}

type MetricEvaluator interface {
	EvaluateMetric(context.Context, MetricSnapshot, json.RawMessage, json.RawMessage) (MetricOutcome, error)
}

// ArtifactWriter persists evaluation output in the same trusted scope. The
// idempotency key is stable across worker retries. The runner verifies the
// returned digest and byte count before treating the artifact as evidence.
type ArtifactWriter interface {
	PutEvaluationOutput(context.Context, Scope, string, int, string, []byte) (ArtifactReference, error)
}

type ArtifactReference struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type DatasetData struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	SourceType   string            `json:"source_type"`
	ReviewStatus string            `json:"review_status"`
	ReviewerID   string            `json:"reviewer_id,omitempty"`
	ReviewReason string            `json:"review_reason,omitempty"`
	ReviewedAt   *time.Time        `json:"reviewed_at,omitempty"`
	SampleCount  int               `json:"sample_count"`
	ContentHash  string            `json:"content_hash"`
	Cases        []json.RawMessage `json:"cases,omitempty"`
}

type MetricData struct {
	MetricID      string          `json:"metric_id"`
	Version       string          `json:"version"`
	Name          string          `json:"name"`
	Kind          string          `json:"kind"`
	PluginID      string          `json:"plugin_id,omitempty"`
	PluginVersion string          `json:"plugin_version,omitempty"`
	PluginDigest  string          `json:"plugin_digest,omitempty"`
	Formula       json.RawMessage `json:"formula"`
	FormulaHash   string          `json:"formula_hash"`
	Status        string          `json:"status"`
}

type SuiteData struct {
	InstallationID       string          `json:"installation_id,omitempty"`
	InstallationRevision uint64          `json:"installation_revision,omitempty"`
	Name                 string          `json:"name"`
	Version              string          `json:"version"`
	DatasetID            string          `json:"dataset_id"`
	AgentID              string          `json:"agent_id"`
	AgentVersionID       string          `json:"agent_version_id"`
	MetricIDs            []string        `json:"metric_ids"`
	Snapshot             json.RawMessage `json:"snapshot"`
	SnapshotHash         string          `json:"snapshot_hash"`
}

type RunData struct {
	Mode                 string            `json:"mode,omitempty"`
	SimulationProfile    string            `json:"simulation_profile,omitempty"`
	InstallationID       string            `json:"installation_id,omitempty"`
	InstallationRevision uint64            `json:"installation_revision,omitempty"`
	Limits               *EvaluationLimits `json:"limits,omitempty"`
	SuiteID              string            `json:"suite_id"`
	AgentID              string            `json:"agent_id"`
	AgentVersionID       string            `json:"agent_version_id"`
	IdempotencyKey       string            `json:"idempotency_key"`
	ExecutionState       string            `json:"execution_state"`
	Total                int               `json:"total"`
	Completed            int               `json:"completed"`
	Failed               int               `json:"failed"`
	ErrorCode            string            `json:"error_code,omitempty"`
	LeaseOwner           string            `json:"lease_owner,omitempty"`
	LeaseToken           string            `json:"lease_token,omitempty"`
	LeaseUntil           time.Time         `json:"lease_until,omitempty"`
	Attempt              int               `json:"attempt,omitempty"`
}

// ModeAdmission validates operator-approved isolation before persistence.
// Runtime adapters recheck it before every case; request labels confer no trust.
type ModeAdmission interface {
	AuthorizeEvaluationMode(context.Context, Actor, RunData, SuiteData) error
}

// EvaluationLimits can only reduce published runtime allowances. The product
// budget is divided between immutable cases, including all delegated children.
type EvaluationLimits struct {
	LimitTokens int64 `json:"limit_tokens"`
	LimitMicros int64 `json:"limit_micros"`
}

type EvidenceData struct {
	RunID              string          `json:"run_id"`
	SuiteID            string          `json:"suite_id"`
	SuiteSnapshotHash  string          `json:"suite_snapshot_hash"`
	DatasetContentHash string          `json:"dataset_content_hash"`
	AgentVersionID     string          `json:"agent_version_id"`
	Status             string          `json:"status"`
	ProviderMode       string          `json:"provider_mode"`
	SourceType         string          `json:"source_type"`
	SampleCount        int             `json:"sample_count"`
	Metrics            []MetricOutcome `json:"metrics"`
	MetricsPresent     bool            `json:"metrics_present"`
	ArtifactsPresent   bool            `json:"artifacts_present"`
	CitationGrounding  string          `json:"citation_grounding"`
	DomainGrounding    string          `json:"domain_grounding"`
	ReportHash         string          `json:"report_hash"`
	ProducedAt         time.Time       `json:"produced_at"`
	Gate               GateDecision    `json:"gate"`
	CaseResultIDs      []string        `json:"case_result_ids"`
}

// CaseResultData stores privacy-preserving, per-case/per-metric execution
// evidence. Inputs and outputs remain in their scoped Artifact Store; only
// content hashes and scorer outcomes are held in the product database.
type CaseResultData struct {
	RunID             string          `json:"run_id"`
	Index             int             `json:"index"`
	InputHash         string          `json:"input_hash"`
	OutputHash        string          `json:"output_hash"`
	OutputArtifactID  string          `json:"output_artifact_id"`
	ProviderMode      string          `json:"provider_mode"`
	CitationGrounding string          `json:"citation_grounding"`
	DomainGrounding   string          `json:"domain_grounding"`
	Metrics           []MetricOutcome `json:"metrics"`
	ProducedAt        time.Time       `json:"produced_at"`
}

type MetricOutcome struct {
	MetricID          string   `json:"metric_id"`
	Status            string   `json:"status"`
	Value             *float64 `json:"value,omitempty"`
	Direction         string   `json:"direction"`
	AllowedRegression float64  `json:"allowed_regression,omitempty"`
}

type ReviewData struct {
	EvidenceID string `json:"evidence_id"`
	RunID      string `json:"run_id"`
	ReviewerID string `json:"reviewer_id"`
	Decision   string `json:"decision"`
	Reason     string `json:"reason"`
}

type BaselineData struct {
	SuiteID       string          `json:"suite_id"`
	EvidenceID    string          `json:"evidence_id"`
	EvidenceHash  string          `json:"evidence_hash"`
	MetricResults json.RawMessage `json:"metric_results"`
}

type GateDecision struct {
	State      string   `json:"state"`
	Reason     string   `json:"reason"`
	EvidenceID string   `json:"evidence_id,omitempty"`
	Failures   []string `json:"failures,omitempty"`
}

const (
	GatePass    = "PASS"
	GateBlocked = "BLOCKED"
	GateUnknown = "UNKNOWN"
	MaxPageSize = 100
	MaxBodySize = 4 << 20
)
