package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

const runtimeAuditVersion = "runtime-execution-audit/v1"

const (
	runtimeStepPageMax       = 100
	runtimeStepScanLimit     = 200
	runtimeStepSummaryMax    = 16 << 10
	runtimeStepCursorMaxSize = 2048
)

var (
	ErrInvalidRuntimeSteps = errors.New("invalid runtime steps query")
	ErrRuntimeStepCorrupt  = errors.New("runtime audit record is invalid")
	runtimeStepIDPattern   = regexp.MustCompile(`^runtime-[0-9a-f]{64}$`)
	runtimeStepHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// RuntimeExecutionAudit is the only projection disclosed by the runtime-steps
// endpoint. It intentionally excludes the underlying audit Summary, call
// fingerprint, lease fence, approval digest and all tool payloads.
type RuntimeExecutionAudit struct {
	Version             string                       `json:"version"`
	RunID               string                       `json:"run_id"`
	StepID              string                       `json:"step_id"`
	ToolName            string                       `json:"tool_name"`
	ExecutionType       *string                      `json:"execution_type"`
	PermissionScopeHash string                       `json:"permission_scope_hash"`
	PermissionScope     *RuntimeAuditPermissionScope `json:"permission_scope"`
	AuthorizationEpoch  uint64                       `json:"authorization_epoch"`
	PolicySnapshotHash  *string                      `json:"policy_snapshot_hash"`
	StartedAt           *time.Time                   `json:"started_at"`
	FinishedAt          *time.Time                   `json:"finished_at"`
	DurationMS          *int64                       `json:"duration_ms"`
	Status              string                       `json:"status"`
	ObservationStatus   *string                      `json:"observation_status"`
	ErrorType           *string                      `json:"error_type"`
	OutputSizeBytes     *int64                       `json:"output_size_bytes"`
	ResourceUsage       RuntimeAuditResourceUsage    `json:"resource_usage"`
	TraceID             string                       `json:"trace_id"`
}

// The permission projection is deliberately closed to these three fields.
type RuntimeAuditPermissionScope struct {
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
}

// Nil measurements remain JSON null; absent historical measurements are not
// represented as zero. The allowlisted measurement source values are fixed.
type RuntimeAuditResourceUsage struct {
	CPUTimeMS             *int64  `json:"cpu_time_ms"`
	PeakMemoryBytes       *int64  `json:"peak_memory_bytes"`
	DiskBytes             *int64  `json:"disk_bytes"`
	SampledPeakMemory     *int64  `json:"sampled_peak_memory_bytes"`
	SampleCount           *int64  `json:"sample_count"`
	DiskSampleCount       *int64  `json:"disk_sample_count"`
	MeasurementComplete   *bool   `json:"measurement_complete"`
	MeasurementSource     *string `json:"measurement_source"`
	DiskMeasurementSource *string `json:"disk_measurement_source"`
}

type RuntimeStepsQuery struct {
	Scope    MetadataScope
	RunID    string
	StepID   string
	PageSize int
	Cursor   string
}

type RuntimeStepsPage struct {
	Items      []RuntimeExecutionAudit `json:"items"`
	NextCursor string                  `json:"next_cursor"`
}

// RuntimeStepsReader is intentionally separate from generic audit content
// access: callers receive only the typed, versioned runtime projection.
type RuntimeStepsReader interface {
	ListRuntimeSteps(context.Context, RuntimeStepsQuery) (RuntimeStepsPage, error)
}

type runtimeStepsCursor struct {
	Version       string `json:"version"`
	TenantID      string `json:"tenant_id"`
	DepartmentID  string `json:"department_id"`
	ApplicationID string `json:"application_id"`
	RunID         string `json:"run_id"`
	StepID        string `json:"step_id"`
	CreatedAt     string `json:"created_at"`
	EventID       string `json:"event_id"`
}

type runtimeAuditRecord struct {
	Version             string                       `json:"version"`
	RunID               string                       `json:"run_id"`
	StepID              string                       `json:"step_id"`
	CallID              string                       `json:"call_id"`
	ToolName            string                       `json:"tool_name"`
	PermissionScopeHash string                       `json:"permission_scope_hash"`
	PermissionScope     *RuntimeAuditPermissionScope `json:"permission_scope"`
	AuthorizationEpoch  uint64                       `json:"authorization_epoch"`
	Fingerprint         string                       `json:"fingerprint"`
	LeaseFence          uint64                       `json:"lease_fence"`
	Status              string                       `json:"status"`
	ExecutionType       *string                      `json:"execution_type"`
	Risk                *string                      `json:"risk"`
	PolicySnapshotHash  *string                      `json:"policy_snapshot_hash"`
	ApprovalDigest      *string                      `json:"approval_digest"`
	StartedAt           *time.Time                   `json:"started_at"`
	FinishedAt          *time.Time                   `json:"finished_at"`
	DurationMS          *int64                       `json:"duration_ms"`
	ErrorType           *string                      `json:"error_type"`
	OutputSizeBytes     *int64                       `json:"output_size_bytes"`
	ResourceUsage       *RuntimeAuditResourceUsage   `json:"resource_usage"`
	ObservationStatus   *string                      `json:"observation_status"`
}

func encodeRuntimeStepsCursor(query RuntimeStepsQuery, event Event) (string, error) {
	if validateRuntimeStepsQuery(query) != nil || event.TenantID != query.Scope.TenantID || event.DepartmentID != query.Scope.DepartmentID || event.ApplicationID != query.Scope.ApplicationID ||
		event.AggregateID != query.RunID || event.AggregateType != "run" || !validEventID(event.ID) || event.CreatedAt.IsZero() {
		return "", ErrInvalidRuntimeSteps
	}
	value := runtimeStepsCursor{
		Version: "runtime-steps-cursor/v1", TenantID: query.Scope.TenantID,
		DepartmentID: query.Scope.DepartmentID, ApplicationID: query.Scope.ApplicationID,
		RunID: query.RunID, StepID: query.StepID,
		CreatedAt: event.CreatedAt.UTC().Format(time.RFC3339Nano), EventID: event.ID,
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", ErrInvalidRuntimeSteps
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeRuntimeStepsCursor(encoded string, query RuntimeStepsQuery) (time.Time, string, error) {
	if encoded == "" {
		return time.Time{}, "", nil
	}
	if len(encoded) > runtimeStepCursorMaxSize || query.Scope.Validate() != nil || query.Scope.Type != "application" || !validEventID(query.RunID) {
		return time.Time{}, "", ErrInvalidRuntimeSteps
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return time.Time{}, "", ErrInvalidRuntimeSteps
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cursor runtimeStepsCursor
	if decoder.Decode(&cursor) != nil || decoder.Decode(new(any)) != io.EOF || cursor.Version != "runtime-steps-cursor/v1" ||
		cursor.TenantID != query.Scope.TenantID || cursor.DepartmentID != query.Scope.DepartmentID || cursor.ApplicationID != query.Scope.ApplicationID ||
		cursor.RunID != query.RunID || cursor.StepID != query.StepID || !validEventID(cursor.EventID) {
		return time.Time{}, "", ErrInvalidRuntimeSteps
	}
	createdAt, err := time.Parse(time.RFC3339Nano, cursor.CreatedAt)
	if err != nil || createdAt.UTC().Format(time.RFC3339Nano) != cursor.CreatedAt {
		return time.Time{}, "", ErrInvalidRuntimeSteps
	}
	return createdAt.UTC(), cursor.EventID, nil
}

func decodeRuntimeAuditRecord(event Event, runID string) (RuntimeExecutionAudit, error) {
	if event.Validate() != nil || event.AggregateType != "run" || event.AggregateID != runID || !runtimeToolAuditAction(event.Action) || event.Outcome == "" || len(event.Summary) == 0 || len(event.Summary) > runtimeStepSummaryMax {
		return RuntimeExecutionAudit{}, ErrRuntimeStepCorrupt
	}
	decoder := json.NewDecoder(strings.NewReader(event.Summary))
	decoder.DisallowUnknownFields()
	var record runtimeAuditRecord
	if decoder.Decode(&record) != nil || decoder.Decode(new(any)) != io.EOF {
		return RuntimeExecutionAudit{}, ErrRuntimeStepCorrupt
	}
	if record.Version != runtimeAuditVersion || record.RunID != runID || !runtimeStepIDPattern.MatchString(record.StepID) ||
		record.ToolName == "" || len(record.ToolName) > 128 || strings.TrimSpace(record.ToolName) != record.ToolName || strings.ContainsAny(record.ToolName, "\x00\r\n") ||
		!runtimeStepHashPattern.MatchString(record.PermissionScopeHash) || record.AuthorizationEpoch == 0 || record.Fingerprint == "" || !runtimeStepHashPattern.MatchString(record.Fingerprint) || record.CallID == "" || len(record.CallID) > 128 ||
		record.LeaseFence == 0 || !validRuntimeAuditStatus(record.Status) || event.Action != "runtime.tool."+record.Status || event.Outcome != record.Status || record.ResourceUsage == nil {
		return RuntimeExecutionAudit{}, ErrRuntimeStepCorrupt
	}
	stepDigest := sha256.Sum256([]byte(record.PermissionScopeHash + "\x00" + record.CallID))
	if record.StepID != "runtime-"+hex.EncodeToString(stepDigest[:]) {
		return RuntimeExecutionAudit{}, ErrRuntimeStepCorrupt
	}
	if record.PermissionScope != nil && (record.PermissionScope.Action != "tool.invoke" || record.PermissionScope.ResourceType != "tool" || record.PermissionScope.ResourceID != record.ToolName) {
		return RuntimeExecutionAudit{}, ErrRuntimeStepCorrupt
	}
	if record.ExecutionType != nil && *record.ExecutionType != "tool" && *record.ExecutionType != "api" && *record.ExecutionType != "code" {
		return RuntimeExecutionAudit{}, ErrRuntimeStepCorrupt
	}
	if record.Risk != nil && *record.Risk != "read_only" && *record.Risk != "write" && *record.Risk != "high" {
		return RuntimeExecutionAudit{}, ErrRuntimeStepCorrupt
	}
	if record.PolicySnapshotHash != nil && !runtimeStepHashPattern.MatchString(*record.PolicySnapshotHash) {
		return RuntimeExecutionAudit{}, ErrRuntimeStepCorrupt
	}
	if record.ApprovalDigest != nil && !runtimeStepHashPattern.MatchString(*record.ApprovalDigest) {
		return RuntimeExecutionAudit{}, ErrRuntimeStepCorrupt
	}
	if record.StartedAt != nil && record.FinishedAt != nil && record.FinishedAt.Before(*record.StartedAt) {
		return RuntimeExecutionAudit{}, ErrRuntimeStepCorrupt
	}
	if record.DurationMS != nil && *record.DurationMS < 0 || record.OutputSizeBytes != nil && (*record.OutputSizeBytes < 0 || *record.OutputSizeBytes > sharedkernel.MaxToolObservationOutputBytes) {
		return RuntimeExecutionAudit{}, ErrRuntimeStepCorrupt
	}
	if record.ErrorType != nil && !validRuntimeAuditError(*record.ErrorType) {
		return RuntimeExecutionAudit{}, ErrRuntimeStepCorrupt
	}
	if record.ObservationStatus != nil && !validRuntimeObservationStatus(*record.ObservationStatus) {
		return RuntimeExecutionAudit{}, ErrRuntimeStepCorrupt
	}
	if err := record.ResourceUsage.validate(); err != nil {
		return RuntimeExecutionAudit{}, err
	}
	return RuntimeExecutionAudit{
		Version: record.Version, RunID: record.RunID, StepID: record.StepID, ToolName: record.ToolName,
		ExecutionType: record.ExecutionType, PermissionScopeHash: record.PermissionScopeHash,
		PermissionScope: record.PermissionScope, AuthorizationEpoch: record.AuthorizationEpoch,
		PolicySnapshotHash: record.PolicySnapshotHash, StartedAt: record.StartedAt, FinishedAt: record.FinishedAt,
		DurationMS: record.DurationMS, Status: record.Status, ObservationStatus: record.ObservationStatus,
		ErrorType: record.ErrorType, OutputSizeBytes: record.OutputSizeBytes, ResourceUsage: *record.ResourceUsage,
		TraceID: event.TraceID,
	}, nil
}

func (r RuntimeAuditResourceUsage) validate() error {
	for _, value := range []*int64{r.CPUTimeMS, r.PeakMemoryBytes, r.DiskBytes, r.SampledPeakMemory, r.SampleCount, r.DiskSampleCount} {
		if value != nil && (*value < 0 || *value >= 1<<53) {
			return ErrRuntimeStepCorrupt
		}
	}
	if r.MeasurementSource != nil && *r.MeasurementSource != "docker_engine_sampled/v1" && *r.MeasurementSource != "unavailable" {
		return ErrRuntimeStepCorrupt
	}
	if r.DiskMeasurementSource != nil && *r.DiskMeasurementSource != "docker_exec_tmpfs_stat/v1" && *r.DiskMeasurementSource != "unavailable" {
		return ErrRuntimeStepCorrupt
	}
	return nil
}

func runtimeToolAuditAction(action string) bool {
	switch action {
	case "runtime.tool.executing", "runtime.tool.completed", "runtime.tool.failed", "runtime.tool.unknown", "runtime.tool.preparation_expired", "runtime.tool.execution_expired", "runtime.tool.receipt_reconciled":
		return true
	default:
		return false
	}
}

func validRuntimeAuditStatus(value string) bool {
	switch value {
	case "executing", "completed", "failed", "unknown", "preparation_expired", "execution_expired", "receipt_reconciled":
		return true
	default:
		return false
	}
}

func validRuntimeAuditError(value string) bool {
	switch value {
	case "TOOL_NOT_SUBMITTED", "TOOL_RESULT_UNKNOWN", "CODE_EXITED", "OUTPUT_LIMIT", "CANCELLED", "TIME_LIMIT", "RESOURCE_LIMIT", "TOOL_OUTPUT_INVALID", "EXECUTOR_ERROR":
		return true
	default:
		return false
	}
}

func validRuntimeObservationStatus(value string) bool {
	switch value {
	case "succeeded", "failed", "unknown", "cancelled", "timeout", "timed_out":
		return true
	default:
		return false
	}
}

func validateRuntimeStepsQuery(query RuntimeStepsQuery) error {
	if query.Scope.Validate() != nil || query.Scope.Type != "application" || !validEventID(query.RunID) ||
		(query.StepID != "" && !runtimeStepIDPattern.MatchString(query.StepID)) || query.PageSize < 1 || query.PageSize > runtimeStepPageMax || len(query.Cursor) > runtimeStepCursorMaxSize {
		return ErrInvalidRuntimeSteps
	}
	return nil
}
