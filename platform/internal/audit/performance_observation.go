package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	agenteval "github.com/lexagent/agent-evaluation"
	"github.com/lexagent/platform/internal/sharedkernel"
)

const PerformanceObservationVersion = "capability-performance-observation/v1"
const performanceObservationLimit = 10000

var ErrInvalidPerformanceObservation = errors.New("invalid capability performance observation")

// Platform-created measurements only. No business/model inputs, outputs,
// cache keys, credentials or provider error messages enter this projection.
type PerformanceObservation struct {
	Version          string    `json:"version"`
	ScopeFingerprint string    `json:"scope_fingerprint"`
	RunID            string    `json:"run_id"`
	StepID           string    `json:"step_id"`
	Kind             string    `json:"kind"`
	Status           string    `json:"status"`
	StartedAt        time.Time `json:"started_at"`
	FinishedAt       time.Time `json:"finished_at"`
	DurationMS       int64     `json:"duration_ms"`
	TimingSource     string    `json:"timing_source"`
	Operation        string    `json:"operation,omitempty"`
	ModelVersionID   string    `json:"model_version_id,omitempty"`
	UsageStepID      string    `json:"usage_step_id,omitempty"`
	CacheMode        string    `json:"cache_mode,omitempty"`
	CacheLookups     *int64    `json:"cache_lookups"`
	CacheHits        *int64    `json:"cache_hits"`
	CacheFailures    *int64    `json:"cache_failures"`
}

type PerformanceRecorder interface {
	RecordPerformance(context.Context, sharedkernel.Scope, PerformanceObservation) error
}

func (o PerformanceObservation) BelongsTo(s sharedkernel.Scope) bool {
	return o.RunID == s.RunID && o.ScopeFingerprint == performanceScopeFingerprint(s)
}

func (o PerformanceObservation) Validate(s sharedkernel.Scope) error { return o.validate(s) }

// MergePerformanceEvidence accepts only actual platform measurements recovered
// from durable receipts. Conflicting duplicates fail; none are guessed.
func MergePerformanceEvidence(scope sharedkernel.Scope, items, receipts []PerformanceObservation) ([]PerformanceObservation, error) {
	out, complete, err := MergePerformanceEvidenceProfile(scope, items, receipts, "")
	if err != nil || !complete {
		return nil, ErrInvalidPerformanceObservation
	}
	return out, nil
}

func MergePerformanceEvidenceProfile(scope sharedkernel.Scope, items, receipts []PerformanceObservation, profile string) ([]PerformanceObservation, bool, error) {
	limits, valid := agenteval.TrajectoryReadLimitsFor(profile)
	if !valid {
		return nil, false, ErrInvalidPerformanceObservation
	}
	byID := map[string]PerformanceObservation{}
	out := []PerformanceObservation{}
	for _, group := range [][]PerformanceObservation{items, receipts} {
		for _, item := range group {
			if item.validate(scope) != nil {
				return nil, false, ErrInvalidPerformanceObservation
			}
			if previous, found := byID[item.StepID]; found {
				a, _ := json.Marshal(previous)
				b, _ := json.Marshal(item)
				if !bytes.Equal(a, b) {
					return nil, false, ErrInvalidPerformanceObservation
				}
				continue
			}
			if len(out) >= limits.Events {
				return out, false, nil
			}
			byID[item.StepID] = item
			out = append(out, item)
		}
	}
	return out, true, nil
}

// Exact run/session/installation/principal identity; an authorization epoch
// renewal does not move historical measurements to another business Run.
func performanceScopeFingerprint(s sharedkernel.Scope) string {
	raw, _ := json.Marshal([]string{s.TenantID, s.DepartmentID, s.ApplicationID, s.AgentID, s.AgentInstanceID,
		s.PrincipalType, s.PrincipalID, s.InstallationID, s.AgentVersionID, s.SessionID, s.RunID, s.ParentRunID})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func NewPerformanceObservation(s sharedkernel.Scope, key, kind, status string, started, finished time.Time) PerformanceObservation {
	// UTC strips Go's process-local monotonic clock. The serialized interval
	// and its duration must use the same wall clock after database round trips.
	started, finished = started.UTC(), finished.UTC()
	fingerprint := performanceScopeFingerprint(s)
	id := sha256.Sum256([]byte(fingerprint + "\x00" + kind + "\x00" + key))
	return PerformanceObservation{Version: PerformanceObservationVersion, ScopeFingerprint: fingerprint,
		RunID: s.RunID, StepID: "performance-" + hex.EncodeToString(id[:]), Kind: kind, Status: status,
		StartedAt: started.UTC(), FinishedAt: finished.UTC(), DurationMS: finished.Sub(started).Milliseconds(),
		TimingSource: "platform_wall_clock"}
}

// HasInconsistentWallDuration classifies only an otherwise valid, exact-scope
// historical measurement. Readers may retain a missing timing instead of
// rejecting independently settled accounting. It never repairs the value.
func (o PerformanceObservation) HasInconsistentWallDuration(s sharedkernel.Scope) bool {
	wall := o.FinishedAt.Sub(o.StartedAt).Milliseconds()
	if o.DurationMS < 0 || o.DurationMS == wall {
		return false
	}
	o.DurationMS = wall
	return o.validate(s) == nil
}

func (o PerformanceObservation) validate(s sharedkernel.Scope) error {
	if s.ValidateTrusted() != nil || o.Version != PerformanceObservationVersion || o.ScopeFingerprint != performanceScopeFingerprint(s) ||
		o.RunID != s.RunID || len(o.StepID) != 76 || !strings.HasPrefix(o.StepID, "performance-") ||
		o.StartedAt.IsZero() || o.FinishedAt.Before(o.StartedAt) || o.DurationMS < 0 ||
		o.FinishedAt.Sub(o.StartedAt).Milliseconds() != o.DurationMS || o.TimingSource != "platform_wall_clock" {
		return ErrInvalidPerformanceObservation
	}
	if decoded, err := hex.DecodeString(strings.TrimPrefix(o.StepID, "performance-")); err != nil || len(decoded) != 32 {
		return ErrInvalidPerformanceObservation
	}
	switch o.Status {
	case "succeeded", "failed", "cancelled", "timeout":
	default:
		return ErrInvalidPerformanceObservation
	}
	switch o.Kind {
	case "model_gateway":
		if (o.Operation != "generate" && o.Operation != "embed") || o.ModelVersionID == "" || len(o.ModelVersionID) > 128 || o.CacheMode != "" ||
			o.CacheLookups != nil || o.CacheHits != nil || o.CacheFailures != nil {
			return ErrInvalidPerformanceObservation
		}
		if len(o.UsageStepID) != 75 || !strings.HasPrefix(o.UsageStepID, "model-step-") {
			return ErrInvalidPerformanceObservation
		}
		if raw, err := hex.DecodeString(strings.TrimPrefix(o.UsageStepID, "model-step-")); err != nil || len(raw) != 32 {
			return ErrInvalidPerformanceObservation
		}
	case "knowledge_query":
		if o.Operation != "" || o.ModelVersionID != "" || o.UsageStepID != "" || (o.CacheMode != "use" && o.CacheMode != "cold" && o.CacheMode != "bypass") ||
			o.CacheLookups == nil || o.CacheHits == nil || o.CacheFailures == nil || *o.CacheLookups < 0 || *o.CacheLookups > 100 ||
			*o.CacheHits < 0 || *o.CacheFailures < 0 || *o.CacheHits > *o.CacheLookups || *o.CacheFailures > *o.CacheLookups ||
			*o.CacheHits+*o.CacheFailures > *o.CacheLookups {
			return ErrInvalidPerformanceObservation
		}
	default:
		return ErrInvalidPerformanceObservation
	}
	return nil
}

func (s *SQLStore) RecordPerformance(ctx context.Context, scope sharedkernel.Scope, o PerformanceObservation) error {
	if s == nil || s.db == nil || o.validate(scope) != nil {
		return ErrInvalidPerformanceObservation
	}
	raw, err := json.Marshal(o)
	if err != nil {
		return ErrInvalidPerformanceObservation
	}
	return s.Record(ctx, Event{ID: o.StepID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
		ActorType: scope.PrincipalType, ActorID: scope.PrincipalID, TraceID: scope.TraceID, AggregateType: "run", AggregateID: scope.RunID,
		Action: "runtime.performance." + o.Kind, Outcome: o.Status, Summary: string(raw), CreatedAt: o.FinishedAt})
}

func decodePerformanceObservation(raw string, scope sharedkernel.Scope) (PerformanceObservation, error) {
	var o PerformanceObservation
	if len(raw) == 0 || len(raw) > 4096 {
		return o, ErrInvalidPerformanceObservation
	}
	d := json.NewDecoder(bytes.NewBufferString(raw))
	d.DisallowUnknownFields()
	if d.Decode(&o) != nil || d.Decode(new(any)) != io.EOF || o.validate(scope) != nil {
		return PerformanceObservation{}, ErrInvalidPerformanceObservation
	}
	return o, nil
}
