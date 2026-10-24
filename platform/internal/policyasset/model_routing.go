package policyasset

import (
	"context"
	"encoding/hex"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// ModelRoutingPolicy is reviewed public policy, not a request-supplied model pool.
// Absence keeps existing snapshots and fixed model execution unchanged.
type ModelRoutingPolicy struct {
	Version                string                          `json:"version"`
	ExecutionContextSHA256 string                          `json:"execution_context_sha256"`
	SimpleMaxInputTokens   int64                           `json:"simple_max_input_tokens"`
	ComplexMinInputTokens  int64                           `json:"complex_min_input_tokens"`
	SimpleMaxOutputTokens  int                             `json:"simple_max_output_tokens"`
	MaxEstimatedMicros     int64                           `json:"max_estimated_micros"`
	Candidates             []ModelRouteCandidate           `json:"candidates"`
	Availability           *ModelRouteAvailabilityPolicy   `json:"availability,omitempty"`
	QualificationReuse     *ModelRouteQualificationReuse   `json:"qualification_reuse,omitempty"`
	QualificationExports   []ModelRouteQualificationExport `json:"qualification_exports,omitempty"`
}

// QualificationReuse is an explicit reviewed release attestation, never a
// request override. Original verdicts keep their source version and hashes.
type ModelRouteQualificationReuse struct {
	Version                      string                         `json:"version"`
	SourceAgentVersionID         string                         `json:"source_agent_version_id"`
	SourceExecutionContextSHA256 string                         `json:"source_execution_context_sha256"`
	SourceArtifactDigest         string                         `json:"source_artifact_digest"`
	TargetArtifactDigest         string                         `json:"target_artifact_digest"`
	BehaviorContextSHA256        string                         `json:"behavior_context_sha256"`
	FrozenDatasetManifestSHA256  string                         `json:"frozen_dataset_manifest_sha256"`
	ChangeReviewSHA256           string                         `json:"change_review_sha256"`
	RegressionEvidenceSHA256     string                         `json:"regression_evidence_sha256"`
	Source                       *ModelRouteQualificationSource `json:"source,omitempty"`
}

func (r ModelRouteQualificationReuse) Validate() error {
	if (r.Version != "reviewed-routing-qualification-reuse/v1" && r.Version != "reviewed-routing-qualification-reuse/v2") || !routingID(r.SourceAgentVersionID) ||
		!strings.HasPrefix(r.SourceArtifactDigest, "sha256:") || !strings.HasPrefix(r.TargetArtifactDigest, "sha256:") ||
		!routingSHA(strings.TrimPrefix(r.SourceArtifactDigest, "sha256:")) || !routingSHA(strings.TrimPrefix(r.TargetArtifactDigest, "sha256:")) ||
		r.SourceArtifactDigest == r.TargetArtifactDigest {
		return ErrMissingPolicy
	}
	if r.Version == "reviewed-routing-qualification-reuse/v1" && r.Source != nil ||
		r.Version == "reviewed-routing-qualification-reuse/v2" && (r.Source == nil || r.Source.Validate() != nil || r.Source.Scope.AgentVersionID != r.SourceAgentVersionID) {
		return ErrMissingPolicy
	}
	for _, value := range []string{r.SourceExecutionContextSHA256, r.BehaviorContextSHA256,
		r.FrozenDatasetManifestSHA256, r.ChangeReviewSHA256, r.RegressionEvidenceSHA256} {
		if !routingSHA(value) {
			return ErrMissingPolicy
		}
	}
	return nil
}

// Availability is opt-in and part of the immutable reviewed routing policy.
// v2 may authorize a new physical identity while retaining an unknown original.
// It never authorizes replay or release of that original provider request.
type ModelRouteAvailabilityPolicy struct {
	Version               string `json:"version"`
	FailureThreshold      int    `json:"failure_threshold"`
	CooldownSeconds       int    `json:"cooldown_seconds"`
	ProbeSeconds          int    `json:"probe_seconds"`
	MaxAttempts           int    `json:"max_attempts"`
	ManualFallback        bool   `json:"manual_fallback,omitempty"`
	UnknownOutcome        string `json:"unknown_outcome,omitempty"`
	AttemptTimeoutSeconds int    `json:"attempt_timeout_seconds,omitempty"`
}

func (p ModelRouteAvailabilityPolicy) Validate() error {
	if (p.Version != "model-route-availability/v1" && p.Version != "model-route-availability/v2") || p.FailureThreshold < 1 || p.FailureThreshold > 10 ||
		p.CooldownSeconds < 5 || p.CooldownSeconds > 300 || p.ProbeSeconds < 1 || p.ProbeSeconds > 60 ||
		p.MaxAttempts < 1 || p.MaxAttempts > 3 {
		return ErrMissingPolicy
	}
	if p.Version == "model-route-availability/v1" && (p.ManualFallback || p.UnknownOutcome != "" || p.AttemptTimeoutSeconds != 0) ||
		p.Version == "model-route-availability/v2" && (p.AttemptTimeoutSeconds < 1 || p.AttemptTimeoutSeconds > 60) ||
		p.UnknownOutcome != "" && p.UnknownOutcome != "retain_and_continue" {
		return ErrMissingPolicy
	}
	return nil
}

// ModelSelection is a product command preference, not an Agent/provider override.
// Manual uses the primary published model; automatic uses only its reviewed pool.
type ModelSelection struct {
	Mode string `json:"mode"`
}

func (s ModelSelection) EffectiveMode() string {
	if s.Mode == "" {
		return "manual"
	}
	return s.Mode
}

func (s ModelSelection) Validate() error {
	if s.EffectiveMode() != "manual" && s.EffectiveMode() != "automatic" {
		return ErrMissingPolicy
	}
	return nil
}

type ModelSelectionBinding struct {
	Selection          ModelSelection `json:"selection"`
	PolicySHA256       string         `json:"policy_sha256"`
	CommandFingerprint string         `json:"command_fingerprint"`
	// Platform-derived from original business input before Prompt rendering.
	// Empty fields retain conservative compatibility for historical bindings.
	TaskComplexity string `json:"task_complexity,omitempty"`
	TaskSHA256     string `json:"task_sha256,omitempty"`
}

func (b ModelSelectionBinding) ValidateTask() bool {
	return b.TaskComplexity == "" && b.TaskSHA256 == "" ||
		ModelComplexityRank(b.TaskComplexity) > 0 && routingSHA(b.TaskSHA256)
}

type ModelSelectionStore interface {
	BindModelSelection(context.Context, sharedkernel.Scope, ModelSelectionBinding) error
	LookupModelSelection(context.Context, sharedkernel.Scope) (ModelSelectionBinding, bool, error)
}

type RunModelRoutingSummary struct {
	Version   string                `json:"version"`
	Mode      string                `json:"mode"`
	Decisions []ModelRoutingReceipt `json:"decisions"`
	Truncated bool                  `json:"truncated"`
}

type ModelRoutingReceipt struct {
	QualificationReuse     *ModelRouteQualificationReuse `json:"qualification_reuse,omitempty"`
	ModelKey               string                        `json:"model_key"`
	DecisionSHA256         string                        `json:"decision_sha256"`
	ModelVersionID         string                        `json:"model_version_id"`
	PriceVersionID         string                        `json:"price_version_id"`
	Complexity             string                        `json:"complexity"`
	Reasons                []string                      `json:"reasons"`
	EstimatedMicros        int64                         `json:"estimated_micros"`
	InvocationStatus       string                        `json:"invocation_status"`
	ActualCostMicros       *int64                        `json:"actual_cost_micros,omitempty"`
	FallbackAttempt        int                           `json:"fallback_attempt,omitempty"`
	PreviousDecisionSHA256 string                        `json:"previous_decision_sha256,omitempty"`
}

type ModelRoutingSummaryReader interface {
	ReadRunModelRouting(context.Context, sharedkernel.Scope) (RunModelRoutingSummary, error)
}

func (p ModelPolicy) ValidateRouting() error {
	if p.Routing == nil {
		return nil
	}
	if p.ModelVersionID == "" || p.Routing.Validate() != nil {
		return ErrMissingPolicy
	}
	for _, c := range p.Routing.Candidates {
		if c.ModelVersionID == p.ModelVersionID && c.MaxComplexity == "complex" {
			return nil
		}
	}
	return ErrMissingPolicy
}

type ModelRouteCandidate struct {
	QualityEvidenceID     string               `json:"quality_evidence_id"`
	Reasoning             *ModelRouteReasoning `json:"reasoning,omitempty"`
	ModelVersionID        string               `json:"model_version_id"`
	PriceVersionID        string               `json:"price_version_id"`
	CapabilitySHA256      string               `json:"capability_sha256"`
	QualityEvidenceSHA256 string               `json:"quality_evidence_sha256"`
	MaxComplexity         string               `json:"max_complexity"`
}

type ModelRouteReasoning struct {
	Mode   string `json:"mode,omitempty"`
	Effort string `json:"effort,omitempty"`
}

func (c ModelRouteCandidate) EffectiveReasoning(p ModelPolicy) (string, string) {
	if c.Reasoning != nil {
		return c.Reasoning.Mode, c.Reasoning.Effort
	}
	return p.ReasoningMode, p.ReasoningEffort
}

func ModelComplexityRank(value string) int {
	switch value {
	case "simple":
		return 1
	case "medium":
		return 2
	case "complex":
		return 3
	default:
		return 0
	}
}

func (p ModelRoutingPolicy) Validate() error {
	if len(p.QualificationExports) > 16 {
		return ErrMissingPolicy
	}
	seenExports := map[Scope]bool{}
	for _, export := range p.QualificationExports {
		if export.Validate() != nil || seenExports[export.TargetScope] {
			return ErrMissingPolicy
		}
		seenExports[export.TargetScope] = true
	}
	if p.QualificationReuse != nil && p.QualificationReuse.Validate() != nil {
		return ErrMissingPolicy
	}
	if p.Availability != nil && p.Availability.Validate() != nil {
		return ErrMissingPolicy
	}
	if p.Version != "model-routing/v1" || !routingSHA(p.ExecutionContextSHA256) || p.SimpleMaxInputTokens < 1 ||
		p.ComplexMinInputTokens <= p.SimpleMaxInputTokens || p.ComplexMinInputTokens > 1048576 ||
		p.SimpleMaxOutputTokens < 1 || p.SimpleMaxOutputTokens > 65536 || p.MaxEstimatedMicros < 1 ||
		len(p.Candidates) < 2 || len(p.Candidates) > 8 {
		return ErrMissingPolicy
	}
	seen, complex := map[string]bool{}, false
	for _, c := range p.Candidates {
		if c.Reasoning != nil && (ModelPolicy{ReasoningMode: c.Reasoning.Mode, ReasoningEffort: c.Reasoning.Effort}).ValidateReasoningMode() != nil {
			return ErrMissingPolicy
		}
		if !routingID(c.ModelVersionID) || !routingID(c.PriceVersionID) || !routingID(c.QualityEvidenceID) || seen[c.ModelVersionID] ||
			!routingSHA(c.CapabilitySHA256) || !routingSHA(c.QualityEvidenceSHA256) || ModelComplexityRank(c.MaxComplexity) == 0 {
			return ErrMissingPolicy
		}
		seen[c.ModelVersionID] = true
		complex = complex || c.MaxComplexity == "complex"
	}
	if !complex {
		return ErrMissingPolicy
	}
	return nil
}

type ModelRoutingPublicationValidator interface {
	ValidateModelRoutingPublication(context.Context, Scope, ModelPolicy) error
}

func routingID(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, ":\x00\r\n")
}

func routingSHA(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && value == strings.ToLower(value)
}
