package capability

import (
	"context"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/policyasset"
)

var ErrModelRouteOutcomePending = errors.New("model route outcome not ready for disposition")

// The business choice is separate from the provider billing record. Once a
// step is disposed, a late result can settle money but cannot become the answer.
type ModelRouteExecution struct {
	Version            string                          `json:"version"`
	RequestFingerprint string                          `json:"request_fingerprint"`
	PolicySHA256       string                          `json:"policy_sha256"`
	MaxAttempts        int                             `json:"max_attempts"`
	Revision           int64                           `json:"revision"`
	Status             string                          `json:"status"`
	Deadline           time.Time                       `json:"deadline"`
	Steps              []ModelRouteExecutionStep       `json:"steps"`
	RecoveryPolicy     *policyasset.ModelRoutingPolicy `json:"recovery_policy,omitempty"`
}

type ModelRouteExecutionStep struct {
	KeySHA256                 string `json:"key_sha256"`
	Fingerprint               string `json:"fingerprint"`
	ModelVersionID            string `json:"model_version_id"`
	DecisionSHA256            string `json:"decision_sha256"`
	OutcomeSHA256             string `json:"outcome_sha256"`
	Disposition               string `json:"disposition"`
	Reason                    string `json:"reason"`
	MinimumQualityRank        int    `json:"minimum_quality_rank"`
	RetainedReservationSHA256 string `json:"retained_reservation_sha256,omitempty"`
	RetainedMicros            int64  `json:"retained_micros,omitempty"`
}

type ModelRouteExecutionStore interface {
	LookupModelRouteExecution(context.Context, string, string) (ModelRouteExecution, bool, error)
	BeginModelRouteExecution(context.Context, string, string, ModelRouteExecution) (ModelRouteExecution, error)
	AdvanceModelRouteExecution(context.Context, string, string, ModelRouteExecution, StoredModelRoute, string, policyasset.ModelRoutingPolicy) (ModelRouteExecution, error)
}

func validModelRouteExecution(s ModelRouteExecution) bool {
	if s.RecoveryPolicy != nil && (s.RecoveryPolicy.Validate() != nil ||
		modelRouteHash(*s.RecoveryPolicy) != s.PolicySHA256 || s.RecoveryPolicy.Availability == nil ||
		s.RecoveryPolicy.Availability.Version != "model-route-availability/v2") {
		return false
	}
	if s.Version != "model-route-execution/v1" || !isRouteSHA(s.RequestFingerprint) || !isRouteSHA(s.PolicySHA256) ||
		s.MaxAttempts < 1 || s.MaxAttempts > 3 || len(s.Steps) > s.MaxAttempts || s.Revision != int64(len(s.Steps)+1) || s.Deadline.IsZero() {
		return false
	}
	if s.Status != "active" && s.Status != "completed" && s.Status != "exhausted" ||
		s.Status == "active" && len(s.Steps) >= s.MaxAttempts || s.Status != "active" && len(s.Steps) == 0 ||
		s.Status == "exhausted" && len(s.Steps) != s.MaxAttempts {
		return false
	}
	for i, step := range s.Steps {
		if !isRouteSHA(step.KeySHA256) || !isRouteSHA(step.Fingerprint) || !isRouteSHA(step.DecisionSHA256) ||
			!isRouteSHA(step.OutcomeSHA256) || step.ModelVersionID == "" || step.MinimumQualityRank < 1 || step.MinimumQualityRank > 3 {
			return false
		}
		switch step.Disposition {
		case "selected":
			if i != len(s.Steps)-1 || s.Status != "completed" || step.Reason != "completed_response" {
				return false
			}
		case "incomplete":
			if step.Reason != "output_incomplete" {
				return false
			}
		case "unsent":
			if step.Reason != "verified_unsent" {
				return false
			}
		case "retained_unknown":
			if !isRouteSHA(step.RetainedReservationSHA256) || step.RetainedMicros < 0 || !recoverableProviderFailure(step.Reason) {
				return false
			}
		default:
			return false
		}
		if step.Disposition != "retained_unknown" && (step.RetainedReservationSHA256 != "" || step.RetainedMicros != 0) {
			return false
		}
	}
	return s.Status != "completed" || s.Steps[len(s.Steps)-1].Disposition == "selected"
}

func recoverableProviderFailure(kind string) bool {
	switch kind {
	case "provider_network", "provider_body_read", "provider_dial_timeout", "provider_tls_timeout",
		"provider_response_timeout", "provider_transport_timeout", "invalid_response", "response_too_large",
		"provider_http_401", "provider_http_403", "provider_http_408", "provider_http_429",
		"provider_http_500", "provider_http_502", "provider_http_503", "provider_http_504":
		return true
	}
	return false
}

func advanceModelRouteExecution(s ModelRouteExecution, logical string, route StoredModelRoute, fingerprint string,
	p policyasset.ModelRoutingPolicy, record ModelInvocation) (ModelRouteExecution, error) {
	if !validModelRouteExecution(s) || s.Status != "active" || !validStoredModelRoute(route) || p.Validate() != nil ||
		p.Availability == nil || p.Availability.Version != "model-route-availability/v2" || s.PolicySHA256 != modelRouteHash(p) ||
		route.RequestFingerprint != s.RequestFingerprint || route.Decision.PolicySHA256 != s.PolicySHA256 ||
		s.MaxAttempts != p.Availability.MaxAttempts || !isRouteSHA(fingerprint) || record.Fingerprint != fingerprint ||
		record.Key != physicalRouteAttemptKey(logical, len(s.Steps)) {
		return ModelRouteExecution{}, ErrModelInvocationConflict
	}
	rank := 0
	for _, c := range p.Candidates {
		if c.ModelVersionID == route.Decision.ModelVersionID {
			rank = policyasset.ModelComplexityRank(c.MaxComplexity)
		}
	}
	step := ModelRouteExecutionStep{KeySHA256: modelRouteHash(record.Key), Fingerprint: fingerprint,
		ModelVersionID: route.Decision.ModelVersionID, DecisionSHA256: route.DecisionSHA256, MinimumQualityRank: rank}
	switch {
	case record.Status == "completed":
		if _, err := routeSummaryReceipt(route, record, true); err != nil {
			return ModelRouteExecution{}, err
		}
		routing, _ := record.Response["routing"].(map[string]any)
		if routing["decision_sha256"] != route.DecisionSHA256 {
			return ModelRouteExecution{}, ErrModelInvocationConflict
		}
		step.OutcomeSHA256 = modelRouteHash(record.Response)
		step.Disposition, step.Reason = "selected", "completed_response"
		if record.Response["completion_status"] == "incomplete" {
			step.Disposition, step.Reason = "incomplete", "output_incomplete"
		}
	case record.Status == "failed" && record.Recovery != nil && record.Recovery.Unsent:
		if !recordedSystemUnsentProof(record) ||
			record.Recovery.PriceID != route.Decision.Price.ID {
			return ModelRouteExecution{}, ErrModelRouteOutcomePending
		}
		step.Disposition, step.Reason, step.OutcomeSHA256 = "unsent", "verified_unsent", modelRouteHash(record.Recovery)
	case record.Status == "reconcile" && record.Recovery != nil && p.Availability.UnknownOutcome == "retain_and_continue":
		r := record.Recovery
		if !r.HoldConfirmed || r.Event != nil || r.Decision != nil || r.Unsent || !r.SendDeadline.IsZero() || !r.AdmissionUntil.IsZero() ||
			record.Response != nil || r.AttemptToken == "" || !recoverableProviderFailure(r.FailureKind) ||
			r.Reservation.ReservationID == "" || r.Reservation.Fingerprint != fingerprint || r.PriceID != route.Decision.Price.ID ||
			r.Reservation.PriceVersionID != r.PriceID || r.Reservation.ReserveMicros < 0 {
			return ModelRouteExecution{}, ErrModelRouteOutcomePending
		}
		step.Disposition, step.Reason, step.OutcomeSHA256 = "retained_unknown", r.FailureKind, modelRouteHash(r)
		step.RetainedReservationSHA256, step.RetainedMicros = modelRouteHash(r.Reservation), r.Reservation.ReserveMicros
	default:
		return ModelRouteExecution{}, ErrModelRouteOutcomePending
	}
	s.Steps = append(append([]ModelRouteExecutionStep(nil), s.Steps...), step)
	s.Revision++
	if step.Disposition == "selected" {
		s.Status = "completed"
	} else if len(s.Steps) == s.MaxAttempts {
		s.Status = "exhausted"
	}
	if !validModelRouteExecution(s) {
		return ModelRouteExecution{}, ErrModelInvocationConflict
	}
	return s, nil
}

func modelRouteExecutionFallback(logical string, s ModelRouteExecution, index int) routeFallbackContext {
	var out routeFallbackContext
	rank := 0
	for i := 0; i < index; i++ {
		step := s.Steps[i]
		if step.MinimumQualityRank > rank {
			rank = step.MinimumQualityRank
		}
		out.Excluded = append(out.Excluded, step.ModelVersionID)
		out.Fallback = &ModelRouteFallback{Version: "model-route-fallback/v1", LogicalKeySHA256: modelRouteHash(logical),
			Attempt: i + 1, PreviousDecisionSHA256: step.DecisionSHA256, PreviousOutcomeSHA256: step.OutcomeSHA256, MinimumQualityRank: rank}
	}
	return out
}

func executionRetainsUnknown(s ModelRouteExecution, key, fingerprint string, recovery *BillingRecovery) bool {
	if !validModelRouteExecution(s) || recovery == nil || !recovery.HoldConfirmed || recovery.Event != nil || recovery.Decision != nil ||
		recovery.Unsent || !recovery.SendDeadline.IsZero() || !recovery.AdmissionUntil.IsZero() {
		return false
	}
	for _, step := range s.Steps {
		if step.Disposition == "retained_unknown" && step.KeySHA256 == modelRouteHash(key) && step.Fingerprint == fingerprint &&
			step.RetainedReservationSHA256 == modelRouteHash(recovery.Reservation) && step.Reason == recovery.FailureKind {
			return true
		}
	}
	return false
}
