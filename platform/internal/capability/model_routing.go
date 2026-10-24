package capability

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/modelcapacity"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

var (
	ErrModelRouteUnavailable          = errors.New("model routing dependency unavailable")
	ErrModelRouteNoCandidate          = errors.New("no authorized model satisfies routing constraints")
	ErrModelRouteCandidateUnavailable = errors.New("model route candidate temporarily unavailable")
	// A malformed invocation is the caller's defect, not a platform outage: it
	// must surface as a non-retryable rejection instead of a retryable 503.
	ErrModelRouteInvalidRequest = errors.New("model route request invalid")
	routingDatePattern          = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`)
)

type ModelRouteRequest struct {
	DeadlineMS                       int64
	ResponseSchema                   json.RawMessage
	ResponseSchemaMode               string
	ContextCacheMode                 string
	AllowUnreportedPrefixPreparation bool
	Messages                         []modelgateway.Message
	FunctionNames                    []string
	RequireJSON                      bool
	MaxTokens                        int
	ReasoningMode                    string
	ReasoningEffort                  string
	TaskComplexity                   string
	MinimumQualityRank               int
	PreferredModelVersionID          string
}

type ModelRouteFeatures struct {
	InputTokenBound  int64    `json:"input_token_bound"`
	OutputTokenBound int      `json:"output_token_bound"`
	UserTurns        int      `json:"user_turns"`
	DistinctDates    int      `json:"distinct_dates"`
	Complexity       string   `json:"complexity"`
	Reasons          []string `json:"reasons"`
}

type ModelRouteExclusion struct {
	ModelVersionID string `json:"model_version_id"`
	Reason         string `json:"reason"`
}

// A selector proposal is NOT permission to send. The invocation adapter must
// persist it, recheck authorization and reserve the existing RunTree budget.
type ModelRouteDecision struct {
	Version               string                                    `json:"version"`
	PolicySHA256          string                                    `json:"policy_sha256"`
	FeaturesSHA256        string                                    `json:"features_sha256"`
	Features              ModelRouteFeatures                        `json:"features"`
	ModelVersionID        string                                    `json:"model_version_id"`
	ModelKey              string                                    `json:"model_key"`
	CapabilitySHA256      string                                    `json:"capability_sha256"`
	QualityEvidenceSHA256 string                                    `json:"quality_evidence_sha256"`
	Price                 modelgovernance.PriceVersion              `json:"price"`
	EstimatedMicros       int64                                     `json:"estimated_micros"`
	Excluded              []ModelRouteExclusion                     `json:"excluded"`
	Fallback              *ModelRouteFallback                       `json:"fallback,omitempty"`
	SelectionMode         string                                    `json:"selection_mode,omitempty"`
	QualificationReuse    *policyasset.ModelRouteQualificationReuse `json:"qualification_reuse,omitempty"`
}

func modelRouteHash(value any) string {
	raw, _ := json.Marshal(value)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func classifyModelRoute(p policyasset.ModelRoutingPolicy, request ModelRouteRequest, tools policyasset.ToolPolicy) (ModelRouteFeatures, error) {
	raw, mode, schemaErr := modelgateway.NormalizeResponseSchema(request.ResponseSchema, request.ResponseSchemaMode, request.RequireJSON, request.FunctionNames)
	if schemaErr != nil {
		return ModelRouteFeatures{}, ErrModelRouteInvalidRequest
	}
	input, err := conservativeInputTokenEstimate(modelSchemaBudgetMessages(request.Messages, tools, request.FunctionNames, request.RequireJSON, raw, mode))
	if err != nil || input > 1048576 || request.MaxTokens < 1 || request.MaxTokens > 65536 || len(request.Messages) == 0 ||
		modelgateway.ValidateFunctionRequest(tools, request.FunctionNames, request.Messages) != nil {
		return ModelRouteFeatures{}, ErrModelRouteInvalidRequest
	}
	f := ModelRouteFeatures{InputTokenBound: input, OutputTokenBound: request.MaxTokens, Complexity: "complex", Reasons: []string{"unknown_task_conservative"}}
	dates, text := map[string]bool{}, ""
	for _, message := range request.Messages {
		if message.Role == "user" {
			f.UserTurns++
			text += "\n" + strings.ToLower(message.Content)
		}
	}
	if f.UserTurns == 0 || strings.TrimSpace(text) == "" {
		return ModelRouteFeatures{}, ErrModelRouteInvalidRequest
	}
	for _, date := range routingDatePattern.FindAllString(text, -1) {
		dates[date] = true
	}
	f.DistinctDates = len(dates)
	if len(request.FunctionNames) > 0 || f.DistinctDates > 1 || f.UserTurns > 1 || input >= p.ComplexMinInputTokens {
		f.Reasons = []string{"structural_complexity"}
		return f, nil
	}
	if request.TaskComplexity != "" {
		if policyasset.ModelComplexityRank(request.TaskComplexity) == 0 {
			return ModelRouteFeatures{}, ErrModelRouteInvalidRequest
		}
		f.Complexity, f.Reasons = request.TaskComplexity, []string{"original_business_task"}
		if f.Complexity == "simple" && (input > p.SimpleMaxInputTokens || request.MaxTokens > p.SimpleMaxOutputTokens) {
			f.Complexity = "medium"
		}
		return f, nil
	}
	for _, term := range []string{"比较", "对比", "跨版本", "分别", "多个", "多步骤", "分析原因", "推导", "compare", "contrast", "multi-step", "plan", "reason why"} {
		if strings.Contains(text, term) {
			f.Reasons = []string{"complex_task_marker"}
			return f, nil
		}
	}
	// An opaque or unfamiliar request is never down-routed solely because short.
	for _, term := range []string{"定义", "是什么", "计算", "提取", "翻译", "what is", "calculate", "extract", "translate"} {
		if strings.Contains(text, term) {
			f.Complexity, f.Reasons = "medium", []string{"bounded_known_task"}
			if input <= p.SimpleMaxInputTokens && request.MaxTokens <= p.SimpleMaxOutputTokens {
				f.Complexity = "simple"
			}
			return f, nil
		}
	}
	return f, nil
}

// SelectModelRoute uses common catalog/IAM/prices and the existing billing
// estimate. It performs no provider call, reservation, charge or persistence.
func SelectModelRoute(ctx context.Context, scope sharedkernel.Scope, p policyasset.ModelRoutingPolicy,
	request ModelRouteRequest, tools policyasset.ToolPolicy, allowExternal bool,
	metadata modelgateway.RoutingMetadataResolver, prices modelgovernance.PriceResolver, at time.Time) (ModelRouteDecision, error) {
	if scope.ValidateTrusted() != nil || p.Validate() != nil || metadata == nil || prices == nil || at.IsZero() {
		return ModelRouteDecision{}, policyasset.ErrMissingPolicy
	}
	if err := ctx.Err(); err != nil {
		return ModelRouteDecision{}, err
	}
	features, err := classifyModelRoute(p, request, tools)
	if err != nil {
		return ModelRouteDecision{}, err
	}
	decision := ModelRouteDecision{Version: "model-route-decision/v1", PolicySHA256: modelRouteHash(p),
		FeaturesSHA256: modelRouteHash(features), Features: features, Excluded: []ModelRouteExclusion{}}
	bestRank := 0
	for _, c := range p.Candidates {
		if err := ctx.Err(); err != nil {
			return ModelRouteDecision{}, err
		}
		reason := ""
		model, resolveErr := metadata.ResolveRoutingModel(ctx, scope, c.ModelVersionID)
		mode, effort := c.EffectiveReasoning(policyasset.ModelPolicy{ReasoningMode: request.ReasoningMode, ReasoningEffort: request.ReasoningEffort})
		if resolveErr != nil {
			if errors.Is(resolveErr, modelcapacity.ErrUnavailable) || errors.Is(resolveErr, modelcapacity.ErrExceeded) || errors.Is(resolveErr, ErrModelRouteCandidateUnavailable) {
				reason = "temporarily_unavailable"
			} else if !errors.Is(resolveErr, modelgovernance.ErrModelAccessDenied) && !errors.Is(resolveErr, modelgovernance.ErrForbidden) && !errors.Is(resolveErr, modelgovernance.ErrNotFound) {
				return ModelRouteDecision{}, ErrModelRouteUnavailable
			} else {
				reason = "current_access_denied"
			}
		} else if model.Selection.ModelVersionID != c.ModelVersionID || model.Kind != "chat" || model.Selection.ProviderID == "" || model.Selection.ModelID == "" || model.Selection.ProviderKey == "" || model.Selection.ModelKey == "" || c.CapabilitySHA256 != model.CapabilitySHA256() {
			reason = "catalog_capability_mismatch"
		} else if model.Selection.TrustZone != modelgovernance.TrustLocal && model.Selection.TrustZone != modelgovernance.TrustPrivate && model.Selection.TrustZone != modelgovernance.TrustExternal {
			reason = "unknown_trust_zone"
		} else if model.Selection.TrustZone == modelgovernance.TrustExternal && !allowExternal {
			reason = "external_not_allowed"
		} else if model.Selection.TrustZone == modelgovernance.TrustLocal && (model.Selection.DeploymentID == "" || model.Selection.CapacityUnits < 1 || model.Selection.EndpointRef == "") {
			reason = "managed_local_deployment_missing"
		} else if int64(model.ContextLimit) < features.InputTokenBound+int64(request.MaxTokens) || len(request.FunctionNames) > 0 && !model.SupportsFunctions || request.RequireJSON && !model.SupportsJSON || len(request.ResponseSchema) > 0 && request.ResponseSchemaMode != "prefer_supported" && !modelgateway.SupportsResponseSchema(model.ResponseSchemaDialect) || modelgateway.ValidateWireReasoning(model.ReasoningDialect, mode, effort) != nil {
			reason = "required_capability_missing"
		} else if policyasset.ModelComplexityRank(c.MaxComplexity) < policyasset.ModelComplexityRank(features.Complexity) {
			reason = "quality_tier_insufficient"
		} else if policyasset.ModelComplexityRank(c.MaxComplexity) < request.MinimumQualityRank {
			reason = "fallback_quality_tier_insufficient"
		} else if !request.allowsContextCacheMode(model.ContextCacheMode) {
			reason = "context_cache_capability_missing"
		}
		if reason != "" {
			decision.Excluded = append(decision.Excluded, ModelRouteExclusion{c.ModelVersionID, reason})
			continue
		}
		price, priceErr := prices.ResolvePrice(ctx, c.ModelVersionID, at)
		if priceErr != nil && !errors.Is(priceErr, modelgovernance.ErrNotFound) {
			return ModelRouteDecision{}, ErrModelRouteUnavailable
		}
		if priceErr != nil || !validRuntimeModelPrice(price, c.ModelVersionID, at) || price.ID != c.PriceVersionID || model.Selection.TrustZone == modelgovernance.TrustExternal && (price.InputMicrosPer1K <= 0 || price.OutputMicrosPer1K <= 0) {
			decision.Excluded = append(decision.Excluded, ModelRouteExclusion{c.ModelVersionID, "pinned_price_unavailable"})
			continue
		}
		cost, estimateErr := approvedModelCost(price, features.InputTokenBound, int64(request.MaxTokens))
		if estimateErr != nil || cost > p.MaxEstimatedMicros {
			decision.Excluded = append(decision.Excluded, ModelRouteExclusion{c.ModelVersionID, "estimated_cost_exceeds_limit"})
			continue
		}
		rank := policyasset.ModelComplexityRank(c.MaxComplexity)
		preferred := request.PreferredModelVersionID != "" && c.ModelVersionID == request.PreferredModelVersionID
		bestPreferred := request.PreferredModelVersionID != "" && decision.ModelVersionID == request.PreferredModelVersionID
		if decision.ModelVersionID == "" || preferred && !bestPreferred || preferred == bestPreferred && (cost < decision.EstimatedMicros || cost == decision.EstimatedMicros && (rank < bestRank || rank == bestRank && c.ModelVersionID < decision.ModelVersionID)) {
			decision.ModelVersionID, decision.Price, decision.EstimatedMicros = c.ModelVersionID, price, cost
			decision.ModelKey = model.Selection.ModelKey
			decision.CapabilitySHA256, decision.QualityEvidenceSHA256, bestRank = c.CapabilitySHA256, c.QualityEvidenceSHA256, rank
		}
	}
	if decision.ModelVersionID == "" {
		return ModelRouteDecision{}, ErrModelRouteNoCandidate
	}
	decision.QualificationReuse = p.QualificationReuse
	if err := ctx.Err(); err != nil {
		return ModelRouteDecision{}, err
	}
	return decision, nil
}
