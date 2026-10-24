package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	agenteval "github.com/lexagent/agent-evaluation"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/evaluationproduct"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/policyasset"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

type modelRoutingPublicationValidator struct {
	models        modelgovernance.Store
	evaluations   evaluationproduct.Store
	caseModels    evaluationproduct.RoutingCaseModelVerifier
	reuseCatalog  routingReuseCatalog
	reusePolicies routingReusePolicies
}

func (v modelRoutingPublicationValidator) ValidateModelRoutingPublication(ctx context.Context, scope policyasset.Scope, p policyasset.ModelPolicy) error {
	if p.ValidateContextCache() != nil {
		return policyasset.ErrInvalidAsset
	}
	if p.ContextCache != nil {
		versions := []string{p.ModelVersionID}
		if p.Routing != nil {
			for _, c := range p.Routing.Candidates {
				versions = append(versions, c.ModelVersionID)
			}
		}
		for _, id := range versions {
			metadata, err := modelgovernance.ApprovedRoutingMetadata(ctx, v.models, id)
			if err != nil || !p.AllowsContextCacheMode(metadata.ContextCacheMode) {
				return policyasset.ErrInvalidAsset
			}
		}
	}
	if p.Routing == nil {
		return nil
	}
	if p.ValidateRouting() != nil || v.models == nil || v.evaluations == nil || v.caseModels == nil {
		return policyasset.ErrInvalidAsset
	}
	qualificationTarget, err := v.reviewedQualificationTarget(ctx, scope, p)
	if err != nil {
		return err
	}
	if err := v.validateQualificationExports(ctx, scope, p); err != nil {
		return err
	}
	for _, candidate := range p.Routing.Candidates {
		resolved, err := v.models.GetResolvedVersion(ctx, candidate.ModelVersionID)
		if err != nil || resolved.VersionStatus != modelgovernance.StatusApproved || resolved.ProviderStatus != modelgovernance.StatusApproved || resolved.Kind != modelgovernance.ModelKindChat {
			return policyasset.ErrInvalidAsset
		}
		definition, err := v.models.GetDefinition(ctx, resolved.DefinitionID)
		if err != nil || definition.Kind != modelgovernance.ModelKindChat || definition.LifecycleStatus != modelgovernance.StatusDraft || definition.ProviderID != resolved.ProviderID || definition.ModelKey != resolved.ModelKey {
			return policyasset.ErrInvalidAsset
		}
		var capabilities struct {
			Functions bool `json:"function_calling"`
			JSON      bool `json:"json_output"`
		}
		wire, err := modelgateway.ParseWireCapabilities(definition.Capabilities)
		if err != nil || json.Unmarshal(definition.Capabilities, &capabilities) != nil {
			return policyasset.ErrInvalidAsset
		}
		metadata := modelgateway.RoutingMetadata{Selection: modelgateway.Selection{ModelVersionID: resolved.VersionID,
			ProviderID: resolved.ProviderID, ModelID: resolved.DefinitionID, ModelKey: resolved.ModelKey, TrustZone: resolved.TrustZone},
			Kind: definition.Kind, ContextLimit: definition.ContextLimit, SupportsFunctions: capabilities.Functions, SupportsJSON: capabilities.JSON,
			WireModel: wire.WireModel, ReasoningDialect: wire.ReasoningDialect, ContextCacheMode: wire.ContextCacheMode, ResponseSchemaDialect: wire.ResponseSchemaDialect}
		mode, effort := candidate.EffectiveReasoning(p)
		if metadata.CapabilitySHA256() != candidate.CapabilitySHA256 || modelgateway.ValidateWireReasoning(wire.ReasoningDialect, mode, effort) != nil {
			return policyasset.ErrInvalidAsset
		}
		price, err := v.models.ResolvePrice(ctx, candidate.ModelVersionID, time.Now().UTC())
		if err != nil || price.ID != candidate.PriceVersionID || price.Status != modelgovernance.StatusApproved || price.Currency != "USD" ||
			(resolved.TrustZone == modelgovernance.TrustExternal && (price.InputMicrosPer1K <= 0 || price.OutputMicrosPer1K <= 0)) {
			return policyasset.ErrInvalidAsset
		}
		if err := evaluationproduct.VerifyModelRoutingQualificationWithMaxAge(ctx, v.evaluations, routingQualificationScope(scope, p),
			candidate.QualityEvidenceID, candidate.QualityEvidenceSHA256, candidate.ModelVersionID, candidate.MaxComplexity, v.caseModels,
			qualificationTarget, p.Routing.QualificationEvidenceMaxAgeSeconds()); err != nil {
			return policyasset.ErrInvalidAsset
		}
	}
	return nil
}

type routingQualificationRuns interface {
	Get(string) (platformruntime.Run, error)
	GetOutcome(string) (platformruntime.Outcome, error)
}
type routingQualificationCaseModels struct {
	runs     routingQualificationRuns
	receipts *capability.SQLModelInvocationStore
	identity identity.Store
}

func (v routingQualificationCaseModels) VerifyRoutingCaseModel(ctx context.Context, scope evaluationproduct.Scope, parent string, index int, modelVersion string, target evaluationproduct.RoutingQualificationTarget) (evaluationproduct.RoutingQualifiedCase, error) {
	if v.runs == nil || v.receipts == nil {
		return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrUnavailable
	}
	run, err := v.runs.Get(evaluationExecutionRunID(parent, index))
	if err != nil || run.Status != platformruntime.StatusSucceeded || run.Scope.TenantID != scope.TenantID || run.Scope.DepartmentID != scope.DepartmentID || run.Scope.ApplicationID != scope.ApplicationID ||
		run.Scope.ParentRunID != parent || run.Scope.SessionID != evaluationSessionID(parent, index) {
		return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrSnapshotInvalid
	}
	var command contract.ExecuteRequest
	if contract.DecodeJSONPreservingNumbers(run.RequestJSON, &command) != nil {
		return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrSnapshotInvalid
	}
	checks := map[string]*bool{}
	if !agenteval.IsJudgeInputVersion(command.Input["version"]) {
		return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrSnapshotInvalid
	}
	// Independent judge evidence refers to a business Run, not to the judge's
	// own larger scoring model. Verify both frozen hashes against that result.
	if agenteval.IsJudgeInputVersion(command.Input["version"]) {
		if run.Scope.AgentID != "agent-eval-judge" || v.identity == nil {
			return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrSnapshotInvalid
		}
		input := map[string]any{}
		for key, value := range command.Input {
			if key != "policy_snapshot" {
				input[key] = value
			}
		}
		raw, _ := json.Marshal(input)
		var judge agenteval.JudgeInput
		if json.Unmarshal(raw, &judge) != nil {
			return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrSnapshotInvalid
		}
		ref, err := judge.SourceReference()
		if err != nil {
			return evaluationproduct.RoutingQualifiedCase{}, err
		}
		judged, err := v.runs.GetOutcome(run.ID)
		var graded struct {
			Schema    string              `json:"schema"`
			Judgement agenteval.Judgement `json:"judgement"`
		}
		if err != nil || len(judged.OutputJSON) > 1<<20 || json.Unmarshal(judged.OutputJSON, &graded) != nil {
			return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrSnapshotInvalid
		}
		j := graded.Judgement
		if graded.Schema != "schema://agent-eval-judge/output/v1" || j.Version != agenteval.JudgementVersion || j.Source != "model" ||
			j.JudgeRunID != run.ID || j.JudgeVersionID != run.Scope.AgentVersionID || j.SourceRunID != ref.RunID || j.SourceOutputHash != ref.OutputHash ||
			j.SourceRedactedOutputHash != ref.RedactedOutputHash || j.RubricHash != judge.RubricHash || agenteval.RubricDigest(j.Rubric) != judge.RubricHash || agenteval.ValidateVerdicts(judge, j.Verdicts) != nil {
			return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrSnapshotInvalid
		}
		judgeSnapshot, snapshotErr := policyasset.SnapshotFromRoutingExecutionInput(command.Input["policy_snapshot"])
		if snapshotErr != nil || j.ScoringModelVersion == "" || j.ScoringModelVersion != judgeSnapshot.Model.ModelVersionID || j.ScoringModel != judgeSnapshot.Model.Model {
			return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrSnapshotInvalid
		}
		judgeUsedModel, usageErr := v.receipts.EvaluationUsedChatModel(ctx, run.Scope, j.ScoringModelVersion)
		if usageErr != nil || !judgeUsedModel {
			return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrSnapshotInvalid
		}
		var frozenExpected agenteval.Expected
		if json.Unmarshal(judge.Evidence["expected"], &frozenExpected) != nil ||
			j.ExpectedHash != agenteval.ExpectedDigest(frozenExpected) {
			return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrSnapshotInvalid
		}
		for _, verdict := range j.Verdicts {
			checks[verdict.MetricID] = verdict.Value
		}
		source, err := v.runs.Get(ref.RunID)
		if err != nil || source.Status != platformruntime.StatusSucceeded || source.Scope.TenantID != scope.TenantID || source.Scope.DepartmentID != scope.DepartmentID || source.Scope.ApplicationID != scope.ApplicationID ||
			authorizeBusinessResource(ctx, v.identity, source.Scope, run.Scope.PrincipalID, "history.read") != nil {
			return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrForbidden
		}
		outcome, err := v.runs.GetOutcome(source.ID)
		if err != nil || len(outcome.OutputJSON) > 1<<20 {
			return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrSnapshotInvalid
		}
		digest := sha256.Sum256(outcome.OutputJSON)
		if hex.EncodeToString(digest[:]) != ref.OutputHash {
			return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrSnapshotInvalid
		}
		var output any
		decoder := json.NewDecoder(bytes.NewReader(outcome.OutputJSON))
		decoder.UseNumber()
		if decoder.Decode(&output) != nil {
			return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrSnapshotInvalid
		}
		redacted, _ := json.Marshal(agenteval.Sanitize(output))
		digest = sha256.Sum256(redacted)
		if hex.EncodeToString(digest[:]) != ref.RedactedOutputHash || contract.DecodeJSONPreservingNumbers(source.RequestJSON, &command) != nil {
			return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrSnapshotInvalid
		}
		run = source
	}
	snapshot, err := policyasset.SnapshotFromRoutingExecutionInput(command.Input["policy_snapshot"])
	if err != nil || snapshot.Model.ModelVersionID != modelVersion || snapshot.Model.Routing != nil ||
		run.Scope.AgentID != target.AgentID || run.Scope.AgentVersionID != target.AgentVersionID || policyasset.RoutingExecutionContextSHA256(snapshot) != target.ExecutionContextSHA256 {
		return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrSnapshotInvalid
	}
	verified, err := v.receipts.EvaluationUsedChatModel(ctx, run.Scope, modelVersion)
	if err != nil {
		return evaluationproduct.RoutingQualifiedCase{}, err
	}
	if !verified {
		return evaluationproduct.RoutingQualifiedCase{}, evaluationproduct.ErrSnapshotInvalid
	}
	input, err := json.Marshal(command.Input)
	if err != nil {
		return evaluationproduct.RoutingQualifiedCase{}, err
	}
	hash, err := conversation.BusinessRequestHash(input)
	return evaluationproduct.RoutingQualifiedCase{BusinessInputSHA256: hash, QualityChecks: checks}, err
}

var _ policyasset.ModelRoutingPublicationValidator = modelRoutingPublicationValidator{}
var _ evaluationproduct.RoutingCaseModelVerifier = routingQualificationCaseModels{}
