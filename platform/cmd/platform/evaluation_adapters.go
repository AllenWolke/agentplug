package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	agenteval "github.com/lexagent/agent-evaluation"

	"github.com/lexagent/platform/internal/agentgateway"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/evaluationproduct"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"google.golang.org/grpc/status"
)

// evaluationAgentInvoker is the local modular-monolith adapter for product
// evaluation. Each case re-resolves its exact Catalog target and rechecks the
// Run creator's installation-level `run` Grant before sending input.
// 每个 Case 调用都重查精确 Catalog 部署与 Run 创建者的安装级 run 授权。
type evaluationAgentInvoker struct {
	catalog   *catalog.Module
	store     evaluationproduct.ExecutionStore
	identity  identity.Store
	policies  policyasset.Resolver
	signer    conversation.ContextTokenSigner
	modes     evaluationproduct.ModeAdmission
	sources   evaluationproduct.SourceAuthorizer
	execution interface {
		InvokeSynchronous(context.Context, sharedkernel.Scope, string, contract.ExecuteRequest) (contract.ExecuteResponse, error)
	}
}

func (a evaluationAgentInvoker) InvokeEvaluationCase(ctx context.Context, request evaluationproduct.InvocationRequest) (result evaluationproduct.InvocationResult, returnErr error) {
	stage := "validate_request"
	defer func() {
		if returnErr != nil {
			errorClass, errorType := evaluationInvocationErrorClass(returnErr)
			// Log only stable identifiers and a bounded stage label; never emit
			// prompts, case input, policy contents, credentials, or upstream bodies.
			// 仅记录稳定标识和阶段标签，不记录 Prompt、用例输入、策略正文、凭证或上游响应体。
			log.Printf("evaluation_agent_invocation_failed run_id=%q case_index=%d stage=%q error_class=%q error_type=%q", request.RunID, request.CaseIndex, stage, errorClass, errorType)
		}
	}()
	if a.catalog == nil || a.store == nil || a.identity == nil || a.policies == nil || a.signer == nil || a.execution == nil ||
		request.RunID == "" || request.AgentID == "" || request.AgentVersionID == "" || request.CaseIndex < 0 ||
		len(request.Input) == 0 || !json.Valid(request.Input) || len(request.IdempotencyKey) < 8 {
		return evaluationproduct.InvocationResult{}, errors.New("evaluation Agent invocation dependencies or request are invalid")
	}
	stage = "load_run_creator"
	run, err := a.store.Get(ctx, request.Scope, evaluationproduct.KindRun, request.RunID)
	if err != nil || run.Scope != request.Scope || run.ID != request.RunID || run.Kind != evaluationproduct.KindRun || strings.TrimSpace(run.CreatedBy) == "" {
		return evaluationproduct.InvocationResult{}, errors.New("evaluation run creator cannot be verified")
	}
	var runData evaluationproduct.RunData
	if json.Unmarshal(run.Data, &runData) != nil {
		return result, evaluationproduct.ErrUnavailable
	}
	if runData.Mode == "simulation" {
		if a.modes == nil {
			return result, evaluationproduct.ErrUnavailable
		}
		suiteRow, e := a.store.Get(ctx, request.Scope, evaluationproduct.KindSuite, runData.SuiteID)
		var suite evaluationproduct.SuiteData
		if e != nil || json.Unmarshal(suiteRow.Data, &suite) != nil {
			return result, evaluationproduct.ErrUnavailable
		}
		if e = a.modes.AuthorizeEvaluationMode(ctx, evaluationproduct.Actor{Scope: request.Scope, PrincipalType: "user", PrincipalID: run.CreatedBy}, runData, suite); e != nil {
			return result, e
		}
	}
	stage = "validate_run_principal"
	principal, err := a.identity.GetPrincipal(ctx, identity.PrincipalUser, run.CreatedBy)
	if err != nil || !principal.IsActive || principal.ID != run.CreatedBy || principal.Type != identity.PrincipalUser || principal.TenantID != request.Scope.TenantID {
		return evaluationproduct.InvocationResult{}, errors.New("evaluation run creator is not an active scoped user")
	}
	sessionID := evaluationSessionID(request.RunID, request.CaseIndex)
	traceID := conversation.NewContextTraceID(fmt.Sprintf("evaluation:%s:%d", request.RunID, request.CaseIndex))
	targetScope := sharedkernel.Scope{
		TenantID: request.Scope.TenantID, DepartmentID: request.Scope.DepartmentID, ApplicationID: request.Scope.ApplicationID,
		AgentID: request.AgentID, AgentVersionID: request.AgentVersionID,
		InstallationID: request.InstallationID, AgentInstanceID: request.InstallationID,
		PrincipalType: string(identity.PrincipalUser), PrincipalID: principal.ID,
		SessionID: sessionID, RunID: evaluationExecutionRunID(request.RunID, request.CaseIndex), ParentRunID: request.RunID, TraceID: traceID,
	}
	stage = "resolve_catalog_target"
	target, err := a.catalog.ResolveEvaluationAgentTarget(ctx, targetScope, request.AgentID, request.AgentVersionID)
	if err != nil {
		return evaluationproduct.InvocationResult{}, fmt.Errorf("resolve exact ready evaluation Agent: %w", err)
	}
	if request.InstallationID != "" && (target.InstallationID != request.InstallationID || target.Revision != request.InstallationRevision) {
		return evaluationproduct.InvocationResult{}, errors.New("frozen installation changed; rediscover and prepare a new suite")
	}
	targetScope.AgentInstanceID, targetScope.InstallationID = target.InstallationID, target.InstallationID
	authority, ok := a.identity.(identity.AuthorizationVersionPort)
	if !ok {
		return evaluationproduct.InvocationResult{}, errors.New("evaluation IAM authorization version unavailable")
	}
	targetScope.AuthorizationEpoch, err = authority.CurrentAuthorizationEpoch(ctx, targetScope, "run")
	if err != nil {
		return evaluationproduct.InvocationResult{}, errors.New("evaluation current IAM access denied")
	}
	stage = "validate_execution_scope"
	if err := targetScope.ValidateTrusted(); err != nil {
		return evaluationproduct.InvocationResult{}, fmt.Errorf("invalid evaluation signing scope: %w", err)
	}
	stage = "authorize_run_grant"
	decision, err := identity.CheckPrincipalAccess(ctx, a.identity, targetScope, identity.PrincipalUser, principal.ID, "run")
	if err != nil || !decision.Allowed {
		return evaluationproduct.InvocationResult{}, errors.New("evaluation run creator lacks the exact installation run Grant")
	}
	stage = "resolve_policy_snapshot"
	snapshot, err := a.policies.Resolve(ctx, targetScope, request.AgentVersionID)
	if err != nil {
		return evaluationproduct.InvocationResult{}, fmt.Errorf("resolve published evaluation policy snapshot: %w", err)
	}
	stage = "materialize_policy_snapshot"
	policyInput, err := snapshot.ExecutionInput()
	if err != nil {
		return evaluationproduct.InvocationResult{}, fmt.Errorf("materialize evaluation policy snapshot: %w", err)
	}
	stage = "decode_case_input"
	var agentInput map[string]any
	decoder := json.NewDecoder(bytes.NewReader(request.Input))
	decoder.UseNumber()
	if err := decoder.Decode(&agentInput); err != nil || agentInput == nil {
		return evaluationproduct.InvocationResult{}, errors.New("evaluation case input must be a JSON object")
	}
	if _, forged := agentInput["policy_snapshot"]; forged {
		return evaluationproduct.InvocationResult{}, errors.New("evaluation case cannot supply its own policy snapshot")
	}
	if agentInput["version"] == "agent-eval-judge-input/v1" {
		var input agenteval.JudgeInput
		if json.Unmarshal(request.Input, &input) != nil {
			return result, evaluationproduct.ErrInvalid
		}
		ref, e := input.SourceReference()
		if e != nil || a.sources == nil || request.AgentID != "agent-eval-judge" {
			return result, evaluationproduct.ErrForbidden
		}
		if e = a.sources.AuthorizeSources(ctx, evaluationproduct.Actor{Scope: request.Scope, PrincipalType: "user", PrincipalID: principal.ID}, []agenteval.SourceReference{ref}); e != nil {
			return result, e
		}
	}
	agentInput["policy_snapshot"] = policyInput
	envelope := contract.ExecuteRequest{
		ProtocolVersion: contract.ProtocolVersion,
		Scope: contract.ScopeKey{
			TenantID: targetScope.TenantID, DepartmentID: targetScope.DepartmentID, ApplicationID: targetScope.ApplicationID,
			AgentInstanceID: targetScope.AgentInstanceID, AgentID: targetScope.AgentID, AgentVersionID: targetScope.AgentVersionID,
			PrincipalType: targetScope.PrincipalType, PrincipalID: targetScope.PrincipalID,
			SessionID: targetScope.SessionID, RunID: targetScope.RunID, ParentRunID: targetScope.ParentRunID,
			AuthorizationEpoch: targetScope.AuthorizationEpoch, TraceID: targetScope.TraceID,
			InstallationID: targetScope.InstallationID,
		},
		Operation: "invoke", IdempotencyKey: request.IdempotencyKey,
		InputSchema: target.InputSchemaURI, Input: agentInput,
	}
	stage = "sign_context"
	token, err := a.signer.Sign(ctx, targetScope, envelope)
	if err != nil {
		return evaluationproduct.InvocationResult{}, fmt.Errorf("sign evaluation Agent request: %w", err)
	}
	envelope.ContextToken = token
	stage = "governed_execution_run"
	response, err := a.execution.InvokeSynchronous(ctx, targetScope, target.Endpoint, envelope)
	if err != nil {
		return evaluationproduct.InvocationResult{}, fmt.Errorf("invoke evaluation Agent through Gateway: %w", err)
	}
	stage = "validate_agent_response"
	if response.RunID != targetScope.RunID || response.Status != "succeeded" || response.Output == nil {
		return evaluationproduct.InvocationResult{}, errors.New("evaluation Agent did not return a synchronous successful result")
	}
	stage = "encode_agent_output"
	output, err := json.Marshal(response.Output)
	if err != nil {
		return evaluationproduct.InvocationResult{}, fmt.Errorf("encode evaluation Agent output: %w", err)
	}
	mode := evaluationProviderMode(snapshot.Model.Provider)
	if runData.Mode == "simulation" {
		mode = "synthetic"
	}
	return evaluationproduct.InvocationResult{
		Output: output, ProviderMode: mode,
		// Grounding is established by the published independent metrics, never
		// by a remote Agent's self-reported "grounding" output fields.
		CitationGrounding: "unknown",
		DomainGrounding:   "unknown",
	}, nil
}

func evaluationInvocationErrorClass(err error) (string, string) {
	errorClass := "internal"
	var appErr contract.AppError
	var appErrPointer *contract.AppError
	switch {
	case errors.As(err, &appErr) && appErr.Code != "":
		errorClass = appErr.Code
	case errors.As(err, &appErrPointer) && appErrPointer != nil && appErrPointer.Code != "":
		errorClass = appErrPointer.Code
	case errors.Is(err, agentgateway.ErrGRPCInvalidResponse):
		errorClass = "grpc_invalid_response"
	case errors.Is(err, agentgateway.ErrGRPCInputEncoding):
		errorClass = "grpc_input_encoding"
	case errors.Is(err, agentgateway.ErrInvalidResponse):
		errorClass = "gateway_invalid_response"
	case errors.Is(err, agentgateway.ErrInvalidTarget):
		errorClass = "gateway_invalid_target"
	case errors.Is(err, agentgateway.ErrTargetMismatch):
		errorClass = "gateway_target_mismatch"
	case errors.Is(err, agentgateway.ErrNoAdapter):
		errorClass = "gateway_adapter_unavailable"
	case errors.Is(err, agentgateway.ErrGRPCServicePath):
		errorClass = "grpc_service_path_invalid"
	case errors.Is(err, contract.ErrProtocolNotSupported):
		errorClass = "PROTOCOL_NOT_SUPPORTED"
	case errors.Is(err, contract.ErrSchemaValidation):
		errorClass = "SCHEMA_VALIDATION_FAILED"
	case errors.Is(err, context.DeadlineExceeded):
		errorClass = "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		errorClass = "canceled"
	default:
		if grpcStatus, ok := status.FromError(err); ok {
			errorClass = "grpc_" + strings.ToLower(grpcStatus.Code().String())
		}
	}

	deepest := err
	for {
		unwrapped := errors.Unwrap(deepest)
		if unwrapped == nil {
			break
		}
		deepest = unwrapped
	}
	return errorClass, fmt.Sprintf("%T", deepest)
}

func evaluationSessionID(runID string, index int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("evaluation-session:%s:%d", runID, index)))
	return "eval-" + hex.EncodeToString(sum[:16])
}

func evaluationExecutionRunID(runID string, index int) string {
	encoded, _ := json.Marshal([]any{"evaluation-case", runID, index})
	sum := sha256.Sum256(encoded)
	return "evalrun-" + hex.EncodeToString(sum[:])
}

func evaluationProviderMode(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "mock":
		return "mock"
	case "replay":
		return "replay"
	case "synthetic":
		return "synthetic"
	case "", "local":
		// A local provider can be real or a deterministic fixture; unknown
		// provenance must keep release gates closed.
		return "unknown"
	default:
		return "real"
	}
}

var _ evaluationproduct.AgentInvoker = evaluationAgentInvoker{}
