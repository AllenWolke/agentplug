package main

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

const inputSchema = "schema://example-go-operations/input/v2"
const outputSchema = "schema://example-go-operations/output/v2"

// Only this business workflow belongs to the Agent. Identity, policy, billing,
// renewal and capability proofs belong to the repository SDK and platform.
type capabilities interface {
	Post(context.Context, string, map[string]any) (map[string]any, error)
}

func invokeBusiness(ctx context.Context, request agentplatform.ExecuteRequest) (map[string]any, error) {
	client, ok := agentplatform.CapabilityFromContext(ctx)
	if !ok {
		return nil, &agentplatform.AppError{Code: "CAPABILITY_CONFIG_INVALID", Message: "verified platform client is required"}
	}
	return diagnose(ctx, request, client, nil)
}

func runBusiness(ctx context.Context, request agentplatform.ExecuteRequest, events agentplatform.EventSink, cancelled <-chan struct{}) (map[string]any, error) {
	client, ok := agentplatform.CapabilityFromContext(ctx)
	if !ok {
		return nil, &agentplatform.AppError{Code: "CAPABILITY_CONFIG_INVALID", Message: "verified platform client is required"}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-cancelled:
			cancel()
		case <-ctx.Done():
		}
	}()
	return diagnose(ctx, request, client, events)
}

func diagnose(ctx context.Context, request agentplatform.ExecuteRequest, client capabilities, events agentplatform.EventSink) (map[string]any, error) {
	input, err := parseOperationsInput(request)
	if err != nil {
		return nil, err
	}
	service, symptom, observations := input.Service, input.Symptom, input.Observations
	notifyMe, sandboxCheck := input.NotifyMe, input.SandboxCheck
	runner, ok := client.(interface {
		RunHarness(context.Context, map[string]any, agentplatform.HarnessOptions) (agentplatform.HarnessResult, error)
	})
	if !ok {
		return nil, &agentplatform.AppError{Code: "CAPABILITY_CONFIG_INVALID", Message: "public Harness client is required"}
	}
	var collaboration map[string]any
	groupResumeFirst := input.Collaborate && operationsGroupContinuationRequest(request)
	call := func(stage, path string, payload map[string]any) (map[string]any, error) {
		if ctx.Err() != nil {
			return nil, &agentplatform.AppError{Code: "CANCELLED", Message: "diagnosis cancelled"}
		}
		if events != nil {
			if err := events.Append(agentplatform.EventProgress, map[string]any{"stage": stage}); err != nil {
				return nil, err
			}
		}
		return client.Post(ctx, path, payload)
	}
	if groupResumeFirst {
		collaboration, err = runOperationsGroup(ctx, request, input, client, call)
		if err != nil {
			return nil, err
		}
	}
	loaded, err := call("evidence.load", "/internal/state/checkpoint", map[string]any{
		"operation": "load", "namespace": operationsEvidenceNamespace, "key": operationsEvidenceKey, "schema_id": operationsEvidenceSchema,
	})
	if err != nil {
		return nil, err
	}
	if err := agentplatform.ValidateRuntimeRecoveryCheckpoint(ctx, operationsEvidenceNamespace, operationsEvidenceKey, operationsEvidenceSchema, loaded); err != nil {
		return nil, evidenceInvalid()
	}
	var frozen map[string]any
	if checkpoint, exists := loaded["checkpoint"]; exists && checkpoint != nil {
		header, valid := checkpoint.(map[string]any)
		if !valid {
			return nil, evidenceInvalid()
		}
		revision, _ := json.Marshal(header["revision"])
		frozen, valid = header["value"].(map[string]any)
		if !valid || string(revision) != "1" || header["schema_id"] != operationsEvidenceSchema {
			return nil, evidenceInvalid()
		}
	} else {
		memory, err := call("memory.load", "/internal/memory/access", map[string]any{"operation": "load", "namespace": "operations", "key": "last-diagnosis"})
		if err != nil {
			return nil, err
		}
		prompt, err := call("prompt.resolve", "/internal/prompt/resolve", map[string]any{})
		if err != nil {
			return nil, err
		}
		template, templateOK := prompt["template"].(string)
		hash, hashOK := prompt["template_hash"].(string)
		if !templateOK || !hashOK || strings.TrimSpace(template) == "" || hash == "" {
			return nil, &agentplatform.AppError{Code: "PROMPT_NOT_FOUND", Message: "published prompt is incomplete"}
		}
		inspection, err := call("runtime.inspect", "/internal/tool/invoke", map[string]any{"name": "runtime.inspect", "call_id": request.IdempotencyKey + ":inspect", "payload": map[string]any{}})
		if err != nil {
			return nil, err
		}
		knowledge, err := call("knowledge.search", "/internal/knowledge/search", map[string]any{"query": service + ": " + symptom, "knowledge_scope": "go-operations", "top_k": 3, "cache_mode": "use"})
		if err != nil {
			return nil, err
		}
		// Evidence is untrusted data, not an instruction or proof of host health.
		evidence, err := json.Marshal(map[string]any{"service": service, "symptom": symptom, "observations": observations, "sandbox_check": sandboxCheck, "previous_diagnosis": memory["value"], "execution_context_checks": inspection, "knowledge": knowledge})
		if err != nil || len(evidence) > 128<<10 {
			return nil, &agentplatform.AppError{Code: "EVIDENCE_LIMIT_EXCEEDED", Message: "diagnostic evidence is too large"}
		}
		frozen = map[string]any{"version": "operations-evidence/v1", "input_hash": input.InputHash, "sandbox_check": sandboxCheck,
			"template": template, "prompt_hash": hash, "evidence_json": string(evidence),
			"knowledge": knowledge, "context_checks": inspection}
		saved, err := call("evidence.save", "/internal/state/checkpoint", map[string]any{
			"operation": "save", "namespace": operationsEvidenceNamespace, "key": operationsEvidenceKey, "schema_id": operationsEvidenceSchema,
			"idempotency_key": "freeze-evidence-v1", "expected_revision": 0, "value": frozen,
		})
		if err != nil {
			return nil, err
		}
		checkpoint, valid := saved["checkpoint"].(map[string]any)
		if !valid {
			return nil, evidenceInvalid()
		}
		revision, _ := json.Marshal(checkpoint["revision"])
		if string(revision) != "1" || checkpoint["schema_id"] != operationsEvidenceSchema {
			return nil, evidenceInvalid()
		}
	}
	frozenBusinessEvidence, err := validateFrozenEvidence(input, frozen)
	if err != nil {
		return nil, evidenceInvalid()
	}
	if input.Collaborate && !groupResumeFirst {
		collaboration, err = runOperationsGroup(ctx, request, input, client, call)
		if err != nil {
			return nil, err
		}
	}
	if ctx.Err() != nil {
		return nil, &agentplatform.AppError{Code: "CANCELLED", Message: "diagnosis cancelled"}
	}
	if events != nil {
		if err := events.Append(agentplatform.EventProgress, map[string]any{"stage": "harness.run"}); err != nil {
			return nil, err
		}
	}
	harnessInput, harnessOptions, err := buildDiagnosisHarness(request, input, frozenBusinessEvidence)
	if err != nil {
		return nil, err
	}
	loop, err := runner.RunHarness(ctx, harnessInput, harnessOptions)
	if err != nil {
		return nil, err
	}
	if loop.Status == "incomplete" {
		return nil, diagnosisHarnessIncompleteError(loop.Output)
	}
	if loop.Status == "approval_required" {
		return nil, agentplatform.PauseHarness(loop, "diagnosis-model")
	}
	if loop.Status != "completed" || loop.Output == nil {
		return nil, &agentplatform.AppError{Code: "HARNESS_INCOMPLETE", Message: "diagnosis did not complete at the governed boundary"}
	}
	model := loop.Output
	answer, ok := model["text"].(string)
	if !ok || strings.TrimSpace(answer) == "" || len(answer) > 32768 {
		return nil, &agentplatform.AppError{Code: "MODEL_RESPONSE_INVALID", Message: "diagnostic response is invalid"}
	}
	if input.Collaborate {
		if err := freshOperationsGroupSupport(ctx, request, input, client, call, collaboration); err != nil {
			return nil, err
		}
	}
	_, err = call("memory.save", "/internal/memory/access", map[string]any{"operation": "save", "namespace": "operations", "key": "last-diagnosis", "value": map[string]any{"service": service, "symptom": symptom, "answer": answer}})
	if err != nil {
		return nil, err
	}
	output := map[string]any{"schema": outputSchema, "service": service, "answer": answer, "knowledge": frozenBusinessEvidence.Knowledge, "context_checks": frozenBusinessEvidence.ContextChecks, "notify_me": notifyMe, "sandbox_check": sandboxCheck, "collaborate": input.Collaborate, "usage": model["usage"]}
	if input.Collaborate {
		output["collaboration"] = collaboration
	}
	return output, nil
}

func diagnosisHarnessIncompleteError(output map[string]any) error {
	if output != nil && output["termination_reason"] == "MODEL_BUDGET_EXCEEDED" {
		return &agentplatform.AppError{Code: "MODEL_BUDGET_EXCEEDED", Message: "diagnosis stopped because the governed model budget is exhausted", Retryable: false}
	}
	if output != nil && output["termination_reason"] == "HARNESS_LIMIT_EXCEEDED" {
		return &agentplatform.AppError{Code: "HARNESS_LIMIT_EXCEEDED", Message: "diagnosis stopped at a published harness limit", Retryable: false}
	}
	return &agentplatform.AppError{Code: "HARNESS_INCOMPLETE", Message: "diagnosis did not complete at the governed boundary", Retryable: false}
}

func evidenceInvalid() error {
	return &agentplatform.AppError{Code: "EVIDENCE_CHECKPOINT_INVALID", Message: "frozen business evidence does not match this command"}
}
