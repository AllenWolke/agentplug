package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"

	"github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

type operationsGroupMarker struct {
	Version          string `json:"version"`
	Phase            string `json:"phase"`
	GroupKey         string `json:"group_key"`
	InputFingerprint string `json:"input_fingerprint"`
	PlanHash         string `json:"plan_hash"`
}

func operationsGroupInput(input operationsInput) map[string]any {
	// Keep the child request within the target's immutable v2 schema. User text
	// can describe the question, but cannot select a route or enable child tools.
	question := "Find relevant published documentation for this service issue. Service: " + input.Service +
		". Symptom: " + input.Symptom + ". Return concise evidence with citations; do not execute actions or claim repairs."
	return map[string]any{
		"question": question, "top_k": 3, "cache_mode": "use", "workflow_mode": "direct",
		"collaborate": false, "notify_me": false, "sandbox_check": false,
	}
}

func operationsGroupPlanHash(input operationsInput) (string, error) {
	return agentplatform.AgentGroupPlanInputHash(operationsGroupOperation, operationsGroupTaskType,
		[]map[string]any{operationsGroupInput(input)})
}

func operationsGroupMarkerHash(input operationsInput, planHash string) string {
	encoded, err := json.Marshal([]any{operationsGroupKey, operationsGroupOperation, operationsGroupTaskType, input.InputHash, planHash})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func operationsGroupContinuationRequest(request agentplatform.ExecuteRequest) bool {
	if request.Operation != "resume" || request.ResumeInput == nil {
		return false
	}
	switch request.ResumeInput["version"] {
	case "agent-group-resume/v1":
		return true
	case "runtime-recovery/v1":
		_, exists := request.ResumeInput["group_resume"]
		return exists
	default:
		return false
	}
}

func decodeOperationsGroupMarker(header map[string]any, input operationsInput, planHash string) (operationsGroupMarker, uint64, error) {
	var marker operationsGroupMarker
	invalid := func() (operationsGroupMarker, uint64, error) {
		return operationsGroupMarker{}, 0, evidenceInvalid()
	}
	if header == nil || header["schema_id"] != operationsGroupSchema {
		return invalid()
	}
	revision, ok := stateRevision(header["revision"])
	value, valueOK := header["value"].(map[string]any)
	if !ok || revision < 1 || revision > 64 || !valueOK || len(value) != 5 {
		return invalid()
	}
	for key := range value {
		if key != "version" && key != "phase" && key != "group_key" && key != "input_fingerprint" && key != "plan_hash" {
			return invalid()
		}
	}
	if err := decodeStrictObject(value, &marker); err != nil || marker.Version != "operations-collaboration/v1" ||
		(marker.Phase != "group_planned" && marker.Phase != "group_gathered") || marker.GroupKey != operationsGroupKey ||
		marker.InputFingerprint != input.InputHash || marker.PlanHash != planHash {
		return invalid()
	}
	return marker, revision, nil
}

func stateRevision(value any) (uint64, bool) {
	raw, err := json.Marshal(value)
	if err != nil {
		return 0, false
	}
	var number json.Number
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if decoder.Decode(&number) != nil || decoder.Decode(new(any)) != io.EOF {
		return 0, false
	}
	parsed, err := number.Int64()
	return uint64(parsed), err == nil && parsed > 0
}

func decodeStrictObject(source map[string]any, destination any) error {
	raw, err := json.Marshal(source)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil || decoder.Decode(new(any)) != io.EOF {
		return evidenceInvalid()
	}
	return nil
}

func validateOperationsGroupState(request agentplatform.ExecuteRequest, input operationsInput, planHash string, header map[string]any) (string, error) {
	if header == nil || header["schema_id"] != agentplatform.AgentGroupStateSchema {
		return "", evidenceInvalid()
	}
	value, ok := header["value"].(map[string]any)
	if !ok || len(value) != 11 {
		return "", evidenceInvalid()
	}
	for key := range value {
		switch key {
		case "version", "parent_run_id", "group_key", "operation_key", "input_fingerprint", "input_hash", "phase", "ordinal", "targets", "bindings", "child_keys":
		default:
			return "", evidenceInvalid()
		}
	}
	var state struct {
		Version          string `json:"version"`
		ParentRunID      string `json:"parent_run_id"`
		GroupKey         string `json:"group_key"`
		OperationKey     string `json:"operation_key"`
		InputFingerprint string `json:"input_fingerprint"`
		InputHash        string `json:"input_hash"`
		Phase            string `json:"phase"`
		Ordinal          int    `json:"ordinal"`
		Targets          []struct {
			InputSchema  string `json:"input_schema"`
			OutputSchema string `json:"output_schema"`
		} `json:"targets"`
		Bindings []struct {
			ChildKey         string `json:"child_key"`
			InputFingerprint string `json:"input_fingerprint"`
			OutputSchema     string `json:"output_schema"`
		} `json:"bindings"`
		ChildKeys []string `json:"child_keys"`
	}
	if decodeStrictObject(value, &state) != nil || state.Version != "agent-group/v1" || state.ParentRunID != request.Scope.RunID ||
		state.GroupKey != operationsGroupKey || state.OperationKey != operationsGroupOperation ||
		!validOperationsDigest(state.InputFingerprint) || !validOperationsDigest(state.InputHash) || state.InputHash != planHash {
		return "", evidenceInvalid()
	}
	switch state.Phase {
	case "route":
		if state.Ordinal != 0 || len(state.Targets) != 0 || len(state.Bindings) != 0 || len(state.ChildKeys) != 0 {
			return "", evidenceInvalid()
		}
	case "prepare":
		if state.Ordinal != 0 || len(state.Targets) != 1 || len(state.Bindings) != 0 || len(state.ChildKeys) != 0 {
			return "", evidenceInvalid()
		}
	case "admitting":
		if state.Ordinal != 0 || len(state.Targets) != 1 || len(state.Bindings) != 1 || len(state.ChildKeys) != 1 {
			return "", evidenceInvalid()
		}
	case "gather":
		if state.Ordinal != 1 || len(state.Targets) != 1 || len(state.Bindings) != 1 || len(state.ChildKeys) != 1 {
			return "", evidenceInvalid()
		}
	default:
		return "", evidenceInvalid()
	}
	if len(state.Targets) > 0 && (state.Targets[0].InputSchema != operationsChildInputSchema(input) ||
		state.Targets[0].OutputSchema != operationsChildOutputSchema(input)) {
		return "", evidenceInvalid()
	}
	for index, binding := range state.Bindings {
		if index >= len(state.ChildKeys) || binding.ChildKey != state.ChildKeys[index] ||
			!validOperationsDigest(binding.ChildKey) || !validOperationsDigest(binding.InputFingerprint) ||
			binding.OutputSchema != operationsChildOutputSchema(input) {
			return "", evidenceInvalid()
		}
	}
	return state.Phase, nil
}

func validOperationsDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == hex.EncodeToString(decoded)
}

func operationsGroupSupport(request agentplatform.ExecuteRequest, input operationsInput, result map[string]any) (map[string]any, error) {
	group, ok := result["group"].(map[string]any)
	if !ok || group["version"] != "agent-group-result/v1" || group["parent_run_id"] != request.Scope.RunID ||
		group["operation_key"] != operationsGroupOperation || group["status"] != "completed" ||
		group["terminal"] != true || group["outputs_complete"] != true || group["instruction_trust"] != "untrusted_data" {
		return nil, evidenceInvalid()
	}
	children, ok := group["children"].([]any)
	if !ok || len(children) != 1 {
		return nil, evidenceInvalid()
	}
	child, ok := children[0].(map[string]any)
	if !ok || child["status"] != "completed" || child["output_schema"] != operationsChildOutputSchema(input) ||
		child["instruction_trust"] != "untrusted_data" || child["output_omitted"] != false {
		return nil, evidenceInvalid()
	}
	childKey, keyOK := child["child_key"].(string)
	childInputHash, fingerprintOK := child["input_fingerprint"].(string)
	outputDigest, digestOK := child["output_digest"].(string)
	output, outputOK := child["output"].(map[string]any)
	answer, answerOK := output["answer"].(string)
	question, questionOK := output["question"].(string)
	if !keyOK || !validOperationsDigest(childKey) || !fingerprintOK || !validOperationsDigest(childInputHash) ||
		!digestOK || !validOperationsDigest(outputDigest) || !outputOK || output["schema"] != operationsChildOutputSchema(input) ||
		!answerOK || strings.TrimSpace(answer) == "" || len(answer) > 16384 || !questionOK || question != operationsGroupInput(input)["question"] {
		return nil, evidenceInvalid()
	}
	references, referencesOK := output["references"].([]any)
	citationIDs, citationOK := output["citation_ids"].([]any)
	if !referencesOK || len(references) == 0 || len(references) > 32 || !citationOK || len(citationIDs) == 0 || len(citationIDs) > 128 {
		return nil, evidenceInvalid()
	}
	for _, citation := range citationIDs {
		if _, ok := citation.(string); !ok {
			return nil, evidenceInvalid()
		}
	}
	support := map[string]any{
		"instruction_trust": "untrusted_data", "task_type": operationsGroupTaskType,
		"children": []map[string]any{{
			"child_key": childKey, "input_fingerprint": childInputHash, "output_digest": outputDigest,
			"output_schema": child["output_schema"], "question": question, "answer": answer,
			"references": references, "citation_ids": citationIDs,
		}},
	}
	encoded, err := json.Marshal(support)
	if err != nil || len(encoded) > 65536 {
		return nil, evidenceInvalid()
	}
	return support, nil
}

func runOperationsGroup(ctx context.Context, request agentplatform.ExecuteRequest, input operationsInput,
	client capabilities, call func(string, string, map[string]any) (map[string]any, error)) (map[string]any, error) {
	runner, ok := client.(interface {
		RunAgentGroup(context.Context, []map[string]any, agentplatform.AgentGroupOptions) (map[string]any, error)
	})
	if !ok {
		return nil, &agentplatform.AppError{Code: "CAPABILITY_CONFIG_INVALID", Message: "public AgentGroup client is required"}
	}
	planHash, err := operationsGroupPlanHash(input)
	if err != nil {
		return nil, err
	}
	resumeFirst := operationsGroupContinuationRequest(request)
	var marker operationsGroupMarker
	var markerRevision uint64
	if !resumeFirst {
		loaded, err := call("collaboration.load", "/internal/state/checkpoint", map[string]any{
			"operation": "load", "namespace": operationsGroupNamespace, "key": operationsGroupKey, "schema_id": operationsGroupSchema,
		})
		if err != nil {
			return nil, err
		}
		if err := agentplatform.ValidateRuntimeRecoveryCheckpoint(ctx, operationsGroupNamespace, operationsGroupKey, operationsGroupSchema, loaded); err != nil {
			return nil, evidenceInvalid()
		}
		if checkpoint, exists := loaded["checkpoint"]; exists && checkpoint != nil {
			header, valid := checkpoint.(map[string]any)
			if !valid {
				return nil, evidenceInvalid()
			}
			marker, markerRevision, err = decodeOperationsGroupMarker(header, input, planHash)
			if err != nil {
				return nil, err
			}
		} else {
			marker = operationsGroupMarker{Version: "operations-collaboration/v1", Phase: "group_planned",
				GroupKey: operationsGroupKey, InputFingerprint: input.InputHash, PlanHash: planHash}
			markerRevision = 0
			if err := saveOperationsGroupMarker(ctx, input, marker, markerRevision, client, call); err != nil {
				return nil, err
			}
			markerRevision = 1
		}
	}
	if ctx.Err() != nil {
		return nil, &agentplatform.AppError{Code: "CANCELLED", Message: "diagnosis cancelled"}
	}
	result, err := runner.RunAgentGroup(ctx, []map[string]any{operationsGroupInput(input)}, agentplatform.AgentGroupOptions{
		Key: operationsGroupKey, OperationKey: operationsGroupOperation, TaskType: operationsGroupTaskType,
	})
	if err != nil {
		return nil, err
	}
	support, err := operationsGroupSupport(request, input, result)
	if err != nil {
		return nil, err
	}
	if resumeFirst {
		loaded, err := call("collaboration.load", "/internal/state/checkpoint", map[string]any{
			"operation": "load", "namespace": operationsGroupNamespace, "key": operationsGroupKey, "schema_id": operationsGroupSchema,
		})
		if err != nil {
			return nil, err
		}
		if err := agentplatform.ValidateRuntimeRecoveryCheckpoint(ctx, operationsGroupNamespace, operationsGroupKey, operationsGroupSchema, loaded); err != nil {
			return nil, evidenceInvalid()
		}
		header, valid := loaded["checkpoint"].(map[string]any)
		if !valid {
			return nil, evidenceInvalid()
		}
		marker, markerRevision, err = decodeOperationsGroupMarker(header, input, planHash)
		if err != nil {
			return nil, err
		}
	}
	if marker.Phase == "group_planned" {
		marker.Phase = "group_gathered"
		if err := saveOperationsGroupMarker(ctx, input, marker, markerRevision, client, call); err != nil {
			return nil, err
		}
	}
	if err := verifyOperationsGroupMarker(ctx, input, planHash, client, call); err != nil {
		return nil, err
	}
	return support, nil
}

func saveOperationsGroupMarker(ctx context.Context, input operationsInput, marker operationsGroupMarker, expectedRevision uint64,
	client capabilities, call func(string, string, map[string]any) (map[string]any, error)) error {
	planHash, err := operationsGroupPlanHash(input)
	if err != nil || marker.PlanHash != planHash || marker.InputFingerprint != input.InputHash || marker.GroupKey != operationsGroupKey {
		return evidenceInvalid()
	}
	if expectedRevision == 0 {
		inputHash := operationsGroupMarkerHash(input, planHash)
		if err := agentplatform.AuthorizeRuntimeRecoveryStart(ctx, operationsGroupNamespace, operationsGroupKey, operationsGroupSchema, inputHash); err != nil {
			return evidenceInvalid()
		}
	}
	value := map[string]any{"version": marker.Version, "phase": marker.Phase, "group_key": marker.GroupKey,
		"input_fingerprint": marker.InputFingerprint, "plan_hash": marker.PlanHash}
	idempotencyKey := "operations-group-planned-v1"
	if marker.Phase == "group_gathered" {
		idempotencyKey = "operations-group-gathered-v1"
	}
	if _, err := call("collaboration.save", "/internal/state/checkpoint", map[string]any{
		"operation": "save", "namespace": operationsGroupNamespace, "key": operationsGroupKey,
		"schema_id": operationsGroupSchema, "idempotency_key": idempotencyKey,
		"expected_revision": expectedRevision, "value": value,
	}); err != nil {
		return err
	}
	loaded, err := call("collaboration.verify", "/internal/state/checkpoint", map[string]any{
		"operation": "load", "namespace": operationsGroupNamespace, "key": operationsGroupKey, "schema_id": operationsGroupSchema,
	})
	if err != nil {
		return err
	}
	if err := agentplatform.ValidateRuntimeRecoveryCheckpoint(ctx, operationsGroupNamespace, operationsGroupKey, operationsGroupSchema, loaded); err != nil {
		return evidenceInvalid()
	}
	header, ok := loaded["checkpoint"].(map[string]any)
	actual, revision, err := decodeOperationsGroupMarker(header, input, planHash)
	if err != nil || !ok || actual != marker || revision != expectedRevision+1 {
		return evidenceInvalid()
	}
	recoveryClient, ok := agentplatform.CapabilityFromContext(ctx)
	if !ok {
		return &agentplatform.AppError{Code: "CAPABILITY_CONFIG_INVALID", Message: "verified platform client is required"}
	}
	return recoveryClient.CompleteRuntimeRecoveryStep(ctx, operationsGroupNamespace, operationsGroupKey, operationsGroupSchema)
}

func verifyOperationsGroupMarker(ctx context.Context, input operationsInput, planHash string, client capabilities,
	call func(string, string, map[string]any) (map[string]any, error)) error {
	loaded, err := call("collaboration.verify", "/internal/state/checkpoint", map[string]any{
		"operation": "load", "namespace": operationsGroupNamespace, "key": operationsGroupKey, "schema_id": operationsGroupSchema,
	})
	if err != nil {
		return err
	}
	if err := agentplatform.ValidateRuntimeRecoveryCheckpoint(ctx, operationsGroupNamespace, operationsGroupKey, operationsGroupSchema, loaded); err != nil {
		return evidenceInvalid()
	}
	header, ok := loaded["checkpoint"].(map[string]any)
	if !ok {
		return evidenceInvalid()
	}
	marker, _, err := decodeOperationsGroupMarker(header, input, planHash)
	if err != nil || marker.Phase != "group_gathered" {
		return evidenceInvalid()
	}
	return nil
}

func freshOperationsGroupSupport(ctx context.Context, request agentplatform.ExecuteRequest, input operationsInput,
	client capabilities, call func(string, string, map[string]any) (map[string]any, error), expected map[string]any) error {
	runner, ok := client.(interface {
		RunAgentGroup(context.Context, []map[string]any, agentplatform.AgentGroupOptions) (map[string]any, error)
	})
	if !ok {
		return &agentplatform.AppError{Code: "CAPABILITY_CONFIG_INVALID", Message: "public AgentGroup client is required"}
	}
	loaded, err := call("collaboration.recheck", "/internal/state/checkpoint", map[string]any{
		"operation": "load", "namespace": operationsGroupNamespace, "key": operationsGroupKey, "schema_id": operationsGroupSchema,
	})
	if err != nil {
		return err
	}
	if err := agentplatform.ValidateRuntimeRecoveryCheckpoint(ctx, operationsGroupNamespace, operationsGroupKey, operationsGroupSchema, loaded); err != nil {
		return evidenceInvalid()
	}
	result, err := runner.RunAgentGroup(ctx, []map[string]any{operationsGroupInput(input)}, agentplatform.AgentGroupOptions{
		Key: operationsGroupKey, OperationKey: operationsGroupOperation, TaskType: operationsGroupTaskType,
	})
	if err != nil {
		return err
	}
	actual, err := operationsGroupSupport(request, input, result)
	if err != nil || !sameOperationsJSON(actual, expected) {
		return evidenceInvalid()
	}
	planHash, err := operationsGroupPlanHash(input)
	if err != nil {
		return evidenceInvalid()
	}
	return verifyOperationsGroupMarker(ctx, input, planHash, client, call)
}

func sameOperationsJSON(left, right any) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftRaw) == string(rightRaw)
}

func operationsChildInputSchema(input operationsInput) string {
	if input.Legacy {
		return "schema://example-python-documents/input/v2"
	}
	return "schema://example-python-documents/input/v3"
}
func operationsChildOutputSchema(input operationsInput) string {
	if input.Legacy {
		return "schema://example-python-documents/output/v2"
	}
	return "schema://example-python-documents/output/v3"
}
