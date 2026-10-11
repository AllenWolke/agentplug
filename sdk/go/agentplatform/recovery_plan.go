package agentplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sync"
	"time"
)

// RecoveryCheckpointStep describes a fixed business boundary, not a client
// supplied permission. Validators inspect the complete checkpoint against the
// original signed business request. Completion must be persisted in State.
type RecoveryCheckpointStep struct {
	Namespace, Key, SchemaID string
	ValidateCheckpoint       func(ExecuteRequest, map[string]any) error
	IsComplete               func(map[string]any) bool
	AllowInitialStart        bool
	InitialInputHash         string
	// A future step may depend on genuinely completed preceding evidence.
	// Keys in priorValues are namespace + "/" + key; no pending value is exposed.
	InitialInputHashSelector func(ExecuteRequest, map[string]map[string]any) (string, error)
}

type RecoveryPlan struct {
	Steps []RecoveryCheckpointStep
	// AllowGroupResume is retained for source compatibility but does not by
	// itself authorize a coordination checkpoint. Use AllowedAgentGroupKey.
	AllowGroupResume bool
	// AllowedAgentGroupKey binds this plan to exactly one coordination State
	// key. The normal recovery plan still loads and validates that checkpoint.
	AllowedAgentGroupKey string
}

// Snapshots have already passed stop-provenance, current-head and expiry
// validation before the selector is called. Auxiliary Skill/Context snapshots
// remain valid inputs; they cannot replace a fixed workflow step.
type RecoveryCheckpointSnapshot struct {
	Reference map[string]any
	Response  map[string]any
}

type RecoveryCheckpointSelector func(ExecuteRequest, []RecoveryCheckpointSnapshot, map[string]any) (RecoveryPlan, error)

type recoveryPlanContextKey struct{}
type runtimeRecoveryPlanBinding struct {
	mu                sync.Mutex
	request           ExecuteRequest
	steps             []RecoveryCheckpointStep
	originallyMissing []bool
	next              int
	completedValues   map[string]map[string]any
	agentGroupKey     string
	agentGroupHead    *runtimeRecoveryCheckpoint
}

func expectedRecoveryStateKey(scope ScopeKey, namespace, key string) (string, bool) {
	raw, err := json.Marshal([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID,
		scope.AgentInstanceID, scope.PrincipalType, scope.PrincipalID, scope.InstallationID,
		scope.AgentVersionID, scope.SessionID, scope.RunID})
	if err != nil {
		return "", false
	}
	prefix := sha256.Sum256(raw)
	raw, err = json.Marshal([]string{hex.EncodeToString(prefix[:]), namespace, key})
	if err != nil {
		return "", false
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), true
}

func recoveryPlanCheckpoint(request ExecuteRequest, step RecoveryCheckpointStep, loaded map[string]any) (map[string]any, bool, error) {
	key, ok := expectedRecoveryStateKey(request.Scope, step.Namespace, step.Key)
	cp, present := loaded["checkpoint"]
	if !ok || loaded["state_key"] != key || !present {
		return nil, false, ErrInvalidTransition
	}
	if cp == nil {
		return nil, false, nil
	}
	header, ok := cp.(map[string]any)
	if !ok || header["schema_id"] != step.SchemaID {
		return nil, false, ErrInvalidTransition
	}
	revision, revisionOK := handoffUint64(header["revision"])
	executionRevision, executionOK := handoffUint64(header["execution_revision"])
	hash, hashOK := header["content_hash"].(string)
	expires, expiryOK := header["expires_at"].(string)
	expiresAt, err := time.Parse(time.RFC3339Nano, expires)
	value, valueOK := header["value"].(map[string]any)
	if !revisionOK || revision == 0 || revision > 64 || !executionOK || executionRevision == 0 ||
		!hashOK || !validHandoffDigest(hash) || !expiryOK || err != nil || !expiresAt.After(time.Now()) || !valueOK ||
		step.ValidateCheckpoint(request, header) != nil {
		return nil, false, ErrInvalidTransition
	}
	return value, true, nil
}

func (s *ExecutionServer) bindRuntimeRecoveryPlan(ctx context.Context, client *CapabilityClient, request ExecuteRequest,
	snapshots []RecoveryCheckpointSnapshot, group map[string]any, hasGroup bool) (*runtimeRecoveryPlanBinding, error) {
	if s.cfg.RecoveryCheckpointSelector == nil {
		return nil, ErrInvalidTransition
	}
	plan, err := s.cfg.RecoveryCheckpointSelector(request, snapshots, group)
	if err != nil || len(plan.Steps) == 0 || len(plan.Steps) > 16 || hasGroup && plan.AllowedAgentGroupKey == "" {
		return nil, ErrInvalidTransition
	}
	binding := &runtimeRecoveryPlanBinding{request: request, steps: append([]RecoveryCheckpointStep(nil), plan.Steps...),
		originallyMissing: make([]bool, len(plan.Steps)), completedValues: make(map[string]map[string]any)}
	original := make(map[string]RecoveryCheckpointSnapshot, len(snapshots))
	for _, snapshot := range snapshots {
		key, ok := snapshot.Reference["state_key"].(string)
		if !ok || original[key].Reference != nil {
			return nil, ErrInvalidTransition
		}
		original[key] = snapshot
	}
	if plan.AllowedAgentGroupKey != "" {
		if !agentGroupStateKey.MatchString(plan.AllowedAgentGroupKey) {
			return nil, ErrInvalidTransition
		}
		stateKey, ok := expectedRecoveryStateKey(request.Scope, "coordination", plan.AllowedAgentGroupKey)
		if !ok {
			return nil, ErrInvalidTransition
		}
		if snapshot, found := original[stateKey]; found {
			raw, err := json.Marshal(snapshot.Reference)
			var reference runtimeRecoveryCheckpoint
			if err != nil || json.Unmarshal(raw, &reference) != nil || reference.StateKey != stateKey ||
				reference.SchemaID != AgentGroupStateSchema || !validRecoveryCheckpointResponse(snapshot.Response, reference, s.now()) ||
				!validAgentGroupRecoveryCheckpoint(request, plan.AllowedAgentGroupKey, snapshot.Response) {
				return nil, ErrInvalidTransition
			}
			if group != nil && !sameRecoveryJSONValue(group, snapshot.Response) {
				return nil, ErrInvalidTransition
			}
			binding.agentGroupHead = &reference
		} else if group != nil {
			return nil, ErrInvalidTransition
		}
		binding.agentGroupKey = plan.AllowedAgentGroupKey
	} else if group != nil {
		return nil, ErrInvalidTransition
	}
	seen := make(map[string]bool)
	blocked := false
	for i, step := range binding.steps {
		if step.Namespace == "" || step.Key == "" || step.SchemaID == "" || step.ValidateCheckpoint == nil || step.IsComplete == nil ||
			step.AllowInitialStart && step.InitialInputHashSelector == nil && !validHandoffDigest(step.InitialInputHash) {
			return nil, ErrInvalidTransition
		}
		stateKey, _ := expectedRecoveryStateKey(request.Scope, step.Namespace, step.Key)
		if step.Namespace == "coordination" && step.Key == plan.AllowedAgentGroupKey &&
			step.SchemaID != AgentGroupStateSchema {
			return nil, ErrInvalidTransition
		}
		if seen[stateKey] {
			return nil, ErrInvalidTransition
		}
		seen[stateKey] = true
		loaded, err := client.LoadCheckpoint(ctx, step.Namespace, step.Key, step.SchemaID, 0)
		if err != nil {
			return nil, err
		}
		value, exists, err := recoveryPlanCheckpoint(request, step, loaded)
		if err != nil {
			return nil, err
		}
		snapshot, recorded := original[stateKey]
		if exists {
			if !recorded || blocked {
				return nil, ErrInvalidTransition
			}
			raw, err := json.Marshal(snapshot.Reference)
			var expected runtimeRecoveryCheckpoint
			if err != nil || json.Unmarshal(raw, &expected) != nil || !validRecoveryCheckpointResponse(loaded, expected, s.now()) {
				return nil, ErrInvalidTransition
			}
			if step.IsComplete(value) {
				binding.next = i + 1
				binding.completedValues[step.Namespace+"/"+step.Key] = value
			} else {
				blocked = true
			}
		} else {
			if recorded || !blocked && !step.AllowInitialStart {
				return nil, ErrInvalidTransition
			}
			binding.originallyMissing[i] = true
			blocked = true
		}
	}
	if binding.agentGroupKey != "" {
		stateKey, _ := expectedRecoveryStateKey(request.Scope, "coordination", binding.agentGroupKey)
		if !seen[stateKey] {
			return nil, ErrInvalidTransition
		}
	}
	if ctx.Err() != nil || client.ValidateCurrentExecution(ctx) != nil {
		return nil, ErrInvalidTransition
	}
	return binding, nil
}

func validAgentGroupRecoveryCheckpoint(request ExecuteRequest, groupKey string, response map[string]any) bool {
	expectedStateKey, ok := expectedRecoveryStateKey(request.Scope, "coordination", groupKey)
	stateKey, stateKeyOK := response["state_key"].(string)
	header, headerOK := response["checkpoint"].(map[string]any)
	if !ok || !stateKeyOK || stateKey != expectedStateKey || !headerOK || header["schema_id"] != AgentGroupStateSchema {
		return false
	}
	value, valueOK := header["value"].(map[string]any)
	if !valueOK || len(value) != 11 || value["version"] != "agent-group/v1" || value["parent_run_id"] != request.Scope.RunID ||
		value["group_key"] != groupKey {
		return false
	}
	fingerprint, fingerprintOK := value["input_fingerprint"].(string)
	operationKey, operationOK := value["operation_key"].(string)
	inputHash, inputHashOK := value["input_hash"].(string)
	phase, phaseOK := value["phase"].(string)
	if !fingerprintOK || !validHandoffDigest(fingerprint) || fingerprint != businessFingerprintForRequest(request) ||
		!operationOK || !harnessSkillIdentifier(operationKey) || !inputHashOK || !validHandoffDigest(inputHash) || !phaseOK {
		return false
	}
	switch phase {
	case "route", "prepare", "admitting", "gather":
	default:
		return false
	}
	return true
}

func businessFingerprintForRequest(request ExecuteRequest) string {
	fingerprint, err := executionBusinessHash(request)
	if err != nil {
		return ""
	}
	return fingerprint
}

func sameRecoveryJSONValue(left, right any) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && reflect.DeepEqual(leftRaw, rightRaw)
}

func capabilityScopeFromContext(ctx context.Context) (ScopeKey, bool) {
	client, ok := CapabilityFromContext(ctx)
	if !ok || client == nil {
		return ScopeKey{}, false
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	value := func(key string) string {
		result, _ := client.context[key].(string)
		return result
	}
	scope := ScopeKey{
		TenantID: value("tenant_id"), DepartmentID: value("department_id"), ApplicationID: value("application_id"),
		AgentID: value("agent_id"), AgentInstanceID: value("agent_instance_id"), PrincipalType: value("principal_type"),
		PrincipalID: value("actor_id"), InstallationID: value("installation_id"), AgentVersionID: value("agent_version_id"),
		SessionID: value("session_id"), RunID: value("task_id"),
	}
	if scope.TenantID == "" || scope.DepartmentID == "" || scope.ApplicationID == "" || scope.AgentID == "" ||
		scope.AgentInstanceID == "" || scope.PrincipalType == "" || scope.PrincipalID == "" || scope.InstallationID == "" ||
		scope.AgentVersionID == "" || scope.SessionID == "" || scope.RunID == "" {
		return ScopeKey{}, false
	}
	return scope, true
}

func validateRuntimeRecoveryAgentGroupCheckpoint(ctx context.Context, key string, loaded map[string]any) error {
	binding, ok := ctx.Value(recoveryPlanContextKey{}).(*runtimeRecoveryPlanBinding)
	if !ok {
		return nil
	}
	binding.mu.Lock()
	defer binding.mu.Unlock()
	if binding.agentGroupKey != key || key == "" {
		return ErrInvalidTransition
	}
	if binding.agentGroupHead == nil {
		if loaded["checkpoint"] != nil {
			return ErrInvalidTransition
		}
		return nil
	}
	if !agentGroupCheckpointMatches(loaded, groupReferenceFromRuntime(*binding.agentGroupHead)) {
		return ErrInvalidTransition
	}
	return nil
}

func advanceRuntimeRecoveryAgentGroupCheckpoint(ctx context.Context, key string, expectedRevision uint64, state map[string]any, receipt map[string]any) error {
	binding, ok := ctx.Value(recoveryPlanContextKey{}).(*runtimeRecoveryPlanBinding)
	var scope ScopeKey
	if ok {
		scope = binding.request.Scope
	} else {
		var scopeOK bool
		scope, scopeOK = capabilityScopeFromContext(ctx)
		if !scopeOK {
			return ErrInvalidTransition
		}
	}
	stateKey, keyOK := expectedRecoveryStateKey(scope, "coordination", key)
	actualStateKey, stateKeyOK := receipt["state_key"].(string)
	header, headerOK := receipt["checkpoint"].(map[string]any)
	if !keyOK || !stateKeyOK || actualStateKey != stateKey || !headerOK || len(header) != 6 ||
		header["schema_id"] != AgentGroupStateSchema || !sameRecoveryJSONValue(header["value"], state) {
		return ErrInvalidTransition
	}
	revision, revisionOK := handoffUint64(header["revision"])
	executionRevision, executionOK := handoffUint64(header["execution_revision"])
	contentHash, hashOK := header["content_hash"].(string)
	expiresRaw, expiryOK := header["expires_at"].(string)
	expiresAt, expiryErr := time.Parse(time.RFC3339Nano, expiresRaw)
	claims, claimsOK := ctx.Value(verifiedExecutionKey{}).(Claims)
	if !revisionOK || revision != expectedRevision+1 || !executionOK || executionRevision == 0 || !claimsOK || executionRevision != claims.ExecutionRevision ||
		!hashOK || !validHandoffDigest(contentHash) || !expiryOK || expiryErr != nil || !expiresAt.After(time.Now()) {
		return ErrInvalidTransition
	}
	next := &runtimeRecoveryCheckpoint{StateKey: stateKey, Revision: revision, SchemaID: AgentGroupStateSchema,
		ContentHash: contentHash, ExecutionRevision: executionRevision, ExpiresAt: expiresAt}
	if !ok {
		return nil
	}
	binding.mu.Lock()
	defer binding.mu.Unlock()
	if binding.agentGroupKey != key {
		return ErrInvalidTransition
	}
	if binding.agentGroupHead == nil {
		if expectedRevision != 0 {
			return ErrInvalidTransition
		}
	} else if binding.agentGroupHead.StateKey != stateKey || binding.agentGroupHead.Revision != expectedRevision ||
		binding.agentGroupHead.SchemaID != AgentGroupStateSchema {
		return ErrInvalidTransition
	}
	binding.agentGroupHead = next
	return nil
}

// AuthorizeRuntimeRecoveryStart binds an explicitly unstarted step to the
// exact input the workflow will execute, before any model or tool dispatch.
func AuthorizeRuntimeRecoveryStart(ctx context.Context, namespace, key, schema, inputHash string) error {
	binding, ok := ctx.Value(recoveryPlanContextKey{}).(*runtimeRecoveryPlanBinding)
	if !ok {
		return nil
	}
	binding.mu.Lock()
	defer binding.mu.Unlock()
	if binding.next >= len(binding.steps) {
		return ErrInvalidTransition
	}
	step := binding.steps[binding.next]
	if step.Namespace != namespace || step.Key != key || step.SchemaID != schema || !step.AllowInitialStart ||
		!binding.originallyMissing[binding.next] || !validHandoffDigest(inputHash) {
		return ErrInvalidTransition
	}
	expected := step.InitialInputHash
	if step.InitialInputHashSelector != nil {
		var err error
		expected, err = step.InitialInputHashSelector(binding.request, binding.completedValues)
		if err != nil {
			return ErrInvalidTransition
		}
	}
	if !validHandoffDigest(expected) || expected != inputHash {
		return ErrInvalidTransition
	}
	return nil
}

// ValidateRuntimeRecoveryCheckpoint guards a workflow's loaded state. Normal
// invocation and human approval do not carry this private recovery binding.
func ValidateRuntimeRecoveryCheckpoint(ctx context.Context, namespace, key, schema string, loaded map[string]any) error {
	binding, ok := ctx.Value(recoveryPlanContextKey{}).(*runtimeRecoveryPlanBinding)
	if !ok {
		return nil
	}
	binding.mu.Lock()
	defer binding.mu.Unlock()
	for i, step := range binding.steps {
		if step.Namespace != namespace || step.Key != key || step.SchemaID != schema {
			continue
		}
		value, exists, err := recoveryPlanCheckpoint(binding.request, step, loaded)
		if err != nil || i > binding.next {
			return ErrInvalidTransition
		}
		if !exists && (i != binding.next || !binding.originallyMissing[i] || !step.AllowInitialStart) {
			return ErrInvalidTransition
		}
		if exists && i < binding.next && !step.IsComplete(value) {
			return ErrInvalidTransition
		}
		return nil
	}
	return ErrInvalidTransition
}

// CompleteRuntimeRecoveryStep reloads the real current State record. Returning
// a business result or supplying a map with phase=done cannot advance a plan.
func (c *CapabilityClient) CompleteRuntimeRecoveryStep(ctx context.Context, namespace, key, schema string) error {
	binding, ok := ctx.Value(recoveryPlanContextKey{}).(*runtimeRecoveryPlanBinding)
	if !ok {
		return nil
	}
	loaded, err := c.LoadCheckpoint(ctx, namespace, key, schema, 0)
	if err != nil {
		return err
	}
	binding.mu.Lock()
	defer binding.mu.Unlock()
	for i, step := range binding.steps {
		if step.Namespace != namespace || step.Key != key || step.SchemaID != schema {
			continue
		}
		value, exists, err := recoveryPlanCheckpoint(binding.request, step, loaded)
		if err != nil || !exists || i > binding.next || !step.IsComplete(value) {
			return ErrInvalidTransition
		}
		if i == binding.next {
			binding.completedValues[step.Namespace+"/"+step.Key] = value
			binding.next++
		}
		return nil
	}
	return ErrInvalidTransition
}
