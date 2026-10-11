package agentplatform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"time"
)

const agentGroupResumeVersion = "agent-group-resume/v1"

// AgentGroupPause is an SDK control result raised only after RunAgentGroup has
// persisted its gather phase and freshly observed at least one nonterminal
// child. Its evidence is private so business code cannot manufacture a wait.
type AgentGroupPause struct{ data agentGroupPauseData }

type agentGroupPauseData struct {
	groupKey     string
	operationKey string
	checkpoint   AgentGroupCheckpointReference
	childKeys    []string
}

type agentGroupResumeBinding struct {
	groupKey         string
	operationKey     string
	inputFingerprint string
	checkpoint       AgentGroupCheckpointReference
	childKeys        []string
}

func newAgentGroupResumeBinding(handoff AgentGroupHandoff) *agentGroupResumeBinding {
	return &agentGroupResumeBinding{
		groupKey: handoff.GroupKey, operationKey: handoff.OperationKey,
		inputFingerprint: handoff.InputFingerprint, checkpoint: handoff.Checkpoint,
		childKeys: append([]string(nil), handoff.ChildKeys...),
	}
}

func (c *CapabilityClient) setAgentGroupResumeBinding(binding *agentGroupResumeBinding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if binding == nil {
		c.agentGroupResume = nil
		c.agentGroupResumeConsumed = false
		c.agentGroupGatherAllowed = false
		c.agentGroupGatherUsed = false
		return
	}
	copy := *binding
	copy.childKeys = append([]string(nil), binding.childKeys...)
	c.agentGroupResume = &copy
	c.agentGroupResumeConsumed = false
	c.agentGroupGatherAllowed = false
	c.agentGroupGatherUsed = false
}

func (c *CapabilityClient) currentAgentGroupResumeBinding() *agentGroupResumeBinding {
	c.mu.Lock()
	defer c.mu.Unlock()
	// A verified terminal Gather consumes this one-shot continuation. Later
	// disclosure still performs a normal, freshly authorized checkpoint/Gather
	// read rather than attempting to consume the same continuation again.
	if c.agentGroupResume == nil || c.agentGroupResumeConsumed {
		return nil
	}
	copy := *c.agentGroupResume
	copy.childKeys = append([]string(nil), c.agentGroupResume.childKeys...)
	return &copy
}

func (c *CapabilityClient) consumeAgentGroupResume(binding *agentGroupResumeBinding) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.agentGroupResume == nil || !c.agentGroupGatherUsed ||
		c.agentGroupResume.groupKey != binding.groupKey || c.agentGroupResume.operationKey != binding.operationKey ||
		c.agentGroupResume.inputFingerprint != binding.inputFingerprint ||
		!reflect.DeepEqual(c.agentGroupResume.checkpoint, binding.checkpoint) ||
		!reflect.DeepEqual(c.agentGroupResume.childKeys, binding.childKeys) {
		return false
	}
	c.agentGroupResumeConsumed = true
	return true
}

func (c *CapabilityClient) allowAgentGroupGather(binding *agentGroupResumeBinding) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.agentGroupResume == nil || binding == nil || c.agentGroupResumeConsumed || c.agentGroupGatherUsed ||
		c.agentGroupResume.groupKey != binding.groupKey || c.agentGroupResume.operationKey != binding.operationKey ||
		c.agentGroupResume.inputFingerprint != binding.inputFingerprint ||
		!reflect.DeepEqual(c.agentGroupResume.checkpoint, binding.checkpoint) ||
		!reflect.DeepEqual(c.agentGroupResume.childKeys, binding.childKeys) {
		return false
	}
	c.agentGroupGatherAllowed = true
	return true
}

func (c *CapabilityClient) hasConsumedAgentGroupResume() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.agentGroupResume == nil || c.agentGroupResumeConsumed
}

func (c *CapabilityClient) hasUsedAgentGroupGather() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.agentGroupResume == nil || c.agentGroupGatherUsed
}

// agentGroupResumeAllowsPostLocked fences a resumed handler to reading only
// the bound coordination checkpoint until RunAgentGroup has verified and
// consumed that gather continuation. The caller holds c.mu.
func (c *CapabilityClient) agentGroupResumeAllowsPostLocked(path string, payload map[string]any) bool {
	if c.agentGroupResume == nil || c.agentGroupResumeConsumed {
		return true
	}
	if c.agentGroupGatherUsed || payload == nil {
		return false
	}
	// The bounded runtime policy read is idempotent and has no execution side
	// effects. It may run before the original gather, but must not consume the
	// AgentGroup continuation or authorize any other capability request.
	if path == harnessPolicyPath && len(payload) == 0 {
		return true
	}
	if path == "/internal/agent/gather" && c.agentGroupGatherAllowed && len(payload) == 1 &&
		payload["operation_key"] == c.agentGroupResume.operationKey {
		c.agentGroupGatherAllowed = false
		c.agentGroupGatherUsed = true
		return true
	}
	if path != "/internal/state/checkpoint" || len(payload) != 5 || payload["operation"] != "load" ||
		payload["namespace"] != "coordination" || payload["key"] != c.agentGroupResume.groupKey ||
		payload["schema_id"] != AgentGroupStateSchema {
		return false
	}
	revision, ok := handoffUint64(payload["revision"])
	return ok && revision == 0
}

func activeAgentGroupResumeConsumed(ctx context.Context, active *activeExecution) bool {
	if active == nil || active.agentGroupResume == nil {
		return true
	}
	client, ok := CapabilityFromContext(ctx)
	return ok && client.hasConsumedAgentGroupResume()
}

func activeAgentGroupGatherUsed(ctx context.Context, active *activeExecution) bool {
	if active == nil || active.agentGroupResume == nil {
		return true
	}
	client, ok := CapabilityFromContext(ctx)
	return ok && client.hasUsedAgentGroupGather()
}

func (p *AgentGroupPause) Error() string { return "AgentGroup has nonterminal children" }

func newAgentGroupPause(groupKey, operationKey string, checkpoint AgentGroupCheckpointReference, childKeys []string) *AgentGroupPause {
	return &AgentGroupPause{data: agentGroupPauseData{
		groupKey: groupKey, operationKey: operationKey, checkpoint: checkpoint,
		childKeys: append([]string(nil), childKeys...),
	}}
}

type agentGroupResumeCommand struct {
	Version         string                      `json:"version"`
	OriginOperation string                      `json:"origin_operation"`
	WaitingRevision uint64                      `json:"waiting_revision"`
	Handoff         AgentGroupHandoff           `json:"handoff"`
	Checkpoints     []runtimeRecoveryCheckpoint `json:"checkpoints"`
}

func isAgentGroupResumeRequest(request ExecuteRequest) bool {
	version, ok := request.ResumeInput["version"].(string)
	return ok && version == agentGroupResumeVersion
}

func decodeAgentGroupResumeCommand(request ExecuteRequest) (agentGroupResumeCommand, error) {
	var command agentGroupResumeCommand
	if request.Operation != "resume" || request.ResumeInput == nil {
		return command, ErrInvalidTransition
	}
	raw, err := json.Marshal(request.ResumeInput)
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		return command, ErrInvalidTransition
	}
	var outer map[string]json.RawMessage
	if json.Unmarshal(raw, &outer) != nil || !hasExactJSONFields(outer,
		[]string{"version", "origin_operation", "waiting_revision", "handoff", "checkpoints"}, nil) {
		return command, ErrInvalidTransition
	}
	var handoff map[string]json.RawMessage
	if json.Unmarshal(outer["handoff"], &handoff) != nil || !hasExactJSONFields(handoff,
		[]string{"version", "run_id", "execution_revision", "body_hash", "lease_token_hash", "input_fingerprint", "origin_operation", "group_key", "operation_key", "last_event_seq", "checkpoint", "child_keys"}, nil) {
		return command, ErrInvalidTransition
	}
	var checkpoint map[string]json.RawMessage
	if json.Unmarshal(handoff["checkpoint"], &checkpoint) != nil || !hasExactJSONFields(checkpoint,
		[]string{"state_key", "revision", "schema_id", "content_hash", "execution_revision", "expires_at"}, nil) {
		return command, ErrInvalidTransition
	}
	var checkpoints []json.RawMessage
	if json.Unmarshal(outer["checkpoints"], &checkpoints) != nil || len(checkpoints) == 0 || len(checkpoints) > 128 {
		return command, ErrInvalidTransition
	}
	for _, rawCheckpoint := range checkpoints {
		var fields map[string]json.RawMessage
		if json.Unmarshal(rawCheckpoint, &fields) != nil || !hasExactJSONFields(fields,
			[]string{"state_key", "revision", "schema_id", "content_hash", "execution_revision", "expires_at"}, nil) {
			return command, ErrInvalidTransition
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if decoder.Decode(&command) != nil || decoder.Decode(new(any)) != io.EOF {
		return agentGroupResumeCommand{}, ErrInvalidTransition
	}
	return command, nil
}

func validAgentGroupReference(reference AgentGroupCheckpointReference, maxExecutionRevision uint64, now time.Time) bool {
	return validHandoffDigest(reference.StateKey) && reference.Revision > 0 && reference.Revision <= 64 &&
		reference.SchemaID == AgentGroupStateSchema && validHandoffDigest(reference.ContentHash) &&
		reference.ExecutionRevision > 0 && reference.ExecutionRevision <= maxExecutionRevision &&
		!reference.ExpiresAt.IsZero() && reference.ExpiresAt.After(now)
}

func groupReferenceFromRuntime(reference runtimeRecoveryCheckpoint) AgentGroupCheckpointReference {
	return AgentGroupCheckpointReference{
		StateKey: reference.StateKey, Revision: reference.Revision, SchemaID: reference.SchemaID,
		ContentHash: reference.ContentHash, ExecutionRevision: reference.ExecutionRevision, ExpiresAt: reference.ExpiresAt,
	}
}

func expectedAgentGroupStateKey(scope ScopeKey, groupKey string) (string, bool) {
	scopeJSON, err := json.Marshal([]string{
		scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID,
		scope.AgentInstanceID, scope.PrincipalType, scope.PrincipalID, scope.InstallationID,
		scope.AgentVersionID, scope.SessionID, scope.RunID,
	})
	if err != nil {
		return "", false
	}
	prefix := sha256.Sum256(scopeJSON)
	stateJSON, err := json.Marshal([]string{hex.EncodeToString(prefix[:]), "coordination", groupKey})
	if err != nil {
		return "", false
	}
	stateKey := sha256.Sum256(stateJSON)
	return hex.EncodeToString(stateKey[:]), true
}

func (c *CapabilityClient) loadCurrentAgentGroupCheckpoint(ctx context.Context, groupKey string, expected agentGroupState) (AgentGroupCheckpointReference, error) {
	loaded, err := c.LoadCheckpoint(ctx, "coordination", groupKey, AgentGroupStateSchema, 0)
	if err != nil {
		return AgentGroupCheckpointReference{}, err
	}
	return agentGroupCheckpointReferenceFromLoad(loaded, expected)
}

func agentGroupCheckpointReferenceFromLoad(loaded map[string]any, expected agentGroupState) (AgentGroupCheckpointReference, error) {
	stateKey, keyOK := loaded["state_key"].(string)
	checkpointMap, checkpointOK := loaded["checkpoint"].(map[string]any)
	if !keyOK || !checkpointOK || !validHandoffDigest(stateKey) {
		return AgentGroupCheckpointReference{}, harnessError("AGENT_GROUP_STATE_REJECTED")
	}
	raw, err := json.Marshal(checkpointMap)
	var fields map[string]json.RawMessage
	if err != nil || json.Unmarshal(raw, &fields) != nil || !hasExactJSONFields(fields,
		[]string{"revision", "schema_id", "value", "content_hash", "expires_at", "execution_revision"}, nil) {
		return AgentGroupCheckpointReference{}, harnessError("AGENT_GROUP_STATE_REJECTED")
	}
	var checkpoint struct {
		Revision          uint64         `json:"revision"`
		SchemaID          string         `json:"schema_id"`
		Value             map[string]any `json:"value"`
		ContentHash       string         `json:"content_hash"`
		ExpiresAt         time.Time      `json:"expires_at"`
		ExecutionRevision uint64         `json:"execution_revision"`
	}
	if groupDecode(checkpointMap, &checkpoint) != nil || checkpoint.Revision == 0 || checkpoint.Revision > 64 ||
		checkpoint.SchemaID != AgentGroupStateSchema || checkpoint.Value == nil ||
		!validHandoffDigest(checkpoint.ContentHash) || checkpoint.ExecutionRevision == 0 ||
		checkpoint.ExecutionRevision > ExecutionEventRangeMaxRevision || checkpoint.ExpiresAt.IsZero() ||
		!checkpoint.ExpiresAt.After(time.Now()) {
		return AgentGroupCheckpointReference{}, harnessError("AGENT_GROUP_STATE_REJECTED")
	}
	var actual agentGroupState
	if groupDecode(checkpoint.Value, &actual) != nil || !reflect.DeepEqual(actual, expected) {
		return AgentGroupCheckpointReference{}, harnessError("AGENT_GROUP_STATE_REJECTED")
	}
	reference := AgentGroupCheckpointReference{
		StateKey: stateKey, Revision: checkpoint.Revision, SchemaID: checkpoint.SchemaID,
		ContentHash: checkpoint.ContentHash, ExecutionRevision: checkpoint.ExecutionRevision,
		ExpiresAt: checkpoint.ExpiresAt,
	}
	if !validAgentGroupReference(reference, ExecutionEventRangeMaxRevision, time.Now()) {
		return AgentGroupCheckpointReference{}, harnessError("AGENT_GROUP_STATE_REJECTED")
	}
	return reference, nil
}

func agentGroupCheckpointMatches(loaded map[string]any, expected AgentGroupCheckpointReference) bool {
	stateKey, keyOK := loaded["state_key"].(string)
	checkpoint, checkpointOK := loaded["checkpoint"].(map[string]any)
	if !keyOK || !checkpointOK || stateKey != expected.StateKey {
		return false
	}
	revision, revisionOK := handoffUint64(checkpoint["revision"])
	executionRevision, executionRevisionOK := handoffUint64(checkpoint["execution_revision"])
	schemaID, schemaOK := checkpoint["schema_id"].(string)
	contentHash, hashOK := checkpoint["content_hash"].(string)
	expiresRaw, expiresOK := checkpoint["expires_at"].(string)
	expiresAt, expiresErr := time.Parse(time.RFC3339Nano, expiresRaw)
	return revisionOK && executionRevisionOK && schemaOK && hashOK && expiresOK && expiresErr == nil &&
		revision == expected.Revision && schemaID == expected.SchemaID && contentHash == expected.ContentHash &&
		executionRevision == expected.ExecutionRevision && expiresAt.Equal(expected.ExpiresAt) && expiresAt.After(time.Now())
}

func validAgentGroupHandoff(handoff AgentGroupHandoff, runID, businessHash string, now time.Time) bool {
	base, maxSequence, validRange := executionEventRange(handoff.ExecutionRevision)
	if !validRange || handoff.Version != AgentGroupHandoffVersion || handoff.RunID != runID ||
		!validHandoffIdentifier(handoff.RunID) || !validHandoffDigest(handoff.BodyHash) ||
		!validHandoffDigest(handoff.LeaseTokenHash) || !validHandoffDigest(handoff.InputFingerprint) ||
		handoff.InputFingerprint != businessHash ||
		(handoff.OriginOperation != "invoke" && handoff.OriginOperation != "run") ||
		!agentGroupStateKey.MatchString(handoff.GroupKey) || !harnessSkillIdentifier(handoff.OperationKey) ||
		handoff.LastEventSeq <= base || handoff.LastEventSeq > maxSequence ||
		!validAgentGroupReference(handoff.Checkpoint, handoff.ExecutionRevision, now) ||
		len(handoff.ChildKeys) < 1 || len(handoff.ChildKeys) > 16 {
		return false
	}
	seen := make(map[string]bool, len(handoff.ChildKeys))
	for _, childKey := range handoff.ChildKeys {
		if !childReceiptHash(childKey) || seen[childKey] {
			return false
		}
		seen[childKey] = true
	}
	return true
}

func validAgentGroupResumeRelation(command agentGroupResumeCommand, request ExecuteRequest, claims Claims, businessHash string, now time.Time) bool {
	handoff := command.Handoff
	expectedStateKey, stateKeyOK := expectedAgentGroupStateKey(request.Scope, handoff.GroupKey)
	if command.Version != agentGroupResumeVersion || command.OriginOperation != handoff.OriginOperation ||
		command.WaitingRevision == 0 || command.WaitingRevision >= ExecutionEventRangeMaxRevision ||
		handoff.ExecutionRevision == 0 || handoff.ExecutionRevision > ExecutionEventRangeMaxRevision-3 ||
		handoff.ExecutionRevision+1 != command.WaitingRevision ||
		claims.ExecutionRevision != command.WaitingRevision+2 || claims.ExecutionRevision > ExecutionEventRangeMaxRevision ||
		request.Scope.RunID != handoff.RunID || request.IdempotencyKey == "" ||
		claims.BodyHash == handoff.BodyHash || claims.LeaseTokenHash == handoff.LeaseTokenHash ||
		!validHandoffDigest(claims.BodyHash) || !validHandoffDigest(claims.LeaseTokenHash) ||
		!validAgentGroupHandoff(handoff, request.Scope.RunID, businessHash, now) || !stateKeyOK ||
		handoff.Checkpoint.StateKey != expectedStateKey {
		return false
	}
	base, _, ok := executionEventRange(claims.ExecutionRevision)
	return ok && base >= handoff.LastEventSeq
}

func agentGroupCheckpointInput(reference runtimeRecoveryCheckpoint) map[string]any {
	return map[string]any{
		"state_key": reference.StateKey, "revision": reference.Revision, "schema_id": reference.SchemaID,
		"content_hash": reference.ContentHash, "execution_revision": reference.ExecutionRevision,
		"expires_at": reference.ExpiresAt,
	}
}

func validAgentGroupStateCheckpoint(response map[string]any, handoff AgentGroupHandoff) bool {
	stateKey, keyOK := response["state_key"].(string)
	checkpoint, checkpointOK := response["checkpoint"].(map[string]any)
	if !keyOK || !checkpointOK || stateKey != handoff.Checkpoint.StateKey {
		return false
	}
	value, valueOK := checkpoint["value"].(map[string]any)
	var state agentGroupState
	if !valueOK || groupDecode(value, &state) != nil || state.Version != "agent-group/v1" ||
		state.ParentRunID != handoff.RunID || state.GroupKey != handoff.GroupKey ||
		state.OperationKey != handoff.OperationKey || state.InputFingerprint != handoff.InputFingerprint || state.Phase != "gather" ||
		!childReceiptHash(state.InputHash) || len(state.Targets) != len(handoff.ChildKeys) ||
		len(state.Bindings) != len(handoff.ChildKeys) || len(state.ChildKeys) != len(handoff.ChildKeys) ||
		state.Ordinal != len(handoff.ChildKeys) {
		return false
	}
	for index, binding := range state.Bindings {
		if binding.ChildKey != handoff.ChildKeys[index] || !childReceiptHash(binding.InputFingerprint) ||
			state.ChildKeys[index] != handoff.ChildKeys[index] ||
			binding.OutputSchema != state.Targets[index].OutputSchema ||
			!validGroupSchema(binding.OutputSchema) || !validGroupSchema(state.Targets[index].InputSchema) {
			return false
		}
	}
	return true
}

func validGroupSchema(value string) bool {
	return len(value) > len("schema://") && len(value) <= 256 && value[:len("schema://")] == "schema://" &&
		!containsAny(value, "*\x00\r\n\t ")
}

func containsAny(value, chars string) bool {
	for _, char := range value {
		for _, forbidden := range chars {
			if char == forbidden {
				return true
			}
		}
	}
	return false
}

func (s *ExecutionServer) validateAgentGroupCheckpoints(ctx context.Context, client *CapabilityClient, command agentGroupResumeCommand) bool {
	if err := client.ValidateCurrentExecution(ctx); err != nil {
		logAgentGroupResumeRejection(command.Handoff.RunID, "renew_before_checkpoints", err)
		return false
	}
	var groupResponse map[string]any
	groupFound := false
	previousKey := ""
	for _, checkpoint := range command.Checkpoints {
		if !validHandoffDigest(checkpoint.StateKey) || checkpoint.StateKey <= previousKey ||
			checkpoint.Revision == 0 || checkpoint.Revision > 64 || !validGroupSchema(checkpoint.SchemaID) ||
			!validHandoffDigest(checkpoint.ContentHash) || checkpoint.ExecutionRevision == 0 ||
			checkpoint.ExecutionRevision > command.Handoff.ExecutionRevision ||
			checkpoint.ExpiresAt.IsZero() || !checkpoint.ExpiresAt.After(s.now()) {
			return false
		}
		previousKey = checkpoint.StateKey
		loaded, err := client.LoadRecoveryCheckpoint(ctx, agentGroupCheckpointInput(checkpoint))
		if err != nil || !validRecoveryCheckpointResponse(loaded, checkpoint, s.now()) {
			logAgentGroupResumeRejection(command.Handoff.RunID, "checkpoint_readback", err)
			return false
		}
		if checkpoint.StateKey == command.Handoff.Checkpoint.StateKey {
			if !reflect.DeepEqual(groupReferenceFromRuntime(checkpoint), command.Handoff.Checkpoint) {
				return false
			}
			groupResponse, groupFound = loaded, true
		}
	}
	if !groupFound || ctx.Err() != nil {
		return false
	}
	if err := client.ValidateCurrentExecution(ctx); err != nil {
		logAgentGroupResumeRejection(command.Handoff.RunID, "renew_after_checkpoints", err)
		return false
	}
	for _, checkpoint := range command.Checkpoints {
		if !checkpoint.ExpiresAt.After(s.now()) {
			return false
		}
	}
	return validAgentGroupStateCheckpoint(groupResponse, command.Handoff)
}

func groupPauseMatchesRecord(record RunRecord, handoff AgentGroupHandoff) bool {
	if record.Status != RunStatusWaiting || record.RunID != handoff.RunID ||
		stableExecutionScope(record.Scope).RunID != handoff.RunID || record.Error != nil || len(record.Output) != 0 || len(record.Events) == 0 {
		return false
	}
	last := record.Events[len(record.Events)-1]
	if last.RunID != handoff.RunID || last.EventType != EventWaiting || last.Seq != handoff.LastEventSeq || len(last.Payload) != 4 ||
		last.Payload["reason"] != "agent_group_waiting" {
		return false
	}
	groupKey, groupOK := last.Payload["group_key"].(string)
	operationKey, operationOK := last.Payload["operation_key"].(string)
	childCount, childCountOK := handoffUint64(last.Payload["child_count"])
	return groupOK && operationOK && childCountOK && groupKey == handoff.GroupKey &&
		operationKey == handoff.OperationKey && childCount == uint64(len(handoff.ChildKeys))
}

func groupOldExecutionStopped(active *activeExecution, request ExecuteRequest, handoff AgentGroupHandoff, businessHash string) bool {
	if active == nil || stableExecutionScope(active.scope) != stableExecutionScope(request.Scope) ||
		active.revision != handoff.ExecutionRevision || active.bodyHash != handoff.BodyHash ||
		active.leaseHash != handoff.LeaseTokenHash || active.businessHash != businessHash ||
		active.originOperation != handoff.OriginOperation {
		return false
	}
	select {
	case <-active.done:
	default:
		return false
	}
	return active.parkedGroup && active.groupPause != nil &&
		active.groupPause.groupKey == handoff.GroupKey && active.groupPause.operationKey == handoff.OperationKey &&
		reflect.DeepEqual(active.groupPause.childKeys, handoff.ChildKeys) &&
		reflect.DeepEqual(active.groupPause.checkpoint, handoff.Checkpoint)
}

func validAgentGroupPauseData(data agentGroupPauseData, runID string, executionRevision uint64, now time.Time) bool {
	if !validHandoffIdentifier(runID) || !agentGroupStateKey.MatchString(data.groupKey) ||
		!harnessSkillIdentifier(data.operationKey) || !validAgentGroupReference(data.checkpoint, executionRevision, now) ||
		len(data.childKeys) < 1 || len(data.childKeys) > 16 {
		return false
	}
	seen := make(map[string]bool, len(data.childKeys))
	for _, childKey := range data.childKeys {
		if !childReceiptHash(childKey) || seen[childKey] {
			return false
		}
		seen[childKey] = true
	}
	return true
}

func (s *ExecutionServer) parkAgentGroup(active *activeExecution, runID string, pause *AgentGroupPause) error {
	if pause == nil || active == nil || s.cfg.Store == nil {
		return ErrInvalidTransition
	}
	if _, ok := s.cfg.Store.(GenerationRunStore); !ok {
		return ErrInvalidTransition
	}
	if active.revision == 0 || (active.originOperation != "invoke" && active.originOperation != "run") ||
		!validHandoffDigest(active.bodyHash) || !validHandoffDigest(active.leaseHash) || !validHandoffDigest(active.businessHash) ||
		!validAgentGroupPauseData(pause.data, runID, active.revision, s.now()) {
		return ErrInvalidTransition
	}
	if _, _, ok := executionEventRange(active.revision); !ok {
		return ErrInvalidTransition
	}
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if s.active[runID] != active || active.scope.RunID != runID || active.parked || active.parkedGroup || active.groupPause != nil {
		return ErrInvalidTransition
	}
	metadata := map[string]any{
		"reason": "agent_group_waiting", "group_key": pause.data.groupKey, "operation_key": pause.data.operationKey,
		"child_count": len(pause.data.childKeys),
	}
	if err := s.cfg.Store.MarkWaiting(runID, metadata); err != nil {
		return err
	}
	record, exists := s.cfg.Store.GetRun(runID)
	base, maxSequence, rangeOK := executionEventRange(active.revision)
	if !exists || record.Status != RunStatusWaiting || stableExecutionScope(record.Scope) != stableExecutionScope(active.scope) ||
		len(record.Events) == 0 {
		return ErrInvalidTransition
	}
	event := record.Events[len(record.Events)-1]
	childCount, childCountOK := handoffUint64(event.Payload["child_count"])
	if event.RunID != runID || event.EventType != EventWaiting || event.Seq <= base || event.Seq > maxSequence || len(event.Payload) != 4 ||
		event.Payload["reason"] != "agent_group_waiting" ||
		event.Payload["group_key"] != pause.data.groupKey || event.Payload["operation_key"] != pause.data.operationKey ||
		!childCountOK || childCount != uint64(len(pause.data.childKeys)) || !rangeOK {
		return ErrInvalidTransition
	}
	copy := pause.data
	copy.childKeys = append([]string(nil), pause.data.childKeys...)
	active.parkedGroup = true
	active.groupPause = &copy
	return nil
}

func (s *ExecutionServer) agentGroupHandoff(active *activeExecution, runID string) *AgentGroupHandoff {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	return s.agentGroupHandoffLocked(active, runID)
}

// agentGroupHandoffLocked requires activeMu. It exposes a receipt only after
// the exact waiting event is durable and this SDK handler has actually exited.
func (s *ExecutionServer) agentGroupHandoffLocked(active *activeExecution, runID string) *AgentGroupHandoff {
	if active == nil || runID == "" || s.active[runID] != active || active.scope.RunID != runID ||
		!active.parkedGroup || active.groupPause == nil {
		return nil
	}
	select {
	case <-active.done:
	default:
		return nil
	}
	record, exists := s.cfg.Store.GetRun(runID)
	if !exists || record.Status != RunStatusWaiting || stableExecutionScope(record.Scope) != stableExecutionScope(active.scope) ||
		record.IdempotencyKey == "" || len(record.Events) == 0 {
		return nil
	}
	last := record.Events[len(record.Events)-1]
	data := active.groupPause
	base, maxSequence, validRange := executionEventRange(active.revision)
	childCount, childCountOK := handoffUint64(last.Payload["child_count"])
	if !validRange || last.RunID != runID || last.EventType != EventWaiting || last.Seq <= base || last.Seq > maxSequence ||
		len(last.Payload) != 4 || last.Payload["reason"] != "agent_group_waiting" ||
		last.Payload["group_key"] != data.groupKey || last.Payload["operation_key"] != data.operationKey ||
		!childCountOK || childCount != uint64(len(data.childKeys)) ||
		!validAgentGroupPauseData(*data, runID, active.revision, s.now()) {
		return nil
	}
	receipt := &AgentGroupHandoff{
		Version: AgentGroupHandoffVersion, RunID: runID, ExecutionRevision: active.revision,
		BodyHash: active.bodyHash, LeaseTokenHash: active.leaseHash, InputFingerprint: active.businessHash,
		OriginOperation: active.originOperation, GroupKey: data.groupKey, OperationKey: data.operationKey,
		LastEventSeq: last.Seq, Checkpoint: data.checkpoint, ChildKeys: append([]string(nil), data.childKeys...),
	}
	if !validAgentGroupHandoff(*receipt, runID, active.businessHash, s.now()) {
		return nil
	}
	return receipt
}

func (s *ExecutionServer) resumeAgentGroup(ctx context.Context, request ExecuteRequest) (resumedExecution *activeExecution, started bool, resultErr error) {
	stage := "claims"
	defer func() {
		if resultErr != nil {
			logAgentGroupResumeRejection(request.Scope.RunID, stage, resultErr)
		}
	}()
	claims, ok := ctx.Value(verifiedExecutionKey{}).(Claims)
	if !ok || request.Operation != "resume" || s.cfg.Capability == nil {
		return nil, false, ErrInvalidTransition
	}
	stage = "command_shape"
	command, err := decodeAgentGroupResumeCommand(request)
	if err != nil {
		return nil, false, err
	}
	stage = "generation_relation"
	businessHash, err := executionBusinessHash(request)
	if err != nil || !validAgentGroupResumeRelation(command, request, claims, businessHash, s.now()) {
		return nil, false, ErrInvalidTransition
	}
	stage = "run_store_support"
	if _, ok := s.cfg.Store.(HandoffRunStore); !ok {
		return nil, false, ErrInvalidTransition
	}
	generationStore, ok := s.cfg.Store.(GenerationRunStore)
	if !ok {
		return nil, false, ErrInvalidTransition
	}
	stage = "current_checkpoint_authority"
	client, err := NewCapabilityClient(*s.cfg.Capability, request)
	if err != nil || !s.validateAgentGroupCheckpoints(ctx, client, command) {
		return nil, false, ErrInvalidTransition
	}

	stage = "prior_handler_exit"
	s.activeMu.Lock()
	previous := s.active[request.Scope.RunID]
	replayCandidate := agentGroupCurrentExecution(previous, request.Scope, claims, businessHash, command.OriginOperation)
	oldStopped := previous != nil && groupOldExecutionStopped(previous, request, command.Handoff, businessHash)
	if previous != nil && !replayCandidate && !oldStopped {
		s.activeMu.Unlock()
		return nil, false, ErrInvalidTransition
	}
	if current := s.active[request.Scope.RunID]; current != previous {
		s.activeMu.Unlock()
		return nil, false, ErrInvalidTransition
	}
	if replayCandidate {
		s.activeMu.Unlock()
		return previous, false, nil
	}

	stage = "waiting_ledger"
	before, exists := s.cfg.Store.GetRun(request.Scope.RunID)
	if previous == nil {
		if exists {
			s.activeMu.Unlock()
			return nil, false, ErrInvalidTransition
		}
	} else if !exists || stableExecutionScope(before.Scope) != stableExecutionScope(request.Scope) ||
		before.IdempotencyKey != request.IdempotencyKey || !groupPauseMatchesRecord(before, command.Handoff) {
		s.activeMu.Unlock()
		return nil, false, ErrInvalidTransition
	}

	stage = "waiting_adoption"
	var projection RunRecord
	if previous == nil {
		projection, err = s.cfg.Store.(HandoffRunStore).AdoptWaiting(request.Scope, request.IdempotencyKey, command.Handoff.LastEventSeq)
		if err != nil || projection.RunID != request.Scope.RunID || stableExecutionScope(projection.Scope) != stableExecutionScope(request.Scope) ||
			projection.IdempotencyKey != request.IdempotencyKey || projection.Status != RunStatusWaiting ||
			len(projection.Events) != 0 || len(projection.Output) != 0 || projection.Error != nil {
			s.activeMu.Unlock()
			return nil, false, ErrInvalidTransition
		}
	} else {
		projection = before
	}
	stage = "generation_transition"
	base, maxSequence, validRange := executionEventRange(claims.ExecutionRevision)
	if !validRange || base < command.Handoff.LastEventSeq || ctx.Err() != nil ||
		generationStore.ResumeGeneration(request.Scope, request.IdempotencyKey, claims.ExecutionRevision) != nil {
		s.activeMu.Unlock()
		return nil, false, ErrInvalidTransition
	}
	stage = "generation_projection"
	resumed, exists := s.cfg.Store.GetRun(request.Scope.RunID)
	if !exists || resumed.RunID != request.Scope.RunID || stableExecutionScope(resumed.Scope) != stableExecutionScope(request.Scope) ||
		resumed.IdempotencyKey != request.IdempotencyKey ||
		!validGenerationResumeProjection(projection, resumed, request.Scope, request.IdempotencyKey, base, maxSequence, command.Handoff.LastEventSeq) {
		s.activeMu.Unlock()
		return nil, false, ErrInvalidTransition
	}
	businessCtx, cancel := context.WithCancel(ctx)
	active := &activeExecution{
		scope: request.Scope, bodyHash: claims.BodyHash, revision: claims.ExecutionRevision,
		leaseHash: claims.LeaseTokenHash, ctx: businessCtx, cancel: cancel, done: make(chan struct{}),
		businessHash: businessHash, originOperation: command.OriginOperation,
		dispatchOperation: request.Operation, resumed: true,
		agentGroupResume: newAgentGroupResumeBinding(command.Handoff),
	}
	s.active[request.Scope.RunID] = active
	s.activeMu.Unlock()
	return active, true, nil
}

// Only bounded stage identifiers and an allowlisted error code are emitted.
// Never log the error message, checkpoint, business input or capability token.
func logAgentGroupResumeRejection(runID, stage string, err error) {
	code := "UNCLASSIFIED"
	var app *AppError
	if errors.As(err, &app) {
		switch app.Code {
		case "CAPABILITY_RENEWAL_DENIED", "RENEWAL_DENIED", "CAPABILITY_CONFIG_INVALID",
			"STATE_AUTHORITY_DENIED", "STATE_CONTINUITY_LOST", "STATE_REVISION_CONFLICT",
			"STATE_SCHEMA_CONFLICT", "STATE_UNAVAILABLE", "AGENT_GROUP_RESUME_REJECTED",
			"AGENT_GROUP_STATE_REJECTED", "AGENT_GROUP_REJECTED", "AGENT_ROUTE_DENIED",
			"CAPABILITY_DENIED", "REQUEST_INVALID", "EVIDENCE_CHECKPOINT_INVALID":
			code = app.Code
		}
	}
	if !validHandoffIdentifier(runID) {
		runID = "invalid"
	}
	slog.Warn("agent_group_resume_rejected", "run_id", runID, "stage", stage, "cause_code", code)
}

func agentGroupCurrentExecution(active *activeExecution, scope ScopeKey, claims Claims, businessHash, originOperation string) bool {
	return active != nil && stableExecutionScope(active.scope) == stableExecutionScope(scope) &&
		active.bodyHash == claims.BodyHash && active.revision == claims.ExecutionRevision &&
		active.leaseHash == claims.LeaseTokenHash && active.businessHash == businessHash &&
		active.originOperation == originOperation && active.dispatchOperation == "resume"
}
