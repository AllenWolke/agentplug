package agentplatform

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"
)

const runtimeRecoveryVersion = "runtime-recovery/v1"
const runtimeRecoveryStopVersion = "runtime-recovery-stop/v1"

type runtimeRecoveryCommand struct {
	maximumCheckpoints int
	Version            string                       `json:"version"`
	OriginOperation    string                       `json:"origin_operation"`
	Reference          runtimeRecoveryStopReference `json:"reference"`
	ConfirmationToken  *string                      `json:"confirmation_token,omitempty"`
	GroupResume        *agentGroupResumeCommand     `json:"group_resume,omitempty"`
	BusinessReview     *runtimeBusinessReview       `json:"business_review,omitempty"`
}

type runtimeBusinessReview struct {
	Decision   string `json:"decision"`
	ReviewerID string `json:"reviewer_id"`
}

type runtimeRecoveryStopReference struct {
	Version         string                      `json:"version"`
	RunID           string                      `json:"run_id"`
	StoppedRevision uint64                      `json:"stopped_revision"`
	ReadyRevision   uint64                      `json:"ready_revision"`
	Operation       string                      `json:"operation"`
	BodyHash        string                      `json:"body_hash"`
	PolicyHash      string                      `json:"policy_hash"`
	LeaseTokenHash  string                      `json:"lease_token_hash"`
	RequestHash     string                      `json:"request_hash"`
	ResumeInputHash string                      `json:"resume_input_hash"`
	Source          string                      `json:"source"`
	ProofDigest     *string                     `json:"proof_digest,omitempty"`
	RuntimeID       *string                     `json:"runtime_id,omitempty"`
	Checkpoints     []runtimeRecoveryCheckpoint `json:"checkpoints"`
}

type runtimeRecoveryCheckpoint struct {
	StateKey          string    `json:"state_key"`
	Revision          uint64    `json:"revision"`
	SchemaID          string    `json:"schema_id"`
	ContentHash       string    `json:"content_hash"`
	ExecutionRevision uint64    `json:"execution_revision"`
	ExpiresAt         time.Time `json:"expires_at"`
}

func isRuntimeRecoveryRequest(request ExecuteRequest) bool {
	version, ok := request.ResumeInput["version"].(string)
	return ok && (version == runtimeRecoveryVersion || version == "runtime-recovery/v2")
}

func decodeRuntimeRecoveryCommand(request ExecuteRequest) (runtimeRecoveryCommand, error) {
	return decodeRuntimeRecoveryCommandBounded(request, 1<<20)
}

func decodeRuntimeRecoveryCommandBounded(request ExecuteRequest, maximumBytes int) (runtimeRecoveryCommand, error) {
	var command runtimeRecoveryCommand
	if request.ResumeInput == nil || request.Operation != "resume" {
		return command, ErrInvalidTransition
	}
	raw, err := json.Marshal(request.ResumeInput)
	if err != nil || len(raw) == 0 || len(raw) > maximumBytes {
		return command, ErrInvalidTransition
	}
	var outer map[string]json.RawMessage
	if json.Unmarshal(raw, &outer) != nil || !hasExactJSONFields(outer,
		[]string{"version", "origin_operation", "reference"}, []string{"confirmation_token", "group_resume", "business_review"}) {
		return runtimeRecoveryCommand{}, ErrInvalidTransition
	}
	if rawReview, exists := outer["business_review"]; exists {
		var fields map[string]json.RawMessage
		if json.Unmarshal(rawReview, &fields) != nil || !hasExactJSONFields(fields, []string{"decision", "reviewer_id"}, nil) {
			return command, ErrInvalidTransition
		}
	}
	var groupResume *agentGroupResumeCommand
	_, hasConfirmation := outer["confirmation_token"]
	rawGroupResume, hasGroupResume := outer["group_resume"]
	if hasConfirmation && hasGroupResume {
		return runtimeRecoveryCommand{}, ErrInvalidTransition
	}
	if hasGroupResume {
		var nested map[string]any
		nestedDecoder := json.NewDecoder(bytes.NewReader(rawGroupResume))
		nestedDecoder.UseNumber()
		if nestedDecoder.Decode(&nested) != nil || nested == nil || nestedDecoder.Decode(new(any)) != io.EOF {
			return runtimeRecoveryCommand{}, ErrInvalidTransition
		}
		decoded, err := decodeAgentGroupResumeCommand(ExecuteRequest{Operation: "resume", ResumeInput: nested})
		if err != nil {
			return runtimeRecoveryCommand{}, ErrInvalidTransition
		}
		groupResume = &decoded
	}
	if value, exists := outer["confirmation_token"]; exists {
		var token string
		if json.Unmarshal(value, &token) != nil || token == "" {
			return runtimeRecoveryCommand{}, ErrInvalidTransition
		}
	}
	var reference map[string]json.RawMessage
	if json.Unmarshal(outer["reference"], &reference) != nil || !hasExactJSONFields(reference,
		[]string{"version", "run_id", "stopped_revision", "ready_revision", "operation", "body_hash", "policy_hash", "lease_token_hash", "request_hash", "resume_input_hash", "source", "checkpoints"},
		[]string{"proof_digest", "runtime_id"}) {
		return runtimeRecoveryCommand{}, ErrInvalidTransition
	}
	for _, key := range []string{"proof_digest", "runtime_id"} {
		if value, exists := reference[key]; exists {
			var field string
			if json.Unmarshal(value, &field) != nil || field == "" {
				return runtimeRecoveryCommand{}, ErrInvalidTransition
			}
		}
	}
	var checkpoints []json.RawMessage
	if json.Unmarshal(reference["checkpoints"], &checkpoints) != nil {
		return runtimeRecoveryCommand{}, ErrInvalidTransition
	}
	for _, rawCheckpoint := range checkpoints {
		var fields map[string]json.RawMessage
		if json.Unmarshal(rawCheckpoint, &fields) != nil || !hasExactJSONFields(fields,
			[]string{"state_key", "revision", "schema_id", "content_hash", "execution_revision", "expires_at"}, nil) {
			return runtimeRecoveryCommand{}, ErrInvalidTransition
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if decoder.Decode(&command) != nil || decoder.Decode(new(any)) != io.EOF {
		return runtimeRecoveryCommand{}, ErrInvalidTransition
	}
	if groupResume != nil {
		command.GroupResume = groupResume
	}
	return command, nil
}

func hasExactJSONFields(fields map[string]json.RawMessage, required, optional []string) bool {
	if fields == nil || len(fields) < len(required) || len(fields) > len(required)+len(optional) {
		return false
	}
	for _, key := range required {
		if _, exists := fields[key]; !exists {
			return false
		}
	}
	for key := range fields {
		found := false
		for _, known := range required {
			if key == known {
				found = true
				break
			}
		}
		if !found {
			for _, known := range optional {
				if key == known {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func validRuntimeRecoveryCommand(command runtimeRecoveryCommand, request ExecuteRequest, claims Claims, businessHash string, now time.Time) bool {
	reference := command.Reference
	if review := command.BusinessReview; review != nil {
		if reference.Operation != "resume" || command.ConfirmationToken != nil || command.GroupResume != nil ||
			(review.Decision != "approve" && review.Decision != "reject") || !validHandoffIdentifier(review.ReviewerID) ||
			review.ReviewerID == request.Scope.PrincipalID {
			return false
		}
	}
	validOrigin := command.OriginOperation == "invoke"
	if command.GroupResume != nil {
		validOrigin = (command.OriginOperation == "invoke" || command.OriginOperation == "run") &&
			command.OriginOperation == command.GroupResume.OriginOperation
	}
	if command.Version != runtimeRecoveryVersion || !validOrigin ||
		(command.ConfirmationToken != nil && (*command.ConfirmationToken == "" || len(*command.ConfirmationToken) > 8192)) ||
		(command.GroupResume != nil && command.ConfirmationToken != nil) ||
		reference.Version != runtimeRecoveryStopVersion || reference.RunID != request.Scope.RunID ||
		!validHandoffIdentifier(reference.RunID) || reference.StoppedRevision == 0 ||
		reference.StoppedRevision > ExecutionEventRangeMaxRevision-3 ||
		reference.ReadyRevision != reference.StoppedRevision+2 ||
		claims.ExecutionRevision != reference.ReadyRevision+1 || claims.ExecutionRevision > ExecutionEventRangeMaxRevision ||
		(reference.Operation != "invoke" && reference.Operation != "run" && reference.Operation != "resume") ||
		request.IdempotencyKey == "" || len(request.IdempotencyKey) > 128 || !validHandoffDigest(claims.BodyHash) ||
		!validHandoffDigest(reference.BodyHash) || !validHandoffDigest(reference.PolicyHash) ||
		!validHandoffDigest(reference.LeaseTokenHash) || !validHandoffDigest(reference.RequestHash) ||
		!validHandoffDigest(reference.ResumeInputHash) || !validHandoffDigest(claims.LeaseTokenHash) ||
		claims.LeaseTokenHash == reference.LeaseTokenHash {
		return false
	}
	policy, ok := request.Input["policy_snapshot"].(map[string]any)
	policyHash, hashOK := policy["content_hash"].(string)
	if !ok || !hashOK || !validHandoffDigest(policyHash) || policyHash != reference.PolicyHash || claims.PolicySnapshotHash != policyHash {
		return false
	}
	if reference.Source == "sdk-cancel-exit/v1" {
		if reference.ProofDigest != nil || reference.RuntimeID != nil {
			return false
		}
	} else if reference.Source == "runtime-process-stop/v1" {
		if reference.ProofDigest == nil || reference.RuntimeID == nil ||
			!validHandoffDigest(*reference.ProofDigest) || !validHandoffDigest(*reference.RuntimeID) {
			return false
		}
	} else {
		return false
	}
	if len(reference.Checkpoints) == 0 || len(reference.Checkpoints) > func() int {
		if command.maximumCheckpoints == 8192 {
			return 8192
		}
		return 128
	}() {
		return false
	}
	previousStateKey := ""
	for _, checkpoint := range reference.Checkpoints {
		if !validHandoffDigest(checkpoint.StateKey) || checkpoint.StateKey <= previousStateKey ||
			checkpoint.Revision == 0 || checkpoint.Revision > 4096 ||
			checkpoint.ExecutionRevision == 0 || checkpoint.ExecutionRevision > reference.StoppedRevision ||
			!validHandoffDigest(checkpoint.ContentHash) ||
			len(checkpoint.SchemaID) <= len("schema://") || len(checkpoint.SchemaID) > 256 ||
			strings.TrimSpace(checkpoint.SchemaID) != checkpoint.SchemaID || !strings.HasPrefix(checkpoint.SchemaID, "schema://") ||
			strings.ContainsAny(checkpoint.SchemaID, "\x00\r\n\t* ") || checkpoint.ExpiresAt.IsZero() || !checkpoint.ExpiresAt.After(now) {
			return false
		}
		previousStateKey = checkpoint.StateKey
	}
	return command.GroupResume == nil || validRuntimeRecoveryGroupResume(*command.GroupResume, request, reference, businessHash, now)
}

func validRuntimeRecoveryGroupResume(command agentGroupResumeCommand, request ExecuteRequest, stop runtimeRecoveryStopReference, businessHash string, now time.Time) bool {
	handoff := command.Handoff
	if command.Version != agentGroupResumeVersion || command.OriginOperation != handoff.OriginOperation ||
		command.WaitingRevision < 2 || command.WaitingRevision > ExecutionEventRangeMaxRevision ||
		handoff.ExecutionRevision == 0 || handoff.ExecutionRevision > ExecutionEventRangeMaxRevision-3 ||
		handoff.ExecutionRevision+1 != command.WaitingRevision || stop.StoppedRevision < command.WaitingRevision ||
		stop.StoppedRevision-command.WaitingRevision < 2 ||
		!validAgentGroupHandoff(handoff, request.Scope.RunID, businessHash, now) {
		return false
	}
	expectedStateKey, ok := expectedAgentGroupStateKey(request.Scope, handoff.GroupKey)
	if !ok || handoff.Checkpoint.StateKey != expectedStateKey || len(command.Checkpoints) == 0 || len(command.Checkpoints) > 128 {
		return false
	}
	previousStateKey := ""
	foundHandoffCheckpoint := false
	for _, checkpoint := range command.Checkpoints {
		if !validHandoffDigest(checkpoint.StateKey) || checkpoint.StateKey <= previousStateKey ||
			checkpoint.Revision == 0 || checkpoint.Revision > 4096 || !validGroupSchema(checkpoint.SchemaID) ||
			!validHandoffDigest(checkpoint.ContentHash) || checkpoint.ExecutionRevision == 0 ||
			checkpoint.ExecutionRevision > handoff.ExecutionRevision || checkpoint.ExpiresAt.IsZero() {
			return false
		}
		previousStateKey = checkpoint.StateKey
		if checkpoint.StateKey == handoff.Checkpoint.StateKey {
			foundHandoffCheckpoint = reflect.DeepEqual(groupReferenceFromRuntime(checkpoint), handoff.Checkpoint)
		}
	}
	if !foundHandoffCheckpoint {
		return false
	}
	for _, checkpoint := range stop.Checkpoints {
		if checkpoint.StateKey == handoff.Checkpoint.StateKey {
			return reflect.DeepEqual(groupReferenceFromRuntime(checkpoint), handoff.Checkpoint)
		}
	}
	return false
}

func runtimeRecoveryCheckpointInput(checkpoint runtimeRecoveryCheckpoint) map[string]any {
	return map[string]any{
		"state_key": checkpoint.StateKey, "revision": checkpoint.Revision, "schema_id": checkpoint.SchemaID,
		"content_hash": checkpoint.ContentHash, "execution_revision": checkpoint.ExecutionRevision,
		"expires_at": checkpoint.ExpiresAt,
	}
}

func validRecoveryCheckpointResponse(response map[string]any, expected runtimeRecoveryCheckpoint, now time.Time) bool {
	stateKey, ok := response["state_key"].(string)
	checkpoint, checkpointOK := response["checkpoint"].(map[string]any)
	if !ok || !checkpointOK || stateKey != expected.StateKey {
		return false
	}
	revision, revisionOK := handoffUint64(checkpoint["revision"])
	executionRevision, executionRevisionOK := handoffUint64(checkpoint["execution_revision"])
	schemaID, schemaOK := checkpoint["schema_id"].(string)
	contentHash, hashOK := checkpoint["content_hash"].(string)
	expiresRaw, expiresOK := checkpoint["expires_at"].(string)
	expiresAt, expiresErr := time.Parse(time.RFC3339Nano, expiresRaw)
	limit, capacityError := checkpointReplyLimit(response)
	return capacityError == nil && revisionOK && executionRevisionOK && schemaOK && hashOK && expiresOK && expiresErr == nil &&
		revision <= limit && revision == expected.Revision && schemaID == expected.SchemaID && contentHash == expected.ContentHash &&
		executionRevision == expected.ExecutionRevision && expiresAt.Equal(expected.ExpiresAt) && expiresAt.After(now)
}

func (s *ExecutionServer) validateRuntimeRecoveryCheckpoints(ctx context.Context, client *CapabilityClient, reference runtimeRecoveryStopReference, groupResume *agentGroupResumeCommand) (map[string]any, []RecoveryCheckpointSnapshot, bool) {
	var groupResponse map[string]any
	snapshots := make([]RecoveryCheckpointSnapshot, 0, len(reference.Checkpoints))
	for _, checkpoint := range reference.Checkpoints {
		if !checkpoint.ExpiresAt.After(s.now()) {
			return nil, nil, false
		}
		loaded, err := client.LoadRecoveryCheckpoint(ctx, runtimeRecoveryCheckpointInput(checkpoint))
		if err != nil || !validRecoveryCheckpointResponse(loaded, checkpoint, s.now()) {
			return nil, nil, false
		}
		snapshots = append(snapshots, RecoveryCheckpointSnapshot{Reference: runtimeRecoveryCheckpointInput(checkpoint), Response: loaded})
		if groupResume != nil && checkpoint.StateKey == groupResume.Handoff.Checkpoint.StateKey {
			if !reflect.DeepEqual(groupReferenceFromRuntime(checkpoint), groupResume.Handoff.Checkpoint) {
				return nil, nil, false
			}
			groupResponse = loaded
		}
	}
	if ctx.Err() != nil || client.ValidateCurrentExecution(ctx) != nil {
		return nil, nil, false
	}
	for _, checkpoint := range reference.Checkpoints {
		if !checkpoint.ExpiresAt.After(s.now()) {
			return nil, nil, false
		}
	}
	if groupResume != nil && (groupResponse == nil || !validAgentGroupStateCheckpoint(groupResponse, groupResume.Handoff)) {
		return nil, nil, false
	}
	return groupResponse, snapshots, true
}

func recoveryCurrentExecution(active *activeExecution, scope ScopeKey, claims Claims, businessHash string) bool {
	return active != nil && stableExecutionScope(active.scope) == stableExecutionScope(scope) &&
		active.bodyHash == claims.BodyHash && active.revision == claims.ExecutionRevision &&
		active.leaseHash == claims.LeaseTokenHash && active.businessHash == businessHash
}

func recoveryOldExecutionStopped(active *activeExecution, request ExecuteRequest, claims Claims, reference runtimeRecoveryStopReference, businessHash string) bool {
	if active == nil || stableExecutionScope(active.scope) != stableExecutionScope(request.Scope) ||
		active.dispatchOperation != reference.Operation || active.bodyHash != reference.BodyHash ||
		active.revision != reference.StoppedRevision || active.leaseHash != reference.LeaseTokenHash ||
		active.businessHash != businessHash || claims.LeaseTokenHash == active.leaseHash {
		return false
	}
	select {
	case <-active.done:
		return true
	default:
		return false
	}
}

func validRecoveryGenerationProjection(before *RunRecord, after RunRecord, request ExecuteRequest, base, maxSequence uint64) bool {
	if after.RunID != request.Scope.RunID || stableExecutionScope(after.Scope) != stableExecutionScope(request.Scope) ||
		after.IdempotencyKey != request.IdempotencyKey || after.Status != RunStatusRunning ||
		len(after.Output) != 0 || after.Error != nil {
		return false
	}
	var oldEvents []ExecutionEvent
	var oldLastSequence uint64
	if before != nil {
		if before.RunID != request.Scope.RunID || stableExecutionScope(before.Scope) != stableExecutionScope(request.Scope) ||
			before.IdempotencyKey != request.IdempotencyKey || !before.Status.Terminal() {
			return false
		}
		oldEvents = before.Events
		oldLastSequence = actualLastEventSeq(oldEvents)
	}
	if len(after.Events) != len(oldEvents)+1 || !sameEventHistory(oldEvents, after.Events) {
		return false
	}
	if base > oldLastSequence {
		oldLastSequence = base
	}
	if oldLastSequence == ^uint64(0) {
		return false
	}
	started := after.Events[len(after.Events)-1]
	if started.RunID != request.Scope.RunID || started.EventType != EventStarted ||
		started.Seq != oldLastSequence+1 || started.Seq > maxSequence || len(started.Payload) != 2 {
		return false
	}
	return started.Payload["operation"] == "resume" && started.Payload["reason"] == "runtime_recovery"
}

func (s *ExecutionServer) resumeRuntimeRecovery(ctx context.Context, request ExecuteRequest) (*activeExecution, bool, error) {
	claims, ok := ctx.Value(verifiedExecutionKey{}).(Claims)
	if !ok || request.Operation != "resume" || s.cfg.Capability == nil {
		return nil, false, ErrInvalidTransition
	}
	client, err := NewCapabilityClient(*s.cfg.Capability, request)
	if err != nil {
		return nil, false, ErrInvalidTransition
	}
	command, err := expandRuntimeRecovery(ctx, client, request)
	businessHash, hashErr := executionBusinessHash(request)
	if err != nil || hashErr != nil || !validRuntimeRecoveryCommand(command, request, claims, businessHash, s.now()) {
		return nil, false, ErrInvalidTransition
	}

	s.activeMu.Lock()
	previous := s.active[request.Scope.RunID]
	replayCandidate := recoveryCurrentExecution(previous, request.Scope, claims, businessHash)
	s.activeMu.Unlock()
	if !replayCandidate && previous != nil && !recoveryOldExecutionStopped(previous, request, claims, command.Reference, businessHash) {
		return nil, false, ErrInvalidTransition
	}
	if replayCandidate {
		// This private Active was created only after full recovery admission.
		// Its handler may have legitimately advanced the old checkpoint heads;
		// replay observes this same execution instead of re-admitting a handler.
		if err != nil || ctx.Err() != nil || client.ValidateCurrentExecution(ctx) != nil {
			return nil, false, ErrInvalidTransition
		}
		s.activeMu.Lock()
		current := s.active[request.Scope.RunID]
		if current != previous || !recoveryCurrentExecution(current, request.Scope, claims, businessHash) {
			s.activeMu.Unlock()
			return nil, false, ErrInvalidTransition
		}
		s.activeMu.Unlock()
		return previous, false, nil
	}
	checkpointsValid := false
	var planBinding *runtimeRecoveryPlanBinding
	if err == nil {
		var group map[string]any
		var snapshots []RecoveryCheckpointSnapshot
		group, snapshots, checkpointsValid = s.validateRuntimeRecoveryCheckpoints(ctx, client, command.Reference, command.GroupResume)
		if checkpointsValid {
			planBinding, err = s.bindRuntimeRecoveryPlan(ctx, client, request, snapshots, group, command.GroupResume != nil)
		}
	}
	if err != nil || !checkpointsValid {
		return nil, false, ErrInvalidTransition
	}
	recoveryStore, ok := s.cfg.Store.(RecoveryGenerationRunStore)
	if !ok {
		return nil, false, ErrInvalidTransition
	}
	base, maxSequence, validRange := executionEventRange(claims.ExecutionRevision)
	if !validRange || ctx.Err() != nil {
		return nil, false, ErrInvalidTransition
	}

	s.activeMu.Lock()
	current := s.active[request.Scope.RunID]
	if current != previous {
		if recoveryCurrentExecution(current, request.Scope, claims, businessHash) {
			s.activeMu.Unlock()
			return current, false, nil
		}
		s.activeMu.Unlock()
		return nil, false, ErrInvalidTransition
	}
	if previous != nil && !recoveryOldExecutionStopped(previous, request, claims, command.Reference, businessHash) {
		s.activeMu.Unlock()
		return nil, false, ErrInvalidTransition
	}
	var before *RunRecord
	if record, exists := s.cfg.Store.GetRun(request.Scope.RunID); exists {
		if previous == nil || stableExecutionScope(record.Scope) != stableExecutionScope(request.Scope) ||
			record.IdempotencyKey != request.IdempotencyKey || !record.Status.Terminal() {
			s.activeMu.Unlock()
			return nil, false, ErrInvalidTransition
		}
		before = &record
	} else if previous != nil {
		s.activeMu.Unlock()
		return nil, false, ErrInvalidTransition
	}
	record, err := recoveryStore.RecoverGeneration(request.Scope, request.IdempotencyKey, command.Reference.StoppedRevision, claims.ExecutionRevision)
	if err != nil || !validRecoveryGenerationProjection(before, record, request, base, maxSequence) {
		s.activeMu.Unlock()
		return nil, false, ErrInvalidTransition
	}
	businessCtx, cancel := context.WithCancel(ctx)
	var groupBinding *agentGroupResumeBinding
	if command.GroupResume != nil {
		groupBinding = newAgentGroupResumeBinding(command.GroupResume.Handoff)
	}
	active := &activeExecution{
		scope:               request.Scope,
		bodyHash:            claims.BodyHash,
		revision:            claims.ExecutionRevision,
		leaseHash:           claims.LeaseTokenHash,
		ctx:                 businessCtx,
		cancel:              cancel,
		done:                make(chan struct{}),
		businessHash:        businessHash,
		originOperation:     command.OriginOperation,
		dispatchOperation:   request.Operation,
		resumed:             true,
		agentGroupResume:    groupBinding,
		runtimeRecoveryPlan: planBinding,
	}
	s.active[request.Scope.RunID] = active
	s.activeMu.Unlock()
	return active, true, nil
}
