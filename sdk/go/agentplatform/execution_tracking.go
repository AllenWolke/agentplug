package agentplatform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strconv"
)

type verifiedExecutionKey struct{}

// Retained for the lifetime of this server, like its development RunStore.
// The done channel proves that this exact local handler has returned. Durable
// RunStore state or lease expiry alone cannot establish this proof after restart.
type activeExecution struct {
	scope               ScopeKey
	bodyHash            string
	revision            uint64
	leaseHash           string
	ctx                 context.Context
	cancel              context.CancelFunc
	done                chan struct{}
	businessHash        string
	originOperation     string
	dispatchOperation   string
	parked              bool
	parkedGroup         bool
	resumed             bool
	pauseKey            string
	pauseToolName       string
	pauseCallID         string
	groupPause          *agentGroupPauseData
	agentGroupResume    *agentGroupResumeBinding
	runtimeRecoveryPlan *runtimeRecoveryPlanBinding
}

func stableExecutionScope(scope ScopeKey) ScopeKey {
	scope.TraceID, scope.AuthorizationEpoch = "", 0
	return scope
}

func executionBusinessHash(request ExecuteRequest) (string, error) {
	raw, err := json.Marshal([]any{request.InputSchema, request.IdempotencyKey, request.Input})
	if err != nil {
		return "", ErrInvalidTransition
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), nil
}

func validGenerationStartProjection(record RunRecord, scope ScopeKey, idempotencyKey string, base, maxSequence uint64) bool {
	if record.RunID != scope.RunID || stableExecutionScope(record.Scope) != stableExecutionScope(scope) ||
		record.IdempotencyKey != idempotencyKey || record.Status != RunStatusRunning ||
		len(record.Output) != 0 || record.Error != nil || len(record.Events) != 1 {
		return false
	}
	accepted := record.Events[0]
	return accepted.RunID == scope.RunID && accepted.Seq == base+1 && accepted.Seq <= maxSequence && accepted.EventType == EventAccepted
}

func actualLastEventSeq(events []ExecutionEvent) uint64 {
	var last uint64
	for _, event := range events {
		if event.Seq > last {
			last = event.Seq
		}
	}
	return last
}

func sameEventHistory(before, after []ExecutionEvent) bool {
	if len(after) < len(before) {
		return false
	}
	for index, event := range before {
		current := after[index]
		if event.RunID != current.RunID || event.Seq != current.Seq || event.EventType != current.EventType ||
			!event.OccurredAt.Equal(current.OccurredAt) || !reflect.DeepEqual(event.Payload, current.Payload) {
			return false
		}
	}
	return true
}

func validGenerationResumeProjection(before, after RunRecord, scope ScopeKey, idempotencyKey string, base, maxSequence, legacyLastSeq uint64) bool {
	if before.RunID != scope.RunID || after.RunID != scope.RunID ||
		stableExecutionScope(before.Scope) != stableExecutionScope(scope) || stableExecutionScope(after.Scope) != stableExecutionScope(scope) ||
		before.IdempotencyKey != idempotencyKey || after.IdempotencyKey != idempotencyKey ||
		before.Status != RunStatusWaiting || after.Status != RunStatusRunning ||
		!reflect.DeepEqual(before.Output, after.Output) || !reflect.DeepEqual(before.Error, after.Error) ||
		len(after.Events) != len(before.Events)+1 || !sameEventHistory(before.Events, after.Events) {
		return false
	}
	lastSequence := actualLastEventSeq(before.Events)
	if legacyLastSeq > lastSequence {
		lastSequence = legacyLastSeq
	}
	if base > lastSequence {
		lastSequence = base
	}
	if lastSequence == ^uint64(0) {
		return false
	}
	started := after.Events[len(after.Events)-1]
	return started.RunID == scope.RunID && started.EventType == EventStarted &&
		started.Seq == lastSequence+1 && started.Seq <= maxSequence
}

func validHandoffDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func validHandoffIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range []byte(value) {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' || char == '.' || char == ':' || char == '-' {
			continue
		}
		return false
	}
	return true
}

type handoffCheckpointReference struct {
	Namespace         string `json:"namespace"`
	Key               string `json:"key"`
	SchemaID          string `json:"schema_id"`
	Revision          uint64 `json:"revision"`
	ContentHash       string `json:"content_hash"`
	ExecutionRevision uint64 `json:"execution_revision"`
}

type approvedResumeInput struct {
	ConfirmationToken string                     `json:"confirmation_token"`
	Handoff           HandlerHandoff             `json:"handoff"`
	Checkpoint        handoffCheckpointReference `json:"checkpoint"`
}

func decodeApprovedResumeInput(request ExecuteRequest) (approvedResumeInput, error) {
	var decoded approvedResumeInput
	raw, err := json.Marshal(request.ResumeInput)
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		return decoded, ErrInvalidTransition
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil || decoder.Decode(new(any)) != io.EOF ||
		decoded.ConfirmationToken == "" || len(decoded.ConfirmationToken) > 8192 {
		return approvedResumeInput{}, ErrInvalidTransition
	}
	return decoded, nil
}

func handoffUint64(value any) (uint64, bool) {
	switch number := value.(type) {
	case json.Number:
		parsed, err := strconv.ParseUint(number.String(), 10, 64)
		return parsed, err == nil
	case uint64:
		return number, true
	case uint:
		return uint64(number), true
	case int:
		return uint64(number), number >= 0
	case int64:
		return uint64(number), number >= 0
	case float64:
		if number < 0 || number >= 1<<53 || number != float64(uint64(number)) {
			return 0, false
		}
		return uint64(number), true
	default:
		return 0, false
	}
}

func validateHandoffCheckpointValue(value map[string]any, receipt HandlerHandoff) bool {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > 256<<10 {
		return false
	}
	var state struct {
		Version string `json:"version"`
		Phase   string `json:"phase"`
		Pending []struct {
			Name        string         `json:"name"`
			CallID      string         `json:"call_id"`
			Payload     map[string]any `json:"payload"`
			ModelCallID string         `json:"model_call_id"`
			RunID       string         `json:"run_id"`
		} `json:"pending"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if decoder.Decode(&state) != nil || state.Version != "harness-loop/v1" || state.Phase != "approval_required" || len(state.Pending) == 0 || len(state.Pending) > 16 {
		return false
	}
	operation := state.Pending[0]
	return operation.Name == receipt.ToolName && operation.CallID == receipt.CallID &&
		operation.Payload != nil && validHandoffIdentifier(operation.Name) &&
		validHandoffIdentifier(operation.CallID) && validHandoffIdentifier(operation.ModelCallID) &&
		(operation.RunID == "" || operation.RunID == receipt.RunID)
}

func validateHandoffCheckpointHead(loaded map[string]any, reference handoffCheckpointReference, receipt HandlerHandoff) bool {
	checkpoint, ok := loaded["checkpoint"].(map[string]any)
	if !ok || checkpoint == nil {
		return false
	}
	revision, revisionOK := handoffUint64(checkpoint["revision"])
	executionRevision, executionRevisionOK := handoffUint64(checkpoint["execution_revision"])
	schemaID, schemaOK := checkpoint["schema_id"].(string)
	contentHash, hashOK := checkpoint["content_hash"].(string)
	value, valueOK := checkpoint["value"].(map[string]any)
	return revisionOK && executionRevisionOK && schemaOK && hashOK && valueOK &&
		revision == reference.Revision && schemaID == reference.SchemaID &&
		contentHash == reference.ContentHash && executionRevision == reference.ExecutionRevision &&
		validateHandoffCheckpointValue(value, receipt)
}

// adoptHandoffExecution validates the signed platform handoff and current
// public checkpoint without holding activeMu. The final lock prevents a
// concurrently admitted local generation from being replaced.
func (s *ExecutionServer) adoptHandoffExecution(ctx context.Context, request ExecuteRequest) (*activeExecution, error) {
	claims, ok := ctx.Value(verifiedExecutionKey{}).(Claims)
	if !ok || request.Operation != "resume" || request.ResumeInput == nil || s.cfg.Capability == nil {
		return nil, ErrInvalidTransition
	}
	store, ok := s.cfg.Store.(HandoffRunStore)
	if !ok {
		return nil, ErrInvalidTransition
	}
	resume, err := decodeApprovedResumeInput(request)
	if err != nil {
		return nil, err
	}
	receipt := resume.Handoff
	inputHash, err := executionBusinessHash(request)
	generationStore, hasGenerationStore := s.cfg.Store.(GenerationRunStore)
	newGenerationValid := false
	newEventBase := uint64(0)
	newEventMax := uint64(0)
	if claims.ExecutionRevision > 0 {
		newEventBase, newEventMax, newGenerationValid = executionEventRange(claims.ExecutionRevision)
	}
	if err != nil || receipt.Version != HandlerHandoffVersion || receipt.RunID != request.Scope.RunID ||
		receipt.ExecutionRevision == 0 || receipt.ExecutionRevision >= 1<<53 ||
		receipt.LastEventSeq == 0 || receipt.LastEventSeq > MaxSafeExecutionEventSequence ||
		!validHandoffDigest(receipt.BodyHash) || !validHandoffDigest(receipt.LeaseTokenHash) ||
		!validHandoffDigest(receipt.InputFingerprint) || receipt.InputFingerprint != inputHash ||
		(claims.ExecutionRevision <= receipt.ExecutionRevision || claims.ExecutionRevision >= 1<<53) ||
		!newGenerationValid || (hasGenerationStore && newEventBase < receipt.LastEventSeq) ||
		!validHandoffDigest(claims.BodyHash) || !validHandoffDigest(claims.LeaseTokenHash) || claims.LeaseTokenHash == receipt.LeaseTokenHash ||
		(receipt.OriginOperation != "invoke" && receipt.OriginOperation != "run") ||
		!agentGroupStateKey.MatchString(receipt.HarnessKey) || !validHandoffIdentifier(receipt.ToolName) || !validHandoffIdentifier(receipt.CallID) {
		return nil, ErrInvalidTransition
	}
	reference := resume.Checkpoint
	if reference.Namespace != "harness" || reference.Key != receipt.HarnessKey || reference.SchemaID != HarnessStateSchema ||
		reference.Revision == 0 || reference.Revision > 64 || !validHandoffDigest(reference.ContentHash) ||
		reference.ExecutionRevision != receipt.ExecutionRevision {
		return nil, ErrInvalidTransition
	}
	client, err := NewCapabilityClient(*s.cfg.Capability, request)
	if err != nil || client.ValidateCurrentExecution(ctx) != nil {
		return nil, ErrInvalidTransition
	}
	loaded, err := client.LoadCheckpoint(ctx, reference.Namespace, reference.Key, reference.SchemaID, 0)
	if err != nil || !validateHandoffCheckpointHead(loaded, reference, receipt) {
		return nil, ErrInvalidTransition
	}
	if client.ValidateCurrentExecution(ctx) != nil || ctx.Err() != nil {
		return nil, ErrInvalidTransition
	}

	businessCtx, cancel := context.WithCancel(ctx)
	active := &activeExecution{
		scope:             request.Scope,
		bodyHash:          claims.BodyHash,
		revision:          claims.ExecutionRevision,
		leaseHash:         claims.LeaseTokenHash,
		ctx:               businessCtx,
		cancel:            cancel,
		done:              make(chan struct{}),
		businessHash:      inputHash,
		originOperation:   receipt.OriginOperation,
		dispatchOperation: request.Operation,
		resumed:           true,
	}

	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if s.active[request.Scope.RunID] != nil {
		cancel()
		return nil, ErrInvalidTransition
	}
	projection, err := store.AdoptWaiting(request.Scope, request.IdempotencyKey, receipt.LastEventSeq)
	if err != nil || projection.RunID != request.Scope.RunID || stableExecutionScope(projection.Scope) != stableExecutionScope(request.Scope) ||
		projection.IdempotencyKey != request.IdempotencyKey || projection.Status != RunStatusWaiting {
		cancel()
		return nil, ErrInvalidTransition
	}
	// Never persist the signed confirmation token or the handoff envelope.
	var resumeErr error
	if hasGenerationStore && claims.ExecutionRevision > 0 {
		resumeErr = generationStore.ResumeGeneration(request.Scope, request.IdempotencyKey, claims.ExecutionRevision)
	} else {
		resumeErr = s.cfg.Store.Resume(request.Scope.RunID, map[string]any{"operation": "resume"})
	}
	if resumeErr != nil {
		cancel()
		return nil, ErrInvalidTransition
	}
	resumedProjection, exists := s.cfg.Store.GetRun(request.Scope.RunID)
	if !exists || resumedProjection.RunID != request.Scope.RunID || stableExecutionScope(resumedProjection.Scope) != stableExecutionScope(request.Scope) ||
		resumedProjection.IdempotencyKey != request.IdempotencyKey || resumedProjection.Status != RunStatusRunning {
		cancel()
		return nil, ErrInvalidTransition
	}
	if hasGenerationStore && !validGenerationResumeProjection(projection, resumedProjection, request.Scope, request.IdempotencyKey, newEventBase, newEventMax, receipt.LastEventSeq) {
		cancel()
		return nil, ErrInvalidTransition
	}
	s.active[request.Scope.RunID] = active
	return active, nil
}

// handlerHandoff returns a receipt only for the current SDK-managed Harness
// pause after its exact local handler has exited and the RunStore is waiting.
// The activeMu fence serializes this snapshot with pause/resume transitions.
func (s *ExecutionServer) handlerHandoff(active *activeExecution, runID string) *HandlerHandoff {
	if active == nil || runID == "" {
		return nil
	}
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if s.active[runID] != active || active.scope.RunID != runID || !active.parked {
		return nil
	}
	select {
	case <-active.done:
	default:
		return nil
	}
	record, exists := s.cfg.Store.GetRun(runID)
	if !exists || record.Status != RunStatusWaiting || stableExecutionScope(record.Scope) != stableExecutionScope(active.scope) {
		return nil
	}
	if len(record.Events) == 0 {
		return nil
	}
	lastEvent := record.Events[len(record.Events)-1]
	if lastEvent.RunID != runID || lastEvent.EventType != EventWaiting ||
		lastEvent.Seq == 0 || lastEvent.Seq > MaxSafeExecutionEventSequence || lastEvent.Payload["reason"] != "approval_required" ||
		lastEvent.Payload["harness_key"] != active.pauseKey || lastEvent.Payload["tool_name"] != active.pauseToolName ||
		lastEvent.Payload["call_id"] != active.pauseCallID {
		return nil
	}
	if active.revision == 0 || active.revision >= 1<<53 ||
		!validHandoffIdentifier(runID) || !validHandoffDigest(active.bodyHash) ||
		!validHandoffDigest(active.leaseHash) || !validHandoffDigest(active.businessHash) ||
		(active.originOperation != "invoke" && active.originOperation != "run") ||
		!agentGroupStateKey.MatchString(active.pauseKey) || !validHandoffIdentifier(active.pauseToolName) || !validHandoffIdentifier(active.pauseCallID) {
		return nil
	}
	return &HandlerHandoff{
		Version:           HandlerHandoffVersion,
		RunID:             active.scope.RunID,
		ExecutionRevision: active.revision,
		BodyHash:          active.bodyHash,
		LeaseTokenHash:    active.leaseHash,
		InputFingerprint:  active.businessHash,
		OriginOperation:   active.originOperation,
		HarnessKey:        active.pauseKey,
		ToolName:          active.pauseToolName,
		CallID:            active.pauseCallID,
		LastEventSeq:      lastEvent.Seq,
	}
}

func (s *ExecutionServer) admitExecution(ctx context.Context, request ExecuteRequest) (*activeExecution, bool, error) {
	claims, ok := ctx.Value(verifiedExecutionKey{}).(Claims)
	if !ok || request.Scope.RunID == "" {
		return nil, false, ErrInvalidCapability
	}
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if existing := s.active[request.Scope.RunID]; existing != nil {
		if existing.scope != request.Scope || existing.bodyHash != claims.BodyHash || existing.revision != claims.ExecutionRevision || existing.leaseHash != claims.LeaseTokenHash {
			return nil, false, ErrIdempotencyConflict
		}
		return existing, false, nil
	}
	var created bool
	var err error
	if claims.ExecutionRevision > 0 {
		base, maxSequence, validRange := executionEventRange(claims.ExecutionRevision)
		if !validRange {
			return nil, false, ErrInvalidTransition
		}
		if generationStore, supportsGeneration := s.cfg.Store.(GenerationRunStore); supportsGeneration {
			projection, wasCreated, startErr := generationStore.StartGeneration(request.Scope, request.IdempotencyKey, claims.ExecutionRevision)
			if startErr != nil || !wasCreated || !validGenerationStartProjection(projection, request.Scope, request.IdempotencyKey, base, maxSequence) {
				return nil, false, ErrInvalidTransition
			}
			created = wasCreated
		} else {
			_, created, err = s.cfg.Store.StartRun(request)
		}
	} else {
		_, created, err = s.cfg.Store.StartRun(request)
	}
	if err != nil || !created {
		// Existing durable records lack this server's input and exit proof.
		return nil, false, ErrInvalidTransition
	}
	businessCtx, cancel := context.WithCancel(ctx)
	active := &activeExecution{scope: request.Scope, bodyHash: claims.BodyHash, revision: claims.ExecutionRevision, leaseHash: claims.LeaseTokenHash, ctx: businessCtx, cancel: cancel, done: make(chan struct{})}
	active.businessHash, err = executionBusinessHash(request)
	if err != nil {
		cancel()
		return nil, false, err
	}
	active.originOperation = request.Operation
	active.dispatchOperation = request.Operation
	s.active[request.Scope.RunID] = active
	return active, true, nil
}

func (s *ExecutionServer) ownsExecution(scope ScopeKey) bool {
	record, ok := s.cfg.Store.GetRun(scope.RunID)
	return ok && stableExecutionScope(record.Scope) == stableExecutionScope(scope)
}

// Resume a locally exited SDK-managed pause only. A persistent status alone
// cannot prove that a former process or execution generation has stopped.
func (s *ExecutionServer) resumeParkedExecution(ctx context.Context, request ExecuteRequest) (*activeExecution, bool, error) {
	claims, ok := ctx.Value(verifiedExecutionKey{}).(Claims)
	if !ok || request.Operation != "resume" || request.ResumeInput == nil {
		return nil, false, ErrInvalidCapability
	}
	hash, err := executionBusinessHash(request)
	if err != nil {
		return nil, false, err
	}
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	previous := s.active[request.Scope.RunID]
	if previous == nil || stableExecutionScope(previous.scope) != stableExecutionScope(request.Scope) || previous.businessHash != hash {
		return nil, false, ErrIdempotencyConflict
	}
	if !previous.parked {
		if previous.bodyHash == claims.BodyHash && previous.revision == claims.ExecutionRevision && previous.leaseHash == claims.LeaseTokenHash {
			return previous, false, nil
		}
		return nil, false, ErrInvalidTransition
	}
	select {
	case <-previous.done:
	default:
		return nil, false, ErrInvalidTransition
	}
	record, exists := s.cfg.Store.GetRun(request.Scope.RunID)
	if !exists || record.Status != RunStatusWaiting || claims.ExecutionRevision <= previous.revision || claims.LeaseTokenHash == previous.leaseHash {
		return nil, false, ErrInvalidTransition
	}
	beforeResume := record
	var newEventBase, newEventMax uint64
	if claims.ExecutionRevision > 0 {
		var validRange bool
		newEventBase, newEventMax, validRange = executionEventRange(claims.ExecutionRevision)
		if !validRange {
			return nil, false, ErrInvalidTransition
		}
	}
	// Do not persist confirmation tokens or arbitrary signed resume input as
	// lifecycle events. The new per-execution client consumes it transiently.
	var resumeErr error
	var generationStore GenerationRunStore
	var supportsGeneration bool
	if claims.ExecutionRevision > 0 {
		if generationStore, supportsGeneration = s.cfg.Store.(GenerationRunStore); supportsGeneration {
			resumeErr = generationStore.ResumeGeneration(request.Scope, request.IdempotencyKey, claims.ExecutionRevision)
		} else {
			resumeErr = s.cfg.Store.Resume(request.Scope.RunID, map[string]any{"operation": "resume"})
		}
	} else {
		resumeErr = s.cfg.Store.Resume(request.Scope.RunID, map[string]any{"operation": "resume"})
	}
	if resumeErr != nil {
		return nil, false, resumeErr
	}
	resumedRecord, exists := s.cfg.Store.GetRun(request.Scope.RunID)
	if !exists || resumedRecord.Status != RunStatusRunning {
		return nil, false, ErrInvalidTransition
	}
	if supportsGeneration && !validGenerationResumeProjection(beforeResume, resumedRecord, request.Scope, request.IdempotencyKey, newEventBase, newEventMax, 0) {
		return nil, false, ErrInvalidTransition
	}
	businessCtx, cancel := context.WithCancel(ctx)
	active := &activeExecution{scope: request.Scope, bodyHash: claims.BodyHash, revision: claims.ExecutionRevision, leaseHash: claims.LeaseTokenHash, ctx: businessCtx, cancel: cancel, done: make(chan struct{}), businessHash: hash, originOperation: previous.originOperation, dispatchOperation: request.Operation, resumed: true}
	s.active[request.Scope.RunID] = active
	return active, true, nil
}

func (s *ExecutionServer) parkExecution(active *activeExecution, runID string, pause *HarnessPause) error {
	if pause == nil || !agentGroupStateKey.MatchString(pause.Key) || !harnessSkillIdentifier(pause.ToolName) || !harnessSkillIdentifier(pause.CallID) {
		return ErrInvalidTransition
	}
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if s.active[runID] != active {
		return ErrInvalidTransition
	}
	if active.parked {
		return ErrInvalidTransition
	}
	if err := s.cfg.Store.MarkWaiting(runID, pause.metadata()); err != nil {
		return err
	}
	active.parked = true
	active.pauseKey = pause.Key
	active.pauseToolName = pause.ToolName
	active.pauseCallID = pause.CallID
	return nil
}

func (s *ExecutionServer) failUnparkedGroupWait(runID string) {
	if record, ok := s.cfg.Store.GetRun(runID); ok && record.Status == RunStatusRunning {
		_ = s.cfg.Store.Fail(runID, AppError{Code: "AGENT_GROUP_WAIT_UNAVAILABLE", Message: "AgentGroup wait could not be safely recorded"})
	}
}

func (s *ExecutionServer) controlExecution(ctx context.Context, scope ScopeKey) (*activeExecution, bool) {
	claims, ok := ctx.Value(verifiedExecutionKey{}).(Claims)
	if !ok {
		return nil, false
	}
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	active := s.active[scope.RunID]
	if active != nil && active.parked && stableExecutionScope(active.scope) == stableExecutionScope(scope) && claims.ExecutionRevision >= active.revision {
		select {
		case <-active.done:
			// Verified cancel may acknowledge an already-exited SDK pause;
			// no live handler is stopped through a foreign generation.
			return active, true
		default:
		}
	}
	if active != nil && active.parkedGroup && stableExecutionScope(active.scope) == stableExecutionScope(scope) && claims.ExecutionRevision >= active.revision {
		if s.agentGroupHandoffLocked(active, scope.RunID) != nil {
			return active, true
		}
	}
	return active, active != nil && active.scope == scope && active.revision == claims.ExecutionRevision && active.leaseHash == claims.LeaseTokenHash
}

func (s *ExecutionServer) cancellationRequested(runID string) bool {
	channel, ok := s.cfg.Store.Cancelled(runID)
	if !ok {
		return false
	}
	select {
	case <-channel:
		return true
	default:
		return false
	}
}

func (s *ExecutionServer) executionExited(scope ScopeKey) bool {
	s.activeMu.Lock()
	active := s.active[scope.RunID]
	s.activeMu.Unlock()
	if active == nil || stableExecutionScope(active.scope) != stableExecutionScope(scope) {
		return false
	}
	select {
	case <-active.done:
		return true
	default:
		return false
	}
}

func (s *ExecutionServer) writeExecutionReplay(w http.ResponseWriter, r *http.Request, request ExecuteRequest, active *activeExecution) {
	runID := request.Scope.RunID
	if s.cfg.Capability != nil {
		client, err := NewCapabilityClient(*s.cfg.Capability, request)
		if err == nil {
			err = client.ValidateCurrentExecution(r.Context())
		}
		if err != nil {
			s.writeAppFailure(w, runID, err)
			return
		}
	}
	select {
	case <-active.done:
		record, ok := s.cfg.Store.GetRun(runID)
		if !ok || (!record.Status.Terminal() && record.Status != RunStatusWaiting) {
			writeServerError(w, http.StatusConflict, "RUN_RESULT_UNCONFIRMED", "run result is unavailable")
			return
		}
		if record.Error != nil {
			s.writeAppFailure(w, runID, record.Error)
			return
		}
		var handoff *HandlerHandoff
		var groupHandoff *AgentGroupHandoff
		if record.Status == RunStatusWaiting {
			handoff = s.handlerHandoff(active, runID)
			groupHandoff = s.agentGroupHandoff(active, runID)
		}
		writeServerJSON(w, http.StatusOK, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: runID, Status: string(record.Status), Output: record.Output, Handoff: handoff, AgentGroupHandoff: groupHandoff})
	default:
		writeServerJSON(w, http.StatusAccepted, ExecuteResponse{ProtocolVersion: ProtocolVersion, RunID: runID, Status: "running"})
	}
}
