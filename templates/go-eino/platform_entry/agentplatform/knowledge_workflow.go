package agentplatform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

const KnowledgeSearchSchema = "schema://agentplug/knowledge-search/v1"
const KnowledgeHarnessSchema = "schema://agentplug/knowledge-harness/v1"

// KnowledgeWorkflowOptions binds retrieval parameters to a durable boundary.
// A replay always reads the original platform receipt under current authority.
type KnowledgeWorkflowOptions struct {
	Key string
	KnowledgeOptions
}

func (c *CapabilityClient) RunKnowledgeSearch(ctx context.Context, query, scope string, o KnowledgeWorkflowOptions) (map[string]any, error) {
	if requirePublicName(o.Key) != nil || o.AsOf == "" {
		return nil, publicError("KNOWLEDGE_SEARCH_CONFIG_INVALID")
	}
	if o.TopK == 0 {
		o.TopK = 5
	}
	if o.CacheMode == "" {
		o.CacheMode = "use"
	}
	if _, err := knowledgeIdentity(query, scope, o.KnowledgeOptions); err != nil {
		return nil, err
	}
	var sources any
	if o.SourceIDs != nil {
		sources = o.SourceIDs
	}
	digest, err := publicDigest([]any{query, scope, o.AsOf, o.TopK, o.CacheMode, sources})
	if err != nil {
		return nil, err
	}
	state := map[string]any{"version": "knowledge-search/v1", "input_hash": digest, "phase": "dispatch"}
	return c.runKnowledgeBoundary(ctx, "knowledge-search", KnowledgeSearchSchema, query, scope, o, state, false)
}

func (c *CapabilityClient) RunKnowledgeHarness(ctx context.Context, query, scope string, o KnowledgeWorkflowOptions) (map[string]any, error) {
	if requirePublicName(o.Key) != nil {
		return nil, publicError("REQUEST_INVALID")
	}
	if o.TopK == 0 {
		o.TopK = 3
	}
	if o.CacheMode == "" {
		o.CacheMode = "use"
	}
	if o.TopK > 5 {
		return nil, publicError("REQUEST_INVALID")
	}
	if _, err := knowledgeIdentity(query, scope, o.KnowledgeOptions); err != nil {
		return nil, err
	}
	requests, err := harnessSkillRequests(o.SkillRequests, true)
	if err != nil || len(requests) == 0 {
		return nil, publicError("HARNESS_SKILL_REJECTED")
	}
	// Skill selections are hashed exactly as supplied; absent sections stay absent.
	identity := []any{query, scope, o.TopK, o.CacheMode, o.SkillRequests}
	if o.AsOf != "" || o.SourceIDs != nil {
		var sources any
		if o.SourceIDs != nil {
			sources = o.SourceIDs
		}
		identity = append(identity, map[string]any{"as_of": o.AsOf, "source_ids": sources})
	}
	digest, err := publicDigest(identity)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	parent, _ := c.context["task_id"].(string)
	c.mu.Unlock()
	if parent == "" {
		return nil, publicError("HARNESS_STATE_REJECTED")
	}
	bindings, _, err := resolveHarnessSkills(ctx, c, requests, nil, true)
	if err != nil {
		return nil, err
	}
	raw := map[string]any{}
	for id, b := range bindings {
		raw[id] = map[string]any{"version_id": b.VersionID, "digest": b.Digest}
	}
	o.SkillBindings = raw
	state := map[string]any{"version": "knowledge-harness/v1", "parent_run_id": parent, "input_hash": digest, "phase": "answer_dispatch", "skill_bindings": raw}
	return c.runKnowledgeBoundary(ctx, "knowledge-harness", KnowledgeHarnessSchema, query, scope, o, state, true)
}

func (c *CapabilityClient) runKnowledgeBoundary(ctx context.Context, namespace, schema, query, scope string, o KnowledgeWorkflowOptions, state map[string]any, answer bool) (map[string]any, error) {
	loaded, err := c.LoadCheckpoint(ctx, namespace, o.Key, schema, 0)
	if err != nil {
		return nil, err
	}
	if err = ValidateRuntimeRecoveryCheckpoint(ctx, namespace, o.Key, schema, loaded); err != nil {
		return nil, err
	}
	revision := uint64(0)
	initialPhase := state["phase"]
	if loaded["checkpoint"] == nil {
		if o.RecoveryOnly {
			return nil, publicError("KNOWLEDGE_RECONCILIATION_REQUIRED")
		}
		if err = AuthorizeRuntimeRecoveryStart(ctx, namespace, o.Key, schema, state["input_hash"].(string)); err != nil {
			return nil, err
		}
	} else {
		cp, ok := loaded["checkpoint"].(map[string]any)
		if !ok {
			return nil, publicError("HARNESS_STATE_REJECTED")
		}
		revision, ok = handoffUint64(cp["revision"])
		previous, valid := cp["value"].(map[string]any)
		if !ok || revision < 1 || revision > 2 || !valid || previous["version"] != state["version"] || previous["input_hash"] != state["input_hash"] || previous["parent_run_id"] != state["parent_run_id"] || !sameRecoveryJSONValue(previous["skill_bindings"], state["skill_bindings"]) || (revision == 1 && previous["phase"] != initialPhase) || (revision == 2 && previous["phase"] != "completed") {
			return nil, publicError("HARNESS_STATE_REJECTED")
		}
		state, err = publicClone(previous)
		if err != nil {
			return nil, err
		}
	}
	save := func() error {
		value, e := publicClone(state)
		if e != nil {
			return e
		}
		result, e := c.SaveCheckpoint(ctx, namespace, o.Key, schema, fmt.Sprintf("%s-%d", map[bool]string{true: "knowledge", false: "search"}[answer], revision+1), revision, value)
		if e != nil {
			return e
		}
		cp, ok := result["checkpoint"].(map[string]any)
		next, number := handoffUint64(cp["revision"])
		if !ok || !number || next != revision+1 || !sameRecoveryJSONValue(cp["value"], value) {
			return publicError("HARNESS_STATE_REJECTED")
		}
		revision = next
		return nil
	}
	recovering := revision != 0
	if !recovering {
		if err = save(); err != nil {
			return nil, err
		}
	}
	o.RecoveryOnly = recovering
	var result map[string]any
	if answer {
		result, err = c.AnswerKnowledge(ctx, query, scope, o.KnowledgeOptions)
	} else {
		result, err = c.SearchKnowledge(ctx, query, scope, o.KnowledgeOptions)
	}
	if err != nil {
		return nil, err
	}
	refs, ok := result["references"].([]any)
	if !ok {
		return nil, publicError("KNOWLEDGE_RESPONSE_INVALID")
	}
	if recovering {
		sent, ok := handoffUint64(result["model_requests_sent"])
		if result["recovery_only"] != true || !ok || sent != 0 {
			return nil, publicError("KNOWLEDGE_RECONCILIATION_REQUIRED")
		}
	}
	if answer {
		text, ok := result["text"].(string)
		citations, valid := result["citation_ids"].([]any)
		if !ok || text == "" || len(text) > 32768 || len(refs) == 0 || !valid || len(citations) == 0 {
			return nil, publicError("KNOWLEDGE_RESPONSE_INVALID")
		}
	}
	if state["phase"] != "completed" {
		state["phase"] = "completed"
		if err = save(); err != nil {
			return nil, err
		}
	}
	if err = c.CompleteRuntimeRecoveryStep(ctx, namespace, o.Key, schema); err != nil {
		return nil, err
	}
	return result, nil
}

// DurableStageClient uses the existing Harness and knowledge state machines.
// It stores attribution receipts, never a permission decision or provider key.
type DurableStageClient struct {
	Client     *CapabilityClient
	Key        string
	DeadlineMS int64
	mu         sync.Mutex
	receipts   map[string]map[string]any
}

func NewDurableStageClient(client *CapabilityClient, key string, deadlineMS int64) (*DurableStageClient, error) {
	if client == nil || requirePublicName(key) != nil || deadlineMS < 1 {
		return nil, publicError("STEP_CONFIG_INVALID")
	}
	return &DurableStageClient{Client: client, Key: key, DeadlineMS: deadlineMS, receipts: map[string]map[string]any{}}, nil
}

// ReceiptSnapshot returns detached attribution data safe to read while other
// stages are completing. Receipts never authorize a new call.
func (s *DurableStageClient) ReceiptSnapshot() (map[string]map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := publicJSON(s.receipts)
	if err != nil {
		return nil, err
	}
	var result map[string]map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	err = decoder.Decode(&result)
	return result, err
}
func (s *DurableStageClient) stageKey(kind string, identity any) (string, error) {
	hash, err := publicDigest([]any{s.Key, kind, identity})
	return "stage-" + hash, err
}
func (s *DurableStageClient) Chat(ctx context.Context, messages []map[string]any, o ChatOptions) (map[string]any, error) {
	if o.MaxTokens == 0 {
		o.MaxTokens = 2048
	}
	if o.StepName == "" {
		o.StepName = "model.generate"
	}
	mode, err := validateSchemaRequest(o.ResponseSchema, o.ResponseSchemaMode, o.RequireJSON)
	if err != nil {
		return nil, err
	}
	identity := []any{o.StepName, messages, o.Temperature, o.MaxTokens}
	if o.RequireJSON {
		identity = append(identity, map[string]any{"require_json": true})
	}
	if o.ResponseSchema != nil {
		identity = append(identity, map[string]any{"response_schema": o.ResponseSchema, "response_schema_mode": mode})
	}
	key, err := s.stageKey("model", identity)
	if err != nil {
		return nil, err
	}
	input := map[string]any{"messages": messages, "function_names": []string{}, "idempotency_key": key, "temperature": o.Temperature, "max_tokens": o.MaxTokens, "usage_step": o.StepName}
	if o.RequireJSON {
		input["require_json"] = true
	}
	if o.ResponseSchema != nil {
		input["response_schema"] = o.ResponseSchema
		input["response_schema_mode"] = mode
	}
	result, err := s.Client.RunHarness(ctx, input, HarnessOptions{Key: key, MaxRounds: 1, MaxToolCalls: 1, ExtensionID: "single-model-stage/v1", DeadlineMS: s.DeadlineMS})
	if err != nil {
		return nil, err
	}
	if result.Status != "completed" {
		return nil, publicError("MODEL_STAGE_INCOMPLETE")
	}
	if _, ok := result.Output["text"].(string); !ok {
		return nil, publicError("MODEL_STAGE_INCOMPLETE")
	}
	output, err := publicClone(result.Output)
	if err != nil {
		return nil, err
	}
	output["execution"] = result.Execution
	receipt, _ := publicClone(map[string]any{"status": result.Status, "output": result.Output, "execution": result.Execution})
	s.mu.Lock()
	s.receipts[key] = receipt
	s.mu.Unlock()
	return output, nil
}
func (s *DurableStageClient) SearchKnowledge(ctx context.Context, query, scope string, o KnowledgeOptions) (map[string]any, error) {
	if o.CacheMode == "" {
		o.CacheMode = "use"
	}
	if o.TopK == 0 {
		o.TopK = 3
	}
	var sources any
	if o.SourceIDs != nil {
		sources = o.SourceIDs
	}
	key, err := s.stageKey("knowledge", []any{query, scope, o.AsOf, o.TopK, o.CacheMode, sources})
	if err != nil {
		return nil, err
	}
	if time.Now().UnixMilli() >= s.DeadlineMS {
		o.RecoveryOnly = true
	}
	result, err := s.Client.RunKnowledgeSearch(ctx, query, scope, KnowledgeWorkflowOptions{key, o})
	if err == nil {
		receipt, cloneErr := publicClone(result)
		if cloneErr != nil {
			return nil, cloneErr
		}
		s.mu.Lock()
		s.receipts[key] = receipt
		s.mu.Unlock()
	}
	return result, err
}
