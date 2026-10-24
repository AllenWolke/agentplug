package agentplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// CapabilityPoster is the existing governed gateway transport, not a provider.
type CapabilityPoster interface {
	Post(context.Context, string, map[string]any) (map[string]any, error)
}
type CapabilityPostFunc func(context.Context, string, map[string]any) (map[string]any, error)

func (f CapabilityPostFunc) Post(ctx context.Context, path string, input map[string]any) (map[string]any, error) {
	return f(ctx, path, input)
}

type PublicCapabilities struct {
	port    CapabilityPoster
	binding string
}

func NewPublicCapabilities(port CapabilityPoster, binding string) PublicCapabilities {
	return PublicCapabilities{port, binding}
}
func (c *CapabilityClient) PublicCapabilities() PublicCapabilities {
	c.mu.Lock()
	defer c.mu.Unlock()
	binding, _ := c.context["task_id"].(string)
	if binding == "" {
		binding, _ = c.context["session_id"].(string)
	}
	if binding == "" {
		binding, _ = c.context["request_id"].(string)
	}
	return NewPublicCapabilities(c, binding)
}
func (p PublicCapabilities) operationKey(prefix string, identity map[string]any) (string, error) {
	if p.port == nil || p.binding == "" {
		return "", publicError("CONTEXT_INVALID")
	}
	data, err := publicJSON(identity)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(p.binding + ":" + string(data)))
	return prefix + hex.EncodeToString(hash[:]), nil
}
func (p PublicCapabilities) Chat(ctx context.Context, messages []map[string]any, o ChatOptions) (map[string]any, error) {
	if len(messages) == 0 {
		return nil, publicError("REQUEST_INVALID")
	}
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
	input := map[string]any{"messages": messages, "temperature": o.Temperature, "max_tokens": o.MaxTokens, "usage_step": o.StepName}
	if o.RequireJSON {
		input["require_json"] = true
	}
	if o.ResponseSchema != nil {
		input["response_schema"], input["response_schema_mode"] = o.ResponseSchema, mode
	}
	key, err := p.operationKey("model-", input)
	if err != nil {
		return nil, err
	}
	input["idempotency_key"] = key
	result, err := p.port.Post(ctx, "/internal/model/generate", input)
	if err != nil {
		return nil, err
	}
	if _, valid := result["text"].(string); !valid {
		return nil, publicError("MODEL_RESPONSE_INVALID")
	}
	return result, nil
}

func (p PublicCapabilities) Embed(ctx context.Context, texts []string, stepName string) (map[string]any, error) {
	if len(texts) == 0 {
		return nil, publicError("REQUEST_INVALID")
	}
	if stepName == "" {
		stepName = "knowledge.embedding"
	}
	return p.port.Post(ctx, "/internal/model/embed", map[string]any{"texts": texts, "usage_step": stepName})
}

func (p PublicCapabilities) ResolvePrompt(ctx context.Context) (map[string]any, error) {
	return p.port.Post(ctx, "/internal/prompt/resolve", map[string]any{})
}

func (p PublicCapabilities) MemoryLoad(ctx context.Context, namespace, key string) (map[string]any, error) {
	return p.port.Post(ctx, "/internal/memory/access", map[string]any{"operation": "load", "namespace": namespace, "key": key})
}

func (p PublicCapabilities) MemorySave(ctx context.Context, namespace, key string, value map[string]any) (map[string]any, error) {
	if value == nil {
		return nil, publicError("REQUEST_INVALID")
	}
	return p.port.Post(ctx, "/internal/memory/access", map[string]any{"operation": "save", "namespace": namespace, "key": key, "value": value})
}

func (p PublicCapabilities) SearchKnowledge(ctx context.Context, query, scope string, o KnowledgeOptions) (map[string]any, error) {
	identity, err := knowledgeIdentity(query, scope, o)
	if err != nil {
		return nil, err
	}
	key, err := p.operationKey("knowledge-", identity)
	if err != nil {
		return nil, err
	}
	identity["idempotency_key"] = key
	path := "/internal/knowledge/search"
	if o.RecoveryOnly {
		path += "/recovery"
	}
	return p.port.Post(ctx, path, identity)
}

func (p PublicCapabilities) AnswerKnowledge(ctx context.Context, query, scope string, o KnowledgeOptions) (map[string]any, error) {
	if o.CacheMode == "" {
		o.CacheMode = "use"
	}
	identity, err := knowledgeIdentity(query, scope, o)
	if err != nil {
		return nil, err
	}
	if o.AsOf == "" {
		delete(identity, "as_of")
	}
	if o.SkillRequests != nil || o.SkillBindings != nil {
		if len(o.SkillRequests) < 1 || len(o.SkillRequests) > 4 || len(o.SkillBindings) != len(o.SkillRequests) {
			return nil, publicError("HARNESS_SKILL_REJECTED")
		}
		identity["skill_requests"], identity["skill_bindings"] = o.SkillRequests, o.SkillBindings
	}
	key, err := p.operationKey("knowledge-answer-", identity)
	if err != nil {
		return nil, err
	}
	identity["idempotency_key"] = key
	path := "/internal/knowledge/answer"
	if o.RecoveryOnly {
		path += "/recovery"
	}
	return p.port.Post(ctx, path, identity)
}

func (p PublicCapabilities) ReplayKnowledge(ctx context.Context, requestID string) (map[string]any, error) {
	return p.port.Post(ctx, "/internal/knowledge/replay", map[string]any{"request_id": requestID})
}

func (p PublicCapabilities) AuthorizeReferences(ctx context.Context, references []map[string]any, scope string) error {
	identities := []map[string]any{}
	seen := map[string]bool{}
	for _, reference := range references {
		identity := map[string]any{}
		for _, field := range []string{"source", "provider_knowledge_base_id", "provider_document_id", "document_version"} {
			value, ok := reference[field].(string)
			if !ok || value == "" {
				return publicError("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED")
			}
			identity[field] = value
		}
		digest, err := publicDigest(identity)
		if err != nil {
			return err
		}
		if !seen[digest] {
			seen[digest] = true
			identities = append(identities, identity)
		}
	}
	for offset := 0; offset < len(identities); offset += 128 {
		page := identities[offset:min(offset+128, len(identities))]
		r, err := p.port.Post(ctx, "/internal/knowledge/references/authorize", map[string]any{"version": "knowledge-reference-authorization/v1", "knowledge_scope": scope, "references": page})
		if err != nil {
			return err
		}
		count, valid := handoffUint64(r["reference_count"])
		sends, sendsValid := handoffUint64(r["model_requests_sent"])
		if r["version"] != "knowledge-reference-authorization/v1" || r["authorized"] != true || !valid || count != uint64(len(page)) || !sendsValid || sends != 0 {
			return publicError("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED")
		}
	}
	return nil
}

func (p PublicCapabilities) AuthorizeCachedResult(ctx context.Context, result map[string]any, scope string) error {
	copy, err := publicClone(result)
	if err != nil {
		return err
	}
	refs := []map[string]any{}
	var visit func(any) error
	visit = func(value any) error {
		switch v := value.(type) {
		case map[string]any:
			_, doc := v["doc_id"]
			_, content := v["content"]
			if doc && content {
				refs = append(refs, v)
				if raw, exists := v["parent_context"]; exists {
					parent, ok := raw.(map[string]any)
					if !ok || parent["schema_version"] != "authorized-parent-context/v1" {
						return publicError("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED")
					}
					siblings, ok := parent["source_documents"].([]any)
					if !ok || len(siblings) < 1 || len(siblings) > 1000 {
						return publicError("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED")
					}
					found := false
					for _, raw := range siblings {
						item, ok := raw.(map[string]any)
						if !ok {
							return publicError("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED")
						}
						same := true
						for _, field := range []string{"source", "provider_knowledge_base_id", "provider_document_id", "document_version"} {
							same = same && item[field] == v[field]
						}
						found = found || same
						refs = append(refs, item)
					}
					if !found {
						return publicError("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED")
					}
				}
				return nil
			}
			if raw, exists := v["references"]; exists {
				list, ok := raw.([]any)
				if !ok || len(list) > 4096 {
					return publicError("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED")
				}
				for _, item := range list {
					reference, ok := item.(map[string]any)
					if !ok {
						return publicError("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED")
					}
					refs = append(refs, reference)
				}
			}
			for key, item := range v {
				if key != "context" && key != "prompt_program" && key != "messages" {
					if err := visit(item); err != nil {
						return err
					}
				}
			}
		case []any:
			for _, item := range v {
				if err := visit(item); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(copy); err != nil {
		return err
	}
	return p.AuthorizeReferences(ctx, refs, scope)
}

func (p PublicCapabilities) LoadExecutionPolicy(ctx context.Context) (map[string]any, error) {
	r, err := p.port.Post(ctx, "/internal/runtime/harness-policy", map[string]any{"include_batch": true})
	if err != nil {
		return nil, err
	}
	if err := ValidateExecutionPolicy(r); err != nil {
		return nil, err
	}
	return r, nil
}
