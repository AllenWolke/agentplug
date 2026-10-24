package agentplatform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const PublicCapabilitiesVersion = "2.1.0"

// CapabilityPort keeps orchestration on the signed public gateway. It conveys
// no database, provider credential, approval or permission decision.
type CapabilityPort interface {
	Post(context.Context, string, map[string]any) (map[string]any, error)
	LoadCheckpoint(context.Context, string, string, string, uint64) (map[string]any, error)
	SaveCheckpoint(context.Context, string, string, string, string, uint64, map[string]any) (map[string]any, error)
}

type ChatOptions struct {
	Temperature        float64
	MaxTokens          int
	StepName           string
	RequireJSON        bool
	ResponseSchema     map[string]any
	ResponseSchemaMode string
}

type KnowledgeOptions struct {
	TopK            int
	AsOf, CacheMode string
	SourceIDs       []string
	RecoveryOnly    bool
	SkillRequests   []map[string]any
	SkillBindings   map[string]any
}

func publicError(code string) error {
	return &AppError{Code: code, Message: "public capability stopped at a governed boundary", Retryable: false}
}

func publicJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

func publicDigest(value any) (string, error) {
	data, err := publicJSON(value)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func publicClone(value map[string]any) (map[string]any, error) {
	raw, err := publicJSON(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var result map[string]any
	if err = decoder.Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *CapabilityClient) publicOperationKey(prefix string, identity map[string]any) (string, error) {
	raw, err := publicJSON(identity)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	binding, _ := c.context["task_id"].(string)
	if binding == "" {
		binding, _ = c.context["session_id"].(string)
	}
	if binding == "" {
		binding, _ = c.context["request_id"].(string)
	}
	c.mu.Unlock()
	if binding == "" {
		return "", publicError("CONTEXT_INVALID")
	}
	hash := sha256.Sum256([]byte(binding + ":" + string(raw)))
	return prefix + hex.EncodeToString(hash[:]), nil
}

func validateSchemaRequest(schema map[string]any, mode string, requireJSON bool) (string, error) {
	if schema == nil {
		if mode != "" {
			return "", publicError("REQUEST_INVALID")
		}
		return "", nil
	}
	if !requireJSON || schema["type"] != "object" {
		return "", publicError("REQUEST_INVALID")
	}
	if mode == "" {
		mode = "required"
	}
	raw, err := publicJSON(schema)
	if err != nil || len(raw) > 16384 || (mode != "required" && mode != "prefer_supported") {
		return "", publicError("REQUEST_INVALID")
	}
	return mode, nil
}

// Chat uses the platform model catalogue and preserves measured attribution.
func (c *CapabilityClient) Chat(ctx context.Context, messages []map[string]any, o ChatOptions) (map[string]any, error) {
	return c.PublicCapabilities().Chat(ctx, messages, o)
}

func (c *CapabilityClient) Embed(ctx context.Context, texts []string, stepName string) (map[string]any, error) {
	return c.PublicCapabilities().Embed(ctx, texts, stepName)
}

func (c *CapabilityClient) ResolvePrompt(ctx context.Context) (map[string]any, error) {
	return c.PublicCapabilities().ResolvePrompt(ctx)
}
func (c *CapabilityClient) MemoryLoad(ctx context.Context, namespace, key string) (map[string]any, error) {
	return c.PublicCapabilities().MemoryLoad(ctx, namespace, key)
}
func (c *CapabilityClient) MemorySave(ctx context.Context, namespace, key string, value map[string]any) (map[string]any, error) {
	return c.PublicCapabilities().MemorySave(ctx, namespace, key, value)
}

func knowledgeIdentity(query, scope string, o KnowledgeOptions) (map[string]any, error) {
	if strings.TrimSpace(query) == "" || len(query) > 8192 || scope == "" || len(scope) > 128 {
		return nil, publicError("REQUEST_INVALID")
	}
	if o.TopK == 0 {
		o.TopK = 3
	}
	if o.TopK < 1 || o.TopK > 20 {
		return nil, publicError("REQUEST_INVALID")
	}
	if o.CacheMode != "" && o.CacheMode != "use" && o.CacheMode != "cold" && o.CacheMode != "bypass" {
		return nil, publicError("REQUEST_INVALID")
	}
	if o.AsOf != "" {
		if _, err := time.Parse("2006-01-02", o.AsOf); err != nil {
			return nil, publicError("REQUEST_INVALID")
		}
	}
	identity := map[string]any{"query": query, "knowledge_scope": scope, "top_k": o.TopK, "as_of": o.AsOf}
	if o.CacheMode != "" {
		identity["cache_mode"] = o.CacheMode
	}
	if o.SourceIDs != nil {
		if len(o.SourceIDs) < 1 || len(o.SourceIDs) > 16 {
			return nil, publicError("REQUEST_INVALID")
		}
		seen := map[string]bool{}
		for _, id := range o.SourceIDs {
			if id == "" || id != strings.TrimSpace(id) || len(id) > 128 || seen[id] {
				return nil, publicError("REQUEST_INVALID")
			}
			seen[id] = true
		}
		identity["source_ids"] = append([]string(nil), o.SourceIDs...)
	}
	return identity, nil
}

func (c *CapabilityClient) SearchKnowledge(ctx context.Context, query, scope string, o KnowledgeOptions) (map[string]any, error) {
	return c.PublicCapabilities().SearchKnowledge(ctx, query, scope, o)
}

func (c *CapabilityClient) AnswerKnowledge(ctx context.Context, query, scope string, o KnowledgeOptions) (map[string]any, error) {
	return c.PublicCapabilities().AnswerKnowledge(ctx, query, scope, o)
}

func (c *CapabilityClient) ReplayKnowledge(ctx context.Context, requestID string) (map[string]any, error) {
	return c.PublicCapabilities().ReplayKnowledge(ctx, requestID)
}

// AuthorizeReferences rechecks current document publication and ACL without
// retrieving content or calling models. Parent siblings are checked separately.
func (c *CapabilityClient) AuthorizeReferences(ctx context.Context, references []map[string]any, scope string) error {
	return c.PublicCapabilities().AuthorizeReferences(ctx, references, scope)
}

// AuthorizeCachedResult traverses reference containers, including assembled
// parent context. Missing reference identities deny disclosure.
func (c *CapabilityClient) AuthorizeCachedResult(ctx context.Context, result map[string]any, scope string) error {
	return c.PublicCapabilities().AuthorizeCachedResult(ctx, result, scope)
}

func (c *CapabilityClient) LoadExecutionPolicy(ctx context.Context) (map[string]any, error) {
	return c.PublicCapabilities().LoadExecutionPolicy(ctx)
}

func ModelResultMetadata(result map[string]any) map[string]any {
	out := map[string]any{}
	for _, key := range []string{"routing", "route_execution", "context_cache", "response_schema", "model_version_id", "provider_id", "model_id", "step_id", "billing"} {
		if value, ok := result[key]; ok {
			out[key] = value
		}
	}
	return out
}

var publicName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

func requirePublicName(name string) error {
	if !publicName.MatchString(name) {
		return fmt.Errorf("invalid public operation name")
	}
	return nil
}
