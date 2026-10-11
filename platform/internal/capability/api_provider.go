package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
)

// APIBinding is operator-owned and never supplied by a model or business input.
// This initial executor accepts explicitly read-only GET integrations only.
// An upstream service must enforce read-only credentials and its own row scope.
type APIBinding struct {
	Purpose          string          `json:"purpose,omitempty"`
	ToolName         string          `json:"tool_name"`
	Endpoint         string          `json:"endpoint"`
	TenantID         string          `json:"tenant_id"`
	ApplicationID    string          `json:"application_id"`
	AgentIDs         []string        `json:"agent_ids"`
	ReadOnly         bool            `json:"read_only"`
	TimeoutSeconds   int             `json:"timeout_seconds"`
	MaxResponseBytes int             `json:"max_response_bytes"`
	SecretRef        string          `json:"secret_ref,omitempty"`
	QueryKeys        []string        `json:"query_keys"`
	InputSchema      json.RawMessage `json:"input_schema"`
}

type apiBoundTool struct {
	binding APIBinding
	client  *http.Client
	policy  policyasset.ToolPolicy
}
type APIToolProvider struct {
	tools   map[string]apiBoundTool
	secrets modelgateway.SecretResolver
}

func NewAPIToolProvider(bindings []APIBinding, secrets modelgateway.SecretResolver, developmentLoopback bool, clientFactory func(string, bool) (*http.Client, error)) (*APIToolProvider, error) {
	if clientFactory == nil || len(bindings) == 0 || len(bindings) > 32 {
		return nil, errors.New("API bindings must contain 1 to 32 tools")
	}
	p := &APIToolProvider{tools: map[string]apiBoundTool{}, secrets: secrets}
	for _, b := range bindings {
		b.InputSchema = append(json.RawMessage(nil), b.InputSchema...)
		if !strings.HasPrefix(b.ToolName, "api.") || len(b.ToolName) > 128 || strings.TrimSpace(b.ToolName) != b.ToolName || p.Supports(b.ToolName) || !b.ReadOnly || b.TenantID == "" || b.ApplicationID == "" || len(b.AgentIDs) == 0 || len(b.AgentIDs) > 32 || b.TimeoutSeconds < 1 || b.TimeoutSeconds > 5 || b.MaxResponseBytes < 1024 || b.MaxResponseBytes > 1<<20 || len(b.QueryKeys) > 32 {
			return nil, errors.New("invalid API binding")
		}
		seen := map[string]bool{}
		for _, id := range b.AgentIDs {
			if id == "" || seen[id] {
				return nil, errors.New("invalid API agent scope")
			}
			seen[id] = true
		}
		seen = map[string]bool{}
		for _, key := range b.QueryKeys {
			if key == "" || len(key) > 64 || seen[key] || blockedAPIQueryKey(key) {
				return nil, errors.New("invalid API query key")
			}
			seen[key] = true
		}
		u, err := url.Parse(b.Endpoint)
		if err != nil || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return nil, errors.New("API endpoint must have a fixed path without query or credentials")
		}
		if b.SecretRef != "" && secrets == nil {
			return nil, errors.New("API secret resolver required")
		}
		client, err := clientFactory(b.Endpoint, developmentLoopback)
		if err != nil || client == nil || client.Transport == nil {
			return nil, errors.New("unsafe API endpoint")
		}
		policy := policyasset.ToolPolicy{AllowedTools: []string{b.ToolName}, Functions: []policyasset.FunctionDefinition{{Name: "api_request", ToolName: b.ToolName, Parameters: b.InputSchema}}}
		if policy.ValidateFunctions() != nil {
			client.CloseIdleConnections()
			return nil, errors.New("invalid API input schema")
		}
		// Freeze slices and schema so callers cannot mutate registered configuration.
		b.AgentIDs = append([]string(nil), b.AgentIDs...)
		b.QueryKeys = append([]string(nil), b.QueryKeys...)
		b.InputSchema = append(json.RawMessage(nil), b.InputSchema...)
		client.Timeout = time.Duration(b.TimeoutSeconds) * time.Second
		p.tools[b.ToolName] = apiBoundTool{binding: b, client: client, policy: policy}
	}
	return p, nil
}

func blockedAPIQueryKey(key string) bool {
	key = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
	return key == "secretref" || key == "authorization" || key == "apikey" || key == "accesstoken" || key == "password" || key == "endpoint" || key == "url"
}
func (p *APIToolProvider) Supports(name string) bool {
	if p == nil {
		return false
	}
	_, ok := p.tools[name]
	return ok
}
func (p *APIToolProvider) ExecutionType(name string) string {
	if p.Supports(name) {
		return "api"
	}
	return "tool"
}

func (p *APIToolProvider) RegisteredTools() []string {
	names := []string{}
	if p != nil {
		for name := range p.tools {
			names = append(names, name)
		}
	}
	return names
}
func (p *APIToolProvider) DescribeTool(name string) (RuntimeToolDescriptor, bool) {
	if p == nil {
		return RuntimeToolDescriptor{}, false
	}
	bound, found := p.tools[name]
	return RuntimeToolDescriptor{ExecutionType: "api", Risk: "read_only", TimeoutSeconds: bound.binding.TimeoutSeconds}, found
}

func (p *APIToolProvider) Invoke(ctx context.Context, command ToolCommand) (map[string]any, error) {
	fail := func(err error) (map[string]any, error) { return nil, ToolNoEffectError{Err: err} }
	bound, ok := p.tools[command.Name]
	if !ok || command.Scope.ValidateTrusted() != nil || command.CallID == "" {
		return fail(errors.New("invalid scoped API request"))
	}
	b := bound.binding
	allowed := false
	for _, id := range b.AgentIDs {
		if id == command.Scope.AgentID {
			allowed = true
		}
	}
	if !allowed || b.TenantID != command.Scope.TenantID || b.ApplicationID != command.Scope.ApplicationID {
		return fail(errors.New("API service scope denied"))
	}
	arguments, err := json.Marshal(command.Payload)
	if err != nil || len(arguments) > 16384 {
		return fail(errors.New("invalid API arguments"))
	}
	if _, err = bound.policy.ValidateFunctionArguments("api_request", arguments); err != nil {
		return fail(errors.New("API arguments rejected"))
	}
	u, _ := url.Parse(b.Endpoint)
	query := url.Values{}
	for key, value := range command.Payload {
		permitted := false
		for _, name := range b.QueryKeys {
			if key == name {
				permitted = true
			}
		}
		text, valid := value.(string)
		if !permitted || !valid || len(text) > 2048 || strings.ContainsAny(text, "\r\n\x00") {
			return fail(errors.New("API query rejected"))
		}
		query.Set(key, text)
	}
	u.RawQuery = query.Encode()
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(b.TimeoutSeconds)*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(callCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fail(errors.New("invalid API request"))
	}
	request.Header.Set("Accept", "application/json")
	if b.SecretRef != "" {
		secret, err := p.secrets.ResolveSecret(callCtx, b.SecretRef)
		defer func() {
			for i := range secret {
				secret[i] = 0
			}
		}()
		if err != nil || len(secret) == 0 || len(secret) > 8192 || strings.ContainsAny(string(secret), "\r\n\x00") {
			return fail(errors.New("API credential unavailable"))
		}
		request.Header.Set("Authorization", "Bearer "+string(secret))
	}
	response, err := bound.client.Do(request)
	if err != nil {
		if callCtx.Err() != nil {
			return fail(callCtx.Err())
		}
		return fail(errors.New("API transport failed"))
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fail(errors.New("API returned unsuccessful status"))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(b.MaxResponseBytes)+1))
	if err != nil || len(body) > b.MaxResponseBytes {
		return fail(errors.New("API response unavailable or oversized"))
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var result map[string]any
	if decoder.Decode(&result) != nil || result == nil || decoder.Decode(new(any)) != io.EOF {
		return fail(errors.New("API response is not one JSON object"))
	}
	return result, nil
}
