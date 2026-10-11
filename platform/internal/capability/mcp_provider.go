package capability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCPBinding is operator-owned configuration. Remote annotations and discovery
// never register new capabilities or enlarge the caller's published tool policy.
type MCPBinding struct {
	Risk           string          `json:"risk,omitempty"`
	TimeoutSeconds int             `json:"timeout_seconds,omitempty"`
	ToolName       string          `json:"tool_name"`
	RemoteName     string          `json:"remote_name"`
	Endpoint       string          `json:"endpoint"`
	SecretRef      string          `json:"secret_ref,omitempty"`
	InputSchema    json.RawMessage `json:"input_schema"`
}

type mcpBoundTool struct {
	binding    MCPBinding
	client     *http.Client
	schemaHash string
	policy     policyasset.ToolPolicy
}

// mcpNotSubmittedError establishes that CallTool was never submitted. It
// does not claim a remote, potentially writable tool is a local read-only tool.
type mcpNotSubmittedError struct{ Err error }

func (e mcpNotSubmittedError) Error() string { return "MCP tool was not submitted" }
func (e mcpNotSubmittedError) Unwrap() error { return errors.Join(ErrToolNotSubmitted, e.Err) }

type MCPToolProvider struct {
	tools   map[string]mcpBoundTool
	secrets modelgateway.SecretResolver
}

func NewMCPToolProvider(bindings []MCPBinding, secrets modelgateway.SecretResolver, developmentLoopback bool, clientFactory func(string, bool) (*http.Client, error)) (*MCPToolProvider, error) {
	if clientFactory == nil || len(bindings) == 0 || len(bindings) > 32 {
		return nil, errors.New("MCP bindings must contain 1 to 32 tools")
	}
	provider := &MCPToolProvider{tools: map[string]mcpBoundTool{}, secrets: secrets}
	for _, binding := range bindings {
		binding.InputSchema = append(json.RawMessage(nil), binding.InputSchema...)
		// Missing remote risk is writable. Remote discovery annotations cannot
		// declare a tool safe or increase its operator-owned time allowance.
		if binding.Risk == "" {
			binding.Risk = "write"
		}
		if binding.TimeoutSeconds == 0 {
			binding.TimeoutSeconds = 5
			if binding.Risk == "read_only" {
				binding.TimeoutSeconds = 3
			}
		}
		if (RuntimeToolDescriptor{ExecutionType: "tool", Risk: binding.Risk, TimeoutSeconds: binding.TimeoutSeconds}).Validate() != nil {
			return nil, errors.New("invalid MCP runtime risk or timeout")
		}
		if binding.ToolName == "" || len(binding.ToolName) > 128 || strings.TrimSpace(binding.ToolName) != binding.ToolName || provider.Supports(binding.ToolName) || (builtinToolProvider{}).Supports(binding.ToolName) {
			return nil, errors.New("invalid or duplicate MCP binding")
		}
		if binding.SecretRef != "" && secrets == nil {
			return nil, errors.New("MCP secret resolver is required")
		}
		policy := policyasset.ToolPolicy{AllowedTools: []string{binding.ToolName}, Functions: []policyasset.FunctionDefinition{{Name: binding.RemoteName, ToolName: binding.ToolName, Parameters: binding.InputSchema}}}
		if policy.ValidateFunctions() != nil {
			return nil, errors.New("invalid MCP input schema")
		}
		client, err := clientFactory(binding.Endpoint, developmentLoopback)
		if err != nil || client == nil || client.Transport == nil {
			return nil, errors.New("unsafe MCP endpoint")
		}
		hash, err := canonicalSchemaHash(binding.InputSchema)
		if err != nil {
			return nil, err
		}
		provider.tools[binding.ToolName] = mcpBoundTool{binding: binding, client: client, schemaHash: hash, policy: policy}
	}
	return provider, nil
}

func (p *MCPToolProvider) Supports(name string) bool {
	if p == nil {
		return false
	}
	_, ok := p.tools[name]
	return ok
}

func (p *MCPToolProvider) RegisteredTools() []string {
	names := []string{}
	if p != nil {
		for name := range p.tools {
			names = append(names, name)
		}
	}
	return names
}
func (p *MCPToolProvider) DescribeTool(name string) (RuntimeToolDescriptor, bool) {
	if p == nil {
		return RuntimeToolDescriptor{}, false
	}
	bound, found := p.tools[name]
	return RuntimeToolDescriptor{ExecutionType: "tool", Risk: bound.binding.Risk, TimeoutSeconds: bound.binding.TimeoutSeconds}, found
}

func (p *MCPToolProvider) Invoke(ctx context.Context, command ToolCommand) (map[string]any, error) {
	bound, ok := p.tools[command.Name]
	if !ok || command.Scope.ValidateTrusted() != nil || command.CallID == "" {
		return nil, mcpNotSubmittedError{Err: errors.New("invalid MCP command")}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(bound.binding.TimeoutSeconds)*time.Second)
	defer cancel()
	arguments, err := json.Marshal(command.Payload)
	if err != nil {
		return nil, mcpNotSubmittedError{Err: errors.New("invalid MCP arguments")}
	}
	if _, err = bound.policy.ValidateFunctionArguments(bound.binding.RemoteName, arguments); err != nil {
		return nil, mcpNotSubmittedError{Err: err}
	}
	var secret []byte
	if bound.binding.SecretRef != "" {
		secret, err = p.secrets.ResolveSecret(ctx, bound.binding.SecretRef)
		if err != nil || len(secret) == 0 || len(secret) > 65536 || strings.ContainsAny(string(secret), "\r\n") {
			return nil, mcpNotSubmittedError{Err: errors.New("MCP credential unavailable")}
		}
		defer func() {
			for i := range secret {
				secret[i] = 0
			}
		}()
	}
	client := *bound.client
	client.Transport = mcpBoundTransport{base: bound.client.Transport, secret: secret}
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// No roots, sampling, elicitation, autonomous follow-up or retry of a tool
	// with uncertain effects. The outer SQL tool ledger owns invocation replay.
	protocol := mcp.NewClient(&mcp.Implementation{Name: "agentplug", Version: "1"}, &mcp.ClientOptions{
		Capabilities: &mcp.ClientCapabilities{}, MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	session, err := protocol.Connect(callCtx, &mcp.StreamableClientTransport{Endpoint: bound.binding.Endpoint, HTTPClient: &client, MaxRetries: -1, DisableStandaloneSSE: true, MaxEventSize: 1 << 20}, nil)
	if err != nil {
		return nil, mcpNotSubmittedError{Err: errors.New("MCP connection unavailable")}
	}
	defer session.Close()
	cursor := ""
	found := false
	for page := 0; page < 4; page++ {
		listed, listErr := session.ListTools(callCtx, &mcp.ListToolsParams{Cursor: cursor})
		if listErr != nil || listed == nil || len(listed.Tools) > 128 {
			return nil, mcpNotSubmittedError{Err: errors.New("MCP discovery unavailable")}
		}
		for _, tool := range listed.Tools {
			if tool == nil || tool.Name != bound.binding.RemoteName {
				continue
			}
			if found {
				return nil, mcpNotSubmittedError{Err: errors.New("duplicate MCP tool")}
			}
			hash, hashErr := canonicalSchemaHash(tool.InputSchema)
			if hashErr != nil || hash != bound.schemaHash {
				return nil, mcpNotSubmittedError{Err: errors.New("MCP schema changed")}
			}
			found = true
		}
		cursor = listed.NextCursor
		if cursor == "" {
			break
		}
	}
	if !found || cursor != "" {
		return nil, mcpNotSubmittedError{Err: errors.New("MCP tool not discoverable within configured bounds")}
	}
	called, err := session.CallTool(callCtx, &mcp.CallToolParams{Name: bound.binding.RemoteName, Arguments: command.Payload})
	if err != nil || called == nil {
		// A dropped response does not establish that the remote tool did nothing.
		return nil, errors.New("MCP call outcome is uncertain")
	}
	serialized, err := json.Marshal(called)
	if err != nil || len(serialized) > 1<<20 {
		return nil, errors.New("MCP receipt is invalid or too large")
	}
	var receipt map[string]any
	if json.Unmarshal(serialized, &receipt) != nil {
		return nil, errors.New("MCP receipt is invalid")
	}
	return map[string]any{"protocol": "mcp", "tool": command.Name, "receipt": receipt}, nil
}

func canonicalSchemaHash(schema any) (string, error) {
	serialized, err := json.Marshal(schema)
	if err != nil || len(serialized) > 16384 {
		return "", errors.New("invalid MCP schema")
	}
	var object map[string]any
	if json.Unmarshal(serialized, &object) != nil || object == nil {
		return "", errors.New("invalid MCP schema")
	}
	serialized, _ = json.Marshal(object)
	hash := sha256.Sum256(serialized)
	return hex.EncodeToString(hash[:]), nil
}

type mcpBoundTransport struct {
	base   http.RoundTripper
	secret []byte
}

func (t mcpBoundTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	request = request.Clone(request.Context())
	request.Header = request.Header.Clone()
	if len(t.secret) > 0 {
		request.Header.Set("Authorization", "Bearer "+string(t.secret))
	}
	response, err := t.base.RoundTrip(request)
	if err == nil && response.ContentLength > 1<<20 {
		response.Body.Close()
		return nil, errors.New("MCP response exceeds limit")
	}
	if err == nil {
		response.Body = &mcpLimitedBody{ReadCloser: response.Body, remaining: 1 << 20}
	}
	return response, err
}

type mcpLimitedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *mcpLimitedBody) Read(bytes []byte) (int, error) {
	if b.remaining < 0 {
		return 0, errors.New("MCP response exceeds limit")
	}
	if int64(len(bytes)) > b.remaining+1 {
		bytes = bytes[:b.remaining+1]
	}
	n, err := b.ReadCloser.Read(bytes)
	b.remaining -= int64(n)
	if b.remaining < 0 {
		return 0, errors.New("MCP response exceeds limit")
	}
	return n, err
}

// Runtime providers are composed without replacing an already registered tool.
func (m *Module) installRuntimeExecutor(provider RegisteredRuntimeExecutor) error {
	dispatcher, ok := m.tools.(*ExecutionDispatcher)
	if !ok {
		current, supported := m.tools.(RegisteredRuntimeExecutor)
		if !supported {
			return errors.New("runtime provider cannot replace custom tool provider")
		}
		var err error
		dispatcher, err = NewExecutionDispatcher(current)
		if err != nil {
			return err
		}
	}
	installed, err := dispatcher.WithExecutor(provider)
	if err != nil {
		return err
	}
	m.SetToolProvider(installed)
	return nil
}
func (m *Module) SetMCPToolProvider(provider *MCPToolProvider) error {
	if provider == nil {
		return errors.New("MCP provider required")
	}
	return m.installRuntimeExecutor(provider)
}
func (m *Module) SetAPIToolProvider(provider *APIToolProvider) error {
	if provider == nil {
		return errors.New("API provider required")
	}
	return m.installRuntimeExecutor(provider)
}
