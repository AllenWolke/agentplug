package modelgateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/telemetry"
	"go.opentelemetry.io/otel/trace"
)

const (
	approvedStatus = "approved"
	trustLocal     = "local"
	trustPrivate   = "private"
	trustExternal  = "external"
)

var (
	ErrProviderUnavailable = errors.New("model provider is unavailable")
	ErrModelUnavailable    = errors.New("approved model is unavailable")
	ErrEndpointUnresolved  = errors.New("model endpoint reference could not be resolved")
	ErrUnsafeEndpoint      = errors.New("model endpoint is not allowed")
	ErrSecretUnavailable   = errors.New("model provider secret is unavailable")
	ErrRequestTooLarge     = errors.New("model request exceeds configured limit")
	ErrResponseTooLarge    = errors.New("model response exceeds configured limit")
	ErrProviderResponse    = errors.New("model provider returned an invalid response")
)

// ProviderMetadata and ModelMetadata are read-only results from the approved
// control-plane catalog. They contain references, never credential bytes.
// ProviderMetadata / ModelMetadata 只承载已批准目录元数据，不承载密钥内容。
type ProviderMetadata struct {
	ID          string
	Key         string
	TrustZone   string
	EndpointRef string
	SecretRef   string
	Status      string
}

type ModelMetadata struct {
	ID         string
	VersionID  string
	ProviderID string
	Key        string
	Status     string
	Kind       string
}

type ProviderMetadataPort interface {
	GetApprovedProvider(context.Context, string) (ProviderMetadata, error)
}

type ModelMetadataPort interface {
	GetApprovedModel(context.Context, string) (ModelMetadata, error)
}

// SecretResolver returns secret material for an opaque reference. The adapter
// never logs or serializes the returned bytes.
type SecretResolver interface {
	ResolveSecret(context.Context, string) ([]byte, error)
}

// EndpointResolver maps a control-plane-owned symbolic reference (for example
// service://approved-provider) to a base URL. Callers never submit a URL.
type EndpointResolver interface {
	ResolveEndpoint(context.Context, string) (string, error)
}

type HTTPConfig struct {
	SecretRoot               string
	RequestTimeout           time.Duration
	DialTimeout              time.Duration
	TLSHandshakeTimeout      time.Duration
	ResponseHeaderTimeout    time.Duration
	MaxRequestBytes          int64
	MaxResponseBytes         int64
	MaxSecretBytes           int64
	AllowLoopbackDevelopment bool
	AllowedHTTPSPorts        []string
	Resolver                 IPResolver
}

// IPResolver is injectable for deterministic DNS-rebinding/SSRF tests.
type IPResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type HTTPAdapter struct {
	access    AccessResolver
	providers ProviderMetadataPort
	models    ModelMetadataPort
	secrets   SecretResolver
	endpoints EndpointResolver
	client    *http.Client
	config    HTTPConfig
}

func NewHTTPAdapter(config HTTPConfig, access AccessResolver, providers ProviderMetadataPort, models ModelMetadataPort, secrets SecretResolver, endpoints EndpointResolver) (*HTTPAdapter, error) {
	if access == nil || providers == nil || models == nil || secrets == nil || endpoints == nil {
		return nil, errors.New("model gateway requires access, catalog, secret and endpoint ports")
	}
	if strings.TrimSpace(config.SecretRoot) == "" {
		return nil, errors.New("model gateway secret root is required")
	}
	root, err := filepath.Abs(config.SecretRoot)
	if err != nil {
		return nil, errors.New("model gateway secret root is invalid")
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = 30 * time.Second
	}
	if config.DialTimeout <= 0 {
		config.DialTimeout = 5 * time.Second
	}
	if config.TLSHandshakeTimeout <= 0 {
		config.TLSHandshakeTimeout = 5 * time.Second
	}
	if config.ResponseHeaderTimeout <= 0 {
		config.ResponseHeaderTimeout = 10 * time.Second
	}
	if config.MaxRequestBytes <= 0 {
		config.MaxRequestBytes = 1 << 20
	}
	if config.MaxResponseBytes <= 0 {
		config.MaxResponseBytes = 4 << 20
	}
	if config.MaxSecretBytes <= 0 {
		config.MaxSecretBytes = 64 << 10
	}
	if config.Resolver == nil {
		config.Resolver = net.DefaultResolver
	}
	config.SecretRoot = root
	ports := make(map[string]struct{}, len(config.AllowedHTTPSPorts))
	for _, port := range config.AllowedHTTPSPorts {
		if port == "" || strings.ContainsAny(port, "\r\n") {
			return nil, errors.New("invalid configured model HTTPS port")
		}
		ports[port] = struct{}{}
	}
	if len(ports) == 0 {
		ports["443"] = struct{}{}
		ports["8443"] = struct{}{}
	}
	config.AllowedHTTPSPorts = make([]string, 0, len(ports))
	for port := range ports {
		value, parseErr := strconv.Atoi(port)
		if parseErr != nil || value < 1 || value > 65535 {
			return nil, errors.New("invalid configured model HTTPS port")
		}
		config.AllowedHTTPSPorts = append(config.AllowedHTTPSPorts, port)
	}

	dialer := &safeDialer{resolver: config.Resolver, timeout: config.DialTimeout, allowLoopback: config.AllowLoopbackDevelopment}
	transport := &http.Transport{
		Proxy:                  nil, // Do not inherit proxy environment variables; proxy routing bypasses the guarded dialer.
		DialContext:            dialer.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    config.TLSHandshakeTimeout,
		ResponseHeaderTimeout:  config.ResponseHeaderTimeout,
		MaxResponseHeaderBytes: 32 << 10,
		MaxIdleConns:           16,
		MaxIdleConnsPerHost:    4,
		IdleConnTimeout:        30 * time.Second,
	}
	client := &http.Client{Transport: transport, Timeout: config.RequestTimeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("model endpoint redirects are not allowed")
	}}
	return &HTTPAdapter{access: access, providers: providers, models: models, secrets: secrets, endpoints: endpoints, client: client, config: config}, nil
}

func (a *HTTPAdapter) Generate(ctx context.Context, scope sharedkernel.Scope, snapshot policyasset.Snapshot, request GenerateRequest) (GenerateResult, error) {
	if err := scope.ValidateTrusted(); err != nil {
		return GenerateResult{}, ErrProviderUnavailable
	}
	model, provider, endpoint, secret, err := a.resolve(ctx, scope, request.ModelVersionID, request.ModelID, request.ProviderID)
	if err != nil {
		return GenerateResult{}, err
	}
	defer zero(secret)
	if !snapshotMatches(snapshot, provider, model) || strings.TrimSpace(request.Model) != model.Key {
		return GenerateResult{}, ErrModelUnavailable
	}
	if request.MaxTokens < 0 || snapshot.Model.MaxTokens > 0 && request.MaxTokens > snapshot.Model.MaxTokens {
		return GenerateResult{}, ErrProviderResponse
	}
	if provider.TrustZone == trustExternal && !snapshot.Model.AllowExternal {
		return GenerateResult{}, ErrUnsafeEndpoint
	}
	thinking, err := publishedThinkingMode(endpoint, snapshot.Model.ReasoningMode)
	if err != nil {
		return GenerateResult{}, err
	}
	if snapshot.Model.ValidateReasoningMode() != nil {
		return GenerateResult{}, ErrModelUnavailable
	}
	messages := request.Messages
	if len(messages) == 0 && strings.TrimSpace(request.Prompt) != "" {
		messages = []Message{{Role: "user", Content: request.Prompt}}
	}
	if len(messages) == 0 || request.MaxTokens < 0 || request.Temperature < 0 || request.Temperature > 2 {
		return GenerateResult{}, ErrProviderResponse
	}
	tools, err := prepareFunctions(snapshot.Tool, request.FunctionNames, messages)
	if err != nil {
		return GenerateResult{}, err
	}
	body, err := json.Marshal(struct {
		Model           string        `json:"model"`
		Messages        []Message     `json:"messages"`
		Temperature     float64       `json:"temperature"`
		MaxTokens       int           `json:"max_tokens,omitempty"`
		Thinking        *thinkingMode `json:"thinking,omitempty"`
		ReasoningEffort string        `json:"reasoning_effort,omitempty"`
		Tools           []wireTool    `json:"tools,omitempty"`
	}{Model: model.Key, Messages: messages, Temperature: request.Temperature, MaxTokens: request.MaxTokens, Thinking: thinking, ReasoningEffort: snapshot.Model.ReasoningEffort, Tools: tools})
	if err != nil {
		return GenerateResult{}, ErrProviderResponse
	}
	if int64(len(body)) > a.config.MaxRequestBytes {
		return GenerateResult{}, ErrRequestTooLarge
	}
	url, err := endpointURL(endpoint, "chat/completions", a.config)
	if err != nil {
		return GenerateResult{}, err
	}
	response, err := a.do(ctx, url, secret, body)
	if err != nil {
		return GenerateResult{}, err
	}
	var payload struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content   string     `json:"content"`
				ToolCalls []ToolCall `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     *int `json:"prompt_tokens"`
			CompletionTokens *int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(response, &payload) != nil || len(payload.Choices) == 0 || payload.Usage.PromptTokens == nil || payload.Usage.CompletionTokens == nil || *payload.Usage.PromptTokens < 0 || *payload.Usage.CompletionTokens < 0 || (strings.TrimSpace(payload.Choices[0].Message.Content) == "" && len(payload.Choices[0].Message.ToolCalls) == 0 && payload.Choices[0].FinishReason != "length" && payload.Choices[0].FinishReason != "tool_calls") {
		telemetry.RecordModelProviderResponseInvalid()
		return GenerateResult{}, ErrProviderResponse
	}
	choice := payload.Choices[0]
	result := GenerateResult{Text: choice.Message.Content, InputTokens: *payload.Usage.PromptTokens, OutputTokens: *payload.Usage.CompletionTokens, Incomplete: choice.FinishReason == "length", FinishReason: choice.FinishReason}
	if len(choice.Message.ToolCalls) > 0 || choice.FinishReason == "tool_calls" {
		if choice.FinishReason != "tool_calls" || len(choice.Message.ToolCalls) == 0 || validateToolCalls(snapshot.Tool, request.FunctionNames, choice.Message.ToolCalls) != nil || reusedResponseCallID(messages, choice.Message.ToolCalls) {
			// Preserve authentic provider usage for settlement, but release neither
			// a forged tool instruction nor accompanying untrusted answer text.
			result.Text, result.Incomplete, result.FinishReason = "", true, "invalid_tool_calls"
			return result, nil
		}
		if !result.Incomplete {
			result.ToolCalls = choice.Message.ToolCalls
		}
	}
	return result, nil
}

type thinkingMode struct {
	Type string `json:"type"`
}

// Do not silently map an approved setting to an unsupported vendor dialect.
// DeepSeek's documented switch is currently the only supported wire format.
func publishedThinkingMode(endpoint, mode string) (*thinkingMode, error) {
	if mode == "" {
		return nil, nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != "api.deepseek.com" || (mode != "enabled" && mode != "disabled") {
		return nil, ErrModelUnavailable
	}
	return &thinkingMode{Type: mode}, nil
}

func (a *HTTPAdapter) Embed(ctx context.Context, scope sharedkernel.Scope, snapshot policyasset.Snapshot, inputs []string) ([][]float32, error) {
	result, err := a.embedding(ctx, scope, snapshot, inputs, false)
	return result.Vectors, err
}
func (a *HTTPAdapter) EmbedWithUsage(ctx context.Context, scope sharedkernel.Scope, snapshot policyasset.Snapshot, inputs []string) (EmbeddingResult, error) {
	return a.embedding(ctx, scope, snapshot, inputs, true)
}
func (a *HTTPAdapter) embedding(ctx context.Context, scope sharedkernel.Scope, snapshot policyasset.Snapshot, inputs []string, requireUsage bool) (EmbeddingResult, error) {
	if err := scope.ValidateTrusted(); err != nil || len(inputs) == 0 {
		return EmbeddingResult{}, ErrProviderUnavailable
	}
	selectedPolicy, err := snapshot.Model.ForEmbedding()
	if err != nil {
		return EmbeddingResult{}, ErrModelUnavailable
	}
	snapshot.Model = selectedPolicy
	model, provider, endpoint, secret, err := a.resolve(ctx, scope, snapshot.Model.ModelVersionID, "", "")
	if err != nil {
		return EmbeddingResult{}, err
	}
	defer zero(secret)
	if requireUsage && model.Kind != "embedding" {
		return EmbeddingResult{}, ErrModelUnavailable
	}
	if !snapshotMatches(snapshot, provider, model) || provider.TrustZone == trustExternal && !snapshot.Model.AllowExternal {
		return EmbeddingResult{}, ErrModelUnavailable
	}
	body, err := json.Marshal(struct {
		Model string   `json:"model"`
		Input []string `json:"input"`
	}{model.Key, inputs})
	if err != nil {
		return EmbeddingResult{}, ErrProviderResponse
	}
	if int64(len(body)) > a.config.MaxRequestBytes {
		return EmbeddingResult{}, ErrRequestTooLarge
	}
	url, err := endpointURL(endpoint, "embeddings", a.config)
	if err != nil {
		return EmbeddingResult{}, err
	}
	response, err := a.do(ctx, url, secret, body)
	if err != nil {
		return EmbeddingResult{}, err
	}
	var payload struct {
		Usage struct {
			PromptTokens *int `json:"prompt_tokens"`
			TotalTokens  *int `json:"total_tokens"`
		} `json:"usage"`
		Data []struct {
			Index     int       `json:"index"`
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if json.Unmarshal(response, &payload) != nil || len(payload.Data) != len(inputs) {
		telemetry.RecordModelProviderResponseInvalid()
		return EmbeddingResult{}, ErrProviderResponse
	}
	if requireUsage && (payload.Usage.PromptTokens == nil || payload.Usage.TotalTokens == nil || *payload.Usage.PromptTokens < 0 || *payload.Usage.TotalTokens != *payload.Usage.PromptTokens) {
		telemetry.RecordModelProviderResponseInvalid()
		return EmbeddingResult{}, ErrProviderResponse
	}
	result := make([][]float32, len(inputs))
	seen := make([]bool, len(inputs))
	for _, item := range payload.Data {
		if item.Index < 0 || item.Index >= len(inputs) || seen[item.Index] || len(item.Embedding) == 0 || len(item.Embedding) > 65536 {
			telemetry.RecordModelProviderResponseInvalid()
			return EmbeddingResult{}, ErrProviderResponse
		}
		if requireUsage && len(item.Embedding) > 4096 {
			return EmbeddingResult{}, ErrProviderResponse
		}
		vector := make([]float32, len(item.Embedding))
		norm := float64(0)
		for i, value := range item.Embedding {
			if math.IsNaN(value) || math.IsInf(value, 0) || value > math.MaxFloat32 || value < -math.MaxFloat32 {
				telemetry.RecordModelProviderResponseInvalid()
				return EmbeddingResult{}, ErrProviderResponse
			}
			vector[i] = float32(value)
			norm += float64(vector[i]) * float64(vector[i])
		}
		if requireUsage && (norm == 0 || len(result[0]) > 0 && len(result[0]) != len(vector)) {
			return EmbeddingResult{}, ErrProviderResponse
		}
		result[item.Index], seen[item.Index] = vector, true
	}
	if requireUsage {
		for _, vector := range result {
			if len(vector) != len(result[0]) {
				return EmbeddingResult{}, ErrProviderResponse
			}
		}
	}
	usage := 0
	if payload.Usage.PromptTokens != nil {
		usage = *payload.Usage.PromptTokens
	}
	return EmbeddingResult{Vectors: result, InputTokens: usage}, nil
}

func (a *HTTPAdapter) resolve(ctx context.Context, scope sharedkernel.Scope, versionID, modelID, providerID string) (ModelMetadata, ProviderMetadata, string, []byte, error) {
	if strings.TrimSpace(versionID) == "" {
		return ModelMetadata{}, ProviderMetadata{}, "", nil, ErrModelUnavailable
	}
	selection, err := a.access.ResolveModel(ctx, scope, versionID)
	if err != nil || selection.ModelVersionID != versionID || (modelID != "" && selection.ModelID != modelID) || (providerID != "" && selection.ProviderID != providerID) {
		return ModelMetadata{}, ProviderMetadata{}, "", nil, ErrModelUnavailable
	}
	model, err := a.models.GetApprovedModel(ctx, versionID)
	if err != nil || model.Status != approvedStatus || model.VersionID != versionID || model.ID == "" || model.ProviderID == "" || model.Key == "" || (modelID != "" && model.ID != modelID) || (providerID != "" && model.ProviderID != providerID) {
		return ModelMetadata{}, ProviderMetadata{}, "", nil, ErrModelUnavailable
	}
	provider, err := a.providers.GetApprovedProvider(ctx, model.ProviderID)
	if err != nil || provider.Status != approvedStatus || provider.ID != model.ProviderID || provider.Key == "" || provider.EndpointRef == "" || provider.SecretRef == "" || (provider.TrustZone != trustLocal && provider.TrustZone != trustPrivate && provider.TrustZone != trustExternal) || selection.ProviderID != provider.ID || selection.ProviderKey != provider.Key || selection.ModelID != model.ID || selection.ModelKey != model.Key || selection.TrustZone != provider.TrustZone {
		return ModelMetadata{}, ProviderMetadata{}, "", nil, ErrProviderUnavailable
	}
	endpointRef := provider.EndpointRef
	if provider.TrustZone == trustLocal {
		if selection.DeploymentID == "" || selection.EndpointRef == "" || selection.CapacityUnits <= 0 {
			return ModelMetadata{}, ProviderMetadata{}, "", nil, ErrModelUnavailable
		}
		endpointRef = selection.EndpointRef
	}
	endpoint, err := a.endpoints.ResolveEndpoint(ctx, endpointRef)
	if err != nil {
		return ModelMetadata{}, ProviderMetadata{}, "", nil, ErrEndpointUnresolved
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || validateEndpointURL(parsed, a.config) != nil {
		return ModelMetadata{}, ProviderMetadata{}, "", nil, ErrUnsafeEndpoint
	}
	if !validSecretReference(provider.SecretRef) {
		return ModelMetadata{}, ProviderMetadata{}, "", nil, ErrSecretUnavailable
	}
	secret, err := a.secrets.ResolveSecret(ctx, provider.SecretRef)
	if err != nil || len(secret) == 0 || int64(len(secret)) > a.config.MaxSecretBytes || bytes.IndexAny(secret, "\r\n") >= 0 {
		zero(secret)
		return ModelMetadata{}, ProviderMetadata{}, "", nil, ErrSecretUnavailable
	}
	return model, provider, parsed.String(), secret, nil
}

func (a *HTTPAdapter) do(ctx context.Context, endpoint string, secret, body []byte) (result []byte, returnedErr error) {
	ctx, cancel := context.WithTimeout(ctx, a.config.RequestTimeout)
	defer cancel()
	ctx, span := telemetry.Start(ctx, "platform.model.provider", trace.SpanKindClient)
	defer span.End()
	defer func() {
		if returnedErr != nil {
			telemetry.Failed(span, "MODEL_PROVIDER_FAILED")
		}
	}()
	defer func() { telemetry.RecordModelProviderTransport(returnedErr == nil) }()
	response, err := a.connectProvider(ctx, endpoint, secret, body)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, a.config.MaxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, &ProviderFailure{Category: "body_read", StatusCode: response.StatusCode}
	}
	if int64(len(data)) > a.config.MaxResponseBytes {
		return nil, ErrResponseTooLarge
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &ProviderFailure{Category: "http_response", StatusCode: response.StatusCode}
	}
	return data, nil
}

func snapshotMatches(snapshot policyasset.Snapshot, provider ProviderMetadata, model ModelMetadata) bool {
	return snapshot.Model.ModelVersionID == model.VersionID && snapshot.Model.Provider == provider.Key && snapshot.Model.Model == model.Key
}

func endpointURL(base, suffix string, config HTTPConfig) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil || validateEndpointURL(parsed, config) != nil {
		return "", ErrUnsafeEndpoint
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/" + suffix
	parsed.RawPath = ""
	return parsed.String(), nil
}

func validateEndpointURL(endpoint *url.URL, config HTTPConfig) error {
	if endpoint == nil || endpoint.User != nil || endpoint.Hostname() == "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return ErrUnsafeEndpoint
	}
	host := strings.TrimSuffix(strings.ToLower(endpoint.Hostname()), ".")
	if endpoint.Scheme == "http" {
		ip, err := netip.ParseAddr(host)
		loopbackHost := host == "localhost"
		if err != nil && !loopbackHost || !config.AllowLoopbackDevelopment || err == nil && !ip.IsLoopback() {
			return ErrUnsafeEndpoint
		}
	} else if endpoint.Scheme != "https" {
		return ErrUnsafeEndpoint
	}
	if port := endpoint.Port(); port != "" {
		allowed := endpoint.Scheme == "https" && containsString(config.AllowedHTTPSPorts, port)
		if endpoint.Scheme == "http" && config.AllowLoopbackDevelopment {
			allowed = true
		}
		if !allowed {
			return ErrUnsafeEndpoint
		}
	} else if endpoint.Scheme == "http" || endpoint.Scheme == "https" {
		// Default ports are unambiguous and permitted; explicit ports are allowlisted above.
	} else {
		return ErrUnsafeEndpoint
	}
	return nil
}

func validSecretReference(reference string) bool {
	if !strings.HasPrefix(reference, "secret://") && !strings.HasPrefix(reference, "file://") {
		return false
	}
	value := strings.TrimPrefix(strings.TrimPrefix(reference, "secret://"), "file://")
	if value == "" || strings.ContainsAny(value, "\\\x00\r\n?:#") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

type safeDialer struct {
	resolver      IPResolver
	timeout       time.Duration
	allowLoopback bool
}

func (d *safeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrUnsafeEndpoint
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, ErrUnsafeEndpoint
	}
	if d.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.timeout)
		defer cancel()
	}
	ip, parseErr := netip.ParseAddr(strings.Trim(host, "[]"))
	addresses := []net.IPAddr{}
	if parseErr == nil {
		addresses = append(addresses, net.IPAddr{IP: net.IP(ip.AsSlice())})
	} else {
		addresses, err = d.resolver.LookupIPAddr(ctx, host)
		if err != nil || len(addresses) == 0 {
			return nil, ErrUnsafeEndpoint
		}
	}
	for _, candidate := range addresses {
		addr, ok := netip.AddrFromSlice(candidate.IP)
		if !ok || !allowedResolvedAddress(addr, d.allowLoopback) {
			return nil, ErrUnsafeEndpoint
		}
	}
	dialer := net.Dialer{Timeout: d.timeout}
	var lastErr error
	for _, candidate := range addresses {
		addr, _ := netip.AddrFromSlice(candidate.IP)
		conn, dialErr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(addr.Unmap().String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no resolved address")
	}
	return nil, lastErr
}

var deniedAddressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // Carrier-grade NAT.
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2001::/23"),
}

func allowedResolvedAddress(address netip.Addr, allowLoopback bool) bool {
	address = address.Unmap()
	if allowLoopback && address.IsLoopback() {
		return true
	}
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	for _, prefix := range deniedAddressPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// MountedSecretResolver only accepts relative secret:// or file:// references
// underneath a configured mounted directory. Symlink resolution is checked
// after canonicalizing both the root and target to block escape.
type MountedSecretResolver struct {
	Root     string
	MaxBytes int64
}

func (r MountedSecretResolver) ResolveSecret(_ context.Context, reference string) ([]byte, error) {
	if r.Root == "" || (!strings.HasPrefix(reference, "secret://") && !strings.HasPrefix(reference, "file://")) {
		return nil, ErrSecretUnavailable
	}
	root, err := filepath.EvalSymlinks(r.Root)
	if err != nil {
		return nil, ErrSecretUnavailable
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, ErrSecretUnavailable
	}
	relative := strings.TrimPrefix(strings.TrimPrefix(reference, "secret://"), "file://")
	if relative == "" || strings.ContainsAny(relative, "\\\x00\r\n?:#") {
		return nil, ErrSecretUnavailable
	}
	for _, component := range strings.Split(strings.ReplaceAll(relative, "\\", "/"), "/") {
		if component == "" || component == "." || component == ".." {
			return nil, ErrSecretUnavailable
		}
	}
	clean := filepath.Clean(filepath.FromSlash(relative))
	if filepath.IsAbs(clean) || filepath.VolumeName(clean) != "" {
		return nil, ErrSecretUnavailable
	}
	target, err := filepath.EvalSymlinks(filepath.Join(root, clean))
	if err != nil {
		return nil, ErrSecretUnavailable
	}
	target, err = filepath.Abs(target)
	if err != nil {
		return nil, ErrSecretUnavailable
	}
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, ErrSecretUnavailable
	}
	info, err := os.Stat(target)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrSecretUnavailable
	}
	limit := r.MaxBytes
	if limit <= 0 {
		limit = 64 << 10
	}
	if info.Size() > limit {
		return nil, ErrSecretUnavailable
	}
	file, err := os.Open(target)
	if err != nil {
		return nil, ErrSecretUnavailable
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(value)) > limit {
		zero(value)
		return nil, ErrSecretUnavailable
	}
	trimmed := bytes.Clone(bytes.TrimSpace(value))
	zero(value)
	if len(trimmed) == 0 {
		return nil, ErrSecretUnavailable
	}
	return trimmed, nil
}

// StaticEndpointResolver is useful for deployment-owned configuration and
// tests. Unresolved service://, k8s://, or ref:// references fail closed.
type StaticEndpointResolver map[string]string

func (r StaticEndpointResolver) ResolveEndpoint(_ context.Context, reference string) (string, error) {
	if !strings.HasPrefix(reference, "service://") && !strings.HasPrefix(reference, "k8s://") && !strings.HasPrefix(reference, "ref://") {
		return "", ErrEndpointUnresolved
	}
	endpoint, ok := r[reference]
	if !ok || strings.TrimSpace(endpoint) == "" {
		return "", ErrEndpointUnresolved
	}
	return endpoint, nil
}

var _ Port = (*HTTPAdapter)(nil)
var _ SecretResolver = MountedSecretResolver{}
var _ EndpointResolver = StaticEndpointResolver{}
