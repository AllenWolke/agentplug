// Package modelgovernance owns model Providers, definitions, immutable model
// versions, scoped deployments, and application model-access policy metadata.
// Provider credentials are represented only by SecretRef values; this package
// never resolves or returns secret material.
package modelgovernance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
)

var (
	ErrInvalidRequest    = errors.New("invalid model governance request")
	ErrInvalidSecretRef  = errors.New("invalid model Provider SecretRef")
	ErrUnsafeEndpoint    = errors.New("model Provider endpoint is not allowed")
	ErrNotFound          = errors.New("model governance resource not found")
	ErrRevisionConflict  = errors.New("model governance revision conflict")
	ErrAlreadyExists     = errors.New("model governance resource already exists")
	ErrPriceOverlap      = errors.New("model price effective interval overlaps another version")
	ErrForbidden         = errors.New("model governance operation is forbidden")
	ErrModelAccessDenied = errors.New("model access is denied by governance policy")
)

const (
	ProviderOnPrem          = "on_prem"
	ProviderPrivateCloud    = "private_cloud"
	ProviderExternalManaged = "external_managed"

	TrustLocal    = "local"
	TrustPrivate  = "private"
	TrustExternal = "external"

	StatusDraft    = "draft"
	StatusApproved = "approved"
	StatusDisabled = "disabled"

	ModelKindChat      = "chat"
	ModelKindEmbedding = "embedding"
)

type Action string

const (
	ActionRead             Action = "read"
	ActionCreate           Action = "create"
	ActionTest             Action = "test"
	ActionApprove          Action = "approve"
	ActionDisable          Action = "disable"
	ActionManageDeployment Action = "manage_deployment"
	ActionManagePolicy     Action = "manage_access_policy"
)

// Scope identifies an ownership boundary. Provider/model catalog records use
// the global scope; deployments and access policies use tenant scopes.
type Scope struct {
	TenantID      string `json:"tenant_id"`
	DepartmentID  string `json:"department_id"`
	ApplicationID string `json:"application_id"`
}

func (s Scope) IsGlobal() bool {
	return s.TenantID == "" && s.DepartmentID == "" && s.ApplicationID == ""
}

// Actor is built only from trusted gateway headers. The injected Authorizer
// loads current Identity state and authorizes model control-plane operations.
type Actor struct {
	TenantID      string
	DepartmentID  string
	ApplicationID string
	PrincipalType string
	PrincipalID   string
	Browser       bool
}

type Authorizer interface {
	AuthorizeModelGovernance(context.Context, Actor, Action, Scope) error
}

type Provider struct {
	ID               string          `json:"id"`
	TenantID         string          `json:"tenant_id"`
	DepartmentID     string          `json:"department_id"`
	ApplicationID    string          `json:"application_id"`
	ProviderKey      string          `json:"provider_key"`
	DisplayName      string          `json:"display_name"`
	Type             string          `json:"type"`
	TrustZone        string          `json:"trust_zone"`
	EndpointRef      string          `json:"endpoint_ref"`
	NetworkZone      string          `json:"network_zone"`
	Region           string          `json:"region"`
	OwnerID          string          `json:"owner_id"`
	SecretRef        string          `json:"secret_ref"`
	RetentionMode    string          `json:"retention_mode"`
	TrainingUsage    string          `json:"training_usage"`
	ComplianceStatus string          `json:"compliance_status"`
	Capabilities     json.RawMessage `json:"capabilities"`
	Status           string          `json:"status"`
	HealthStatus     string          `json:"health_status"`
	Revision         uint64          `json:"revision"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// CreateProviderRequest keeps the existing browser payload fields. Legacy
// scope fields are accepted only as consistency hints and are never used to
// establish the actor or the stored ownership scope.
type CreateProviderRequest struct {
	TenantID         string          `json:"tenant_id"`
	DepartmentID     string          `json:"department_id"`
	ApplicationID    string          `json:"application_id"`
	ProviderKey      string          `json:"provider_key"`
	DisplayName      string          `json:"display_name"`
	Type             string          `json:"type"`
	TrustZone        string          `json:"trust_zone"`
	EndpointRef      string          `json:"endpoint_ref"`
	NetworkZone      string          `json:"network_zone"`
	Region           string          `json:"region"`
	OwnerID          string          `json:"owner_id"`
	SecretRef        string          `json:"secret_ref"`
	RetentionMode    string          `json:"retention_mode"`
	TrainingUsage    string          `json:"training_usage"`
	ComplianceStatus string          `json:"compliance_status"`
	Capabilities     json.RawMessage `json:"capabilities"`
}

type ModelDefinition struct {
	ID              string          `json:"id"`
	TenantID        string          `json:"tenant_id"`
	DepartmentID    string          `json:"department_id"`
	ApplicationID   string          `json:"application_id"`
	ProviderID      string          `json:"provider_id"`
	ModelKey        string          `json:"model_key"`
	Kind            string          `json:"kind"`
	DisplayName     string          `json:"display_name"`
	Capabilities    json.RawMessage `json:"capabilities"`
	ContextLimit    int             `json:"context_limit"`
	LifecycleStatus string          `json:"lifecycle_status"`
	Revision        uint64          `json:"revision"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

type CreateModelDefinitionRequest struct {
	ProviderID   string          `json:"provider_id"`
	ModelKey     string          `json:"model_key"`
	Kind         string          `json:"kind"`
	DisplayName  string          `json:"display_name"`
	Capabilities json.RawMessage `json:"capabilities"`
	ContextLimit int             `json:"context_limit"`
}

type ModelVersion struct {
	ID                  string    `json:"id"`
	DefinitionID        string    `json:"definition_id"`
	SemanticVersion     string    `json:"semantic_version"`
	ProviderFingerprint string    `json:"provider_fingerprint"`
	ArtifactDigest      string    `json:"artifact_digest"`
	Quantization        string    `json:"quantization"`
	CapabilityHash      string    `json:"capability_hash"`
	Status              string    `json:"status"`
	Revision            uint64    `json:"revision"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// PriceVersion is an immutable price snapshot for an approved ModelVersion.
// It contains accounting rates only; provider credentials and SecretRefs are
// deliberately outside this public DTO.
type PriceVersion struct {
	CachedInputMicrosPer1K *int64     `json:"cached_input_micros_per_1k_tokens,omitempty"`
	ID                     string     `json:"id"`
	ModelVersionID         string     `json:"model_version_id"`
	Currency               string     `json:"currency"`
	InputMicrosPer1K       int64      `json:"input_micros_per_1k_tokens"`
	OutputMicrosPer1K      int64      `json:"output_micros_per_1k_tokens"`
	EffectiveFrom          time.Time  `json:"effective_from"`
	EffectiveUntil         *time.Time `json:"effective_until,omitempty"`
	ContentHash            string     `json:"content_hash"`
	Status                 string     `json:"status"`
	Revision               uint64     `json:"revision"`
	CreatedBy              string     `json:"created_by"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

// CreatePriceVersionRequest is intentionally free of caller-selected scope
// and credential fields. Its identity is supplied by the trusted gateway.
type CreatePriceVersionRequest struct {
	CachedInputMicrosPer1K *int64     `json:"cached_input_micros_per_1k_tokens,omitempty"`
	ModelVersionID         string     `json:"model_version_id"`
	Currency               string     `json:"currency"`
	InputMicrosPer1K       int64      `json:"input_micros_per_1k_tokens"`
	OutputMicrosPer1K      int64      `json:"output_micros_per_1k_tokens"`
	EffectiveFrom          time.Time  `json:"effective_from"`
	EffectiveUntil         *time.Time `json:"effective_until,omitempty"`
}

// PriceResolver is a read-only port for resolving exactly one approved price
// for a model version at a point in time. Runtime wiring is owned elsewhere.
type PriceResolver interface {
	ResolvePrice(context.Context, string, time.Time) (PriceVersion, error)
}

// Deployment is a scoped desired-state record. It contains no Kubernetes
// object and creating one never triggers an external scheduler.
type Deployment struct {
	ID               string          `json:"id"`
	TenantID         string          `json:"tenant_id"`
	DepartmentID     string          `json:"department_id"`
	ApplicationID    string          `json:"application_id"`
	ModelVersionID   string          `json:"model_version_id"`
	Environment      string          `json:"environment"`
	EndpointRef      string          `json:"endpoint_ref"`
	RuntimeKind      string          `json:"runtime_kind"`
	ResourceProfile  json.RawMessage `json:"resource_profile"`
	MinReplicas      int             `json:"min_replicas"`
	MaxReplicas      int             `json:"max_replicas"`
	Capacity         json.RawMessage `json:"capacity"`
	HealthStatus     string          `json:"health_status"`
	Status           string          `json:"status"`
	ObservedRevision uint64          `json:"observed_revision"`
	Revision         uint64          `json:"revision"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

type CreateDeploymentRequest struct {
	TenantID        string          `json:"tenant_id"`
	DepartmentID    string          `json:"department_id"`
	ApplicationID   string          `json:"application_id"`
	ModelVersionID  string          `json:"model_version_id"`
	Environment     string          `json:"environment"`
	EndpointRef     string          `json:"endpoint_ref"`
	RuntimeKind     string          `json:"runtime_kind"`
	ResourceProfile json.RawMessage `json:"resource_profile"`
	MinReplicas     int             `json:"min_replicas"`
	MaxReplicas     int             `json:"max_replicas"`
	Capacity        json.RawMessage `json:"capacity"`
}

// AccessPolicy has no token or money budgets. Those need a real metering and
// accounting owner; this slice only expresses model and trust-zone allowlists.
type AccessPolicy struct {
	ID               string     `json:"id"`
	TenantID         string     `json:"tenant_id"`
	DepartmentID     string     `json:"department_id"`
	ApplicationID    string     `json:"application_id"`
	InstallationID   string     `json:"installation_id"`
	AgentVersionID   string     `json:"agent_version_id"`
	PrincipalID      string     `json:"principal_id"`
	AllowLocal       bool       `json:"allow_local"`
	AllowPrivate     bool       `json:"allow_private"`
	AllowExternal    bool       `json:"allow_external"`
	AllowedProviders []string   `json:"allowed_providers"`
	AllowedModels    []string   `json:"allowed_models"`
	EffectiveFrom    *time.Time `json:"effective_from,omitempty"`
	EffectiveUntil   *time.Time `json:"effective_until,omitempty"`
	Status           string     `json:"status"`
	Revision         uint64     `json:"revision"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type CreateAccessPolicyRequest struct {
	TenantID         string     `json:"tenant_id"`
	DepartmentID     string     `json:"department_id"`
	ApplicationID    string     `json:"application_id"`
	InstallationID   string     `json:"installation_id"`
	AgentVersionID   string     `json:"agent_version_id"`
	PrincipalID      string     `json:"principal_id"`
	AllowLocal       bool       `json:"allow_local"`
	AllowPrivate     bool       `json:"allow_private"`
	AllowExternal    bool       `json:"allow_external"`
	AllowedProviders []string   `json:"allowed_providers"`
	AllowedModels    []string   `json:"allowed_models"`
	EffectiveFrom    *time.Time `json:"effective_from,omitempty"`
	EffectiveUntil   *time.Time `json:"effective_until,omitempty"`
}

const (
	DeploymentPending  = "pending"
	DeploymentReady    = "ready"
	DeploymentFailed   = "failed"
	DeploymentDraining = "draining"
	DeploymentDisabled = "disabled"
	PolicyDraft        = "draft"
	PolicyApproved     = "approved"
	PolicyRevoked      = "revoked"
)

type ModelAccessScope struct {
	TenantID       string
	DepartmentID   string
	ApplicationID  string
	InstallationID string
	AgentVersionID string
	PrincipalID    string
}

type ResolvedModel struct {
	VersionID      string
	DefinitionID   string
	ProviderID     string
	ProviderKey    string
	ModelKey       string
	Kind           string
	TrustZone      string
	VersionStatus  string
	ProviderStatus string
}

type CreateModelVersionRequest struct {
	SemanticVersion     string `json:"semantic_version"`
	ProviderFingerprint string `json:"provider_fingerprint"`
	ArtifactDigest      string `json:"artifact_digest"`
	Quantization        string `json:"quantization"`
	CapabilityHash      string `json:"capability_hash"`
}

type ProviderTestResult struct {
	ProviderID string    `json:"provider_id"`
	Validated  bool      `json:"validated"`
	Reason     string    `json:"reason"`
	CheckedAt  time.Time `json:"checked_at,omitempty"`
}

var (
	providerKeyPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	endpointRefPattern     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,62}(/[A-Za-z][A-Za-z0-9-]{0,62})?$`)
	semanticVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9._-]+)?$`)
	sha256DigestPattern    = regexp.MustCompile(`^sha256:[a-fA-F0-9]{64}$`)
)

func normalizeJSONObject(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return json.RawMessage(`{}`), nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, fmt.Errorf("%w: capabilities must be a JSON object", ErrInvalidRequest)
	}
	canonical, err := json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("%w: capabilities must be a JSON object", ErrInvalidRequest)
	}
	return canonical, nil
}

func validateSecretRef(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "..") || strings.ContainsAny(value, "\\\r\n?#") {
		return ErrInvalidSecretRef
	}
	for _, prefix := range []string{"secret://", "file://"} {
		if strings.HasPrefix(value, prefix) && len(strings.TrimSpace(strings.TrimPrefix(value, prefix))) > 0 {
			return nil
		}
	}
	return ErrInvalidSecretRef
}

func providerTypeMatchesTrust(providerType, trustZone string) bool {
	switch providerType {
	case ProviderOnPrem:
		return trustZone == TrustLocal
	case ProviderPrivateCloud:
		return trustZone == TrustPrivate
	case ProviderExternalManaged:
		return trustZone == TrustExternal
	default:
		return false
	}
}

func validateCreateProvider(in CreateProviderRequest, actor Actor, endpointCheck func(string, bool) error, allowLocal bool) (Provider, error) {
	in.ProviderKey = strings.TrimSpace(in.ProviderKey)
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	in.Type = strings.TrimSpace(in.Type)
	in.TrustZone = strings.TrimSpace(in.TrustZone)
	in.EndpointRef = strings.TrimSpace(in.EndpointRef)
	in.SecretRef = strings.TrimSpace(in.SecretRef)
	if !providerKeyPattern.MatchString(in.ProviderKey) || in.DisplayName == "" || !providerTypeMatchesTrust(in.Type, in.TrustZone) {
		return Provider{}, ErrInvalidRequest
	}
	if in.TenantID != "" && in.TenantID != actor.TenantID || in.DepartmentID != "" && in.DepartmentID != actor.DepartmentID || in.ApplicationID != "" && in.ApplicationID != actor.ApplicationID {
		return Provider{}, ErrForbidden
	}
	if err := validateSecretRef(in.SecretRef); err != nil {
		return Provider{}, err
	}
	if endpointCheck == nil {
		return Provider{}, ErrUnsafeEndpoint
	}
	// Runtime invocation resolves only deployment-owned symbolic references.
	// Persisting an arbitrary URL here would create a control-plane path that
	// could not be deterministically allowlisted at process startup.
	// 运行期只解析运维配置的符号引用；此处不持久化任意 URL，避免绕过进程级白名单。
	if !isEndpointReference(in.EndpointRef) {
		return Provider{}, ErrUnsafeEndpoint
	}
	if err := endpointCheck(in.EndpointRef, allowLocal && in.Type != ProviderExternalManaged); err != nil {
		return Provider{}, err
	}
	capabilities, err := normalizeJSONObject(in.Capabilities)
	if err != nil {
		return Provider{}, err
	}
	return Provider{
		ProviderKey: in.ProviderKey, DisplayName: in.DisplayName, Type: in.Type, TrustZone: in.TrustZone,
		EndpointRef: in.EndpointRef, NetworkZone: strings.TrimSpace(in.NetworkZone), Region: strings.TrimSpace(in.Region),
		OwnerID: actor.PrincipalID, SecretRef: in.SecretRef, RetentionMode: defaultValue(in.RetentionMode, "provider_defined"),
		TrainingUsage: defaultValue(in.TrainingUsage, "unknown"), ComplianceStatus: defaultValue(in.ComplianceStatus, "pending"),
		Capabilities: capabilities, Status: StatusDraft, HealthStatus: "unknown", Revision: 1,
	}, nil
}

func validateCreateDefinition(in CreateModelDefinitionRequest) (ModelDefinition, error) {
	in.ProviderID = strings.TrimSpace(in.ProviderID)
	in.ModelKey = strings.TrimSpace(in.ModelKey)
	in.Kind = strings.TrimSpace(in.Kind)
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.ProviderID == "" || !providerKeyPattern.MatchString(in.ModelKey) || in.DisplayName == "" || (in.Kind != ModelKindChat && in.Kind != ModelKindEmbedding) || in.ContextLimit < 1 || in.ContextLimit > 2_000_000 {
		return ModelDefinition{}, ErrInvalidRequest
	}
	capabilities, err := normalizeJSONObject(in.Capabilities)
	if err != nil {
		return ModelDefinition{}, err
	}
	if wire, err := modelgateway.ParseWireCapabilities(capabilities); err != nil || in.Kind != ModelKindChat && wire.ContextCacheMode != "" {
		return ModelDefinition{}, ErrInvalidRequest
	}
	return ModelDefinition{ProviderID: in.ProviderID, ModelKey: in.ModelKey, Kind: in.Kind, DisplayName: in.DisplayName, Capabilities: capabilities, ContextLimit: in.ContextLimit, LifecycleStatus: StatusDraft, Revision: 1}, nil
}

func validateCreateVersion(definition ModelDefinition, provider Provider, in CreateModelVersionRequest) (ModelVersion, error) {
	in.SemanticVersion = strings.TrimSpace(in.SemanticVersion)
	in.ProviderFingerprint = strings.TrimSpace(in.ProviderFingerprint)
	in.ArtifactDigest = strings.TrimSpace(in.ArtifactDigest)
	in.Quantization = strings.TrimSpace(in.Quantization)
	in.CapabilityHash = strings.TrimSpace(in.CapabilityHash)
	if !semanticVersionPattern.MatchString(in.SemanticVersion) || in.ProviderFingerprint == "" {
		return ModelVersion{}, ErrInvalidRequest
	}
	if provider.Type == ProviderOnPrem && !sha256DigestPattern.MatchString(in.ArtifactDigest) {
		return ModelVersion{}, ErrInvalidRequest
	}
	if in.ArtifactDigest != "" && !sha256DigestPattern.MatchString(in.ArtifactDigest) {
		return ModelVersion{}, ErrInvalidRequest
	}
	if in.CapabilityHash != "" && !sha256DigestPattern.MatchString("sha256:"+strings.TrimPrefix(strings.ToLower(in.CapabilityHash), "sha256:")) {
		return ModelVersion{}, ErrInvalidRequest
	}
	return ModelVersion{DefinitionID: definition.ID, SemanticVersion: in.SemanticVersion, ProviderFingerprint: in.ProviderFingerprint, ArtifactDigest: in.ArtifactDigest, Quantization: in.Quantization, CapabilityHash: strings.TrimPrefix(strings.ToLower(in.CapabilityHash), "sha256:"), Status: StatusDraft, Revision: 1}, nil
}

func defaultValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

// ValidateEndpoint rejects arbitrary network targets that could become SSRF.
// Symbolic service references are resolved later by a trusted runtime adapter.
func ValidateEndpoint(raw string, allowLocal bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return ValidateEndpointContext(ctx, raw, allowLocal, net.DefaultResolver.LookupIP)
}

// ValidateEndpointContext exposes DNS lookup as a seam for deterministic
// tests. Every resolved address must be public; only loopback is permitted for
// explicitly enabled local, non-external Providers.
func ValidateEndpointContext(ctx context.Context, raw string, allowLocal bool, lookup func(context.Context, string, string) ([]net.IP, error)) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("%w: endpoint is empty", ErrUnsafeEndpoint)
	}
	if isEndpointReference(raw) {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: malformed endpoint", ErrUnsafeEndpoint)
	}
	if u.Scheme != "https" && !(allowLocal && u.Scheme == "http") {
		return fmt.Errorf("%w: https is required", ErrUnsafeEndpoint)
	}
	if err := validateEndpointPort(u); err != nil {
		return err
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		if !allowLocal {
			return fmt.Errorf("%w: localhost is not allowed", ErrUnsafeEndpoint)
		}
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if forbiddenEndpointIP(ip) && !(allowLocal && ip.IsLoopback()) {
			return fmt.Errorf("%w: private or special address", ErrUnsafeEndpoint)
		}
		return nil
	}
	if lookup == nil {
		return fmt.Errorf("%w: resolver unavailable", ErrUnsafeEndpoint)
	}
	ips, err := lookup(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("%w: hostname cannot be resolved", ErrUnsafeEndpoint)
	}
	for _, ip := range ips {
		if forbiddenEndpointIP(ip) && !(allowLocal && ip.IsLoopback()) {
			return fmt.Errorf("%w: hostname resolves to private or special address", ErrUnsafeEndpoint)
		}
	}
	return nil
}

func isEndpointReference(raw string) bool {
	lower := strings.ToLower(raw)
	for _, prefix := range []string{"k8s://", "service://", "ref://"} {
		if strings.HasPrefix(lower, prefix) {
			// These are opaque registry keys, never arbitrary hostnames or URLs.
			// A trusted adapter must resolve them before making network calls.
			// 这里只接受受控注册表键，不接受 IP、域名、端口或 URL 路径。
			return endpointRefPattern.MatchString(raw[len(prefix):])
		}
	}
	return false
}

func validateEndpointPort(u *url.URL) error {
	if u.Port() == "" {
		return nil
	}
	port, err := urlPort(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%w: invalid port", ErrUnsafeEndpoint)
	}
	if u.Scheme == "https" && port != 443 && port != 8443 {
		return fmt.Errorf("%w: port is not approved", ErrUnsafeEndpoint)
	}
	return nil
}

func urlPort(value string) (int, error) {
	var port int
	_, err := fmt.Sscanf(value, "%d", &port)
	if err != nil || fmt.Sprintf("%d", port) != value {
		return 0, ErrUnsafeEndpoint
	}
	return port, nil
}

func forbiddenEndpointIP(ip net.IP) bool {
	parsed, err := netip.ParseAddr(ip.String())
	if err != nil {
		return true
	}
	return parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() || parsed.IsUnspecified() || parsed.IsMulticast() || parsed.IsInterfaceLocalMulticast() || !parsed.IsGlobalUnicast()
}
