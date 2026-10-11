package catalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

type DeploymentStatus string

const (
	DeploymentPending  DeploymentStatus = "pending"
	DeploymentReady    DeploymentStatus = "ready"
	DeploymentFailed   DeploymentStatus = "failed"
	DeploymentDraining DeploymentStatus = "draining"
	DeploymentDisabled DeploymentStatus = "disabled"
)

type DefinitionStatus string

const (
	DefinitionDraft     DefinitionStatus = "draft"
	DefinitionEvaluated DefinitionStatus = "evaluated"
	DefinitionPublished DefinitionStatus = "published"
	DefinitionDisabled  DefinitionStatus = "disabled"
	DefinitionRetired   DefinitionStatus = "retired"
)

type InstallationStatus string

const (
	InstallationProvisioning InstallationStatus = "provisioning"
	InstallationActive       InstallationStatus = "active"
	InstallationSuspended    InstallationStatus = "suspended"
	InstallationDraining     InstallationStatus = "draining"
	InstallationFailed       InstallationStatus = "failed"
	InstallationUninstalling InstallationStatus = "uninstalling"
	InstallationUninstalled  InstallationStatus = "uninstalled"
)

var (
	ErrInvalidDefinition         = errors.New("invalid agent definition")
	ErrInvalidVersion            = errors.New("invalid agent version")
	ErrInvalidInstallation       = errors.New("invalid agent installation")
	ErrInvalidDeployment         = errors.New("invalid agent deployment")
	ErrIllegalTransition         = errors.New("illegal installation state transition")
	ErrDeploymentNotReady        = errors.New("latest deployment is not observed ready")
	ErrDeploymentVersionMismatch = errors.New("deployment version does not match installation version")
	ErrRevisionConflict          = errors.New("catalog revision conflict")
)

type Definition struct {
	ID          string           `json:"id"`
	PublisherID string           `json:"publisher_id"`
	AgentKey    string           `json:"agent_key"`
	DisplayName string           `json:"display_name"`
	Description string           `json:"description"`
	Status      DefinitionStatus `json:"status"`
	Revision    uint64           `json:"revision"`
	SubmittedBy string           `json:"submitted_by,omitempty"`
	ApprovedBy  string           `json:"approved_by,omitempty"`
}

// PublishedVersion is the minimal, non-secret projection exposed to scoped
// application administrators when selecting a version to install.
// PublishedVersion 是应用管理员选择安装版本时可见的最小非敏感投影。
type PublishedVersion struct {
	ID              string           `json:"id"`
	DefinitionID    string           `json:"definition_id"`
	SemanticVersion string           `json:"semantic_version"`
	ManifestHash    string           `json:"manifest_hash"`
	ArtifactDigest  string           `json:"artifact_digest"`
	Status          DefinitionStatus `json:"status"`
	Revision        uint64           `json:"revision"`
}

type Version struct {
	ID              string           `json:"id"`
	DefinitionID    string           `json:"definition_id"`
	SemanticVersion string           `json:"semantic_version"`
	ManifestHash    string           `json:"manifest_hash"`
	Manifest        json.RawMessage  `json:"manifest"`
	ArtifactDigest  string           `json:"artifact_digest"`
	InputSchema     json.RawMessage  `json:"input_schema"`
	OutputSchema    json.RawMessage  `json:"output_schema"`
	Status          DefinitionStatus `json:"status"`
	Revision        uint64           `json:"revision"`
	CreatedAt       time.Time        `json:"created_at"`
	EvaluatedAt     *time.Time       `json:"evaluated_at,omitempty"`
	PublishedAt     *time.Time       `json:"published_at,omitempty"`
	SubmittedBy     string           `json:"submitted_by,omitempty"`
	ApprovedBy      string           `json:"approved_by,omitempty"`
}

type Installation struct {
	ID                string             `json:"id"`
	TenantID          string             `json:"tenant_id"`
	DepartmentID      string             `json:"department_id"`
	ApplicationID     string             `json:"application_id"`
	AgentID           string             `json:"agent_id"`
	VersionID         string             `json:"version_id"`
	DisplayName       string             `json:"display_name"`
	DeploymentMode    string             `json:"deployment_mode"`
	DrainPolicy       string             `json:"drain_policy"`
	RetentionPolicyID string             `json:"retention_policy_id"`
	Status            InstallationStatus `json:"status"`
	Revision          uint64             `json:"revision"`
}

// Deployment is the desired/observed release boundary for one installation.
// It owns no identity data and references only stable Catalog IDs.
type Deployment struct {
	ID                  string           `json:"id"`
	TenantID            string           `json:"tenant_id"`
	DepartmentID        string           `json:"department_id"`
	ApplicationID       string           `json:"application_id"`
	AgentVersionID      string           `json:"agent_version_id"`
	AgentInstallationID string           `json:"agent_installation_id"`
	ArtifactDigest      string           `json:"artifact_digest"`
	Transport           string           `json:"transport"`
	EndpointRef         string           `json:"endpoint_ref"`
	PlacementPolicy     json.RawMessage  `json:"placement_policy"`
	ResourcePolicy      json.RawMessage  `json:"resource_policy"`
	Status              DeploymentStatus `json:"status"`
	DesiredRevision     uint64           `json:"desired_revision"`
	ObservedRevision    uint64           `json:"observed_revision"`
	ManifestHash        string           `json:"manifest_hash"`
	CreatedAt           time.Time        `json:"created_at"`
	UpdatedAt           time.Time        `json:"updated_at"`
}

type VersionSnapshot struct {
	DefinitionID   string `json:"definition_id"`
	AgentID        string `json:"agent_id"`
	VersionID      string `json:"version_id"`
	Version        string `json:"version"`
	ManifestHash   string `json:"manifest_hash"`
	ArtifactDigest string `json:"artifact_digest"`
}

func (d Definition) Validate() error {
	if strings.TrimSpace(d.ID) == "" || strings.TrimSpace(d.PublisherID) == "" || strings.TrimSpace(d.AgentKey) == "" || strings.TrimSpace(d.DisplayName) == "" || strings.TrimSpace(d.Description) == "" || d.Revision == 0 || !validDefinitionStatus(d.Status) {
		return ErrInvalidDefinition
	}
	return nil
}

func (v Version) Validate() error {
	if strings.TrimSpace(v.ID) == "" || strings.TrimSpace(v.DefinitionID) == "" || strings.TrimSpace(v.SemanticVersion) == "" || !validSHA256Digest(v.ArtifactDigest) || len(v.Manifest) == 0 || len(v.InputSchema) == 0 || len(v.OutputSchema) == 0 || v.Revision == 0 || !validDefinitionStatus(v.Status) {
		return ErrInvalidVersion
	}
	if !jsonObject(v.Manifest) || !jsonObject(v.InputSchema) || !jsonObject(v.OutputSchema) {
		return ErrInvalidVersion
	}
	var manifest agentManifest
	if err := json.Unmarshal(v.Manifest, &manifest); err != nil || manifest.ManifestVersion != "agent-manifest/v1" || strings.TrimSpace(manifest.AgentID) == "" || manifest.Version != v.SemanticVersion || len(manifest.ExecutionProtocols) == 0 || len(manifest.Capabilities) == 0 || !schemaRef(manifest.Schemas.Input) || !schemaRef(manifest.Schemas.Output) || !schemaRef(manifest.Schemas.Event) || !schemaRef(manifest.Schemas.Checkpoint) || (manifest.Runtime.Transport != "http" && manifest.Runtime.Transport != "grpc") || strings.TrimSpace(manifest.Runtime.Isolation) == "" || !strings.HasPrefix(manifest.Runtime.HealthPath, "/") {
		return ErrInvalidVersion
	}
	expectedHash, err := VersionContentHash(v.Manifest, v.InputSchema, v.OutputSchema)
	if err != nil || v.ManifestHash != expectedHash {
		return ErrInvalidVersion
	}
	return nil
}

type agentManifest struct {
	ManifestVersion    string   `json:"manifest_version"`
	AgentID            string   `json:"agent_id"`
	Version            string   `json:"version"`
	ExecutionProtocols []string `json:"execution_protocols"`
	Capabilities       []string `json:"capabilities"`
	Schemas            struct {
		Input      string `json:"input"`
		Output     string `json:"output"`
		Event      string `json:"event"`
		Checkpoint string `json:"checkpoint"`
	} `json:"schemas"`
	Runtime struct {
		Transport  string `json:"transport"`
		Isolation  string `json:"isolation"`
		HealthPath string `json:"health_path"`
	} `json:"runtime"`
}

func jsonObject(raw json.RawMessage) bool {
	var value map[string]json.RawMessage
	return json.Unmarshal(raw, &value) == nil && value != nil
}

func schemaRef(value string) bool { return strings.HasPrefix(strings.TrimSpace(value), "schema://") }

func validSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

// VersionContentHash binds the manifest and both JSON Schemas into one
// deterministic immutable version fingerprint. JSON object key order and
// insignificant whitespace do not affect the resulting digest.
// VersionContentHash 将 Manifest 与两个 JSON Schema 绑定为不可变摘要。
func VersionContentHash(manifest, inputSchema, outputSchema json.RawMessage) (string, error) {
	canonicalize := func(raw json.RawMessage) (json.RawMessage, error) {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			if err == nil {
				return nil, errors.New("multiple JSON values")
			}
			return nil, err
		}
		canonical, err := json.Marshal(value)
		return canonical, err
	}
	canonicalManifest, err := canonicalize(manifest)
	if err != nil {
		return "", err
	}
	canonicalInput, err := canonicalize(inputSchema)
	if err != nil {
		return "", err
	}
	canonicalOutput, err := canonicalize(outputSchema)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(struct {
		Manifest json.RawMessage `json:"manifest"`
		Input    json.RawMessage `json:"input_schema"`
		Output   json.RawMessage `json:"output_schema"`
	}{canonicalManifest, canonicalInput, canonicalOutput})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validDefinitionStatus(status DefinitionStatus) bool {
	switch status {
	case DefinitionDraft, DefinitionEvaluated, DefinitionPublished, DefinitionDisabled, DefinitionRetired:
		return true
	default:
		return false
	}
}

// ValidateDefinitionTransition is the catalog-owned lifecycle guard for a
// definition. Versions may be evaluated independently, but publishing or
// retiring the definition itself must still use an explicit CAS transition.
// ValidateDefinitionTransition 是 Definition 自己的生命周期边界；版本可独立
// 评测，但 Definition 的发布/停用/退役仍必须经过显式 CAS。
func ValidateDefinitionTransition(from, to DefinitionStatus) error {
	allowed := map[DefinitionStatus]map[DefinitionStatus]bool{
		DefinitionDraft:     {DefinitionEvaluated: true},
		DefinitionEvaluated: {DefinitionPublished: true},
		DefinitionPublished: {DefinitionDisabled: true, DefinitionRetired: true},
		DefinitionDisabled:  {DefinitionPublished: true, DefinitionRetired: true},
	}
	if !allowed[from][to] {
		return ErrIllegalTransition
	}
	return nil
}

func (i Installation) Validate() error {
	if strings.TrimSpace(i.ID) == "" || strings.TrimSpace(i.TenantID) == "" || strings.TrimSpace(i.DepartmentID) == "" || strings.TrimSpace(i.ApplicationID) == "" || strings.TrimSpace(i.AgentID) == "" || strings.TrimSpace(i.VersionID) == "" || strings.TrimSpace(i.DisplayName) == "" || (i.DeploymentMode != "managed" && i.DeploymentMode != "external") || (i.DrainPolicy != "wait" && i.DrainPolicy != "cancel") || strings.TrimSpace(i.RetentionPolicyID) == "" || i.Revision == 0 || !validInstallationStatus(i.Status) {
		return ErrInvalidInstallation
	}
	return nil
}

func validInstallationStatus(status InstallationStatus) bool {
	switch status {
	case InstallationProvisioning, InstallationActive, InstallationSuspended, InstallationDraining, InstallationFailed, InstallationUninstalling, InstallationUninstalled:
		return true
	default:
		return false
	}
}

func (d Deployment) Validate() error {
	if strings.TrimSpace(d.ID) == "" || strings.TrimSpace(d.TenantID) == "" || strings.TrimSpace(d.DepartmentID) == "" || strings.TrimSpace(d.ApplicationID) == "" || strings.TrimSpace(d.AgentVersionID) == "" || strings.TrimSpace(d.AgentInstallationID) == "" || !strings.HasPrefix(d.ArtifactDigest, "sha256:") || strings.TrimSpace(d.ManifestHash) == "" || d.DesiredRevision == 0 || !validDeploymentStatus(d.Status) {
		return ErrInvalidDeployment
	}
	if d.Transport != "http" && d.Transport != "grpc" {
		return ErrInvalidDeployment
	}
	if len(d.PlacementPolicy) == 0 || !json.Valid(d.PlacementPolicy) || len(d.ResourcePolicy) == 0 || !json.Valid(d.ResourcePolicy) {
		return ErrInvalidDeployment
	}
	return nil
}

func validDeploymentStatus(status DeploymentStatus) bool {
	switch status {
	case DeploymentPending, DeploymentReady, DeploymentFailed, DeploymentDraining, DeploymentDisabled:
		return true
	default:
		return false
	}
}

func (v Version) Snapshot(d Definition) (VersionSnapshot, error) {
	if err := d.Validate(); err != nil {
		return VersionSnapshot{}, err
	}
	if err := v.Validate(); err != nil || v.DefinitionID != d.ID {
		return VersionSnapshot{}, ErrInvalidVersion
	}
	return VersionSnapshot{DefinitionID: d.ID, AgentID: d.AgentKey, VersionID: v.ID, Version: v.SemanticVersion, ManifestHash: v.ManifestHash, ArtifactDigest: v.ArtifactDigest}, nil
}

func ValidateInstallationTransition(from, to InstallationStatus) error {
	allowed := map[InstallationStatus]map[InstallationStatus]bool{
		InstallationProvisioning: {InstallationActive: true, InstallationFailed: true, InstallationUninstalling: true},
		InstallationActive:       {InstallationSuspended: true, InstallationDraining: true, InstallationFailed: true},
		InstallationSuspended:    {InstallationActive: true, InstallationUninstalling: true},
		InstallationDraining:     {InstallationSuspended: true, InstallationUninstalling: true, InstallationFailed: true},
		InstallationFailed:       {InstallationProvisioning: true, InstallationUninstalling: true},
		InstallationUninstalling: {InstallationUninstalled: true, InstallationFailed: true},
	}
	if !allowed[from][to] {
		return ErrIllegalTransition
	}
	return nil
}

func latestDeploymentReadyForActivation(installation Installation, deployments []Deployment) bool {
	var latest *Deployment
	for index := range deployments {
		deployment := &deployments[index]
		if deployment.AgentInstallationID != installation.ID || deployment.TenantID != installation.TenantID || deployment.DepartmentID != installation.DepartmentID || deployment.ApplicationID != installation.ApplicationID {
			continue
		}
		if latest == nil || deployment.DesiredRevision > latest.DesiredRevision {
			latest = deployment
		}
	}
	return latest != nil && latest.AgentVersionID == installation.VersionID && latest.Status == DeploymentReady &&
		latest.DesiredRevision > 0 && latest.ObservedRevision == latest.DesiredRevision
}
