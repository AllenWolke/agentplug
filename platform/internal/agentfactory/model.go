package agentfactory

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalidRequest    = errors.New("agent factory request is invalid")
	ErrNotFound          = errors.New("agent factory resource not found")
	ErrConflict          = errors.New("agent factory revision conflict")
	ErrAlreadyExists     = errors.New("agent factory resource already exists")
	ErrForbidden         = errors.New("agent factory operation forbidden")
	ErrInvalidScope      = errors.New("agent factory scope is invalid")
	ErrConformanceNeeded = errors.New("mapping needs passing conformance evidence")
)

const (
	StatusDraft      = "draft"
	StatusPublished  = "published"
	maxMappingBytes  = 1 << 20
	maxFixtureBytes  = 1 << 20
	maxArtifactBytes = 8 << 20
)

// Scope is taken from trusted Gateway identity headers and binds every stored row.
// Scope 从可信 Gateway 身份头取得，并绑定每一条持久化记录。
type Scope struct {
	TenantID      string `json:"tenant_id"`
	DepartmentID  string `json:"department_id"`
	ApplicationID string `json:"application_id"`
}

func (s Scope) Validate() error {
	for _, value := range []string{s.TenantID, s.DepartmentID, s.ApplicationID} {
		if value == "" || strings.TrimSpace(value) != value || len(value) > 128 || strings.ContainsAny(value, "\x00\r\n") {
			return ErrInvalidScope
		}
	}
	return nil
}

// Actor is derived only from trusted Gateway headers, never from a request body.
// Actor 只从可信 Gateway 身份头派生，绝不从请求体读取。
type Actor struct {
	TenantID, DepartmentID, ApplicationID string
	PrincipalType, PrincipalID            string
}

type Action string

const (
	ActionRead    Action = "read"
	ActionManage  Action = "manage"
	ActionPublish Action = "publish"
)

type Authorizer interface {
	AuthorizeAgentFactory(context.Context, Actor, Action, Scope) error
}

type Template struct {
	ID         string    `json:"id"`
	Scope      Scope     `json:"scope"`
	TemplateID string    `json:"template_id"`
	Name       string    `json:"name"`
	Language   string    `json:"language"`
	Framework  string    `json:"framework"`
	Status     string    `json:"status"`
	CreatedBy  string    `json:"created_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// TemplateVersion stores artifact identity and hashes only; artifact bytes are never persisted or returned.
// TemplateVersion 只保存制品身份与摘要；制品正文不会持久化或返回。
type TemplateVersion struct {
	ID              string    `json:"id"`
	Scope           Scope     `json:"scope"`
	DefinitionID    string    `json:"definition_id"`
	SemanticVersion string    `json:"semantic_version"`
	ArtifactURI     string    `json:"artifact_uri"`
	ContentHash     string    `json:"content_hash"`
	LockHash        string    `json:"lock_hash"`
	ArtifactSize    int       `json:"artifact_size"`
	CreatedBy       string    `json:"created_by,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

type Mapping struct {
	ID          string          `json:"id"`
	Scope       Scope           `json:"scope"`
	MappingID   string          `json:"mapping_id"`
	Kind        string          `json:"kind"`
	Status      string          `json:"status"`
	Spec        json.RawMessage `json:"spec"`
	ContentHash string          `json:"content_hash"`
	Revision    uint64          `json:"revision"`
	CreatedBy   string          `json:"created_by,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// ConformanceEvidence deliberately persists hashes and counts, not fixtures or transformed values.
// ConformanceEvidence 只持久化摘要和检查数量，不保存夹具或转换后的值。
type ConformanceEvidence struct {
	ID              string    `json:"id"`
	Scope           Scope     `json:"scope"`
	MappingID       string    `json:"mapping_id"`
	MappingRevision uint64    `json:"mapping_revision"`
	MappingHash     string    `json:"mapping_hash"`
	FixtureHash     string    `json:"fixture_hash"`
	ResultHash      string    `json:"result_hash"`
	Status          string    `json:"status"`
	CheckCount      int       `json:"check_count"`
	CreatedBy       string    `json:"created_by,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

type Store interface {
	EnsureSchema(context.Context) error
	Ping(context.Context) error
	CreateTemplate(context.Context, Template) error
	GetTemplate(context.Context, Scope, string) (Template, error)
	ListTemplates(context.Context, Scope, int, string) ([]Template, error)
	CreateTemplateVersion(context.Context, TemplateVersion) error
	ListTemplateVersions(context.Context, Scope, string, int) ([]TemplateVersion, error)
	CreateMapping(context.Context, Mapping) error
	GetMapping(context.Context, Scope, string) (Mapping, error)
	ListMappings(context.Context, Scope, int, string) ([]Mapping, error)
	SaveEvidence(context.Context, ConformanceEvidence) error
	ListEvidence(context.Context, Scope, string, int) ([]ConformanceEvidence, error)
	PublishMapping(context.Context, Scope, string, uint64) (Mapping, error)
}

type CreateTemplateRequest struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Language   string `json:"language"`
	Framework  string `json:"framework"`
}

type CreateTemplateVersionRequest struct {
	Version        string `json:"version"`
	ArtifactURI    string `json:"artifact_uri"`
	ArtifactBase64 string `json:"artifact_base64"`
}

type CreateMappingRequest struct {
	ID        string          `json:"id,omitempty"`
	MappingID string          `json:"mapping_id"`
	Kind      string          `json:"kind"`
	Spec      json.RawMessage `json:"spec"`
}

type DryRunRequest struct {
	Input   map[string]any `json:"input"`
	Context map[string]any `json:"context"`
	Body    map[string]any `json:"body"`
}

type DryRunResult struct {
	MappingID string              `json:"mapping_id"`
	Version   string              `json:"version"`
	Revision  uint64              `json:"revision"`
	Request   map[string]any      `json:"request"`
	Response  map[string]any      `json:"response"`
	Input     map[string]any      `json:"input"`
	Steps     int                 `json:"steps"`
	Evidence  ConformanceEvidence `json:"evidence"`
}
