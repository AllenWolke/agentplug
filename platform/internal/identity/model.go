package identity

import (
	"errors"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type PrincipalType string

const (
	PrincipalUser             PrincipalType = "user"
	PrincipalServicePrincipal PrincipalType = "service_principal"
)

// Principal is the authenticated subject; credentials never cross this
// domain boundary.
// Principal 是已认证主体，凭证不得进入领域层。
type Principal struct {
	Type     PrincipalType `json:"type"`
	ID       string        `json:"id"`
	TenantID string        `json:"tenant_id"`
	Roles    []string      `json:"roles,omitempty"`
	Groups   []string      `json:"groups,omitempty"`
	IsActive bool          `json:"is_active"`
	Revision uint64        `json:"revision"`
}

type AccessContext struct {
	Scope     sharedkernel.Scope
	Principal Principal
	Action    string
}

// Tenant, Department and Application are control-plane identities. They are
// intentionally small here; business modules reference their IDs instead of
// owning another tenant hierarchy.
// Tenant、Department、Application 是控制面身份；业务模块只引用稳定 ID，不能再复制一套租户树。
type Tenant struct {
	ID        string    `json:"id"`
	Code      string    `json:"code"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Revision  uint64    `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
}

type Department struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Code      string    `json:"code"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Revision  uint64    `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
}

type Application struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	DepartmentID string    `json:"department_id"`
	Code         string    `json:"code"`
	Name         string    `json:"name"`
	Status       string    `json:"status"`
	Revision     uint64    `json:"revision"`
	CreatedAt    time.Time `json:"created_at"`
}

// OrganizationPage is a bounded identity projection. The module returns this
// envelope instead of loading an unbounded tenant tree into the browser.
// OrganizationPage 是有界身份投影，避免一次性把租户组织树全部加载到浏览器。
type OrganizationPage[T any] struct {
	Items    []T   `json:"items"`
	Total    int64 `json:"total"`
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
}

type Grant struct {
	AgentUsePackageID          string `json:"agent_use_package_id,omitempty"`
	AgentUsePackageRevision    uint64 `json:"agent_use_package_revision,omitempty"`
	AgentUseRequirementsDigest string `json:"agent_use_requirements_digest,omitempty"`
	Validity
	ResourceType  string    `json:"resource_type,omitempty"`
	ResourceID    string    `json:"resource_id,omitempty"`
	DataScope     DataScope `json:"data_scope,omitempty"`
	SourceID      string    `json:"source_id,omitempty"`
	PresetCode    string    `json:"preset_code,omitempty"`
	PresetVersion uint64    `json:"preset_version,omitempty"`
	DelegationID  string    `json:"delegation_id,omitempty"`
	// Server-derived source version for department-admin grants. Zero keeps an
	// independent company/legacy source; the live department ceiling still applies.
	DepartmentAgentActionVersion uint64        `json:"department_agent_action_version,omitempty"`
	ID                           string        `json:"id"`
	TenantID                     string        `json:"tenant_id"`
	DepartmentID                 string        `json:"department_id"`
	ApplicationID                string        `json:"application_id"`
	AgentInstanceID              string        `json:"agent_instance_id"`
	SubjectType                  PrincipalType `json:"subject_type"`
	SubjectID                    string        `json:"subject_id"`
	Action                       string        `json:"action"`
	Effect                       string        `json:"effect"`
	Status                       string        `json:"status"`
	Revision                     uint64        `json:"revision"`
}

// AgentAccessRequest records a user's request for a narrowly scoped Agent
// installation grant. Scope and subject are derived from the authenticated
// browser session, never accepted from the submitted command.
// AgentAccessRequest 保存用户对特定 Agent 安装实例的最小权限申请；作用域和主体由可信会话推导。
type AgentAccessRequest struct {
	ID              string        `json:"id"`
	TenantID        string        `json:"tenant_id"`
	DepartmentID    string        `json:"department_id"`
	ApplicationID   string        `json:"application_id"`
	AgentID         string        `json:"agent_id"`
	AgentInstanceID string        `json:"agent_instance_id"`
	SubjectType     PrincipalType `json:"subject_type"`
	SubjectID       string        `json:"subject_id"`
	Actions         []string      `json:"actions"`
	Reason          string        `json:"reason"`
	Status          string        `json:"status"`
	ReviewerID      string        `json:"reviewer_id,omitempty"`
	Comment         string        `json:"comment,omitempty"`
	Revision        uint64        `json:"revision"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
}

const (
	AgentAccessRequestPending  = "pending"
	AgentAccessRequestApproved = "approved"
	AgentAccessRequestRejected = "rejected"
)

const (
	GrantActive  = "active"
	GrantRevoked = "revoked"
)

type AccessDecision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

var (
	ErrInvalidPrincipal     = errors.New("invalid principal")
	ErrScopeMismatch        = errors.New("principal scope mismatch")
	ErrInvalidResource      = errors.New("invalid identity resource")
	ErrInvalidAccessRequest = errors.New("invalid agent access request")
)

func (t Tenant) Validate() error {
	if strings.TrimSpace(t.ID) == "" || strings.TrimSpace(t.Code) == "" || strings.TrimSpace(t.Name) == "" || strings.TrimSpace(t.Status) == "" || t.Revision == 0 {
		return ErrInvalidResource
	}
	return nil
}

func (d Department) Validate() error {
	if strings.TrimSpace(d.ID) == "" || strings.TrimSpace(d.TenantID) == "" || strings.TrimSpace(d.Code) == "" || strings.TrimSpace(d.Name) == "" || strings.TrimSpace(d.Status) == "" || d.Revision == 0 {
		return ErrInvalidResource
	}
	return nil
}

func (a Application) Validate() error {
	if strings.TrimSpace(a.ID) == "" || strings.TrimSpace(a.TenantID) == "" || strings.TrimSpace(a.DepartmentID) == "" || strings.TrimSpace(a.Code) == "" || strings.TrimSpace(a.Name) == "" || strings.TrimSpace(a.Status) == "" || a.Revision == 0 {
		return ErrInvalidResource
	}
	return nil
}

func (g Grant) Validate() error {
	if strings.TrimSpace(g.ID) == "" || strings.TrimSpace(g.TenantID) == "" || strings.TrimSpace(g.DepartmentID) == "" || strings.TrimSpace(g.ApplicationID) == "" || strings.TrimSpace(g.AgentInstanceID) == "" || strings.TrimSpace(g.SubjectID) == "" || strings.TrimSpace(g.Action) == "" || strings.TrimSpace(g.Status) == "" || g.Revision == 0 {
		return ErrInvalidResource
	}
	if g.Status != GrantActive && g.Status != GrantRevoked {
		return ErrInvalidResource
	}
	if g.SubjectType != PrincipalUser && g.SubjectType != PrincipalServicePrincipal {
		return ErrInvalidResource
	}
	if g.Effect != "allow" && g.Effect != "deny" {
		return ErrInvalidResource
	}
	return nil
}

func (p Principal) Validate() error {
	if (p.Type != PrincipalUser && p.Type != PrincipalServicePrincipal) || strings.TrimSpace(p.ID) == "" || strings.TrimSpace(p.TenantID) == "" {
		return ErrInvalidPrincipal
	}
	if !p.IsActive {
		return ErrInvalidPrincipal
	}
	return nil
}

func (c AccessContext) Validate() error {
	if err := c.Principal.Validate(); err != nil {
		return err
	}
	if err := c.Scope.Validate(); err != nil {
		return err
	}
	if c.Principal.TenantID != c.Scope.TenantID {
		return ErrScopeMismatch
	}
	if strings.TrimSpace(c.Scope.AgentInstanceID) == "" {
		return ErrScopeMismatch
	}
	if strings.TrimSpace(c.Action) == "" {
		return ErrScopeMismatch
	}
	return nil
}
