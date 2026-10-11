package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// AgentInstallation is the browser-safe identity resolved from Catalog.
// AgentInstallation 是从 Catalog 解析出的浏览器安全 Agent 标识。
type AgentInstallation struct {
	AgentID string
}

// AgentInstallationResolver is a narrow port; Identity never reads Catalog
// tables or accepts an Agent ID supplied by the browser as authoritative.
// AgentInstallationResolver 是窄端口；Identity 不读取 Catalog 表，也不信任浏览器提交的 Agent ID。
type AgentInstallationResolver interface {
	ResolveAgentInstallation(context.Context, sharedkernel.Scope, string) (AgentInstallation, error)
}

// AgentAccessRequestRepository owns durable request lifecycle and atomic grant
// creation. A remote adapter can implement this port without changing HTTP or
// authorization policy.
// AgentAccessRequestRepository 管理持久化申请生命周期及原子授权；远程 Adapter 可替换此端口。
type AgentAccessRequestRepository interface {
	CreateAgentAccessRequest(context.Context, AgentAccessRequest) (AgentAccessRequest, error)
	ListAgentAccessRequests(context.Context, sharedkernel.Scope, string, string) ([]AgentAccessRequest, error)
	DecideAgentAccessRequest(context.Context, sharedkernel.Scope, string, string, string, uint64, string) (AgentAccessRequest, error)
}

type agentAccessRequestCommand struct {
	AgentInstanceID string   `json:"agent_instance_id"`
	Actions         []string `json:"actions"`
	Reason          string   `json:"reason"`
}

type agentAccessDecisionCommand struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	Comment          string `json:"comment"`
}

var allowedAgentAccessActions = map[string]struct{}{
	"discover": {}, "run": {}, "history.read": {}, "history.continue": {}, "history.revise": {},
	"history.regenerate": {}, "history.share": {}, "history.export": {}, "history.delete.request": {}, "cancel": {},
}

var ErrAgentInstallationNotFound = errors.New("agent installation unavailable in application catalog")

func (m *Module) agentAccessRequests(w http.ResponseWriter, r *http.Request) {
	if !m.requireAuth(w, r) {
		return
	}
	actor, ok := m.loadBrowserActor(w, r)
	if !ok {
		return
	}
	if !actor.Browser || actor.Principal.Type != PrincipalUser {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	if actor.Policy != nil {
		m.error(w, http.StatusForbidden, "USE_VERSIONED_PERMISSION_REQUESTS")
		return
	}
	repository, ok := m.accessRequestRepository(w)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		if status != "" && status != AgentAccessRequestPending && status != AgentAccessRequestApproved && status != AgentAccessRequestRejected {
			m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		subjectID := actor.Principal.ID
		if containsIdentityRole(actor.Principal.Roles, "system_admin", "admin", "platform_admin", "department_admin", "application_admin") {
			subjectID = ""
		}
		items, err := repository.ListAgentAccessRequests(r.Context(), actor.Scope, subjectID, status)
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		var command agentAccessRequestCommand
		if err := decode(r, &command); err != nil {
			m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		command.AgentInstanceID = strings.TrimSpace(command.AgentInstanceID)
		command.Reason = strings.TrimSpace(command.Reason)
		command.Actions, ok = normalizeAgentAccessActions(command.Actions)
		if !ok || command.AgentInstanceID == "" || len(command.AgentInstanceID) > 128 || len(command.Reason) < 10 || len(command.Reason) > 1000 {
			m.error(w, http.StatusBadRequest, "SCHEMA_VALIDATION_FAILED")
			return
		}
		if m.installationResolver == nil {
			m.error(w, http.StatusServiceUnavailable, "CATALOG_UNAVAILABLE")
			return
		}
		resolved, err := m.installationResolver.ResolveAgentInstallation(r.Context(), actor.Scope, command.AgentInstanceID)
		if err != nil {
			if errors.Is(err, ErrAgentInstallationNotFound) {
				m.storeError(w, ErrAgentInstallationNotFound)
				return
			}
			m.error(w, http.StatusServiceUnavailable, "CATALOG_UNAVAILABLE")
			return
		}
		requestID, err := newAgentAccessRequestID()
		if err != nil {
			m.error(w, http.StatusInternalServerError, "ID_GENERATION_FAILED")
			return
		}
		request, err := repository.CreateAgentAccessRequest(r.Context(), AgentAccessRequest{
			ID: requestID, TenantID: actor.Scope.TenantID, DepartmentID: actor.Scope.DepartmentID,
			ApplicationID: actor.Scope.ApplicationID, AgentID: resolved.AgentID, AgentInstanceID: command.AgentInstanceID,
			SubjectType: PrincipalUser, SubjectID: actor.Principal.ID, Actions: command.Actions,
			Reason: command.Reason, Status: AgentAccessRequestPending, Revision: 1,
		})
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusCreated, request)
	default:
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
	}
}

func (m *Module) agentAccessRequest(w http.ResponseWriter, r *http.Request) {
	if !m.requireAuth(w, r) {
		return
	}
	actor, ok := m.requireBrowserRoles(w, r, "system_admin", "admin", "platform_admin", "department_admin", "application_admin")
	if !ok {
		return
	}
	if !actor.Browser {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	if actor.Policy != nil {
		m.error(w, http.StatusForbidden, "USE_VERSIONED_PERMISSION_REQUESTS")
		return
	}
	parts := strings.FieldsFunc(strings.TrimPrefix(r.URL.Path, "/access-requests/"), func(value rune) bool { return value == '/' })
	if len(parts) != 2 || r.Method != http.MethodPost || (parts[1] != "approve" && parts[1] != "reject") {
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	repository, ok := m.accessRequestRepository(w)
	if !ok {
		return
	}
	var command agentAccessDecisionCommand
	if err := decode(r, &command); err != nil || command.ExpectedRevision == 0 || len(strings.TrimSpace(command.Comment)) < 2 || len(command.Comment) > 1000 {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	status := AgentAccessRequestRejected
	if parts[1] == "approve" {
		status = AgentAccessRequestApproved
	}
	request, err := repository.DecideAgentAccessRequest(r.Context(), actor.Scope, parts[0], actor.Principal.ID, status, command.ExpectedRevision, strings.TrimSpace(command.Comment))
	if err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusOK, request)
}

func (m *Module) accessRequestRepository(w http.ResponseWriter) (AgentAccessRequestRepository, bool) {
	repository, ok := m.store.(AgentAccessRequestRepository)
	if !ok {
		m.error(w, http.StatusNotImplemented, "ACCESS_REQUESTS_UNAVAILABLE")
		return nil, false
	}
	return repository, true
}

func normalizeAgentAccessActions(actions []string) ([]string, bool) {
	if len(actions) == 0 || len(actions) > len(allowedAgentAccessActions) {
		return nil, false
	}
	seen := make(map[string]struct{}, len(actions))
	result := make([]string, 0, len(actions))
	for _, action := range actions {
		action = strings.TrimSpace(action)
		if _, ok := allowedAgentAccessActions[action]; !ok {
			return nil, false
		}
		if _, duplicate := seen[action]; duplicate {
			return nil, false
		}
		seen[action] = struct{}{}
		result = append(result, action)
	}
	return result, true
}

func newAgentAccessRequestID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "iar_" + hex.EncodeToString(value), nil
}
