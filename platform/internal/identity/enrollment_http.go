package identity

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type enrollmentRegisterRequest struct {
	Username          string   `json:"username"`
	DisplayName       string   `json:"display_name"`
	Contact           string   `json:"contact"`
	Password          string   `json:"password"`
	InviteCode        string   `json:"invite_code"`
	Reason            string   `json:"reason"`
	RequestedAgentIDs []string `json:"requested_agent_ids"`
}

type enrollmentVerifyRequest struct {
	Code string `json:"code"`
}

type enrollmentWithdrawRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
}

type enrollmentDecisionGrant struct {
	AgentInstanceID string   `json:"agent_instance_id"`
	Actions         []string `json:"actions"`
}

type enrollmentApproveRequest struct {
	ExpectedRevision uint64                    `json:"expected_revision"`
	Comment          string                    `json:"comment"`
	Grants           []enrollmentDecisionGrant `json:"grants"`
}

type enrollmentRejectRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	Comment          string `json:"comment"`
}

type credentialsVerifyRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type sessionValidateRequest struct {
	Username      string `json:"username"`
	TenantID      string `json:"tenant_id"`
	DepartmentID  string `json:"department_id"`
	ApplicationID string `json:"application_id"`
	AuthRevision  uint64 `json:"auth_revision"`
}

func (m *Module) registrationAgentCatalog(w http.ResponseWriter, r *http.Request) {
	if !m.requireInternalEnrollmentProxy(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	if m.enrollmentConfig == nil || !m.enrollmentConfig.Scope.valid() || m.enrollmentConfig.CatalogResolver == nil {
		m.error(w, http.StatusServiceUnavailable, "ENROLLMENT_CATALOG_NOT_CONFIGURED")
		return
	}
	items, err := m.enrollmentConfig.CatalogResolver.ListRequestableEnrollmentAgents(r.Context(), m.enrollmentConfig.Scope)
	if err != nil {
		m.error(w, http.StatusServiceUnavailable, "ENROLLMENT_CATALOG_UNAVAILABLE")
		return
	}
	m.json(w, http.StatusOK, map[string]any{"items": items})
}

func (m *Module) registrations(w http.ResponseWriter, r *http.Request) {
	if !m.requireInternalEnrollmentProxy(w, r) {
		return
	}
	if r.URL.Path == "/registrations" {
		if r.Method != http.MethodPost {
			m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		m.createRegistration(w, r)
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/registrations/"), "/"), "/")
	if len(parts) != 2 || parts[0] == "" || strings.Contains(parts[0], "..") {
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	switch parts[1] {
	case "status":
		if r.Method != http.MethodGet {
			m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		m.registrationStatus(w, r, parts[0])
	case "verify-contact":
		if r.Method != http.MethodPost {
			m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		m.verifyRegistrationContact(w, r, parts[0])
	case "withdraw":
		if r.Method != http.MethodPost {
			m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		m.withdrawRegistration(w, r, parts[0])
	default:
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
	}
}

func (m *Module) createRegistration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	repo, ok := m.enrollmentRepository(w)
	if !ok {
		return
	}
	var in enrollmentRegisterRequest
	if decode(r, &in) != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	username, contact := strings.ToLower(strings.TrimSpace(in.Username)), strings.TrimSpace(in.Contact)
	keys := []RegistrationRateKey{
		{Kind: "ip", Value: requestClientIP(r), Limit: 20},
		{Kind: "username", Value: username, Limit: 5},
		{Kind: "contact", Value: strings.ToLower(contact), Limit: 5},
	}
	if err := repo.CheckEnrollmentRateLimit(r.Context(), keys, time.Now().UTC()); err != nil {
		if errors.Is(err, ErrEnrollmentRateLimited) {
			m.error(w, http.StatusTooManyRequests, "RATE_LIMITED")
		} else {
			m.error(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		}
		return
	}
	config := m.enrollmentConfig
	if !validRegistrationInput(in, config) {
		m.error(w, http.StatusBadRequest, "INVALID_REGISTRATION")
		return
	}
	if !config.ContactDeliveryEnabled && config.Environment != "development" {
		m.error(w, http.StatusServiceUnavailable, "CONTACT_VERIFICATION_UNAVAILABLE")
		return
	}
	passwordHash, err := hashEnrollmentPassword(in.Password)
	if err != nil {
		m.error(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		return
	}
	statusToken, err := randomEnrollmentToken(32)
	if err != nil {
		m.error(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		return
	}
	code, err := randomEnrollmentCode()
	if err != nil {
		m.error(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		return
	}
	codeHash, err := enrollmentVerificationCodeHash(config, code)
	if err != nil {
		m.error(w, http.StatusServiceUnavailable, "CONTACT_VERIFICATION_UNAVAILABLE")
		return
	}
	now := time.Now().UTC()
	expires := now.Add(registrationCodeLifetime)
	contactHash := enrollmentTokenHash(strings.ToLower(contact))
	item := EnrollmentCommand{
		ID: newEnrollmentID(), Username: username, DisplayName: strings.TrimSpace(in.DisplayName),
		ContactMasked: maskEnrollmentContact(contact), ContactHash: contactHash, PasswordHash: passwordHash,
		TenantID: config.Scope.TenantID, DepartmentID: config.Scope.DepartmentID, ApplicationID: config.Scope.ApplicationID,
		Reason: strings.TrimSpace(in.Reason), RequestedAgentIDs: normalizeEnrollmentIDs(in.RequestedAgentIDs),
		Status: EnrollmentContactVerificationPending, StatusTokenHash: enrollmentTokenHash(statusToken), VerifyTokenHash: codeHash,
		VerifyExpiresAt: expires, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if config.ContactDeliveryEnabled && config.Environment != "development" {
		// These transient delivery fields are never persisted in the enrollment
		// row; SQLStore uses them only to atomically enqueue an encrypted outbox event.
		item.ContactForDelivery, item.VerificationCode = contact, code
	}
	if err := repo.CreateEnrollment(r.Context(), item); err != nil {
		enrollmentHTTPError(m, w, err)
		return
	}
	receipt := EnrollmentRegistrationReceipt{RegistrationID: item.ID, Status: item.Status, CreatedAt: now, StatusToken: statusToken}
	if config.Environment == "development" {
		receipt.VerificationCode = code
	}
	m.json(w, http.StatusAccepted, receipt)
}

func (m *Module) registrationStatus(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Cache-Control", "no-store")
	repo, ok := m.enrollmentRepository(w)
	if !ok {
		return
	}
	token := registrationTokenFromRequest(r)
	if token == "" {
		m.error(w, http.StatusUnauthorized, "REGISTRATION_TOKEN_REQUIRED")
		return
	}
	item, err := repo.GetEnrollmentByToken(r.Context(), id, enrollmentTokenHash(token))
	if err != nil {
		enrollmentHTTPError(m, w, err)
		return
	}
	m.json(w, http.StatusOK, item)
}

func (m *Module) verifyRegistrationContact(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Cache-Control", "no-store")
	repo, ok := m.enrollmentRepository(w)
	if !ok {
		return
	}
	var in enrollmentVerifyRequest
	token := registrationTokenFromRequest(r)
	if token == "" || decode(r, &in) != nil || len(strings.TrimSpace(in.Code)) != 6 {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	codeHash, err := enrollmentVerificationCodeHash(m.enrollmentConfig, strings.TrimSpace(in.Code))
	if err != nil {
		m.error(w, http.StatusServiceUnavailable, "CONTACT_VERIFICATION_UNAVAILABLE")
		return
	}
	item, err := repo.VerifyEnrollmentContact(r.Context(), id, enrollmentTokenHash(token), codeHash, time.Now().UTC())
	if err != nil {
		enrollmentHTTPError(m, w, err)
		return
	}
	m.json(w, http.StatusOK, item)
}

func (m *Module) withdrawRegistration(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Cache-Control", "no-store")
	repo, ok := m.enrollmentRepository(w)
	if !ok {
		return
	}
	var in enrollmentWithdrawRequest
	token := registrationTokenFromRequest(r)
	if token == "" || decode(r, &in) != nil || in.ExpectedRevision == 0 {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	item, err := repo.WithdrawEnrollment(r.Context(), id, enrollmentTokenHash(token), in.ExpectedRevision, time.Now().UTC())
	if err != nil {
		enrollmentHTTPError(m, w, err)
		return
	}
	m.json(w, http.StatusOK, item)
}

func registrationTokenFromRequest(r *http.Request) string {
	// Registration capabilities are secrets. Never accept them in a URL, where
	// they can leak through browser history, access logs, and referrer headers.
	return strings.TrimSpace(r.Header.Get("X-Registration-Token"))
}

func (m *Module) requireInternalEnrollmentProxy(w http.ResponseWriter, r *http.Request) bool {
	provided := strings.TrimSpace(r.Header.Get("X-Internal-Token"))
	if m.internalToken == "" || len(provided) != len(m.internalToken) || subtle.ConstantTimeCompare([]byte(provided), []byte(m.internalToken)) != 1 {
		m.error(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return false
	}
	return true
}

func (m *Module) enrollments(w http.ResponseWriter, r *http.Request) {
	repo, ok := m.enrollmentRepository(w)
	if !ok {
		return
	}
	if r.URL.Path == "/enrollments" {
		if r.Method != http.MethodGet {
			m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		actor, ok := m.requireBrowserRoles(w, r, "system_admin", "admin", "platform_admin", "department_admin", "application_admin")
		if !ok {
			return
		}
		scope := m.enrollmentConfig.Scope
		if actor.Browser && !actor.canManage(scope.TenantID, scope.DepartmentID, scope.ApplicationID) {
			m.error(w, http.StatusForbidden, "FORBIDDEN")
			return
		}
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		if !validEnrollmentStatusFilter(status) {
			m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
		items, total, err := repo.ListEnrollments(r.Context(), scope, status, page, pageSize)
		if err != nil {
			enrollmentHTTPError(m, w, err)
			return
		}
		if page < 1 {
			page = 1
		}
		if pageSize < 1 || pageSize > 50 {
			pageSize = 20
		}
		m.json(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": page, "page_size": pageSize})
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/enrollments/"), "/"), "/")
	if len(parts) != 2 || parts[0] == "" || strings.Contains(parts[0], "..") {
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	actor, ok := m.requireBrowserRoles(w, r, "system_admin", "admin", "platform_admin", "department_admin", "application_admin")
	if !ok {
		return
	}
	item, err := repo.GetEnrollment(r.Context(), m.enrollmentConfig.Scope, parts[0])
	if err != nil {
		enrollmentHTTPError(m, w, err)
		return
	}
	if actor.Browser && !actor.canManage(item.TenantID, item.DepartmentID, item.ApplicationID) {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	switch parts[1] {
	case "approve":
		if r.Method != http.MethodPost {
			m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		m.approveEnrollment(w, r, actor, item)
	case "reject":
		if r.Method != http.MethodPost {
			m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		m.rejectEnrollment(w, r, actor, item)
	default:
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
	}
}

func validEnrollmentStatusFilter(status string) bool {
	return status == "" || status == EnrollmentContactVerificationPending || status == EnrollmentPending || status == EnrollmentApproved || status == EnrollmentRejected || status == EnrollmentWithdrawn
}

func (m *Module) approveEnrollment(w http.ResponseWriter, r *http.Request, actor browserActor, item Enrollment) {
	if actor.Policy != nil {
		m.error(w, http.StatusForbidden, "USE_VERSIONED_ENROLLMENT_DECISION")
		return
	}
	if actor.Browser && strings.EqualFold(strings.TrimSpace(actor.Principal.ID), item.Username) {
		m.error(w, http.StatusForbidden, "SELF_REVIEW_FORBIDDEN")
		return
	}
	repo := m.store.(EnrollmentRepository)
	var in enrollmentApproveRequest
	if decode(r, &in) != nil || in.ExpectedRevision == 0 || len(in.Grants) == 0 || len(in.Grants) > 50 || len([]rune(strings.TrimSpace(in.Comment))) < 2 || len([]rune(in.Comment)) > 500 {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	requested := make(map[string]struct{}, len(item.RequestedAgentIDs))
	for _, id := range item.RequestedAgentIDs {
		requested[id] = struct{}{}
	}
	resolveScope := sharedEnrollmentScope(item)
	resolveScope.PrincipalID, resolveScope.PrincipalType, resolveScope.TraceID = actor.Scope.PrincipalID, actor.Scope.PrincipalType, actor.Scope.TraceID
	seen := make(map[string]struct{}, len(in.Grants))
	grants := make([]EnrollmentGrant, 0, len(in.Grants))
	for _, candidate := range in.Grants {
		installationID := strings.TrimSpace(candidate.AgentInstanceID)
		if installationID == "" || m.installationResolver == nil {
			m.error(w, http.StatusServiceUnavailable, "AGENT_INSTALLATION_RESOLVER_UNAVAILABLE")
			return
		}
		if _, duplicate := seen[installationID]; duplicate {
			m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		seen[installationID] = struct{}{}
		resolved, err := m.installationResolver.ResolveAgentInstallation(r.Context(), resolveScope, installationID)
		if err != nil {
			m.storeError(w, err)
			return
		}
		if _, ok := requested[resolved.AgentID]; !ok {
			m.error(w, http.StatusForbidden, "AGENT_NOT_REQUESTED")
			return
		}
		actions := normalizeEnrollmentActions(candidate.Actions)
		if len(actions) == 0 {
			m.error(w, http.StatusBadRequest, "INVALID_GRANT_ACTION")
			return
		}
		grants = append(grants, EnrollmentGrant{AgentID: resolved.AgentID, AgentInstanceID: installationID, Actions: actions})
	}
	reviewer := actor.Principal.ID
	if !actor.Browser {
		reviewer = strings.TrimSpace(r.Header.Get("X-Principal-ID"))
		if reviewer == "" {
			reviewer = "identity-admin-service"
		}
	}
	item, err := repo.ApproveEnrollment(r.Context(), m.enrollmentConfig.Scope, item.ID, reviewer, in.ExpectedRevision, strings.TrimSpace(in.Comment), actor.Scope.TraceID, grants, time.Now().UTC())
	if err != nil {
		enrollmentHTTPError(m, w, err)
		return
	}
	m.json(w, http.StatusOK, item)
}

func normalizeEnrollmentActions(actions []string) []string {
	seen := make(map[string]struct{}, len(actions))
	out := make([]string, 0, len(actions))
	for _, action := range actions {
		action = strings.TrimSpace(action)
		if _, ok := enrollmentActions[action]; !ok {
			return nil
		}
		if _, duplicate := seen[action]; !duplicate {
			seen[action] = struct{}{}
			out = append(out, action)
		}
	}
	return out
}

func sharedEnrollmentScope(item Enrollment) sharedkernel.Scope {
	return sharedkernel.Scope{TenantID: item.TenantID, DepartmentID: item.DepartmentID, ApplicationID: item.ApplicationID}
}

func (m *Module) rejectEnrollment(w http.ResponseWriter, r *http.Request, actor browserActor, item Enrollment) {
	if actor.Policy != nil {
		m.error(w, http.StatusForbidden, "USE_VERSIONED_ENROLLMENT_DECISION")
		return
	}
	if actor.Browser && strings.EqualFold(strings.TrimSpace(actor.Principal.ID), item.Username) {
		m.error(w, http.StatusForbidden, "SELF_REVIEW_FORBIDDEN")
		return
	}
	repo := m.store.(EnrollmentRepository)
	var in enrollmentRejectRequest
	if decode(r, &in) != nil || in.ExpectedRevision == 0 || len([]rune(strings.TrimSpace(in.Comment))) < 2 || len([]rune(in.Comment)) > 500 {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	reviewer := actor.Principal.ID
	if !actor.Browser {
		reviewer = strings.TrimSpace(r.Header.Get("X-Principal-ID"))
		if reviewer == "" {
			reviewer = "identity-admin-service"
		}
	}
	item, err := repo.RejectEnrollment(r.Context(), m.enrollmentConfig.Scope, item.ID, reviewer, in.ExpectedRevision, strings.TrimSpace(in.Comment), actor.Scope.TraceID, time.Now().UTC())
	if err != nil {
		enrollmentHTTPError(m, w, err)
		return
	}
	m.json(w, http.StatusOK, item)
}

func (m *Module) enrollmentInternal(w http.ResponseWriter, r *http.Request) {
	provided := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if provided == "" {
		provided = strings.TrimSpace(r.Header.Get("X-Internal-Token"))
	}
	if m.internalToken == "" || len(provided) != len(m.internalToken) || subtle.ConstantTimeCompare([]byte(provided), []byte(m.internalToken)) != 1 {
		m.error(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return
	}
	store, ok := m.store.(EnrollmentCredentials)
	if !ok {
		m.error(w, http.StatusNotImplemented, "CREDENTIAL_STORE_NOT_AVAILABLE")
		return
	}
	switch r.URL.Path {
	case "/internal/credentials/verify":
		if r.Method != http.MethodPost {
			m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		var in credentialsVerifyRequest
		if decode(r, &in) != nil {
			m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		limiter, ok := m.store.(interface {
			CheckEnrollmentRateLimit(context.Context, []RegistrationRateKey, time.Time) error
		})
		if !ok {
			m.error(w, http.StatusServiceUnavailable, "LOGIN_RATE_LIMIT_UNAVAILABLE")
			return
		}
		if err := limiter.CheckEnrollmentRateLimit(r.Context(), []RegistrationRateKey{
			{Kind: "login-ip", Value: requestClientIP(r), Limit: 100},
			{Kind: "login-user", Value: strings.ToLower(strings.TrimSpace(in.Username)), Limit: 10},
		}, time.Now().UTC()); err != nil {
			if errors.Is(err, ErrEnrollmentRateLimited) {
				m.error(w, http.StatusTooManyRequests, "RATE_LIMITED")
			} else {
				m.error(w, http.StatusServiceUnavailable, "LOGIN_RATE_LIMIT_UNAVAILABLE")
			}
			return
		}
		identity, err := store.VerifyEnrollmentCredentials(r.Context(), strings.ToLower(strings.TrimSpace(in.Username)), in.Password)
		if err != nil {
			m.error(w, http.StatusUnauthorized, "CREDENTIALS_REJECTED")
			return
		}
		m.json(w, http.StatusOK, identity)
	case "/internal/sessions/validate":
		if r.Method != http.MethodPost {
			m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		var in sessionValidateRequest
		if decode(r, &in) != nil || in.AuthRevision == 0 {
			m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		identity, err := store.ValidateEnrollmentSession(r.Context(), strings.ToLower(strings.TrimSpace(in.Username)), EnrollmentScope{TenantID: in.TenantID, DepartmentID: in.DepartmentID, ApplicationID: in.ApplicationID}, in.AuthRevision)
		if err != nil {
			m.error(w, http.StatusUnauthorized, "SESSION_REJECTED")
			return
		}
		m.json(w, http.StatusOK, identity)
	default:
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
	}
}
