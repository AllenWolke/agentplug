package identity

// Identity owns enrollment, local credentials, and the approval boundary.
// Scope comes from process configuration; requests cannot choose a tenant.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

const (
	EnrollmentContactVerificationPending = "contact_verification_pending"
	EnrollmentPending                    = "pending_review"
	EnrollmentApproved                   = "approved"
	EnrollmentRejected                   = "rejected"
	EnrollmentWithdrawn                  = "withdrawn"
	registrationCodeLifetime             = 10 * time.Minute
	registrationRateWindow               = 10 * time.Minute
	registrationMaxVerifyAttempts        = 5
)

var (
	ErrEnrollmentUnavailable    = errors.New("identity enrollment is not configured")
	ErrEnrollmentInvalid        = errors.New("invalid identity enrollment request")
	ErrEnrollmentNotFound       = errors.New("identity enrollment not found")
	ErrEnrollmentConflict       = errors.New("identity enrollment revision conflict")
	ErrEnrollmentRateLimited    = errors.New("identity enrollment rate limit exceeded")
	ErrEnrollmentSelfReview     = errors.New("enrollment requester cannot review own request")
	ErrVerificationRejected     = errors.New("identity contact verification rejected")
	ErrDecisionRecorderRequired = errors.New("identity enrollment decision recorder is required")
	enrollmentUsernamePattern   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]{2,63}$`)
)

// EnrollmentScope is immutable server configuration, never request data.
type EnrollmentScope struct {
	TenantID      string `json:"tenant_id"`
	DepartmentID  string `json:"department_id"`
	ApplicationID string `json:"application_id"`
}

func (s EnrollmentScope) valid() bool {
	return strings.TrimSpace(s.TenantID) != "" && strings.TrimSpace(s.DepartmentID) != "" && strings.TrimSpace(s.ApplicationID) != ""
}

func (s EnrollmentScope) shared() sharedkernel.Scope {
	return sharedkernel.Scope{TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID}
}

type EnrollmentAgent struct {
	AgentID         string `json:"agent_id"`
	AgentInstanceID string `json:"agent_instance_id"`
	Name            string `json:"name"`
	Description     string `json:"description,omitempty"`
	SemanticVersion string `json:"semantic_version,omitempty"`
}

type EnrollmentCatalogResolver interface {
	ListRequestableEnrollmentAgents(context.Context, EnrollmentScope) ([]EnrollmentAgent, error)
}

type EnrollmentCommand struct {
	ID, Username, DisplayName, ContactMasked, ContactHash, PasswordHash string
	ContactForDelivery, VerificationCode                                string
	TenantID, DepartmentID, ApplicationID, Reason                       string
	RequestedAgentIDs                                                   []string
	Status, StatusTokenHash, VerifyTokenHash                            string
	VerifyExpiresAt, CreatedAt, UpdatedAt                               time.Time
	Revision                                                            uint64
}

// Enrollment is safe to return from public and admin endpoints.
type Enrollment struct {
	ID                string     `json:"id"`
	Username          string     `json:"username"`
	DisplayName       string     `json:"display_name"`
	Contact           string     `json:"contact"`
	TenantID          string     `json:"tenant_id"`
	DepartmentID      string     `json:"department_id"`
	ApplicationID     string     `json:"application_id"`
	Reason            string     `json:"reason"`
	RequestedAgentIDs []string   `json:"requested_agent_ids"`
	Status            string     `json:"status"`
	PublicComment     string     `json:"public_comment,omitempty"`
	ReviewedBy        string     `json:"reviewed_by,omitempty"`
	Revision          uint64     `json:"revision"`
	VerifiedAt        *time.Time `json:"verified_at,omitempty"`
	ReviewedAt        *time.Time `json:"reviewed_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type EnrollmentRegistrationReceipt struct {
	RegistrationID   string    `json:"registration_id"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	StatusToken      string    `json:"status_token"`
	VerificationCode string    `json:"verification_code,omitempty"`
}

type EnrollmentConfig struct {
	Scope                  EnrollmentScope
	InviteCode             string
	Environment            string
	VerificationHMACKey    string
	ContactDeliveryEnabled bool
	CatalogResolver        EnrollmentCatalogResolver
}

type RegistrationRateKey struct {
	Kind, Value string
	Limit       int
}

type EnrollmentGrant struct {
	AgentID, AgentInstanceID string
	Actions                  []string
}

type EnrollmentRepository interface {
	CheckEnrollmentRateLimit(context.Context, []RegistrationRateKey, time.Time) error
	CreateEnrollment(context.Context, EnrollmentCommand) error
	GetEnrollmentByToken(context.Context, string, string) (Enrollment, error)
	VerifyEnrollmentContact(context.Context, string, string, string, time.Time) (Enrollment, error)
	WithdrawEnrollment(context.Context, string, string, uint64, time.Time) (Enrollment, error)
	ListEnrollments(context.Context, EnrollmentScope, string, int, int) ([]Enrollment, int64, error)
	GetEnrollment(context.Context, EnrollmentScope, string) (Enrollment, error)
	ApproveEnrollment(context.Context, EnrollmentScope, string, string, uint64, string, string, []EnrollmentGrant, time.Time) (Enrollment, error)
	RejectEnrollment(context.Context, EnrollmentScope, string, string, uint64, string, string, time.Time) (Enrollment, error)
}

type EnrollmentCredentials interface {
	VerifyEnrollmentCredentials(context.Context, string, string) (LocalIdentity, error)
	ValidateEnrollmentSession(context.Context, string, EnrollmentScope, uint64) (LocalIdentity, error)
}

type LocalIdentity struct {
	PrincipalID   string   `json:"principal_id"`
	Username      string   `json:"username"`
	DisplayName   string   `json:"display_name"`
	TenantID      string   `json:"tenant_id"`
	DepartmentID  string   `json:"department_id"`
	ApplicationID string   `json:"application_id"`
	Roles         []string `json:"roles"`
	AuthRevision  uint64   `json:"auth_revision"`
}

var enrollmentActions = map[string]struct{}{
	"discover": {}, "run": {}, "history.read": {}, "history.continue": {}, "history.revise": {},
	"history.regenerate": {}, "history.share": {}, "history.export": {}, "history.delete.request": {}, "cancel": {},
}

func (m *Module) ConfigureEnrollment(config EnrollmentConfig) {
	config.Environment = strings.ToLower(strings.TrimSpace(config.Environment))
	if strings.TrimSpace(config.Environment) == "" {
		config.Environment = "production"
	}
	m.enrollmentConfig = &config
}

func (m *Module) SetEnrollmentCatalogResolver(resolver EnrollmentCatalogResolver) {
	if m.enrollmentConfig == nil {
		m.enrollmentConfig = &EnrollmentConfig{Environment: "production"}
	}
	m.enrollmentConfig.CatalogResolver = resolver
}

func (m *Module) enrollmentRepository(w http.ResponseWriter) (EnrollmentRepository, bool) {
	if m.enrollmentConfig == nil || !m.enrollmentConfig.Scope.valid() {
		m.error(w, http.StatusServiceUnavailable, "ENROLLMENT_NOT_CONFIGURED")
		return nil, false
	}
	repo, ok := m.store.(EnrollmentRepository)
	if !ok {
		m.error(w, http.StatusNotImplemented, "ENROLLMENT_STORE_NOT_AVAILABLE")
		return nil, false
	}
	return repo, true
}

func enrollmentTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomEnrollmentToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func randomEnrollmentCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func enrollmentVerificationCodeHash(config *EnrollmentConfig, code string) (string, error) {
	if config == nil {
		return "", ErrEnrollmentUnavailable
	}
	environment := strings.ToLower(strings.TrimSpace(config.Environment))
	if environment != "development" && !validEnrollmentHMACKey(config.VerificationHMACKey) {
		return "", ErrEnrollmentUnavailable
	}
	key := []byte(config.VerificationHMACKey)
	if len(key) < 32 {
		if environment != "development" {
			return "", ErrEnrollmentUnavailable
		}
		// Development returns this one-time code directly, so a fixed local key
		// is acceptable only in that explicitly non-production mode.
		seed := "lexagent-development-enrollment:" + config.Scope.TenantID + ":" + config.Scope.ApplicationID
		sum := sha256.Sum256([]byte(seed))
		key = sum[:]
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func newEnrollmentID() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Sprintf("enr-%d", time.Now().UTC().UnixNano())
	}
	return "enr_" + hex.EncodeToString(raw)
}

func maskEnrollmentContact(contact string) string {
	parts := strings.Split(contact, "@")
	if len(parts) != 2 || len([]rune(parts[0])) == 0 {
		return "***"
	}
	return string([]rune(parts[0])[0]) + "***@" + parts[1]
}

func normalizeEnrollmentIDs(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	result := make([]string, 0, len(ids))
	for _, value := range ids {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
}

func requestClientIP(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Internal-Client-IP")); net.ParseIP(forwarded) != nil {
		return forwarded
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && net.ParseIP(host) != nil {
		return host
	}
	if net.ParseIP(strings.TrimSpace(r.RemoteAddr)) != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return ""
}

func validRegistrationInput(in enrollmentRegisterRequest, config *EnrollmentConfig) bool {
	username := strings.ToLower(strings.TrimSpace(in.Username))
	display, contact, reason := strings.TrimSpace(in.DisplayName), strings.TrimSpace(in.Contact), strings.TrimSpace(in.Reason)
	if config == nil || !config.Scope.valid() || strings.TrimSpace(config.InviteCode) == "" || len(in.InviteCode) != len(config.InviteCode) || subtle.ConstantTimeCompare([]byte(in.InviteCode), []byte(config.InviteCode)) != 1 {
		return false
	}
	if !enrollmentUsernamePattern.MatchString(username) || len([]rune(display)) < 2 || len([]rune(display)) > 128 || !strings.Contains(contact, "@") || len(contact) > 255 || len(in.Password) < 10 || len(in.Password) > 128 || len([]rune(reason)) < 10 || len([]rune(reason)) > 500 || len(in.RequestedAgentIDs) > 50 {
		return false
	}
	for _, id := range in.RequestedAgentIDs {
		if strings.TrimSpace(id) == "" || len(id) > 128 {
			return false
		}
	}
	return true
}

func enrollmentHTTPError(m *Module, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrEnrollmentInvalid):
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
	case errors.Is(err, ErrEnrollmentNotFound), errors.Is(err, ErrApplicationNotFound), errors.Is(err, ErrAgentInstallationNotFound):
		m.error(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
	case errors.Is(err, ErrEnrollmentConflict), errors.Is(err, ErrIdentityConflict):
		m.error(w, http.StatusConflict, "REVISION_CONFLICT")
	case errors.Is(err, ErrEnrollmentSelfReview):
		m.error(w, http.StatusForbidden, "SELF_REVIEW_FORBIDDEN")
	case errors.Is(err, ErrVerificationRejected):
		m.error(w, http.StatusForbidden, "VERIFICATION_REJECTED")
	case errors.Is(err, ErrEnrollmentRateLimited):
		m.error(w, http.StatusTooManyRequests, "RATE_LIMITED")
	case errors.Is(err, ErrEnrollmentUnavailable), errors.Is(err, ErrDecisionRecorderRequired):
		m.error(w, http.StatusServiceUnavailable, "ENROLLMENT_UNAVAILABLE")
	default:
		m.error(w, http.StatusInternalServerError, "INTERNAL_ERROR")
	}
}

// validEnrollmentHMACKey 保护直接配置模块的调用方，避免绕过平台启动校验。
func validEnrollmentHMACKey(value string) bool {
	runes := []rune(value)
	if len(value) < 32 || strings.Count(value, string(runes[0])) == len(runes) {
		return false
	}
	for _, marker := range []string{"replace-", "change-me", "changeme", "placeholder", "dev-internal", "dev-signing"} {
		if strings.Contains(strings.ToLower(value), marker) {
			return false
		}
	}
	return true
}
