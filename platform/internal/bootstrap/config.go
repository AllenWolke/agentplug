package bootstrap

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// RuntimeConfig is the process-level configuration shared by all platform
// modules. Modules receive validated values instead of reading environment
// variables directly.
// RuntimeConfig 是平台进程共享配置；模块只接收已校验值，不直接读取环境变量。
type RuntimeConfig struct {
	Environment                     string
	HTTPAddr                        string
	InternalAddr                    string
	RunWorkers                      int
	DBDriver                        string
	DBDSN                           string
	InternalToken                   string
	BrowserGatewayToken             string
	InternalSigningSecret           string
	PlatformContextPublicKey        string
	PlatformContextPrivateKey       string
	PlatformContextIssuer           string
	PlatformContextAudience         string
	OTelEndpoint                    string
	EventBusMode                    string
	KafkaBrokers                    string
	KafkaClientID                   string
	KafkaNotificationTopic          string
	KafkaNotificationGroup          string
	KafkaNotificationDLQ            string
	KafkaMaxAttempts                int
	KafkaRetryBackoff               time.Duration
	NotificationAdapter             string
	NotificationWebhookURL          string
	KnowledgeDatabaseDSN            string
	PolicyResolverMode              string
	PolicyBootstrapJSON             string
	PromptTemplatesJSON             string
	DemoIdentityBootstrap           bool
	IdentityEnrollmentTenantID      string
	IdentityEnrollmentDepartmentID  string
	IdentityEnrollmentApplicationID string
	IdentityEnrollmentInviteCode    string
	IdentityEnrollmentHMACKey       string
	IdentityEnrollmentDeliveryKey   string
	ModelEndpointMappings           map[string]string
	ModelSecretRoot                 string
}

func LoadRuntimeConfig() (RuntimeConfig, error) {
	demoIdentityBootstrap, err := envBool("PLATFORM_DEMO_IDENTITY_BOOTSTRAP", false)
	if err != nil {
		return RuntimeConfig{}, err
	}
	modelEndpointMappings, err := loadModelEndpointMappings()
	if err != nil {
		return RuntimeConfig{}, err
	}
	notificationWebhook := strings.TrimSpace(os.Getenv("PLATFORM_NOTIFICATION_WEBHOOK_URL"))
	notificationAdapter := strings.ToLower(env("PLATFORM_NOTIFICATION_ADAPTER", "none"))
	// Preserve the historical URL-only configuration while exposing an
	// explicit adapter mode for production manifests.
	if notificationAdapter == "none" && notificationWebhook != "" {
		notificationAdapter = "webhook"
	}
	c := RuntimeConfig{
		Environment:                     strings.ToLower(env("APP_ENV", "development")),
		HTTPAddr:                        env("PLATFORM_HTTP_ADDR", ":8080"),
		InternalAddr:                    env("PLATFORM_INTERNAL_ADDR", ":8081"),
		RunWorkers:                      envInt("PLATFORM_RUN_WORKERS", 4),
		DBDriver:                        strings.ToLower(env("DB_DRIVER", "pgx")),
		DBDSN:                           env("DB_DSN", ""),
		InternalToken:                   envSecret("INTERNAL_TOKEN"),
		BrowserGatewayToken:             envSecret("BROWSER_GATEWAY_TOKEN"),
		InternalSigningSecret:           envSecret("INTERNAL_SIGNING_SECRET"),
		PlatformContextPublicKey:        envSecret("PLATFORM_CONTEXT_PUBLIC_KEY"),
		PlatformContextPrivateKey:       envSecret("PLATFORM_CONTEXT_PRIVATE_KEY"),
		PlatformContextIssuer:           env("PLATFORM_CONTEXT_ISSUER", "platform"),
		PlatformContextAudience:         env("PLATFORM_CONTEXT_AUDIENCE", "agent-runtime"),
		OTelEndpoint:                    env("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
		EventBusMode:                    strings.ToLower(env("EVENT_BUS_MODE", "disabled")),
		KafkaBrokers:                    envFirst("PLATFORM_KAFKA_BROKERS", "KAFKA_BROKERS", "kafka:9092"),
		KafkaClientID:                   envFirst("PLATFORM_KAFKA_CLIENT_ID", "KAFKA_CLIENT_ID", "lexagent-platform"),
		KafkaNotificationTopic:          envFirst("PLATFORM_KAFKA_NOTIFICATION_TOPIC", "KAFKA_NOTIFICATION_TOPIC", "platform.audit"),
		KafkaNotificationGroup:          envFirst("PLATFORM_KAFKA_NOTIFICATION_GROUP", "KAFKA_NOTIFICATION_GROUP", "lexagent-platform-notification-v1"),
		KafkaNotificationDLQ:            envFirst("PLATFORM_KAFKA_NOTIFICATION_DLQ", "KAFKA_NOTIFICATION_DLQ_TOPIC", "platform.notification-dlq.v1"),
		KafkaMaxAttempts:                envInt("PLATFORM_KAFKA_MAX_ATTEMPTS", 5),
		KafkaRetryBackoff:               envDuration("PLATFORM_KAFKA_RETRY_BACKOFF", time.Second),
		NotificationAdapter:             notificationAdapter,
		NotificationWebhookURL:          notificationWebhook,
		KnowledgeDatabaseDSN:            strings.TrimSpace(os.Getenv("KNOWLEDGE_DATABASE_DSN")),
		PolicyResolverMode:              strings.ToLower(env("PLATFORM_POLICY_RESOLVER", "disabled")),
		PolicyBootstrapJSON:             strings.TrimSpace(os.Getenv("PLATFORM_POLICY_BOOTSTRAP_JSON")),
		PromptTemplatesJSON:             strings.TrimSpace(os.Getenv("PLATFORM_PROMPT_TEMPLATES_JSON")),
		DemoIdentityBootstrap:           demoIdentityBootstrap,
		IdentityEnrollmentTenantID:      env("IDENTITY_ENROLLMENT_TENANT_ID", ""),
		IdentityEnrollmentDepartmentID:  env("IDENTITY_ENROLLMENT_DEPARTMENT_ID", ""),
		IdentityEnrollmentApplicationID: env("IDENTITY_ENROLLMENT_APPLICATION_ID", ""),
		IdentityEnrollmentInviteCode:    env("IDENTITY_ENROLLMENT_INVITE_CODE", ""),
		IdentityEnrollmentHMACKey:       envSecret("IDENTITY_ENROLLMENT_HMAC_KEY"),
		IdentityEnrollmentDeliveryKey:   envSecret("IDENTITY_ENROLLMENT_DELIVERY_KEY"),
		ModelEndpointMappings:           modelEndpointMappings,
		ModelSecretRoot:                 env("PLATFORM_MODEL_SECRET_ROOT", "/run/secrets/model-providers"),
	}
	if c.RunWorkers < 1 || c.RunWorkers > 32 {
		return RuntimeConfig{}, errors.New("PLATFORM_RUN_WORKERS must be between 1 and 32")
	}
	if err := c.Validate(); err != nil {
		return RuntimeConfig{}, err
	}
	return c, nil
}

func (c RuntimeConfig) IsProduction() bool {
	environment := strings.ToLower(strings.TrimSpace(c.Environment))
	return environment == "production" || environment == "prod"
}

// Validate fails closed for unsafe production values and malformed common
// settings. Secret values are never included in returned errors.
// Validate 对不安全生产配置和非法通用配置 fail closed，错误中不包含 Secret。
func (c RuntimeConfig) Validate() error {
	if c.RunWorkers < 0 || c.RunWorkers > 32 {
		return errors.New("PLATFORM_RUN_WORKERS must be between 1 and 32")
	}
	if c.HTTPAddr == "" || c.InternalAddr == "" {
		return errors.New("platform listen addresses are required")
	}
	// The public platform supports one relational database: PostgreSQL.
	if c.DBDriver != "pgx" && c.DBDriver != "postgres" {
		return fmt.Errorf("unsupported DB_DRIVER %q; PostgreSQL is required", c.DBDriver)
	}
	if c.EventBusMode != "disabled" && c.EventBusMode != "kafka" {
		return fmt.Errorf("unsupported EVENT_BUS_MODE %q", c.EventBusMode)
	}
	adapter := c.NotificationAdapter
	if adapter == "" {
		adapter = "none"
	}
	if adapter != "none" && adapter != "webhook" && adapter != "audit" {
		return fmt.Errorf("unsupported PLATFORM_NOTIFICATION_ADAPTER %q", adapter)
	}
	if adapter == "webhook" {
		u, err := url.Parse(c.NotificationWebhookURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("PLATFORM_NOTIFICATION_WEBHOOK_URL must be an absolute http(s) URL")
		}
	}
	if c.EventBusMode == "kafka" {
		for name, value := range map[string]string{
			"PLATFORM_KAFKA_BROKERS":            c.KafkaBrokers,
			"PLATFORM_KAFKA_CLIENT_ID":          c.KafkaClientID,
			"PLATFORM_KAFKA_NOTIFICATION_TOPIC": c.KafkaNotificationTopic,
			"PLATFORM_KAFKA_NOTIFICATION_GROUP": c.KafkaNotificationGroup,
			"PLATFORM_KAFKA_NOTIFICATION_DLQ":   c.KafkaNotificationDLQ,
		} {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s is required when EVENT_BUS_MODE=kafka", name)
			}
		}
		if c.KafkaMaxAttempts < 1 || c.KafkaMaxAttempts > 100 {
			return errors.New("PLATFORM_KAFKA_MAX_ATTEMPTS must be between 1 and 100")
		}
		if c.KafkaRetryBackoff <= 0 || c.KafkaRetryBackoff > time.Hour {
			return errors.New("PLATFORM_KAFKA_RETRY_BACKOFF must be between 1ns and 1h")
		}
		if adapter == "none" {
			return errors.New("EVENT_BUS_MODE=kafka requires PLATFORM_NOTIFICATION_ADAPTER")
		}
	}
	// An empty mode is retained for programmatic RuntimeConfig literals used by
	// unit tests and embedders; environment-loaded production config still
	// defaults to disabled and is rejected below unless SQL is selected.
	// 空模式兼容程序化配置；生产环境仍会在下方强制要求 SQL resolver。
	if c.PolicyResolverMode != "" && c.PolicyResolverMode != "disabled" && c.PolicyResolverMode != "sql" {
		return fmt.Errorf("unsupported PLATFORM_POLICY_RESOLVER %q", c.PolicyResolverMode)
	}
	if err := validateModelEndpointMappings(c.ModelEndpointMappings, c.Environment == "development"); err != nil {
		return err
	}
	if c.Environment != "development" && c.PolicyResolverMode == "sql" {
		if len(c.ModelEndpointMappings) == 0 || strings.TrimSpace(c.ModelSecretRoot) == "" {
			return errors.New("non-development SQL policy runtime requires approved model endpoint mappings and mounted secret root")
		}
	}
	if c.DemoIdentityBootstrap && c.Environment != "development" {
		return errors.New("PLATFORM_DEMO_IDENTITY_BOOTSTRAP is allowed only when APP_ENV=development")
	}
	enrollmentConfigured := c.IdentityEnrollmentTenantID != "" || c.IdentityEnrollmentDepartmentID != "" || c.IdentityEnrollmentApplicationID != "" || c.IdentityEnrollmentInviteCode != "" || c.IdentityEnrollmentHMACKey != ""
	if enrollmentConfigured && (c.IdentityEnrollmentTenantID == "" || c.IdentityEnrollmentDepartmentID == "" || c.IdentityEnrollmentApplicationID == "" || c.IdentityEnrollmentInviteCode == "") {
		return errors.New("identity enrollment requires complete tenant, department, application, and invite-code configuration")
	}
	if enrollmentConfigured && c.IsProduction() {
		if !validProductionSecret(c.IdentityEnrollmentHMACKey) {
			return errors.New("production identity enrollment requires IDENTITY_ENROLLMENT_HMAC_KEY with at least 32 bytes")
		}
		if len(c.IdentityEnrollmentDeliveryKey) != 32 || !validProductionSecret(c.IdentityEnrollmentDeliveryKey) {
			return errors.New("production identity enrollment requires IDENTITY_ENROLLMENT_DELIVERY_KEY with exactly 32 bytes")
		}
		if c.NotificationAdapter == "none" {
			return errors.New("production identity enrollment requires a configured notification ChannelAdapter")
		}
	}
	if !c.IsProduction() {
		if c.BrowserGatewayToken != "" && (!validProductionSecret(c.BrowserGatewayToken) || c.BrowserGatewayToken == c.InternalToken) {
			return errors.New("BROWSER_GATEWAY_TOKEN must be independent and contain at least 32 non-placeholder bytes")
		}
		return nil
	}
	if !validProductionSecret(c.BrowserGatewayToken) || c.BrowserGatewayToken == c.InternalToken {
		return errors.New("production requires an independent BROWSER_GATEWAY_TOKEN with at least 32 non-placeholder bytes")
	}
	if strings.TrimSpace(c.OTelEndpoint) == "" {
		return errors.New("production requires OTEL_EXPORTER_OTLP_ENDPOINT")
	}
	for name, value := range map[string]string{
		"DB_DSN": c.DBDSN, "INTERNAL_TOKEN": c.InternalToken,
		"INTERNAL_SIGNING_SECRET": c.InternalSigningSecret,
	} {
		if value == "" || strings.Contains(strings.ToLower(value), "dev-") || strings.Contains(strings.ToLower(value), "root:root") {
			return fmt.Errorf("production requires explicit non-placeholder %s", name)
		}
	}
	for name, value := range map[string]string{"INTERNAL_TOKEN": c.InternalToken, "INTERNAL_SIGNING_SECRET": c.InternalSigningSecret} {
		if !validProductionSecret(value) {
			return fmt.Errorf("production requires non-placeholder %s with at least 32 bytes", name)
		}
	}
	if c.KnowledgeDatabaseDSN == "" {
		return errors.New("production requires KNOWLEDGE_DATABASE_DSN")
	}

	database, err := pgx.ParseConfig(c.DBDSN)
	if err != nil || strings.TrimSpace(c.DBDSN) == "" || database.User == "" || strings.EqualFold(database.User, "postgres") || strings.EqualFold(database.User, "root") || database.Database == "" || len(database.Password) < 16 || repeatedSecret(database.Password) || knownPlaceholder(database.Password) {
		return errors.New("production DB_DSN requires valid PostgreSQL credentials with a non-administrator account, database and a non-placeholder password of at least 16 bytes")
	}
	if c.PolicyResolverMode != "sql" {
		return errors.New("production requires PLATFORM_POLICY_RESOLVER=sql")
	}
	// Direct snapshot/template seeding is an isolated development fixture. In
	// production every change must pass the versioned PolicyAsset publication
	// boundary and its Identity authorization, CAS and audit controls.
	// 直接注入快照/Prompt 仅用于隔离开发验收；生产策略必须经受控发布流程。
	if c.PolicyBootstrapJSON != "" || c.PromptTemplatesJSON != "" {
		return errors.New("production forbids direct policy or prompt bootstrap")
	}
	if strings.EqualFold(env("AUTO_MIGRATE", "false"), "true") {
		return errors.New("production requires AUTO_MIGRATE=false")
	}
	if !validProductionContextKeys(c.PlatformContextPrivateKey, c.PlatformContextPublicKey) {
		return errors.New("production requires a non-repeated Ed25519 PLATFORM_CONTEXT_PRIVATE_KEY and matching PLATFORM_CONTEXT_PUBLIC_KEY")
	}
	return nil
}

// 拒绝已知无熵 seed 和公私钥不一致；随机性仍由受控生成器保证。
func validProductionContextKeys(encodedPrivate, encodedPublic string) bool {
	private, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedPrivate))
	if err != nil || (len(private) != ed25519.SeedSize && len(private) != ed25519.PrivateKeySize) {
		return false
	}
	seed := private[:ed25519.SeedSize]
	repeated := true
	for _, value := range seed[1:] {
		if value != seed[0] {
			repeated = false
			break
		}
	}
	if repeated {
		return false
	}
	expanded := ed25519.NewKeyFromSeed(seed)
	if len(private) == ed25519.PrivateKeySize && subtle.ConstantTimeCompare(private, expanded) != 1 {
		return false
	}
	public, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedPublic))
	return err == nil && len(public) == ed25519.PublicKeySize && subtle.ConstantTimeCompare(public, expanded[ed25519.SeedSize:]) == 1
}

// 凭证格式校验不能证明熵；生产凭证仍须由密码学随机生成器产生。
func validProductionSecret(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) >= 32 && !repeatedSecret(value) && !knownPlaceholder(value)
}

func repeatedSecret(value string) bool {
	runes := []rune(value)
	return len(runes) == 0 || strings.Count(value, string(runes[0])) == len(runes)
}

func knownPlaceholder(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	switch lower {
	case "your_api_key", "your_rag_api_key", "<your_api_key>", "<your_rag_api_key>":
		return true
	}
	for _, marker := range []string{"replace-", "change-me", "changeme", "placeholder", "dev-internal", "dev-signing"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func loadModelEndpointMappings() (map[string]string, error) {
	raw := strings.TrimSpace(os.Getenv("PLATFORM_MODEL_ENDPOINTS_JSON"))
	if raw == "" {
		return nil, nil
	}
	var mappings map[string]string
	if err := json.Unmarshal([]byte(raw), &mappings); err != nil {
		return nil, errors.New("PLATFORM_MODEL_ENDPOINTS_JSON must be a JSON object")
	}
	return mappings, nil
}

func validateModelEndpointMappings(mappings map[string]string, allowLoopback bool) error {
	if len(mappings) > 128 {
		return errors.New("PLATFORM_MODEL_ENDPOINTS_JSON exceeds 128 mappings")
	}
	for reference, rawEndpoint := range mappings {
		if !validModelEndpointReference(reference) {
			return errors.New("PLATFORM_MODEL_ENDPOINTS_JSON contains an invalid symbolic reference")
		}
		endpoint, err := url.Parse(strings.TrimSpace(rawEndpoint))
		if err != nil || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return errors.New("PLATFORM_MODEL_ENDPOINTS_JSON contains an invalid endpoint")
		}
		if endpoint.Scheme == "https" {
			if endpoint.Port() != "" && endpoint.Port() != "443" && endpoint.Port() != "8443" {
				return errors.New("PLATFORM_MODEL_ENDPOINTS_JSON contains a disallowed HTTPS port")
			}
			continue
		}
		if endpoint.Scheme != "http" || !allowLoopback {
			return errors.New("model endpoints require HTTPS outside explicit development mode")
		}
		host := strings.TrimSuffix(strings.ToLower(endpoint.Hostname()), ".")
		ip, parseErr := netip.ParseAddr(host)
		if parseErr == nil && !ip.IsLoopback() || parseErr != nil && host != "localhost" && !strings.HasSuffix(host, ".localhost") {
			return errors.New("development HTTP model endpoints must use loopback")
		}
		if endpoint.Port() == "" {
			return errors.New("development HTTP model endpoints require an explicit port")
		}
		port, parseErr := strconv.Atoi(endpoint.Port())
		if parseErr != nil || port < 1 || port > 65535 {
			return errors.New("development model endpoint has an invalid port")
		}
	}
	return nil
}

func validModelEndpointReference(reference string) bool {
	for _, prefix := range []string{"service://", "k8s://", "ref://"} {
		if strings.HasPrefix(reference, prefix) {
			value := strings.TrimPrefix(reference, prefix)
			if value == "" || len(value) > 128 || strings.ContainsAny(value, "/\\?#\r\n\x00") {
				return false
			}
			for _, r := range value {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
					return false
				}
			}
			return true
		}
	}
	return false
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envFirst(names ...string) string {
	for _, name := range names[:len(names)-1] {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return names[len(names)-1]
}

func envInt(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return parsed
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return parsed
}

func envBool(name string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	switch strings.ToLower(value) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be a boolean", name)
	}
}

func envSecret(name string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	path := strings.TrimSpace(os.Getenv(name + "_FILE"))
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}
