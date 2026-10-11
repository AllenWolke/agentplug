package bootstrap

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestProductionConfigFailsClosedWithoutSecrets(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("AUTO_MIGRATE", "false")
	if _, err := LoadRuntimeConfig(); err == nil {
		t.Fatal("expected missing production secrets to fail")
	}
}

func TestProductionSharedSecretsRejectWeakAndPlaceholderValues(t *testing.T) {
	valid := "test-0123456789abcdef0123456789abcdef"
	base := RuntimeConfig{
		Environment: "production", HTTPAddr: ":8080", InternalAddr: ":8081", DBDriver: "pgx", EventBusMode: "disabled",
		DBDSN: "postgres://fixture_runtime:fixture-db-password-0123456789abcdef@127.0.0.1:5432/agentplug?sslmode=disable", InternalToken: valid, InternalSigningSecret: valid,
		KnowledgeDatabaseDSN: "postgres://knowledge.invalid/knowledge", PolicyResolverMode: "sql",
		ModelEndpointMappings: map[string]string{"service://approved-provider": "https://provider.example/v1"}, ModelSecretRoot: "/run/secrets/model-providers", OTelEndpoint: "https://collector.example",
	}
	addFixtureContextKeys(&base)
	for _, field := range []string{"token", "signing"} {
		for _, value := range []string{"", "short", strings.Repeat("x", 32), strings.Repeat("密", 11), "replace-" + strings.Repeat("0123456789abcdef", 3)} {
			candidate := base
			if field == "token" {
				candidate.InternalToken = value
			} else {
				candidate.InternalSigningSecret = value
			}
			if err := candidate.Validate(); err == nil || (value != "" && strings.Contains(err.Error(), value)) {
				t.Fatalf("unsafe %s accepted or echoed", field)
			}
		}
	}
	base.Environment = "prod"
	if err := base.Validate(); err != nil {
		t.Fatalf("strong production alias config rejected: %v", err)
	}
}

func TestSecretFileIsLoadedWithoutExposingValue(t *testing.T) {
	path := t.TempDir() + "/token"
	if err := writeSecret(path, "file-token-0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APP_ENV", "production")
	t.Setenv("DB_DSN", "postgres://fixture_runtime:fixture-db-password-0123456789abcdef@127.0.0.1:5432/agentplug?sslmode=disable")
	t.Setenv("INTERNAL_TOKEN_FILE", path)
	t.Setenv("INTERNAL_SIGNING_SECRET", "signing-secret-0123456789abcdef0123456789abcdef")
	t.Setenv("AUTO_MIGRATE", "false")
	t.Setenv("INTERNAL_TOKEN", "")
	t.Setenv("KNOWLEDGE_DATABASE_DSN", "postgres://knowledge.invalid/knowledge")
	t.Setenv("PLATFORM_POLICY_RESOLVER", "sql")
	t.Setenv("PLATFORM_MODEL_ENDPOINTS_JSON", `{"service://approved-provider":"https://provider.example/v1"}`)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector.example")
	material := productionCredentialFixture()
	t.Setenv("BROWSER_GATEWAY_TOKEN", material.BrowserGatewayToken)
	t.Setenv("PLATFORM_CONTEXT_PRIVATE_KEY", material.PlatformContextPrivateKey)
	t.Setenv("PLATFORM_CONTEXT_PUBLIC_KEY", material.PlatformContextPublicKey)
	c, err := LoadRuntimeConfig()
	if err != nil {
		t.Fatalf("file secret rejected: %v", err)
	}
	if c.InternalToken != "file-token-0123456789abcdef0123456789abcdef" {
		t.Fatalf("secret file was not loaded")
	}
}

func TestRuntimeConfigPostgresOnly(t *testing.T) {
	for _, driver := range []string{"pgx", "postgres", "mysql", "sqlite", "kingbase", ""} {
		c := RuntimeConfig{Environment: "development", HTTPAddr: ":8080", InternalAddr: ":8081", DBDriver: driver, EventBusMode: "disabled"}
		err := c.Validate()
		if accepted := driver == "pgx" || driver == "postgres"; (err == nil) != accepted {
			t.Fatalf("driver %q acceptance mismatch: %v", driver, err)
		}
	}
}

func TestRunWorkerCountIsBoundedAndDefaultsToFour(t *testing.T) {
	for _, input := range []string{"0", "33", "not-an-integer"} {
		t.Run(input, func(t *testing.T) {
			t.Setenv("PLATFORM_RUN_WORKERS", input)
			if _, err := LoadRuntimeConfig(); err == nil || !strings.Contains(err.Error(), "PLATFORM_RUN_WORKERS") {
				t.Fatalf("invalid worker count accepted or misclassified: %v", err)
			}
		})
	}
	t.Setenv("PLATFORM_RUN_WORKERS", "")
	c, err := LoadRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.RunWorkers != 4 {
		t.Fatalf("default worker count=%d", c.RunWorkers)
	}
}

func TestKafkaRuntimeConfigRequiresDurableConsumerAndChannelSettings(t *testing.T) {
	c := RuntimeConfig{
		Environment:            "development",
		HTTPAddr:               ":8080",
		InternalAddr:           ":8081",
		DBDriver:               "pgx",
		EventBusMode:           "kafka",
		KafkaBrokers:           "kafka:9092",
		KafkaClientID:          "platform-test",
		KafkaNotificationTopic: "platform.audit",
		KafkaNotificationGroup: "platform-test-v1",
		KafkaNotificationDLQ:   "platform.audit-dlq",
		KafkaMaxAttempts:       3,
		KafkaRetryBackoff:      time.Second,
		NotificationAdapter:    "webhook",
		NotificationWebhookURL: "http://notification.test/hook",
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid Kafka configuration rejected: %v", err)
	}
	c.NotificationAdapter = "audit"
	c.NotificationWebhookURL = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("durable internal audit channel rejected: %v", err)
	}
	c.NotificationAdapter = "none"
	if err := c.Validate(); err == nil {
		t.Fatal("Kafka mode must fail closed without a ChannelAdapter")
	}
}

func TestKafkaRuntimeConfigRejectsInvalidWebhook(t *testing.T) {
	c := RuntimeConfig{Environment: "development", HTTPAddr: ":8080", InternalAddr: ":8081", DBDriver: "pgx", EventBusMode: "disabled", NotificationAdapter: "webhook", NotificationWebhookURL: "file:///secret"}
	if err := c.Validate(); err == nil {
		t.Fatal("non-http webhook must be rejected")
	}
}

func TestDemoIdentityBootstrapIsDevelopmentOnly(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("PLATFORM_DEMO_IDENTITY_BOOTSTRAP", "true")
	c, err := LoadRuntimeConfig()
	if err != nil || !c.DemoIdentityBootstrap {
		t.Fatalf("development demo bootstrap should be accepted: config=%+v err=%v", c, err)
	}
	c.Environment = "production"
	if err := c.Validate(); err == nil {
		t.Fatal("demo identity bootstrap must be rejected outside development")
	}
	t.Setenv("PLATFORM_DEMO_IDENTITY_BOOTSTRAP", "perhaps")
	if _, err := LoadRuntimeConfig(); err == nil {
		t.Fatal("invalid demo bootstrap flag must fail configuration loading")
	}
}

func TestProductionEnrollmentRequiresStrongSecretsAndChannel(t *testing.T) {
	base := RuntimeConfig{
		Environment: "production", HTTPAddr: ":8080", InternalAddr: ":8081", DBDriver: "pgx", EventBusMode: "disabled",
		DBDSN: "postgres://fixture_runtime:fixture-db-password-0123456789abcdef@127.0.0.1:5432/agentplug?sslmode=disable", InternalToken: "internal-safe-0123456789abcdef0123456789abcdef", InternalSigningSecret: "signing-safe-0123456789abcdef0123456789abcdef",
		KnowledgeDatabaseDSN: "postgres://knowledge.invalid/knowledge", PolicyResolverMode: "sql",
		ModelEndpointMappings: map[string]string{"service://approved-provider": "https://provider.example/v1"}, ModelSecretRoot: "/run/secrets/model-providers",
		OTelEndpoint:               "https://collector.example",
		IdentityEnrollmentTenantID: "tenant", IdentityEnrollmentDepartmentID: "dept", IdentityEnrollmentApplicationID: "app", IdentityEnrollmentInviteCode: "invite",
	}
	addFixtureContextKeys(&base)
	if err := base.Validate(); err == nil {
		t.Fatal("production enrollment without verification secrets and delivery channel must fail closed")
	}
	base.IdentityEnrollmentHMACKey = "fixture-hmac-0123456789abcdef0123456789abcdef"
	base.IdentityEnrollmentDeliveryKey = "fixture-delivery0123456789abcdef"
	base.NotificationAdapter = "webhook"
	base.NotificationWebhookURL = "https://notify.example/hook"
	if err := base.Validate(); err != nil {
		t.Fatalf("complete production enrollment configuration rejected: %v", err)
	}
}

func TestProductionRejectsDirectPolicySnapshotAndPromptSeeding(t *testing.T) {
	t.Setenv("AUTO_MIGRATE", "false")
	base := RuntimeConfig{
		Environment: "production", HTTPAddr: ":8080", InternalAddr: ":8081", DBDriver: "pgx", EventBusMode: "disabled",
		DBDSN: "postgres://fixture_runtime:fixture-db-password-0123456789abcdef@127.0.0.1:5432/agentplug?sslmode=disable", InternalToken: "internal-safe-0123456789abcdef0123456789abcdef", InternalSigningSecret: "signing-safe-0123456789abcdef0123456789abcdef",
		KnowledgeDatabaseDSN: "postgres://knowledge.invalid/knowledge", PolicyResolverMode: "sql",
		ModelEndpointMappings: map[string]string{"service://approved-provider": "https://provider.example/v1"}, ModelSecretRoot: "/run/secrets/model-providers",
		OTelEndpoint: "https://collector.example",
	}
	addFixtureContextKeys(&base)
	if err := base.Validate(); err != nil {
		t.Fatalf("valid production baseline rejected: %v", err)
	}
	base.OTelEndpoint = ""
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "OTEL_EXPORTER_OTLP_ENDPOINT") {
		t.Fatal("production without trace collector was accepted")
	}
	base.OTelEndpoint = "https://collector.example"
	base.PolicyBootstrapJSON = `[{"tenant_id":"t"}]`
	if err := base.Validate(); err == nil {
		t.Fatal("direct production policy bootstrap bypasses the control plane")
	}
	base.PolicyBootstrapJSON = ""
	base.PromptTemplatesJSON = `{"hash":"prompt"}`
	if err := base.Validate(); err == nil {
		t.Fatal("direct production prompt bootstrap bypasses the control plane")
	}
}

func TestLoadModelEndpointMappingsAndFailClosedValidation(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("PLATFORM_MODEL_ENDPOINTS_JSON", `{"service://local-model":"http://127.0.0.1:8000/v1"}`)
	config, err := LoadRuntimeConfig()
	if err != nil || config.ModelEndpointMappings["service://local-model"] == "" {
		t.Fatalf("loopback model endpoint config rejected: mappings=%v err=%v", config.ModelEndpointMappings, err)
	}
	t.Setenv("PLATFORM_MODEL_ENDPOINTS_JSON", `{"service://external":"http://169.254.169.254/latest"}`)
	if _, err := LoadRuntimeConfig(); err == nil {
		t.Fatal("development HTTP endpoint must not allow non-loopback addresses")
	}
	t.Setenv("PLATFORM_MODEL_ENDPOINTS_JSON", `not-json`)
	if _, err := LoadRuntimeConfig(); err == nil {
		t.Fatal("malformed endpoint mapping JSON must fail config loading")
	}
	if err := validateModelEndpointMappings(map[string]string{"service://model": "http://127.0.0.1:8000/v1"}, false); err == nil {
		t.Fatal("HTTP provider endpoint must not be allowed outside development")
	}
	if err := validateModelEndpointMappings(map[string]string{"service://model": "https://provider.example:9443/v1"}, true); err == nil {
		t.Fatal("unapproved HTTPS port must be rejected")
	}
}

func writeSecret(path, value string) error {
	return os.WriteFile(path, []byte(value), 0o600)
}
