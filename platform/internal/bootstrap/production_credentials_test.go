package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func productionCredentialFixture() RuntimeConfig {
	config := RuntimeConfig{
		Environment: "production", HTTPAddr: ":8080", InternalAddr: ":8081", DBDriver: "pgx", EventBusMode: "disabled",
		DBDSN:         "postgres://fixture_runtime:fixture-db-password-0123456789abcdef@127.0.0.1:5432/agentplug?sslmode=disable",
		InternalToken: "fixture-token-0123456789abcdef0123456789abcdef", InternalSigningSecret: "fixture-signing-0123456789abcdef0123456789abcdef",
		KnowledgeDatabaseDSN: "postgres://knowledge.invalid/knowledge", PolicyResolverMode: "sql",
		ModelEndpointMappings: map[string]string{"service://approved-provider": "https://provider.example/v1"}, ModelSecretRoot: "/run/secrets/model-providers", OTelEndpoint: "https://collector.example",
	}
	addFixtureContextKeys(&config)
	return config
}

func addFixtureContextKeys(config *RuntimeConfig) {
	config.BrowserGatewayToken = "gateway-fixture-0123456789abcdef0123456789abcdef"
	seed := sha256.Sum256([]byte("public synthetic context signing test fixture"))
	private := ed25519.NewKeyFromSeed(seed[:])
	config.PlatformContextPrivateKey = base64.StdEncoding.EncodeToString(seed[:])
	config.PlatformContextPublicKey = base64.StdEncoding.EncodeToString(private[ed25519.SeedSize:])
}

func TestProductionContextKeysRejectMissingRepeatedMalformedAndMismatchedMaterial(t *testing.T) {
	t.Setenv("AUTO_MIGRATE", "false")
	base := productionCredentialFixture()
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*RuntimeConfig){
		func(c *RuntimeConfig) { c.PlatformContextPrivateKey = "" },
		func(c *RuntimeConfig) { c.PlatformContextPublicKey = "" },
		func(c *RuntimeConfig) { c.PlatformContextPrivateKey = "invalid-base64" },
		func(c *RuntimeConfig) {
			c.PlatformContextPrivateKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, ed25519.SeedSize))
		},
		func(c *RuntimeConfig) {
			c.PlatformContextPrivateKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, ed25519.SeedSize))
		},
		func(c *RuntimeConfig) {
			c.PlatformContextPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, ed25519.PublicKeySize))
		},
		func(c *RuntimeConfig) {
			c.PlatformContextPrivateKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, ed25519.PrivateKeySize))
		},
		func(c *RuntimeConfig) {
			seed, err := base64.StdEncoding.DecodeString(c.PlatformContextPrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			private := ed25519.NewKeyFromSeed(seed)
			private[ed25519.SeedSize] ^= 1
			c.PlatformContextPrivateKey = base64.StdEncoding.EncodeToString(private)
		},
	} {
		candidate := base
		mutate(&candidate)
		if err := candidate.Validate(); err == nil || (candidate.PlatformContextPrivateKey != "" && strings.Contains(err.Error(), candidate.PlatformContextPrivateKey)) {
			t.Fatal("unsafe signing material accepted or echoed")
		}
	}
	seed, err := base64.StdEncoding.DecodeString(base.PlatformContextPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	base.PlatformContextPrivateKey = base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed))
	if err := base.Validate(); err != nil {
		t.Fatal("expanded valid private key rejected")
	}
}

func TestProductionDatabaseCredentialsFailClosedWithoutEcho(t *testing.T) {
	t.Setenv("AUTO_MIGRATE", "false")
	base := productionCredentialFixture()
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, dsn := range []string{
		"mysql://not-a-postgres-dsn", "runtime@tcp(localhost:3306)/agentplug?parseTime=true",
		"postgres://postgres:fixture-db-password-0123456789abcdef@localhost:5432/agentplug",
		"postgres://root:fixture-db-password-0123456789abcdef@localhost:5432/agentplug",
		"postgres://runtime:short@localhost:5432/agentplug",
		"postgres://runtime:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx@localhost:5432/agentplug",
		"postgres://runtime:replace-runtime-password@localhost:5432/agentplug",
		"postgres://runtime@localhost:5432/agentplug",
		"postgres://runtime:fixture-db-password-0123456789abcdef@localhost:invalid/agentplug",
	} {
		candidate := base
		candidate.DBDSN = dsn
		if err := candidate.Validate(); err == nil || strings.Contains(err.Error(), dsn) {
			t.Fatal("unsafe DSN accepted or echoed")
		}
	}
}

func TestProductionNameNormalizationDoesNotBypassCredentialChecks(t *testing.T) {
	for _, environment := range []string{"production", "prod", "PRODUCTION", " PROD "} {
		candidate := productionCredentialFixture()
		candidate.Environment = environment
		candidate.InternalToken = "short"
		if !candidate.IsProduction() || candidate.Validate() == nil {
			t.Fatal("production spelling bypassed validation")
		}
	}
}

func TestProductionEnrollmentRejectPlaceholderAndRepeatedKeys(t *testing.T) {
	t.Setenv("AUTO_MIGRATE", "false")
	base := productionCredentialFixture()
	base.IdentityEnrollmentTenantID = "tenant"
	base.IdentityEnrollmentDepartmentID = "department"
	base.IdentityEnrollmentApplicationID = "application"
	base.IdentityEnrollmentInviteCode = "fixture-invite"
	base.IdentityEnrollmentHMACKey = "fixture-hmac-0123456789abcdef0123456789abcdef"
	base.IdentityEnrollmentDeliveryKey = "fixture-delivery0123456789abcdef"
	base.NotificationAdapter = "webhook"
	base.NotificationWebhookURL = "https://notify.example/hook"
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"hmac", "delivery"} {
		candidate := base
		if field == "hmac" {
			candidate.IdentityEnrollmentHMACKey = strings.Repeat("h", 32)
		} else {
			candidate.IdentityEnrollmentDeliveryKey = strings.Repeat("e", 32)
		}
		if candidate.Validate() == nil {
			t.Fatal("repeated enrollment key accepted")
		}
	}
}
