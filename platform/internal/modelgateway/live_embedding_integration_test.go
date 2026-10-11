package modelgateway

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/policyasset"
)

// Explicit opt-in only: one tiny batch through the production guarded adapter.
// Credentials and provider bodies are never emitted in the test output.
func TestLiveEmbeddingGateway(t *testing.T) {
	keyFile := strings.TrimSpace(os.Getenv("LEXAGENT_LIVE_EMBEDDING_KEY_FILE"))
	if keyFile == "" {
		t.Skip("set LEXAGENT_LIVE_EMBEDDING_KEY_FILE for an authorized live embedding call")
	}
	keyFile, err := filepath.Abs(keyFile)
	if err != nil {
		t.Fatal("invalid credential path")
	}
	info, err := os.Lstat(keyFile)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("embedding credential is not an available regular file")
	}
	model := strings.TrimSpace(os.Getenv("LEXAGENT_LIVE_EMBEDDING_MODEL"))
	endpoint := strings.TrimSpace(os.Getenv("LEXAGENT_LIVE_EMBEDDING_BASE_URL"))
	if model == "" || endpoint == "" || !strings.HasPrefix(endpoint, "https://") {
		t.Fatal("explicit model and HTTPS base URL are required")
	}
	const providerID, modelID, versionID, providerKey, endpointRef = "live-embedding-provider", "live-embedding-model", "live-embedding-version", "live-embedding", "service://live-embedding"
	catalog := testCatalog{
		provider: ProviderMetadata{ID: providerID, Key: providerKey, TrustZone: trustExternal, EndpointRef: endpointRef, SecretRef: "secret://" + filepath.Base(keyFile), Status: approvedStatus},
		model:    ModelMetadata{ID: modelID, VersionID: versionID, ProviderID: providerID, Key: model, Kind: "embedding", Status: approvedStatus},
	}
	selection := Selection{ModelVersionID: versionID, ProviderID: providerID, ProviderKey: providerKey, ModelID: modelID, ModelKey: model, TrustZone: trustExternal}
	adapter, err := NewHTTPAdapter(HTTPConfig{SecretRoot: filepath.Dir(keyFile), RequestTimeout: 40 * time.Second, ResponseHeaderTimeout: 30 * time.Second, MaxRequestBytes: 4096, MaxResponseBytes: 1 << 20, AllowedHTTPSPorts: []string{"443"}},
		testAccessResolver{selection: selection}, catalog, catalog, MountedSecretResolver{Root: filepath.Dir(keyFile)}, StaticEndpointResolver{endpointRef: endpoint})
	if err != nil {
		t.Fatal("construct guarded embedding adapter")
	}
	observer := &liveVendorTransportObserver{next: adapter.client.Transport}
	adapter.client.Transport = observer
	snapshot := policyasset.Snapshot{Model: policyasset.ModelPolicy{Provider: providerKey, Model: model, ModelVersionID: versionID, AllowExternal: true}}
	result, err := adapter.EmbedWithUsage(context.Background(), trustedScope(), snapshot, []string{"AgentPlug document retrieval test."})
	if err != nil {
		// Only fixed adapter error classifications and HTTP metadata are logged.
		t.Fatalf("live embedding failed: classification=%v http_status=%d transport_error_type=%s", err, observer.status, observer.errorType)
	}
	if observer.status != http.StatusOK || len(result.Vectors) != 1 || len(result.Vectors[0]) == 0 || result.InputTokens <= 0 {
		t.Fatal("live embedding lacks valid vector batch or token usage")
	}
	t.Logf("guarded embedding succeeded: dimensions=%d input_tokens=%d batches=1", len(result.Vectors[0]), result.InputTokens)
}
