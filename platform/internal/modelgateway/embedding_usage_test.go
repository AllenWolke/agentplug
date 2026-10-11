package modelgateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPEmbeddingRequiresRealUsageAndValidVectorBatch(t *testing.T) {
	payload := `{"data":[{"index":1,"embedding":[0.3,0.4]},{"index":0,"embedding":[0.1,0.2]}],"usage":{"prompt_tokens":12,"total_tokens":12}}`
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/embeddings" {
			t.Error("wrong provider operation")
		}
		w.Write([]byte(payload))
	}))
	defer server.Close()
	catalog := testCatalog{provider: approvedProvider(server.URL), model: approvedModel()}
	catalog.model.Kind = "embedding"
	adapter := newTestAdapterWithCatalog(t, catalog, server.URL+"/v1", nil, true)
	profile := testSnapshot()
	profile.Model.EmbeddingModelVersionID = profile.Model.ModelVersionID
	profile.Model.EmbeddingProvider = profile.Model.Provider
	profile.Model.EmbeddingModel = profile.Model.Model
	profile.Model.ModelVersionID = "separate-chat-version"
	profile.Model.Provider = "separate-chat-provider"
	profile.Model.Model = "separate-chat-model"
	if _, err := adapter.EmbedWithUsage(context.Background(), trustedScope(), profile, []string{"one", "two"}); err != nil {
		t.Fatal("published secondary embedding target not selected", err)
	}
	profile.Model.EmbeddingProvider = ""
	beforeInvalid := calls
	if _, err := adapter.EmbedWithUsage(context.Background(), trustedScope(), profile, []string{"one", "two"}); !errors.Is(err, ErrModelUnavailable) || calls != beforeInvalid {
		t.Fatal("incomplete secondary target sent", err)
	}
	result, err := adapter.EmbedWithUsage(context.Background(), trustedScope(), testSnapshot(), []string{"one", "two"})
	if err != nil || result.InputTokens != 12 || len(result.Vectors) != 2 || result.Vectors[0][0] != .1 || result.Vectors[1][0] != .3 {
		t.Fatal("actual embedding usage/order", err)
	}
	for _, invalid := range []string{
		`{"data":[{"index":0,"embedding":[1,2]},{"index":1,"embedding":[2,3]}]}`,
		`{"data":[{"index":0,"embedding":[1,2]},{"index":1,"embedding":[2,3]}],"usage":{"prompt_tokens":null,"total_tokens":12}}`,
		`{"data":[{"index":0,"embedding":[1,2]},{"index":1,"embedding":[2,3]}],"usage":{"prompt_tokens":-1,"total_tokens":-1}}`,
		`{"data":[{"index":0,"embedding":[1,2]},{"index":1,"embedding":[2,3]}],"usage":{"prompt_tokens":12,"total_tokens":13}}`,
		`{"data":[{"index":0,"embedding":[1,2]},{"index":1,"embedding":[2]}],"usage":{"prompt_tokens":12,"total_tokens":12}}`,
		`{"data":[{"index":0,"embedding":[0,0]},{"index":1,"embedding":[2,3]}],"usage":{"prompt_tokens":12,"total_tokens":12}}`,
		`{"data":[{"index":0,"embedding":[1,2]},{"index":0,"embedding":[2,3]}],"usage":{"prompt_tokens":12,"total_tokens":12}}`,
	} {
		payload = invalid
		if _, err := adapter.EmbedWithUsage(context.Background(), trustedScope(), testSnapshot(), []string{"one", "two"}); !errors.Is(err, ErrProviderResponse) {
			t.Fatal("invalid billable response accepted", err)
		}
	}
	before := calls
	catalog.model.Kind = "chat"
	wrong := newTestAdapterWithCatalog(t, catalog, server.URL+"/v1", nil, true)
	if _, err := wrong.EmbedWithUsage(context.Background(), trustedScope(), testSnapshot(), []string{"one"}); !errors.Is(err, ErrModelUnavailable) || calls != before {
		t.Fatal("non-embedding model sent", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := adapter.EmbedWithUsage(cancelled, trustedScope(), testSnapshot(), []string{"one"}); err == nil || calls != before {
		t.Fatal("cancelled embedding sent", err)
	}
}
