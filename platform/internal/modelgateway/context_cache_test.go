package modelgateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func prefixSnapshot() policyasset.Snapshot {
	s := testSnapshot()
	s.Hash = "immutable-policy-sha"
	s.Model.ContextCache = &policyasset.ContextCachePolicy{Version: "context-prefix/v1", Mode: "provider_prefix", Isolation: "session"}
	return s
}

func TestContextPrefixPreservesTranscriptAndIsolatesTrustedBoundaries(t *testing.T) {
	s, scope := prefixSnapshot(), trustedScope()
	key := []byte("test-context-cache-hmac-secret")
	messages := []Message{{Role: "system", Content: "approved instructions"}, {Role: "user", Content: "private evidence and question"}}
	before, _ := json.Marshal(messages)
	out, partition, err := PrepareContextCachePrefix(scope, s, messages, key)
	if err != nil || len(partition) != 64 || len(out) != len(messages) || !strings.HasSuffix(out[0].Content, messages[0].Content) || !reflect.DeepEqual(out[1:], messages[1:]) {
		t.Fatalf("prefix changed transcript semantics: %v", err)
	}
	after, _ := json.Marshal(messages)
	if string(before) != string(after) || strings.Contains(out[0].Content, scope.PrincipalID) || strings.Contains(out[0].Content, scope.TenantID) {
		t.Fatal("mutated input or disclosed raw identity")
	}
	anotherRun := scope
	anotherRun.RunID, anotherRun.ParentRunID, anotherRun.TraceID = "new-run", "parent", "new-trace"
	_, same, err := PrepareContextCachePrefix(anotherRun, s, messages, key)
	if err != nil || same != partition {
		t.Fatal("Run identity defeated repeated-context reuse")
	}
	for name, change := range map[string]func(*sharedkernel.Scope){
		"tenant":       func(v *sharedkernel.Scope) { v.TenantID += "-other" },
		"department":   func(v *sharedkernel.Scope) { v.DepartmentID += "-other" },
		"application":  func(v *sharedkernel.Scope) { v.ApplicationID += "-other" },
		"user":         func(v *sharedkernel.Scope) { v.PrincipalID += "-other" },
		"session":      func(v *sharedkernel.Scope) { v.SessionID += "-other" },
		"installation": func(v *sharedkernel.Scope) { v.InstallationID += "-other" },
		"version":      func(v *sharedkernel.Scope) { v.AgentVersionID += "-other" },
		"epoch":        func(v *sharedkernel.Scope) { v.AuthorizationEpoch++ },
	} {
		t.Run(name, func(t *testing.T) {
			other := scope
			change(&other)
			_, got, err := PrepareContextCachePrefix(other, s, messages, key)
			if err != nil || got == partition {
				t.Fatal("scope isolation failed")
			}
		})
	}
	s.Hash += "-new"
	_, changed, err := PrepareContextCachePrefix(scope, s, messages, key)
	if err != nil || changed == partition {
		t.Fatal("published version failed to invalidate partition")
	}
	s = testSnapshot()
	legacy, identity, err := PrepareContextCachePrefix(sharedkernel.Scope{}, s, messages, nil)
	if err != nil || identity != "" || !reflect.DeepEqual(legacy, messages) {
		t.Fatal("legacy request changed")
	}
	s = prefixSnapshot()
	if _, _, err := PrepareContextCachePrefix(scope, s, messages, []byte("short")); err == nil {
		t.Fatal("missing server key accepted")
	}
	scope.SessionID = ""
	if _, _, err := PrepareContextCachePrefix(scope, s, messages, key); err == nil {
		t.Fatal("untrusted partition accepted")
	}
}

func TestContextPrefixCacheUsageFromRealHTTPReceipts(t *testing.T) {
	for name, usage := range map[string]string{
		"deepseek":   `"prompt_cache_hit_tokens":750,"prompt_cache_miss_tokens":250`,
		"compatible": `"prompt_tokens_details":{"cached_tokens":750}`,
		"both":       `"prompt_cache_hit_tokens":750,"prompt_cache_miss_tokens":250,"prompt_tokens_details":{"cached_tokens":750}`,
		"zero":       `"prompt_tokens_details":{"cached_tokens":0}`,
		"unknown":    `"other_field":1`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]json.RawMessage
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("invalid request")
				}
				if _, exists := body["cache_control"]; exists {
					t.Error("private wire field sent to generic API")
				}
				_, _ = w.Write([]byte(`{"choices":[{"finish_reason":"stop","message":{"content":"fresh answer"}}],"usage":{"prompt_tokens":1000,"completion_tokens":10,` + usage + `}}`))
			}))
			defer server.Close()
			model := approvedModel()
			model.ContextCacheMode = "provider_prefix"
			adapter := newTestAdapterWithCatalog(t, testCatalog{provider: approvedProvider(server.URL), model: model}, server.URL+"/v1", nil, true)
			result, err := adapter.Generate(context.Background(), trustedScope(), prefixSnapshot(), validRequest())
			if err != nil || result.Text != "fresh answer" || result.InputTokens != 1000 {
				t.Fatalf("HTTP receipt: %v", err)
			}
			if name == "unknown" {
				if result.CachedInputTokens != nil || result.UncachedInputTokens != nil {
					t.Fatal("missing cache usage invented")
				}
			} else {
				want := 750
				if name == "zero" {
					want = 0
				}
				if result.CachedInputTokens == nil || *result.CachedInputTokens != want || *result.UncachedInputTokens != 1000-want {
					t.Fatal("cache split lost")
				}
			}
		})
	}
}

func TestContextPrefixRejectsInvalidSupplierUsageAndUnsupportedModels(t *testing.T) {
	for _, usage := range []string{
		`"prompt_cache_hit_tokens":-1`, `"prompt_cache_hit_tokens":1001`,
		`"prompt_cache_hit_tokens":750,"prompt_cache_miss_tokens":251`,
		`"prompt_cache_hit_tokens":750,"prompt_tokens_details":{"cached_tokens":749}`,
		`"prompt_cache_miss_tokens":250`, `"prompt_tokens_details":{"cached_tokens":true}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"answer"}}],"usage":{"prompt_tokens":1000,"completion_tokens":10,` + usage + `}}`))
		}))
		adapter := newTestAdapter(t, server.URL+"/v1", nil, true)
		if _, err := adapter.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest()); !errors.Is(err, ErrProviderResponse) {
			t.Fatal("invalid cache billing accepted", usage, err)
		}
		server.Close()
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer server.Close()
	adapter := newTestAdapter(t, server.URL+"/v1", nil, true)
	if _, err := adapter.Generate(context.Background(), trustedScope(), prefixSnapshot(), validRequest()); !errors.Is(err, ErrModelUnavailable) || calls != 0 {
		t.Fatal("unsupported model sent")
	}
}

func TestPreparationOnlyPrefixDoesNotRequireDeclaredSupplierCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid request")
		}
		if _, exists := body["cache_control"]; exists {
			t.Error("supplier-specific cache field invented")
		}
		_, _ = w.Write([]byte(`{"choices":[{"finish_reason":"stop","message":{"content":"local answer"}}],"usage":{"prompt_tokens":1000,"completion_tokens":10}}`))
	}))
	defer server.Close()
	adapter := newTestAdapter(t, server.URL+"/v1", nil, true)
	snapshot := prefixSnapshot()
	snapshot.Model.ContextCache.Version = "context-prefix/v2"
	snapshot.Model.ContextCache.UnsupportedModelBehavior = "prepare_prefix"
	result, err := adapter.Generate(context.Background(), trustedScope(), snapshot, validRequest())
	if err != nil || result.Text != "local answer" || result.CachedInputTokens != nil || result.UncachedInputTokens != nil {
		t.Fatal("preparation-only model rejected or unmeasured usage invented", result, err)
	}
}
