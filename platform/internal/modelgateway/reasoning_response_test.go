package modelgateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTruncatedProviderResponsePreservesKnownUsageWithoutReasoning(t *testing.T) {
	missingUsage := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if missingUsage {
			_, _ = w.Write([]byte(`{"choices":[{"finish_reason":"length","message":{"content":""}}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"finish_reason":"length","message":{"content":"","reasoning_content":"private reasoning"}}],"usage":{"prompt_tokens":79,"completion_tokens":256}}`))
	}))
	defer server.Close()
	adapter := newTestAdapter(t, server.URL+"/v1", nil, true)
	result, err := adapter.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest())
	if err != nil || !result.Incomplete || result.Text != "" || result.InputTokens != 79 || result.OutputTokens != 256 || result.FinishReason != "length" {
		t.Fatalf("known truncated usage lost or reasoning disclosed: result=%+v error=%v", result, err)
	}
	missingUsage = true
	if _, err := adapter.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest()); !errors.Is(err, ErrProviderResponse) {
		t.Fatal("missing metering cannot be declared known usage", err)
	}
}

type reasoningWireTransport func(*http.Request) (*http.Response, error)

func (f reasoningWireTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPublishedReasoningEffortReachesWireAndRejectsInvalidPolicyBeforeHTTP(t *testing.T) {
	adapter := newTestAdapter(t, "https://api.deepseek.com/v1", nil, false)
	calls := 0
	adapter.client.Transport = reasoningWireTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		var body struct {
			Thinking  thinkingMode `json:"thinking"`
			Effort    string       `json:"reasoning_effort"`
			MaxTokens int          `json:"max_tokens"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Thinking.Type != "enabled" || body.Effort != "max" || body.MaxTokens != 32 {
			t.Fatalf("reviewed policy was not faithfully serialized: %+v %v", body, err)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"choices":[{"finish_reason":"stop","message":{"content":"OK"}}],"usage":{"prompt_tokens":10,"completion_tokens":2}}`)), Header: make(http.Header)}, nil
	})
	snapshot, request := testSnapshot(), validRequest()
	snapshot.Model.ReasoningMode, snapshot.Model.ReasoningEffort = "enabled", "max"
	request.MaxTokens = 32
	result, err := adapter.Generate(context.Background(), trustedScope(), snapshot, request)
	if err != nil || result.Text != "OK" || calls != 1 {
		t.Fatal("published maximum reasoning request failed", err)
	}
	snapshot.Model.ReasoningMode = "disabled"
	if _, err := adapter.Generate(context.Background(), trustedScope(), snapshot, request); !errors.Is(err, ErrModelUnavailable) || calls != 1 {
		t.Fatal("contradictory policy reached the provider", err)
	}
}

func TestPublishedThinkingModeRejectsUnsupportedAndSpoofedVendors(t *testing.T) {
	for _, endpoint := range []string{"http://api.deepseek.com", "https://api.deepseek.com.evil.example", "https://unrelated.example"} {
		if _, err := publishedThinkingMode(endpoint, "disabled"); !errors.Is(err, ErrModelUnavailable) {
			t.Fatal("unsupported vendor dialect accepted", endpoint, err)
		}
	}
	if _, err := publishedThinkingMode("https://api.deepseek.com", "arbitrary-extension"); !errors.Is(err, ErrModelUnavailable) {
		t.Fatal("unpublished arbitrary setting accepted", err)
	}
	if mode, err := publishedThinkingMode("https://api.deepseek.com", "disabled"); err != nil || mode.Type != "disabled" {
		t.Fatal("approved documented mode unavailable", err)
	}
}
