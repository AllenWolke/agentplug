package agentplatform

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type publicRoundTrip func(*http.Request) (*http.Response, error)

func (f publicRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestLostToolResponseQueriesOnlyOriginalReceipt(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "known_receipt", true: "revoked"}[revoked], func(t *testing.T) {
			sends, lookups := 0, 0
			var original map[string]any
			transport := publicRoundTrip(func(request *http.Request) (*http.Response, error) {
				var body struct {
					Input map[string]any `json:"input"`
				}
				if json.NewDecoder(request.Body).Decode(&body) != nil {
					t.Fatal("invalid signed envelope")
				}
				if request.Header.Get("X-Context-Signature") == "" || request.Header.Get("X-Platform-Context") == "" {
					t.Fatal("unsigned original receipt lookup")
				}
				if request.URL.Path == "/internal/tool/invoke" {
					sends++
					original = body.Input
					return nil, io.ErrUnexpectedEOF
				}
				if request.URL.Path != "/internal/tool/receipt" {
					t.Fatalf("unexpected fresh call %s", request.URL.Path)
				}
				lookups++
				if !sameRecoveryJSONValue(original["payload"], body.Input["payload"]) || original["call_id"] != body.Input["call_id"] || original["name"] != body.Input["name"] {
					t.Fatal("receipt lookup changed operation identity")
				}
				if revoked {
					return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(`{"error_code":"MODEL_BUDGET_UNAVAILABLE"}`)), Header: make(http.Header)}, nil
				}
				data := map[string]any{"version": "tool-receipt/v1", "tool_name": "runtime.inspect", "call_id": "original", "status": "completed", "receipt": map[string]any{"data": map[string]any{"sequence": json.Number("9007199254740993")}, "observation": map[string]any{"version": "runtime-observation/v1", "tool_name": "runtime.inspect", "call_id": "original", "status": "succeeded", "effect": "completed", "instruction_trust": "untrusted_data"}}}
				raw, _ := json.Marshal(map[string]any{"data": data})
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
			})
			request := renewalFixtureRequest(time.Now().Add(time.Minute))
			client, err := NewCapabilityClient(CapabilityConfig{BaseURL: "http://fixture", InternalToken: "internal", SigningSecret: "secret", Transport: transport}, request)
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Post(context.Background(), "/internal/tool/invoke", map[string]any{"name": "runtime.inspect", "call_id": "original", "payload": map[string]any{"probe": "same"}})
			if revoked {
				if err == nil || !AuthorityFailure(err) {
					t.Fatal("403 was hidden by an operational error code", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				value := result["data"].(map[string]any)["sequence"]
				if !sameRecoveryJSONValue(value, json.Number("9007199254740993")) {
					t.Fatal("receipt integer was rounded", value)
				}
			}
			if sends != 1 || lookups != 1 {
				t.Fatalf("unknown operation was resent: sends=%d lookups=%d", sends, lookups)
			}
		})
	}
}

func TestSendLimiterWaitConsumesOriginalDeadline(t *testing.T) {
	limiter, _ := NewCapabilitySendLimiter(1)
	release, err := limiter.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err = limiter.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("capacity wait ignored deadline", err)
	}
}
