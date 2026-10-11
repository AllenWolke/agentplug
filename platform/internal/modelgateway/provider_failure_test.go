package modelgateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProviderFailureKeepsStatusWithoutSensitiveResponse(t *testing.T) {
	for _, status := range []int{400, 401, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(testSecret + " private-input vendor-body"))
			}))
			defer server.Close()
			adapter := newTestAdapter(t, server.URL+"/v1", nil, true)
			_, err := adapter.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest())
			if !errors.Is(err, ErrProviderUnavailable) || err.Error() != ErrProviderUnavailable.Error() {
				t.Fatalf("failure contract changed: %v", err)
			}
			if got := SafeProviderFailureKind(fmt.Errorf("private wrapper: %w", err)); got != fmt.Sprintf("provider_http_%d", status) || strings.Contains(got, testSecret) {
				t.Fatalf("unsafe or missing status category: %q", got)
			}
		})
	}
}

func TestProviderFailureDistinguishesResponseTimeoutAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { time.Sleep(100 * time.Millisecond) }))
	defer server.Close()
	adapter := newTestAdapter(t, server.URL+"/v1", nil, true)
	adapter.client.Timeout = 30 * time.Millisecond
	_, err := adapter.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest())
	if got := SafeProviderFailureKind(err); got != "provider_response_timeout" {
		t.Fatalf("response timeout category: %q", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = adapter.Generate(ctx, trustedScope(), testSnapshot(), validRequest())
	if got := SafeProviderFailureKind(err); got != "provider_cancelled" {
		t.Fatalf("cancellation category: %q", got)
	}
}

func TestProviderFailureBoundsUntrustedCategoriesAndStages(t *testing.T) {
	for _, err := range []error{&ProviderFailure{Category: testSecret}, &ProviderFailure{Category: "http_response", StatusCode: 1000000}} {
		if got := SafeProviderFailureKind(err); got != "provider_unavailable" {
			t.Fatalf("untrusted diagnostic escaped: %q", got)
		}
	}
	for stage, want := range map[int32]string{providerStageDial: "provider_dial_timeout", providerStageTLS: "provider_tls_timeout", providerStageResponse: "provider_response_timeout"} {
		err := providerTransportFailure(context.Background(), context.DeadlineExceeded, stage)
		if !errors.Is(err, ErrProviderUnavailable) || SafeProviderFailureKind(err) != want {
			t.Fatal("timeout stage lost")
		}
	}
	if SafeProviderFailureKind(ErrProviderUnavailable) != "" {
		t.Fatal("untyped errors must retain existing classification")
	}
}
