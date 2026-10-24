package modelgateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestProviderNetworkCauseRetainsSafeDetailWithoutChangingRetryCategory(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{io.EOF, "eof"}, {io.ErrUnexpectedEOF, "unexpected_eof"},
		{syscall.ECONNRESET, "connection_reset"}, {syscall.ECONNREFUSED, "connection_refused"},
		{syscall.EPIPE, "broken_pipe"}, {&net.DNSError{Name: testSecret, Err: "private vendor host"}, "dns"},
		{errors.New(testSecret), "other"},
	}
	for _, tc := range cases {
		err := providerTransportFailure(context.Background(), fmt.Errorf("private host: %w", tc.err), providerStageResponse)
		stage, cause, connection := SafeProviderTransportDetail(err)
		if stage != "response" || cause != tc.want || connection != "unknown" || SafeProviderFailureKind(err) != "provider_network" {
			t.Fatalf("safe transport detail mismatch: %s/%s/%s", stage, cause, connection)
		}
		if strings.Contains(err.Error()+stage+cause+connection, testSecret) {
			t.Fatal("secret in diagnostic")
		}
	}
	unsafe := &ProviderFailure{Category: testSecret, transportStage: testSecret, networkCause: testSecret, connectionState: testSecret}
	stage, cause, connection := SafeProviderTransportDetail(unsafe)
	if stage != "unknown" || cause != "unknown" || connection != "unknown" {
		t.Fatal("unbounded diagnostic")
	}
}

func TestProviderConnectionLostAfterSendIsNotRetriedForDiagnostics(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		conn.Close()
	}))
	defer server.Close()
	adapter := newTestAdapter(t, server.URL+"/v1", nil, true)
	_, err := adapter.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest())
	stage, cause, connection := SafeProviderTransportDetail(err)
	if calls.Load() != 1 || stage != "response" || cause != "eof" || connection != "acquired" {
		t.Fatalf("lost response must retain detail without replay: calls=%d %s/%s/%s", calls.Load(), stage, cause, connection)
	}
}

func TestProviderIncompleteHTTP200BodyRetainsCauseWithoutRetry(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		conn, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = buffer.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n{\"private\":\"")
		_ = buffer.Flush()
		_ = conn.Close()
	}))
	defer server.Close()
	adapter := newTestAdapter(t, server.URL+"/v1", nil, true)
	_, err := adapter.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest())
	stage, cause, connection := SafeProviderTransportDetail(err)
	if calls.Load() != 1 || SafeProviderFailureKind(err) != "provider_body_read" || stage != "response" || cause != "unexpected_eof" || connection != "acquired" || ProvablyUnsent(err) {
		t.Fatalf("incomplete response diagnostic or retry changed: calls=%d %s/%s/%s", calls.Load(), stage, cause, connection)
	}
}

func TestProviderBodyReadClassifiesCancellationAndDeadlineSafely(t *testing.T) {
	for _, tc := range []struct {
		err   error
		cause string
	}{{context.Canceled, "cancelled"}, {context.DeadlineExceeded, "deadline_exceeded"}, {syscall.ECONNRESET, "connection_reset"}, {errors.New(testSecret), "other"}} {
		err := providerBodyReadFailure(context.Background(), fmt.Errorf("private endpoint %s: %w", testSecret, tc.err), 200)
		stage, cause, connection := SafeProviderTransportDetail(err)
		if stage != "response" || cause != tc.cause || connection != "acquired" || ProvablyUnsent(err) || strings.Contains(err.Error()+stage+cause+connection, testSecret) {
			t.Fatal("body failure classification leaked or granted resend", stage, cause, connection)
		}
	}
}

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
