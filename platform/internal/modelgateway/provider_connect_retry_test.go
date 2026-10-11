package modelgateway

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

const connectRetryResponse = `{"choices":[{"message":{"content":"approved answer"}}],"usage":{"prompt_tokens":7,"completion_tokens":3}}`

func TestProviderConnectRetryRecoversBeforeTLSAndSendsExactlyOnce(t *testing.T) {
	for _, mode := range []string{"dial", "tls_timeout", "tls_eof"} {
		t.Run(mode, func(t *testing.T) {
			var requests, connects atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				_, _ = w.Write([]byte(connectRetryResponse))
			}))
			defer server.Close()
			adapter := newTestAdapter(t, server.URL+"/v1", nil, true)
			endpoint, _ := url.Parse(server.URL)
			adapter.config.AllowedHTTPSPorts = append(adapter.config.AllowedHTTPSPorts, endpoint.Port())
			transport := adapter.client.Transport.(*http.Transport)
			defer transport.CloseIdleConnections()
			transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			transport.TLSHandshakeTimeout = 10 * time.Millisecond
			originalDial := transport.DialContext
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if connects.Add(1) <= 2 {
					if mode == "dial" {
						return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("temporary connection failure")}
					}
					client, peer := net.Pipe()
					if mode == "tls_eof" {
						_ = peer.Close()
					} else {
						// 标准 TLS 握手真实超时，未发送 HTTP 请求；关闭夹具防止泄漏。
						time.AfterFunc(50*time.Millisecond, func() { _ = peer.Close() })
					}
					return client, nil
				}
				return originalDial(ctx, network, address)
			}
			result, err := adapter.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest())
			if err != nil || result.Text != "approved answer" || requests.Load() != 1 || connects.Load() != 3 {
				t.Fatalf("bounded pre-TLS recovery: result=%+v error=%v requests=%d connects=%d", result, err, requests.Load(), connects.Load())
			}
		})
	}
}

func TestProviderConnectRetryNeverReplaysSubmittedRequest(t *testing.T) {
	for _, mode := range []string{"disconnect", "http_error", "header_timeout"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				switch mode {
				case "disconnect":
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						_ = conn.Close()
					}
				case "http_error":
					w.WriteHeader(http.StatusServiceUnavailable)
				case "header_timeout":
					time.Sleep(60 * time.Millisecond)
				}
			}))
			defer server.Close()
			adapter := newTestAdapter(t, server.URL+"/v1", nil, true)
			transport := adapter.client.Transport.(*http.Transport)
			defer transport.CloseIdleConnections()
			transport.ResponseHeaderTimeout = 15 * time.Millisecond
			_, err := adapter.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest())
			if !errors.Is(err, ErrProviderUnavailable) || requests.Load() != 1 {
				t.Fatalf("possibly billable request replayed: requests=%d error=%v", requests.Load(), err)
			}
		})
	}
}

func TestProviderConnectRetryIsBoundedAndKeepsCancellationDeadline(t *testing.T) {
	for _, mode := range []string{"exhausted", "deadline", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			adapter := newTestAdapter(t, "https://model.example/v1", nil, false)
			var connects atomic.Int32
			transport := adapter.client.Transport.(*http.Transport)
			transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				connects.Add(1)
				if mode == "deadline" {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("temporary connection failure")}
			}
			ctx := context.Background()
			if mode == "cancelled" {
				cancelCtx, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelCtx
			}
			if mode == "deadline" {
				adapter.config.RequestTimeout = 30 * time.Millisecond
			}
			start := time.Now()
			_, err := adapter.Generate(ctx, trustedScope(), testSnapshot(), validRequest())
			if !errors.Is(err, ErrProviderUnavailable) || connects.Load() > 3 || mode == "exhausted" && connects.Load() != 3 || mode == "deadline" && time.Since(start) > 200*time.Millisecond {
				t.Fatalf("connection retry escaped limits: mode=%s connects=%d duration=%s error=%v", mode, connects.Load(), time.Since(start), err)
			}
		})
	}
}

func TestProviderConnectRetryDoesNotForgetEarlierAcquiredConnection(t *testing.T) {
	ctx, progress := traceProviderTransport(context.Background())
	trace := httptrace.ContextClientTrace(ctx)
	trace.GetConn("approved.example")
	trace.GotConn(httptrace.GotConnInfo{})
	trace.GetConn("approved.example")
	failure := providerTransportFailure(ctx, io.EOF, progress.stage.Load())
	if retryUnsentConnection(ctx, io.EOF, failure, progress) {
		t.Fatal("a later dial failure must not erase an earlier possibly sent request")
	}
}

func TestProviderConnectRetryFailsClosedForInvalidCertificateAndEndpoint(t *testing.T) {
	var requests, connects atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1) }))
	defer server.Close()
	adapter := newTestAdapter(t, server.URL+"/v1", nil, true)
	endpoint, _ := url.Parse(server.URL)
	adapter.config.AllowedHTTPSPorts = append(adapter.config.AllowedHTTPSPorts, endpoint.Port())
	transport := adapter.client.Transport.(*http.Transport)
	originalDial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		connects.Add(1)
		return originalDial(ctx, network, address)
	}
	_, err := adapter.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest())
	if !errors.Is(err, ErrProviderUnavailable) || connects.Load() != 1 || requests.Load() != 0 {
		t.Fatal("invalid certificate must not be retried or bypassed")
	}
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		connects.Add(1)
		return nil, ErrUnsafeEndpoint
	}
	_, err = adapter.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest())
	if !errors.Is(err, ErrProviderUnavailable) || connects.Load() != 2 {
		t.Fatal("unsafe resolution must not be retried")
	}
}
