package modelgateway

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http/httptrace"
	"strconv"
	"sync/atomic"
	"syscall"
)

// ProviderFailure 只保留固定类别及 HTTP 状态，不保留 URL、密钥或厂商正文。
// 分类用于诊断，不证明费用为零，也不授权重试未知副作用。
type ProviderFailure struct {
	Category        string
	StatusCode      int
	transportStage  string
	networkCause    string
	connectionState string
	// unsent is set only by the standard Transport path when the dial itself
	// was refused or the name did not resolve: no connection existed, so no
	// request byte left the process. Timeouts never qualify.
	// 仅标准 Transport 在拨号被拒或 DNS 失败且未拿到连接时置位；超时一律不算。
	unsent bool
}

func (*ProviderFailure) Error() string { return ErrProviderUnavailable.Error() }
func (*ProviderFailure) Unwrap() error { return ErrProviderUnavailable }

// ProvablyUnsent reports a transport failure that happened before any TCP
// connection was established. Callers may finalize it as uncharged.
// 拨号阶段被拒且从未建立连接，可证明请求未发出，调用方可按未计费终结。
func ProvablyUnsent(err error) bool {
	var failure *ProviderFailure
	return errors.As(err, &failure) && failure != nil && failure.unsent
}

// SafeProviderFailureKind 即使遇到外部构造的错误，也只返回受限诊断值。
func SafeProviderFailureKind(err error) string {
	var failure *ProviderFailure
	if !errors.As(err, &failure) || failure == nil {
		return ""
	}
	if failure.Category == "http_response" && failure.StatusCode >= 100 && failure.StatusCode <= 599 {
		return "provider_http_" + strconv.Itoa(failure.StatusCode)
	}
	switch failure.Category {
	case "cancelled", "dial_timeout", "tls_timeout", "response_timeout", "transport_timeout", "network", "body_read", "endpoint_rejected":
		return "provider_" + failure.Category
	default:
		return "provider_unavailable"
	}
}

func providerBodyReadFailure(ctx context.Context, err error, status int) error {
	// Preserve only allowlisted transport detail. Reading an incomplete HTTP 200
	// response never proves the request was unsent and never permits replay.
	failure := providerTransportFailure(ctx, err, providerStageResponse).(*ProviderFailure)
	failure.Category, failure.StatusCode, failure.connectionState = "body_read", status, "acquired"
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		failure.networkCause = "cancelled"
	} else if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		failure.networkCause = "deadline_exceeded"
	}
	return failure
}

const (
	providerStageDial int32 = iota
	providerStageTLS
	providerStageResponse
)

type providerTransportProgress struct {
	stage     atomic.Int32
	started   atomic.Bool
	connected atomic.Bool
}

func traceProviderTransport(ctx context.Context) (context.Context, *providerTransportProgress) {
	progress := new(providerTransportProgress)
	trace := &httptrace.ClientTrace{
		GetConn: func(string) {
			progress.started.Store(true)
			progress.stage.Store(providerStageDial)
		},
		TLSHandshakeStart: func() { progress.stage.Store(providerStageTLS) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				progress.stage.Store(providerStageResponse)
			}
		},
		GotConn: func(httptrace.GotConnInfo) {
			// 一旦拿到连接，就保守地视为可能已发送；内部后续连接失败不得重放。
			progress.connected.Store(true)
			progress.stage.Store(providerStageResponse)
		},
	}
	return httptrace.WithClientTrace(ctx, trace), progress
}

func providerTransportFailure(ctx context.Context, err error, stage int32) error {
	category := "network"
	var timeout net.Error
	switch {
	case errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled):
		category = "cancelled"
	case errors.Is(err, ErrUnsafeEndpoint):
		category = "endpoint_rejected"
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout():
		category = "transport_timeout"
		switch stage {
		case providerStageDial:
			category = "dial_timeout"
		case providerStageTLS:
			category = "tls_timeout"
		case providerStageResponse:
			category = "response_timeout"
		}
	}
	transportStage := "unknown"
	switch stage {
	case providerStageDial:
		transportStage = "dial"
	case providerStageTLS:
		transportStage = "tls"
	case providerStageResponse:
		transportStage = "response"
	}
	cause := "other"
	var dns *net.DNSError
	var certificate *tls.CertificateVerificationError
	var protocol tls.RecordHeaderError
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF):
		cause = "unexpected_eof"
	case errors.Is(err, io.EOF):
		cause = "eof"
	case errors.Is(err, syscall.ECONNRESET):
		cause = "connection_reset"
	case errors.Is(err, syscall.ECONNREFUSED):
		cause = "connection_refused"
	case errors.Is(err, syscall.EPIPE):
		cause = "broken_pipe"
	case errors.As(err, &dns):
		cause = "dns"
	case errors.As(err, &certificate):
		cause = "tls_certificate"
	case errors.As(err, &protocol):
		cause = "tls_protocol"
	}
	return &ProviderFailure{Category: category, transportStage: transportStage, networkCause: cause}
}

// Diagnostic fields never contain an endpoint, address, response, or raw
// exception. They do not change fee certainty, retries, or route eligibility.
func SafeProviderTransportDetail(err error) (stage, cause, connection string) {
	stage, cause, connection = "unknown", "unknown", "unknown"
	var failure *ProviderFailure
	if !errors.As(err, &failure) || failure == nil {
		return
	}
	switch failure.transportStage {
	case "dial", "tls", "response":
		stage = failure.transportStage
	}
	switch failure.networkCause {
	case "eof", "unexpected_eof", "connection_reset", "connection_refused", "broken_pipe", "dns", "tls_certificate", "tls_protocol", "cancelled", "deadline_exceeded", "other":
		cause = failure.networkCause
	}
	switch failure.connectionState {
	case "acquired", "not_acquired":
		connection = failure.connectionState
	}
	return
}
