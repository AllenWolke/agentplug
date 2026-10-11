package modelgateway

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http/httptrace"
	"strconv"
	"sync/atomic"
)

// ProviderFailure 只保留固定类别及 HTTP 状态，不保留 URL、密钥或厂商正文。
// 分类用于诊断，不证明费用为零，也不授权重试未知副作用。
type ProviderFailure struct {
	Category   string
	StatusCode int
}

func (*ProviderFailure) Error() string { return ErrProviderUnavailable.Error() }
func (*ProviderFailure) Unwrap() error { return ErrProviderUnavailable }

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
	return &ProviderFailure{Category: category}
}
