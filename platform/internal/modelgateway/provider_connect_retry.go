package modelgateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"time"

	"github.com/lexagent/platform/internal/telemetry"
)

// connectProvider 只重试标准 Transport 在拿到连接前的暂时失败。
// TLS 握手完成之前不会发送 HTTP 请求；拿到连接之后的任何错误均不重放。
// 三次连接尝试共用原调用截止时间、预算和容量租约，不增加模型执行额度。
func (a *HTTPAdapter) connectProvider(ctx context.Context, endpoint string, secret, body []byte) (*http.Response, error) {
	_, standardTransport := a.client.Transport.(*http.Transport)
	for attempt := 0; ; attempt++ {
		attemptCtx, progress := traceProviderTransport(ctx)
		request, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, ErrUnsafeEndpoint
		}
		request.Header.Set("Authorization", "Bearer "+string(secret))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
		if purpose := embeddingPurpose(ctx); purpose != "" {
			request.Header.Set("X-Agentplug-Embedding-Purpose", purpose)
		}
		telemetry.Inject(attemptCtx, request.Header)
		started := time.Now()
		response, err := a.client.Do(request)
		if err == nil {
			observeProviderAttempt(ctx, attempt, started, response.StatusCode, nil, progress, false)
			return response, nil
		}
		failure := providerTransportFailure(ctx, err, progress.stage.Load())
		if detail, ok := failure.(*ProviderFailure); ok && progress.started.Load() {
			detail.connectionState = "not_acquired"
			if progress.connected.Load() {
				detail.connectionState = "acquired"
			}
			detail.unsent = standardTransport && !progress.connected.Load() &&
				progress.stage.Load() == providerStageDial && detail.Category == "network" &&
				(detail.networkCause == "connection_refused" || detail.networkCause == "dns")
		}
		retry := attempt < 2 && standardTransport && retryUnsentConnection(ctx, err, failure, progress)
		observeProviderAttempt(ctx, attempt, started, 0, failure, progress, retry)
		if !retry {
			return nil, failure
		}
		telemetry.RecordModelProviderConnectRetry()
		timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, providerTransportFailure(ctx, ctx.Err(), progress.stage.Load())
		case <-timer.C:
		}
	}
}

func retryUnsentConnection(ctx context.Context, err, failure error, progress *providerTransportProgress) bool {
	if ctx.Err() != nil || !progress.started.Load() || progress.connected.Load() {
		return false
	}
	var certificate *tls.CertificateVerificationError
	var invalidTLS tls.RecordHeaderError
	if errors.As(err, &certificate) || errors.As(err, &invalidTLS) {
		return false
	}
	switch SafeProviderFailureKind(failure) {
	case "provider_dial_timeout", "provider_tls_timeout", "provider_network":
		return progress.stage.Load() == providerStageDial || progress.stage.Load() == providerStageTLS
	default:
		return false
	}
}
