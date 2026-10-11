package capability

import (
	"errors"
	"github.com/lexagent/platform/internal/modelgateway"
)

// Log a fixed category only, never upstream messages, payloads or secrets.
// 仅记录固定错误类别，不输出厂商正文、业务输入或密钥。
func modelProviderErrorKind(err error) string {
	if kind := modelgateway.SafeProviderFailureKind(err); kind != "" {
		return kind
	}
	switch {
	case errors.Is(err, modelgateway.ErrProviderUnavailable):
		return "provider_unavailable"
	case errors.Is(err, modelgateway.ErrModelUnavailable):
		return "model_unavailable"
	case errors.Is(err, modelgateway.ErrEndpointUnresolved):
		return "endpoint_unresolved"
	case errors.Is(err, modelgateway.ErrUnsafeEndpoint):
		return "unsafe_endpoint"
	case errors.Is(err, modelgateway.ErrSecretUnavailable):
		return "secret_unavailable"
	case errors.Is(err, modelgateway.ErrRequestTooLarge):
		return "request_too_large"
	case errors.Is(err, modelgateway.ErrResponseTooLarge):
		return "response_too_large"
	case errors.Is(err, modelgateway.ErrProviderResponse):
		return "invalid_response"
	default:
		return "unknown"
	}
}
