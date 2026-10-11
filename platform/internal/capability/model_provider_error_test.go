package capability

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/modelgateway"
)

func TestModelProviderErrorKindNeverUsesUpstreamMessage(t *testing.T) {
	const sensitive = "teaching-private-prompt bearer-test-secret provider-body"
	cases := []struct {
		name string
		err  error
	}{
		{"provider_unavailable", modelgateway.ErrProviderUnavailable},
		{"provider_http_429", &modelgateway.ProviderFailure{Category: "http_response", StatusCode: 429}},
		{"provider_tls_timeout", &modelgateway.ProviderFailure{Category: "tls_timeout"}},
		{"provider_unavailable", &modelgateway.ProviderFailure{Category: sensitive}},
		{"model_unavailable", modelgateway.ErrModelUnavailable},
		{"endpoint_unresolved", modelgateway.ErrEndpointUnresolved},
		{"unsafe_endpoint", modelgateway.ErrUnsafeEndpoint},
		{"secret_unavailable", modelgateway.ErrSecretUnavailable},
		{"request_too_large", modelgateway.ErrRequestTooLarge},
		{"response_too_large", modelgateway.ErrResponseTooLarge},
		{"invalid_response", modelgateway.ErrProviderResponse},
		{"unknown", errors.New(sensitive)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := modelProviderErrorKind(fmt.Errorf("%s: %w", sensitive, tc.err))
			if got != tc.name || strings.Contains(got, sensitive) {
				t.Fatalf("classification must use a fixed safe category: %q", got)
			}
		})
	}
	if got := modelProviderErrorKind(nil); got != "unknown" {
		t.Fatalf("nil classification: %q", got)
	}
}
