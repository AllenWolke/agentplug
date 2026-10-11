package agentplatform

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var eventMetadataValue = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

// CheckEventAuthority checks current history access without creating a business
// capability context, renewing a worker lease, or accepting an expired token.
func (config CapabilityConfig) CheckEventAuthority(ctx context.Context, request EventRequest) error {
	if request.AfterSeq > MaxSafeExecutionEventSequence {
		return &AppError{Code: "REQUEST_INVALID", Message: "event cursor is outside the safe integer range"}
	}
	base, err := url.Parse(config.BaseURL)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") || base.User != nil || base.RawQuery != "" || base.Fragment != "" || config.InternalToken == "" || config.SigningSecret == "" || config.WorkloadClientID == "" || len(config.WorkloadClientSecret) < 32 || len(config.WorkloadClientSecret) > 512 {
		return &AppError{Code: "CAPABILITY_CONFIG_INVALID", Message: "event authority wiring is incomplete"}
	}
	config.BaseURL = strings.TrimRight(config.BaseURL, "/")
	body, err := json.Marshal(request)
	if err != nil || len(body) > 32768 {
		return &AppError{Code: "REQUEST_INVALID", Message: "invalid event request"}
	}
	client := &CapabilityClient{config: config, traceID: request.Scope.TraceID, client: &http.Client{
		Timeout: 5 * time.Second, Transport: config.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result, err := client.send(bounded, "/internal/context/events/check", body, request.ContextToken, 32768)
	if err != nil {
		return err
	}
	if allowed, ok := result["allowed"].(bool); !ok || !allowed {
		return &AppError{Code: "CAPABILITY_DENIED", Message: "current event read denied"}
	}
	return nil
}

func safeEventMetadata(payload map[string]any) map[string]any {
	result := map[string]any{}
	for _, key := range []string{"operation", "reason", "harness_key", "tool_name", "call_id", "code"} {
		if value, ok := payload[key].(string); ok && eventMetadataValue.MatchString(value) {
			result[key] = value
		}
	}
	return result
}
