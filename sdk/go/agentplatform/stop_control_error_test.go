package agentplatform

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCapabilityClientStopControlConflictMetadataIsAllowlisted(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		body       string
		wantCode   string
		wantHint   bool
	}{
		{"valid exact hint", http.StatusConflict, `{"error_code":"AGENT_STOP_REVISION_CONFLICT","data":{"stop_control":{"version":"agent-child-stop-control-conflict/v1","status":"running","execution_revision":7}}}`, "AGENT_STOP_REVISION_CONFLICT", true},
		{"wrong status", http.StatusForbidden, `{"error_code":"AGENT_STOP_REVISION_CONFLICT","data":{"stop_control":{"version":"agent-child-stop-control-conflict/v1","status":"running","execution_revision":7}}}`, "AGENT_STOP_REVISION_CONFLICT", false},
		{"ordinary error data", http.StatusConflict, `{"error_code":"AGENT_ROUTE_CONFLICT","data":{"stop_control":{"version":"agent-child-stop-control-conflict/v1","status":"running","execution_revision":7},"output":"private-sentinel"}}`, "AGENT_ROUTE_CONFLICT", false},
		{"extra sensitive field", http.StatusConflict, `{"error_code":"AGENT_STOP_REVISION_CONFLICT","data":{"stop_control":{"version":"agent-child-stop-control-conflict/v1","status":"running","execution_revision":7,"output":"private-sentinel"}}}`, "AGENT_STOP_REVISION_CONFLICT", false},
		{"floating revision", http.StatusConflict, `{"error_code":"AGENT_STOP_REVISION_CONFLICT","data":{"stop_control":{"version":"agent-child-stop-control-conflict/v1","status":"running","execution_revision":7.5}}}`, "AGENT_STOP_REVISION_CONFLICT", false},
		{"zero revision", http.StatusConflict, `{"error_code":"AGENT_STOP_REVISION_CONFLICT","data":{"stop_control":{"version":"agent-child-stop-control-conflict/v1","status":"running","execution_revision":0}}}`, "AGENT_STOP_REVISION_CONFLICT", false},
		{"unknown status", http.StatusConflict, `{"error_code":"AGENT_STOP_REVISION_CONFLICT","data":{"stop_control":{"version":"agent-child-stop-control-conflict/v1","status":"cancelled","execution_revision":7}}}`, "AGENT_STOP_REVISION_CONFLICT", false},
		{"unknown version", http.StatusConflict, `{"error_code":"AGENT_STOP_REVISION_CONFLICT","data":{"stop_control":{"version":"other/v1","status":"running","execution_revision":7}}}`, "AGENT_STOP_REVISION_CONFLICT", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			client := &CapabilityClient{
				config: CapabilityConfig{BaseURL: server.URL, InternalToken: "internal", SigningSecret: "secret"},
				client: server.Client(),
			}
			_, err := client.send(context.Background(), "/internal/agent/cancel", []byte(`{}`), "fixture-token", 1<<20)
			var app *AppError
			if !errors.As(err, &app) {
				t.Fatalf("send error %T %v", err, err)
			}
			if app.Code != tc.wantCode {
				t.Fatalf("error code = %q, want %q", app.Code, tc.wantCode)
			}
			hint, ok := app.Details["stop_control"].(map[string]any)
			if tc.wantHint {
				if !ok || hint["status"] != "running" || hint["version"] != "agent-child-stop-control-conflict/v1" || hint["execution_revision"] != uint64(7) {
					t.Fatalf("safe stop-control details missing: %#v", app.Details)
				}
			} else if len(app.Details) != 0 {
				t.Fatalf("untrusted error details leaked: %#v", app.Details)
			}
			if strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("error text leaked private response data")
			}
		})
	}
}

func TestCapabilityClientOversizedConflictMetadataIsDiscarded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error_code":"AGENT_STOP_REVISION_CONFLICT","data":{"stop_control":{"version":"agent-child-stop-control-conflict/v1","status":"running","execution_revision":7}}}` + strings.Repeat(" ", 256)))
	}))
	defer server.Close()
	client := &CapabilityClient{
		config: CapabilityConfig{BaseURL: server.URL, InternalToken: "internal", SigningSecret: "secret"},
		client: server.Client(),
	}
	_, err := client.send(context.Background(), "/internal/agent/cancel", []byte(`{}`), "fixture-token", 64)
	var app *AppError
	if !errors.As(err, &app) || app.Code != "CAPABILITY_RENEWAL_UNAVAILABLE" || len(app.Details) != 0 {
		t.Fatalf("oversized error was not discarded safely: %#v, %v", app, err)
	}
}
