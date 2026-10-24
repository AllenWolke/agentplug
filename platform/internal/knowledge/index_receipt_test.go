package knowledge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type indexReceiptFixture struct {
	*indexControlFixture
	reads int
}

func (f *indexReceiptFixture) QueryIndexReceipt(_ context.Context, actor sharedkernel.Scope, scope ProjectionScope, installation, key string) (IndexRecoveryReceipt, error) {
	f.reads++
	if actor.PrincipalID != "manager" || scope.KnowledgeID != "docs" || installation != "installation" || key != "original-task-key" {
		panic("forged index receipt selector")
	}
	return IndexRecoveryReceipt{SchemaVersion: "knowledge-index-recovery/v1", Scope: scope, RunID: "existing-run",
		Status: "running", Revision: 2, Request: IndexTaskRequest{InstallationID: installation, IdempotencyKey: key},
		EmbeddingModelVersion: "published-embedding"}, f.failure
}

func TestIndexReceiptReadCannotSubmitOrOverrideAuthority(t *testing.T) {
	for _, mode := range []string{"allowed", "untrusted", "unauthenticated", "old-service", "duplicate", "unknown-query", "missing-key", "malformed-query", "denied", "absent", "ambiguous"} {
		t.Run(mode, func(t *testing.T) {
			base := &indexControlFixture{}
			fixture := &indexReceiptFixture{indexControlFixture: base}
			module := NewControlModule("internal", base)
			module.SetIndexService(fixture)
			path := "/indexes/docs/tasks:receipt?installation_id=installation&idempotency_key=original-task-key"
			expected := http.StatusOK
			switch mode {
			case "untrusted", "unauthenticated":
				expected = http.StatusUnauthorized
			case "old-service":
				module.SetIndexService(base)
				expected = http.StatusServiceUnavailable
			case "duplicate":
				path += "&idempotency_key=second"
				expected = http.StatusBadRequest
			case "unknown-query":
				path += "&principal_id=foreign"
				expected = http.StatusBadRequest
			case "missing-key":
				path = "/indexes/docs/tasks:receipt?installation_id=installation"
				expected = http.StatusBadRequest
			case "malformed-query":
				path += "&bad=%ZZ"
				expected = http.StatusBadRequest
			case "denied":
				base.failure = ErrManagementDenied
				expected = http.StatusForbidden
			case "absent":
				base.failure = ErrIndexTaskNotFound
				expected = http.StatusNotFound
			case "ambiguous":
				base.failure = ErrIndexTaskConflict
				expected = http.StatusConflict
			}
			request := httptest.NewRequest(http.MethodGet, path, nil)
			for key, value := range map[string]string{"X-Internal-Token": "internal", "X-Browser-Module": "1", "X-Tenant-ID": "t", "X-Department-ID": "d", "X-Application-ID": "a", "X-Principal-Type": "user", "X-Principal-ID": "manager", "X-Trace-ID": "trace"} {
				request.Header.Set(key, value)
			}
			if mode == "untrusted" {
				request.Header.Del("X-Browser-Module")
			}
			if mode == "unauthenticated" {
				request.Header.Del("X-Internal-Token")
			}
			response := httptest.NewRecorder()
			module.Handler().ServeHTTP(response, request)
			if response.Code != expected || base.calls != 0 || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("code=%d expected=%d reads=%d mutations=%d", response.Code, expected, fixture.reads, base.calls)
			}
			for _, secret := range []string{"request_json", "lease_token", "context_token", "policy_snapshot"} {
				if strings.Contains(response.Body.String(), secret) {
					t.Fatal("private execution envelope disclosed")
				}
			}
			if mode != "allowed" && mode != "denied" && mode != "absent" && mode != "ambiguous" && fixture.reads != 0 {
				t.Fatal("invalid selector reached native reader")
			}
		})
	}
}
