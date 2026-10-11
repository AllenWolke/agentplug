package capability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBillingMetricsRequireServiceIdentityAndBoundedLabels(t *testing.T) {
	m := &Module{internalToken: "fixture-internal"}
	m.billingStats.Runs.Add(5)
	m.billingStats.Completed.Add(3)
	m.billingStats.Failed.Add(2)
	for _, scenario := range []struct {
		token, browser, method string
		status                 int
	}{{"", "", http.MethodGet, 401}, {"wrong", "", http.MethodGet, 401}, {"fixture-internal", "1", http.MethodGet, 403}, {"fixture-internal", "", http.MethodPost, 405}, {"fixture-internal", "", http.MethodGet, 200}} {
		request := httptest.NewRequest(scenario.method, "/billing/metrics", nil)
		request.Header.Set("X-Internal-Token", scenario.token)
		request.Header.Set("X-Browser-Module", scenario.browser)
		response := httptest.NewRecorder()
		m.Handler().ServeHTTP(response, request)
		if response.Code != scenario.status {
			t.Fatalf("metrics status %d wanted %d", response.Code, scenario.status)
		}
		if response.Code == 200 {
			for _, expected := range []string{"platform_model_billing_worker_runs_total 5", "platform_model_billing_worker_completed_total 3", "platform_model_billing_worker_failed_total 2"} {
				if !strings.Contains(response.Body.String(), expected) {
					t.Fatal("counter absent")
				}
			}
			if strings.Contains(response.Body.String(), "fixture-internal") || strings.Contains(response.Body.String(), "tenant_id=") {
				t.Fatal("sensitive/high-cardinality metric labels")
			}
		}
	}
}
