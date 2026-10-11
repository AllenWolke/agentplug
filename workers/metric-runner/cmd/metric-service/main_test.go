package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postExecute(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, executePath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleExecute(rec, req)
	return rec
}

// TestHandleExecuteRunsBuiltinMetric proves the service speaks the same contract
// as the one-shot runner for a built-in metric.
// TestHandleExecuteRunsBuiltinMetric 证明服务对内置指标讲与一次性 Runner 相同的契约。
func TestHandleExecuteRunsBuiltinMetric(t *testing.T) {
	rec := postExecute(t, `{"metric":"citation_coverage","version":"1.0.0","formula_hash":"sha256:x","total":4,"correct":3,"admission":{"signature_verified":true,"network":"none","secret_access":false,"max_output_bytes":262144,"max_seconds":10,"max_pids":16}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out["status"] != "OK" {
		t.Fatalf("built-in metric was not computed: %+v", out)
	}
}

// TestHandleExecuteRefusesFailedAdmission proves a request whose admission record
// is not fully verified is refused before any plugin resolution, exactly as the
// one-shot runner does.
// TestHandleExecuteRefusesFailedAdmission 证明准入记录未完全校验的请求在任何插件解析之前即被
// 拒绝，与一次性 Runner 完全一致。
func TestHandleExecuteRefusesFailedAdmission(t *testing.T) {
	rec := postExecute(t, `{"metric":"domain_grounded_ratio","plugin":"example_metric","admission":{"signature_verified":false,"network":"none","secret_access":false,"max_output_bytes":262144,"max_seconds":10,"max_pids":128}}`)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out["status"] != "BLOCKED" || out["code"] != "SANDBOX_ADMISSION_DENIED" {
		t.Fatalf("unverified admission must be blocked: %+v", out)
	}
}

// TestHandleExecuteRejectsUnknownField proves the service keeps the strict
// decoding contract: an unexpected field is INVALID_INPUT, never silently
// ignored.
// TestHandleExecuteRejectsUnknownField 证明服务保持严格解码契约：意外字段是 INVALID_INPUT，绝不
// 被静默忽略。
func TestHandleExecuteRejectsUnknownField(t *testing.T) {
	rec := postExecute(t, `{"metric":"citation_coverage","unexpected":true,"admission":{"signature_verified":true,"network":"none","secret_access":false,"max_output_bytes":262144,"max_seconds":10,"max_pids":16}}`)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out["code"] != "INVALID_INPUT" {
		t.Fatalf("unknown field must be INVALID_INPUT: %+v", out)
	}
}

// TestHandleExecuteRejectsNonPost proves only POST is accepted.
// TestHandleExecuteRejectsNonPost 证明只接受 POST。
func TestHandleExecuteRejectsNonPost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, executePath, nil)
	rec := httptest.NewRecorder()
	handleExecute(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// TestHandleExecuteRejectsOversizedBody proves an oversized body is refused with
// 413 rather than truncated and reinterpreted.
// TestHandleExecuteRejectsOversizedBody 证明超长请求体以 413 拒绝，而非被截断后重新解释。
func TestHandleExecuteRejectsOversizedBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, executePath, strings.NewReader(strings.Repeat("a", (2<<20)+10)))
	rec := httptest.NewRecorder()
	handleExecute(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestExecuteEndpointRequiresBearerToken(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	handler := requireBearer(token, http.HandlerFunc(handleExecute))
	for _, tc := range []struct {
		name   string
		header string
		want   int
	}{{name: "missing", want: http.StatusUnauthorized}, {name: "wrong", header: "Bearer wrong", want: http.StatusUnauthorized}, {name: "valid", header: "Bearer " + token, want: http.StatusOK}} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"metric":"citation_coverage","version":"1.0.0","formula_hash":"hash","total":2,"correct":1,"admission":{"signature_verified":true,"network":"none","secret_access":false,"max_output_bytes":262144,"max_seconds":10,"max_pids":16}}`
			req := httptest.NewRequest(http.MethodPost, executePath, strings.NewReader(body))
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestServiceTokenRejectsWeakAndPlaceholderValues(t *testing.T) {
	for _, value := range []string{"", "short", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "密密密密密密密密密密密", "replace-with-a-random-32-byte-token", "placeholder-0123456789abcdef0123456789abcdef"} {
		if validServiceToken(value) {
			t.Fatal("weak service token accepted")
		}
	}
	if !validServiceToken("test-0123456789abcdef0123456789abcdef") {
		t.Fatal("explicit service credential rejected")
	}
}
