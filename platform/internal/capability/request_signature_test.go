package capability

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCapabilitySignatureCrossLanguageVector(t *testing.T) {
	want := `["platform-capability/v2","POST","/internal/model/embed","ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"]`
	if got := string(requestSignaturePayload("POST", "/internal/model/embed", []byte("abc"))); got != want {
		t.Fatalf("canonical payload mismatch: %s", got)
	}
}

func TestCapabilitySignatureRejectsOperationAndBodyReplay(t *testing.T) {
	module := newTestModule("test-internal", "test-secret", nil, "platform", "runtime")
	body := []byte(`{"context":{},"input":{}}`)
	for _, test := range []struct {
		name, signedTarget string
		signedBody         []byte
	}{
		{"another capability", "/internal/knowledge/search", body},
		{"query added", "/internal/model/embed?operation=other", body},
		{"body changed", "/internal/model/embed", []byte(`{"input":{"text":"changed"}}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			mac := hmac.New(sha256.New, []byte(module.signingSecret))
			_, _ = mac.Write(requestSignaturePayload(http.MethodPost, test.signedTarget, test.signedBody))
			request := httptest.NewRequest(http.MethodPost, "/internal/model/embed", bytes.NewReader(body))
			request.Header.Set("X-Internal-Token", module.internalToken)
			request.Header.Set("X-Context-Signature", fmt.Sprintf("sha256=%x", mac.Sum(nil)))
			response := httptest.NewRecorder()
			module.Handler().ServeHTTP(response, request)
			// No provider exists: signature rejection must occur before any capability call.
			// 未装配 Provider：拒绝必须发生在任何能力调用之前。
			if response.Code != http.StatusUnauthorized || !bytes.Contains(response.Body.Bytes(), []byte("INVALID_SIGNATURE")) {
				t.Fatalf("replay not rejected at signature boundary: %d %s", response.Code, response.Body.String())
			}
		})
	}
}
