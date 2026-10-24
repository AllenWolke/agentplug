package capability

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/usagecost"
)

type expiredWindowAudit struct{ events []audit.Event }

type expiredWindowBudget struct {
	captureModelBudgetStore
	releaseErr error
}

func (b *expiredWindowBudget) ResolveUncharged(ctx context.Context, reservation usagecost.ModelBudgetReservation, ref string) error {
	if b.releaseErr != nil {
		return b.releaseErr
	}
	return b.captureModelBudgetStore.ResolveUncharged(ctx, reservation, ref)
}

func (a *expiredWindowAudit) Record(_ context.Context, event audit.Event) error {
	a.events = append(a.events, event)
	return nil
}

func TestExpiredProviderWindowClosesUnsentIntentWithoutInvokingModel(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprintf("release-failure-%t", partial), func(t *testing.T) {
			budgets := &expiredWindowBudget{}
			if partial {
				budgets.releaseErr = errors.New("fixture release unavailable")
			}
			m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
			gateway := &captureModelGateway{}
			m.SetGovernedModelInvocation(fixedModelAccess(), gateway)
			m.SetModelBilling(testApprovedPriceResolver(), budgets)
			m.SetModelCapacity(&captureModelCapacity{})
			recorded := &expiredWindowAudit{}
			m.SetModelAttemptRecorder(recorded)
			input, _ := json.Marshal(map[string]any{"idempotency_key": "expired-provider-window", "prompt_template_hash": "prompt-hash",
				"messages": []map[string]string{{"role": "user", "content": "hello"}}})
			body, _ := json.Marshal(envelope{Context: capabilityContext(), Input: input})
			// The persisted route cutoff can elapse while the final authority
			// check runs. It still permits a durable send-intent grace period,
			// but its provider window has expired before Generate is entered.
			ctx := context.WithValue(context.Background(), modelAttemptDeadlineKey{}, time.Now().Add(-time.Millisecond))
			req := httptest.NewRequest(http.MethodPost, "/internal/model/generate", bytes.NewReader(body)).WithContext(ctx)
			mac := hmac.New(sha256.New, []byte(m.signingSecret))
			mac.Write(requestSignaturePayload(http.MethodPost, req.URL.Path, body))
			req.Header.Set("X-Internal-Token", m.internalToken)
			req.Header.Set("X-Context-Signature", fmt.Sprintf("sha256=%x", mac.Sum(nil)))
			req.Header.Set("X-Platform-Context", "Bearer "+capabilityContext().PlatformContextToken)
			w := httptest.NewRecorder()
			m.Handler().ServeHTTP(w, req)
			expected := "MODEL_NOT_SUBMITTED"
			if partial {
				expected = "MODEL_RECONCILIATION_REQUIRED"
			}
			if gateway.calls != 0 || !strings.Contains(w.Body.String(), expected) {
				t.Fatal("expired window invoked model or lost no-send state", gateway.calls, w.Body.String())
			}
			if len(recorded.events) != 1 || recorded.events[0].Action != "model.send_not_started" || !strings.Contains(recorded.events[0].Summary, `"provider_invoked":false`) {
				t.Fatal("missing safe no-send cause audit", recorded.events)
			}
			store := m.modelStore.(*memoryModelInvocationStore)
			record := store.records[capabilityScopeHash(capabilityContext())+"\x00expired-provider-window"]
			if record.Recovery == nil || record.Recovery.Decision == nil || !record.Recovery.Unsent || record.Recovery.Decision.Outcome != "no_charge" {
				t.Fatal("no-send proof was discarded")
			}
			if partial && record.Status != "reconcile" {
				t.Fatal("partial cleanup claimed success")
			}
			budgets.releaseErr = nil
			m.reconcileBilling(context.Background())
			m.reconcileBilling(context.Background())
			record = store.records[capabilityScopeHash(capabilityContext())+"\x00expired-provider-window"]
			if record.Status != "failed" || gateway.calls != 0 || len(budgets.settled) != 0 || len(budgets.released) != 1 {
				t.Fatal("exact unsent recovery did not close once", record.Status, gateway.calls, len(budgets.released))
			}
		})
	}
}
