package capability

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type cancellationReceiptGateway struct {
	captureModelGateway
	cancel context.CancelFunc
	t      *testing.T
}

func (g *cancellationReceiptGateway) Generate(ctx context.Context, scope sharedkernel.Scope, policy policyasset.Snapshot, request modelgateway.GenerateRequest) (modelgateway.GenerateResult, error) {
	g.cancel()
	if ctx.Err() != nil {
		g.t.Fatal("caller cancellation discarded an already submitted provider receipt")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > time.Minute || time.Until(deadline) <= 0 {
		g.t.Fatal("provider receipt collection must remain bounded by persisted send cutoff")
	}
	return g.captureModelGateway.Generate(ctx, scope, policy, request)
}
func TestCallerCancellationCollectsOneKnownModelReceiptWithoutDisclosure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
	budgets := &captureModelBudgetStore{}
	gateway := &cancellationReceiptGateway{captureModelGateway: captureModelGateway{result: modelgateway.GenerateResult{Text: "private billable answer", InputTokens: 12, OutputTokens: 4}}, cancel: cancel, t: t}
	m.SetGovernedModelInvocation(fixedModelAccess(), gateway)
	m.SetModelBilling(testApprovedPriceResolver(), budgets)
	m.SetModelCapacity(&captureModelCapacity{})
	input, _ := json.Marshal(map[string]any{"idempotency_key": "cancel-receipt", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "hello"}}})
	body, _ := json.Marshal(envelope{Context: capabilityContext(), Input: input})
	req := httptest.NewRequest(http.MethodPost, "/internal/model/generate", bytes.NewReader(body)).WithContext(ctx)
	mac := hmac.New(sha256.New, []byte(m.signingSecret))
	mac.Write(requestSignaturePayload(http.MethodPost, req.URL.Path, body))
	req.Header.Set("X-Internal-Token", m.internalToken)
	req.Header.Set("X-Context-Signature", fmt.Sprintf("sha256=%x", mac.Sum(nil)))
	req.Header.Set("X-Platform-Context", "Bearer "+capabilityContext().PlatformContextToken)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, req)
	if strings.Contains(w.Body.String(), "private billable answer") || w.Code == http.StatusOK {
		t.Fatal("cancelled caller received provider answer")
	}
	m.reconcileBilling(context.Background())
	m.reconcileBilling(context.Background())
	store := m.modelStore.(*memoryModelInvocationStore)
	record := store.records[capabilityScopeHash(capabilityContext())+"\x00cancel-receipt"]
	if gateway.calls != 1 || record.Status != "completed" || len(budgets.settled) != 1 || record.Response["text"] != "private billable answer" {
		t.Fatalf("known receipt not settled exactly once: calls=%d status=%s settled=%d", gateway.calls, record.Status, len(budgets.settled))
	}
}
