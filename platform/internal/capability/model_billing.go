package capability

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"math"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/usagecost"
)

const runtimeModelBudgetCurrency = "USD"

func validRuntimeModelPrice(price modelgovernance.PriceVersion, modelVersionID string, at time.Time) bool {
	if price.ID == "" || len(price.ID) > 128 || price.ModelVersionID != modelVersionID ||
		price.Status != modelgovernance.StatusApproved || price.Revision == 0 ||
		price.Currency != runtimeModelBudgetCurrency || price.InputMicrosPer1K < 0 || price.OutputMicrosPer1K < 0 ||
		price.EffectiveFrom.IsZero() || at.Before(price.EffectiveFrom) ||
		strings.TrimSpace(price.ID) != price.ID || strings.ContainsAny(price.ID, ":\x00") ||
		len(price.ContentHash) != 71 || !strings.HasPrefix(price.ContentHash, "sha256:") {
		return false
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(price.ContentHash, "sha256:")); err != nil {
		return false
	}
	return price.EffectiveUntil == nil || price.EffectiveUntil.After(price.EffectiveFrom) && at.Before(*price.EffectiveUntil)
}

func buildModelBudgetRequest(h harnessContext, messages []struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}, maxTokens int, budgetCents int64, price modelgovernance.PriceVersion, fingerprint, requestID string, now time.Time, leaseSeconds int) (usagecost.ModelBudgetRequest, error) {
	if !validRuntimeModelPrice(price, price.ModelVersionID, now) || maxTokens <= 0 || budgetCents < 0 || requestID == "" {
		return usagecost.ModelBudgetRequest{}, usagecost.ErrInvalidUsage
	}
	// ModelPolicy currently has only an integer cent budget, with no currency or
	// period fields. Runtime therefore binds positive budgets to USD cents and a
	// UTC calendar day. Preserve the old zero-means-unlimited behavior using the
	// largest representable USD-micro limit; all actual spend remains bounded by
	// signed SQL integer capacity.
	limitMicros := int64(math.MaxInt64)
	if budgetCents > 0 {
		if budgetCents > math.MaxInt64/10_000 {
			return usagecost.ModelBudgetRequest{}, usagecost.ErrInvalidUsage
		}
		limitMicros = budgetCents * 10_000
	}
	// Until the provider returns real token counts, reserve each UTF-8 byte plus
	// per-message overhead as an intentionally conservative input token bound.
	inputTokens, err := conservativeInputTokenEstimate(messages)
	if err != nil {
		return usagecost.ModelBudgetRequest{}, err
	}
	reserveMicros, err := approvedModelCost(price, inputTokens, int64(maxTokens))
	if err != nil {
		return usagecost.ModelBudgetRequest{}, err
	}
	if leaseSeconds <= 0 {
		leaseSeconds = 120
	}
	if leaseSeconds > 900 {
		leaseSeconds = 900
	}
	windowStart := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	windowEnd := windowStart.AddDate(0, 0, 1)
	expiresAt := now.UTC().Add(time.Duration(leaseSeconds) * time.Second)
	if expiresAt.After(windowEnd) {
		expiresAt = windowEnd
	}
	if !expiresAt.After(now) {
		return usagecost.ModelBudgetRequest{}, usagecost.ErrInvalidUsage
	}
	runID := runtimeUsageRunID(h)
	return usagecost.ModelBudgetRequest{
		Scope: usagecost.ModelBudgetScope{
			TenantID: h.TenantID, DepartmentID: h.DepartmentID, ApplicationID: h.ApplicationID,
			AgentID: h.AgentID, AgentVersionID: h.AgentVersionID,
		},
		RunID: runID, Window: usagecost.ModelBudgetWindow{Start: windowStart, End: windowEnd},
		RequestID: requestID, Fingerprint: fingerprint, PriceVersionID: price.ID,
		BudgetLimitMicros: limitMicros, ReserveMicros: reserveMicros, ExpiresAt: expiresAt,
	}, nil
}

func conservativeInputTokenEstimate(messages []struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}) (int64, error) {
	var estimate int64
	for _, message := range messages {
		addition := int64(len(message.Content) + len(message.Role) + 4)
		if addition < 0 || estimate > math.MaxInt64-addition {
			return 0, usagecost.ErrInvalidUsage
		}
		estimate += addition
	}
	return estimate, nil
}

func approvedModelCost(price modelgovernance.PriceVersion, inputTokens, outputTokens int64) (int64, error) {
	inputCost, err := tokenCostMicros(price.InputMicrosPer1K, inputTokens)
	if err != nil {
		return 0, err
	}
	outputCost, err := tokenCostMicros(price.OutputMicrosPer1K, outputTokens)
	if err != nil || inputCost > math.MaxInt64-outputCost {
		return 0, errors.New("approved model price overflows cost range")
	}
	return inputCost + outputCost, nil
}

func tokenCostMicros(ratePer1K, tokens int64) (int64, error) {
	if ratePer1K < 0 || tokens < 0 || ratePer1K != 0 && tokens > math.MaxInt64/ratePer1K {
		return 0, errors.New("approved model price inputs are invalid or overflow")
	}
	product := tokens * ratePer1K
	cost := product / 1000
	if product%1000 != 0 {
		if cost == math.MaxInt64 {
			return 0, errors.New("approved model price overflows cost range")
		}
		cost++
	}
	return cost, nil
}

func ceilModelCostCents(costMicros int64) int64 {
	if costMicros <= 0 {
		return 0
	}
	cents := costMicros / 10_000
	if costMicros%10_000 != 0 {
		cents++
	}
	return cents
}

func newModelBudgetAttemptID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "attempt-" + hex.EncodeToString(raw[:]), nil
}

func runtimeUsageRunID(h harnessContext) string {
	// TaskID is the signed execution lease. A delegated child or evaluation
	// case also carries ParentRunID, but charging that parent here disagrees
	// with the execution binding and the run-tree actor. Admission then
	// reports a missing budget ledger. The tree authority still rolls a
	// delegated hold up to the verified root.
	// TaskID 是签名执行租约。委托子 Run 和评测 Case 也会带父 Run，但把账单
	// 直接记到父 Run 会和执行绑定、运行树行动者不一致，准入就会报账本不可用。
	// 运行树仍会把委托占用汇总到已验证的根预算。
	if h.TaskID != "" {
		return h.TaskID
	}
	raw := h.ThreadID
	if raw == "" {
		raw = h.SessionID
	}
	if raw == "" {
		raw = h.RequestID
	}
	digest := sha256.Sum256([]byte(raw))
	return "run-" + hex.EncodeToString(digest[:20])
}

func governedModelUsageScope(h harnessContext) usagecost.Scope {
	return usagecost.Scope{TenantID: h.TenantID, DepartmentID: h.DepartmentID, ApplicationID: h.ApplicationID, AgentID: h.AgentID, AgentVersionID: h.AgentVersionID, RunID: runtimeUsageRunID(h)}
}

func legacyModelUsageScope(h harnessContext) usagecost.Scope {
	runID := h.TaskID
	if h.ParentRunID != "" {
		runID = h.ParentRunID
	}
	if runID == "" {
		runID = h.ThreadID
	}
	if runID == "" {
		runID = h.SessionID
	}
	if runID == "" {
		runID = h.RequestID
	}
	return usagecost.Scope{TenantID: h.TenantID, DepartmentID: h.DepartmentID, ApplicationID: h.ApplicationID, AgentID: h.AgentID, AgentVersionID: h.AgentVersionID, RunID: runID}
}

func attachModelUsageStepID(result map[string]any, scope usagecost.Scope, requestID string) *string {
	stepID := usagecost.StableModelUsageStepID(scope, requestID)
	if stepID != nil && result != nil {
		result["step_id"] = *stepID
	}
	return stepID
}

func modelUsageStepIDFromResult(result map[string]any, scope usagecost.Scope, requestID string) (*string, error) {
	raw, exists := result["step_id"]
	if !exists {
		return nil, nil // Legacy completed receipt: preserve its unlinked state.
	}
	value, ok := raw.(string)
	want := usagecost.StableModelUsageStepID(scope, requestID)
	if !ok || value == "" || want == nil || value != *want {
		return nil, errors.New("model usage step ID does not match its invocation scope")
	}
	return &value, nil
}

func buildModelUsageEvent(h harnessContext, model modelgateway.Selection, inputTokens, outputTokens int, costMicros int64, idempotencyKey string) (usagecost.Event, error) {
	if inputTokens < 0 || outputTokens < 0 || costMicros < 0 {
		return usagecost.Event{}, usagecost.ErrInvalidUsage
	}
	scope := governedModelUsageScope(h)
	if h.TenantID == "" || h.DepartmentID == "" || h.ApplicationID == "" || h.AgentID == "" || h.AgentVersionID == "" {
		return usagecost.Event{}, errors.New("model usage scope is incomplete")
	}
	key := sha256.Sum256([]byte(strings.Join([]string{h.TenantID, h.DepartmentID, h.ApplicationID, scope.RunID, idempotencyKey}, "\x00")))
	return usagecost.Event{
		ID:       "model-" + hex.EncodeToString(key[:]),
		StepID:   usagecost.StableModelUsageStepID(scope, idempotencyKey),
		Scope:    scope,
		Provider: model.ProviderKey, Model: model.ModelKey, InputTokens: int64(inputTokens), OutputTokens: int64(outputTokens), CostMicros: costMicros,
	}, nil
}

func definitelyNoModelCharge(err error) bool {
	// These errors are produced before the adapter sends a generation request.
	return errors.Is(err, modelgateway.ErrModelUnavailable) || errors.Is(err, modelgateway.ErrEndpointUnresolved) ||
		errors.Is(err, modelgateway.ErrUnsafeEndpoint) || errors.Is(err, modelgateway.ErrSecretUnavailable) ||
		errors.Is(err, modelgateway.ErrRequestTooLarge)
}

func (m *Module) releaseModelBudget(ctx context.Context, reservation usagecost.ModelBudgetReservation, traceID string) {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := m.modelBudgets.Release(writeCtx, reservation); err != nil {
		log.Printf("model budget release unavailable trace=%s error_type=%T", traceID, err)
	}
}

func (m *Module) markModelReconciliation(ctx context.Context, scopeHash, key, fingerprint string, reservation usagecost.ModelBudgetReservation, response map[string]any, costCents int64, traceID, attemptToken string, events ...usagecost.Event) error {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var holdErr error
	if store, ok := m.modelBudgets.(usagecost.ModelBudgetReconciliationStore); ok {
		if err := store.MarkReconciliationNeeded(writeCtx, reservation); err != nil {
			log.Printf("model budget reconciliation hold unavailable trace=%s error_type=%T", traceID, err)
			holdErr = err
		}
	} else {
		log.Printf("model budget store has no reconciliation hold port trace=%s", traceID)
		holdErr = errors.New("billing hold store unavailable")
	}
	if store, ok := m.modelStore.(ModelBillingRecoveryStore); ok {
		intent := BillingRecovery{Reservation: reservation, PriceID: reservation.PriceVersionID, AttemptToken: attemptToken}
		if len(events) == 1 {
			intent.Event = &events[0]
		}
		if err := store.SaveBillingRecovery(writeCtx, scopeHash, key, fingerprint, response, costCents, intent); err != nil {
			log.Print("model billing recovery persistence failed code=BILLING_RECOVERY_SAVE_FAILED")
			return errors.Join(holdErr, err)
		}
		return holdErr
	}
	store, ok := m.modelStore.(ModelInvocationReconciliationStore)
	if !ok {
		log.Printf("model result requires reconciliation but invocation store has no reconciliation port trace=%s", traceID)
		return errors.New("billing recovery store unavailable")
	}
	if err := store.MarkReconciliationNeeded(writeCtx, scopeHash, key, fingerprint, response, costCents); err != nil {
		log.Printf("model result reconciliation marker unavailable trace=%s error_type=%T", traceID, err)
		return errors.Join(holdErr, err)
	}
	return errors.Join(holdErr, errors.New("billing recovery store unavailable"))
}
