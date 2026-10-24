package capability

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/modelgateway"
)

type modelAttemptAuditCapture struct {
	events []audit.Event
	fail   bool
}

func TestModelAttemptAuditCarriesActualStrictModeAndDigest(t *testing.T) {
	m, _, _, _ := failoverInvocationFixture(t)
	capture := &modelAttemptAuditCapture{}
	m.SetModelAttemptRecorder(capture)
	scope, _, _, _ := routeFixture()
	ctx, trace := modelgateway.WithProviderAttemptTrace(context.Background())
	receipt := &modelgateway.ResponseSchemaReceipt{Version: "model-response-schema/v1", RequestedMode: "required", AppliedFormat: "json_schema", Dialect: "json-schema/responses/v1", WireProtocol: "responses/v1", Strict: true, SchemaSHA256: strings.Repeat("a", 64)}
	m.recordModelAttempt(ctx, scope, "private-key", "attempt-1", modelgateway.Selection{ModelVersionID: "actual-model"}, false, nil, trace, time.Now(), nil, modelgateway.GenerateResult{ResponseSchema: receipt, Incomplete: true, FinishReason: "invalid_response_schema"})
	if len(capture.events) != 1 {
		t.Fatal("missing audit")
	}
	var value struct {
		ResponseSchema *modelgateway.ResponseSchemaReceipt `json:"response_schema"`
		Outcome        string                              `json:"outcome"`
	}
	if json.Unmarshal([]byte(capture.events[0].Summary), &value) != nil || value.ResponseSchema == nil || *value.ResponseSchema != *receipt || value.Outcome != "incomplete" || strings.Contains(capture.events[0].Summary, "private-key") {
		t.Fatal("actual format/hash lost or secret leaked", capture.events)
	}
}

func (a *modelAttemptAuditCapture) Record(ctx context.Context, event audit.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.events = append(a.events, event)
	if a.fail {
		return errors.New("private audit failure")
	}
	return nil
}

func TestModelAttemptAuditLinksActualFallbackModelWithoutChangingBilling(t *testing.T) {
	for _, auditFailure := range []bool{false, true} {
		m, op, gateway, budgets := failoverInvocationFixture(t)
		gateway.firstIncomplete = true
		capture := &modelAttemptAuditCapture{fail: auditFailure}
		m.SetModelAttemptRecorder(capture)
		result := invokeFailover(m, op, context.Background())
		if result.Code != 200 || len(gateway.calls) != 2 || len(budgets.settled) != 2 || len(capture.events) != 2 {
			t.Fatal("audit must not lose outcomes or cause new sends", result.Code, len(capture.events))
		}
		for i, event := range capture.events {
			outcome := "succeeded"
			if i == 0 {
				outcome = "incomplete"
			}
			var body map[string]any
			if event.Validate() != nil || json.Unmarshal([]byte(event.Summary), &body) != nil ||
				body["model_version_id"] != gateway.calls[i].ModelVersionID || body["operation"] != "generate" ||
				body["transport_observed"] != false || body["outcome"] != outcome ||
				strings.Contains(event.Summary, "logical-call") || strings.Contains(event.Summary, "指标定义") {
				t.Fatal("actual model, unknown transport coverage, or redaction lost", event)
			}
			if i == 1 && (body["fallback"] == nil || capture.events[0].ID == event.ID) {
				t.Fatal("distinct fallback identity and predecessor missing")
			}
		}
		_ = invokeFailover(m, op, context.Background())
		if len(capture.events) != 2 || len(gateway.calls) != 2 {
			t.Fatal("replay invented another attempt")
		}
	}
}

func TestModelAttemptAuditPreservesUnknownFailureWithoutClaimingRetries(t *testing.T) {
	m, op, gateway, budgets := failoverInvocationFixture(t)
	gateway.firstError = &modelgateway.ProviderFailure{Category: "body_read"}
	capture := &modelAttemptAuditCapture{}
	m.SetModelAttemptRecorder(capture)
	_ = invokeFailover(m, op, context.Background())
	if len(capture.events) != 1 || len(gateway.calls) != 1 || len(budgets.settled) != 0 || len(budgets.released) != 0 {
		t.Fatal("diagnostic write changed unknown billing")
	}
	var body map[string]any
	if json.Unmarshal([]byte(capture.events[0].Summary), &body) != nil || body["error_kind"] != "provider_body_read" ||
		body["model_version_id"] != gateway.calls[0].ModelVersionID || body["transport_observed"] != false || body["fallback"] != nil {
		t.Fatal("failure audit fabricated transport or fallback attempts", body)
	}
}
