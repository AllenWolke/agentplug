package capability

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
)

func responseSchemaFixture() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","minLength":1}},"required":["query"],"additionalProperties":false}`)
}

func TestResponseSchemaBudgetCountsSchemaBeforeAnySend(t *testing.T) {
	message := []modelgateway.Message{{Role: "user", Content: "query"}}
	policy := policyasset.ModelPolicy{MaxInputTokens: contextInputEstimate(message, policyasset.ToolPolicy{}, nil, true) + 10}
	raw := responseSchemaFixture()
	if ValidateModelContextLimit(policy, message, policyasset.ToolPolicy{}, nil, true) != nil {
		t.Fatal("legacy fixture invalid")
	}
	if err := ValidateModelContextWithResponseSchema(policy, message, policyasset.ToolPolicy{}, nil, true, raw, "required"); !errors.Is(err, errContextLimit) {
		t.Fatal("schema bytes omitted from input budget", err)
	}
	base := "original"
	if modelResponseSchemaFingerprint(base, nil, "") != base || modelResponseSchemaFingerprint(base, raw, "required") == modelResponseSchemaFingerprint(base, raw, "prefer_supported") {
		t.Fatal("schema format not pinned or legacy identity changed")
	}
}

func TestResponseSchemaRouteRejectsUnsupportedRequiredAndPinsOriginalSchema(t *testing.T) {
	scope, p, catalog, at := routeFixture()
	request := routeRequest("query")
	request.RequireJSON = true
	request.ResponseSchema = responseSchemaFixture()
	request.ResponseSchemaMode = "required"
	if _, err := SelectModelRoute(context.Background(), scope, p, request, policyasset.ToolPolicy{}, true, catalog, catalog, at); !errors.Is(err, ErrModelRouteNoCandidate) {
		t.Fatal("unsupported schema candidate selected", err)
	}
	request.ResponseSchemaMode = "prefer_supported"
	if _, err := SelectModelRoute(context.Background(), scope, p, request, policyasset.ToolPolicy{}, true, catalog, catalog, at); err != nil {
		t.Fatal("declared fallback denied", err)
	}
	m, original, _, gateway := routeInvocationFixture(t)
	op := original
	first, _, err := m.resolveInvocationRoute(context.Background(), &op, "schema-key", request, 0, "prompt", nil, false)
	if err != nil || first == nil {
		t.Fatal(err)
	}
	op = original
	recovered, _, err := m.resolveInvocationRoute(context.Background(), &op, "schema-key", request, 0, "prompt", nil, true)
	if err != nil || recovered.DecisionSHA256 != first.DecisionSHA256 || gateway.calls != 0 {
		t.Fatal("schema receipt rerouted or sent", err)
	}
	request.ResponseSchema = json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","minLength":2}},"required":["query"],"additionalProperties":false}`)
	op = original
	if _, _, err = m.resolveInvocationRoute(context.Background(), &op, "schema-key", request, 0, "prompt", nil, true); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatal("changed schema recovered as old call", err)
	}
}

func TestStrictRouteAcceptsOnlyApprovedChatOrResponsesDialect(t *testing.T) {
	for _, dialect := range []string{modelgateway.ResponseSchemaDialect, "json-schema/responses/v1", "json-schema/unapproved/v1"} {
		scope, p, catalog, at := routeFixture()
		for i := range p.Candidates {
			id := p.Candidates[i].ModelVersionID
			model := catalog.models[id]
			model.ResponseSchemaDialect = dialect
			catalog.models[id] = model
			p.Candidates[i].CapabilitySHA256 = model.CapabilitySHA256()
		}
		request := routeRequest("解释指标定义")
		request.RequireJSON, request.ResponseSchema, request.ResponseSchemaMode = true, responseSchemaFixture(), "required"
		_, err := SelectModelRoute(context.Background(), scope, p, request, policyasset.ToolPolicy{}, true, catalog, catalog, at)
		if dialect == "json-schema/unapproved/v1" {
			if !errors.Is(err, ErrModelRouteNoCandidate) {
				t.Fatal("unsupported adapter routed", err)
			}
		} else if err != nil {
			t.Fatal("approved strict adapter denied", dialect, err)
		}
	}
}
