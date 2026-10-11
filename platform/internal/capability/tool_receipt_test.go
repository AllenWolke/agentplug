package capability

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

type receiptBusinessPort struct {
	calls  int
	query  ToolReceiptQuery
	result map[string]any
}

func (p *receiptBusinessPort) Supports(string) bool { return true }
func (p *receiptBusinessPort) Invoke(context.Context, ToolCommand) (map[string]any, error) {
	p.calls++
	return p.result, nil
}
func (p *receiptBusinessPort) LookupToolReceipt(_ context.Context, q ToolReceiptQuery) (map[string]any, bool, error) {
	if q.CallID != p.query.CallID || q.Name != p.query.Name || q.Fingerprint != p.query.Fingerprint || ToolReceiptScopeHash(q.Scope) != ToolReceiptScopeHash(p.query.Scope) {
		return nil, false, nil
	}
	return cloneMap(p.result), true, nil
}

// Simulate ledger write failure after the business transaction committed.
// 模拟业务事务已经提交，但工具账本完成写入失败。
type failedCompletionToolStore struct{ *memoryToolInvocationStore }

func (s *failedCompletionToolStore) Complete(context.Context, string, string, string, map[string]any) error {
	return errors.New("ledger completion outage")
}

func (s *failedCompletionToolStore) FinishTool(context.Context, ToolExecutionLease, map[string]any) error {
	return errors.New("ledger completion outage")
}

func TestCommittedBusinessReceiptRestoresWithoutAnotherCommand(t *testing.T) {
	ctx := capabilityContext()
	in := map[string]any{"name": "fixture.write", "call_id": "committed-receipt", "payload": map[string]any{"rule_id": "rule"}}
	fp, err := ToolCommandFingerprint("fixture.write", in["payload"].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	port := &receiptBusinessPort{query: ToolReceiptQuery{Scope: scopeFromHarness(ctx), CallID: "committed-receipt", Name: "fixture.write", Fingerprint: fp}, result: map[string]any{"issue_id": "committed-issue", "revision": float64(1)}}
	m := newTestModule("internal-token", "signing-secret", nil, "platform", "agent-runtime")
	m.SetToolProvider(port)
	m.toolStore = &failedCompletionToolStore{newMemoryToolInvocationStore()}
	first := capabilityRequest(t, m, "/internal/tool/invoke", ctx, in)
	if first.Code != http.StatusBadGateway || port.calls != 1 {
		t.Fatal("commit/ledger failure not reproduced")
	}
	second := capabilityRequest(t, m, "/internal/tool/invoke", ctx, in)
	if second.Code != http.StatusOK || !strings.Contains(second.Body.String(), "committed-issue") || port.calls != 1 {
		t.Fatal("recovery repeated the business command")
	}
	third := capabilityRequest(t, m, "/internal/tool/invoke", ctx, in)
	if third.Code != http.StatusOK || third.Body.String() != second.Body.String() || port.calls != 1 {
		t.Fatal("restored receipt did not replay")
	}
}

func TestReceiptRestoreRejectsChangedResult(t *testing.T) {
	s := newMemoryToolInvocationStore()
	ctx := context.Background()
	if _, _, err := s.Reserve(ctx, "scope", "call", "fp"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkUnknown(ctx, "scope", "call", "fp"); err != nil {
		t.Fatal(err)
	}
	if err := s.RestoreCommitted(ctx, "scope", "call", "fp", map[string]any{"id": "receipt"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RestoreCommitted(ctx, "scope", "call", "fp", map[string]any{"id": "changed"}); !errors.Is(err, ErrToolInvocationConflict) {
		t.Fatal("changed committed receipt accepted")
	}
}

func TestReceiptRestoreReplaysStructuredObservationWithoutChangingJSONValues(t *testing.T) {
	store := newMemoryToolInvocationStore()
	ctx := context.Background()
	scope := scopeFromHarness(capabilityContext())
	callID, fingerprint := "structured-observation-receipt", strings.Repeat("c", 64)
	scopeHash := ToolReceiptScopeHash(scope)
	if _, _, err := store.Reserve(ctx, scopeHash, callID, fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkUnknown(ctx, scopeHash, callID, fingerprint); err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, time.October, 5, 9, 0, 0, 123456789, time.UTC)
	observation, output := newToolObservation(scope, "fixture.read", callID, &started, "succeeded", "completed", "", map[string]any{
		"large_integer": json.Number("9007199254740993"),
		"fraction":      json.Number("0.125"),
		"exponent":      json.Number("1e-12"),
	})
	receipt := storedToolObservation(observation, output)
	if err := store.RestoreCommitted(ctx, scopeHash, callID, fingerprint, receipt); err != nil {
		t.Fatal("first committed receipt restore failed:", err)
	}
	if err := store.RestoreCommitted(ctx, scopeHash, callID, fingerprint, receipt); err != nil {
		t.Fatal("identical structured receipt replay failed:", err)
	}

	changed := cloneToolResult(receipt)
	data, ok := changed["data"].(map[string]any)
	if !ok {
		t.Fatal("restored observation data has unexpected shape")
	}
	data["large_integer"] = json.Number("9007199254740992")
	if err := store.RestoreCommitted(ctx, scopeHash, callID, fingerprint, changed); !errors.Is(err, ErrToolInvocationConflict) {
		t.Fatal("changed exact integer receipt accepted")
	}

	invalid := map[string]any{"_runtime_receipt_version": observationVersion, "data": map[string]any{"bad": json.Number("NaN")}}
	if err := store.RestoreCommitted(ctx, scopeHash, callID, fingerprint, invalid); err == nil {
		t.Fatal("invalid JSON number accepted as a committed receipt")
	}
	cyclic := map[string]any{}
	cyclic["self"] = cyclic
	if err := store.RestoreCommitted(ctx, scopeHash, callID, fingerprint, cyclic); err == nil {
		t.Fatal("cyclic result accepted as a committed receipt")
	}
	if err := store.RestoreCommitted(ctx, scopeHash, callID, fingerprint, receipt); err != nil {
		t.Fatal("rejected receipts changed the stored committed result:", err)
	}
}

type committedNotificationReceiptPort struct {
	calls   int
	command NotificationToolCommand
}

func (p *committedNotificationReceiptPort) Enqueue(_ context.Context, c NotificationToolCommand) (NotificationToolReceipt, error) {
	p.calls++
	p.command = c
	return NotificationToolReceipt{}, errors.New("ack lost after durable commit")
}

func (p *committedNotificationReceiptPort) LookupToolReceipt(_ context.Context, q ToolReceiptQuery) (map[string]any, bool, error) {
	if q.Name != "send_notification" || q.CallID != p.command.CallID || q.Fingerprint != p.command.Fingerprint || ToolReceiptScopeHash(q.Scope) != ToolReceiptScopeHash(p.command.Scope) {
		return nil, false, nil
	}
	return map[string]any{"message_id": p.command.EventID, "delivery_status": "pending", "accepted": true, "delivered": false}, true, nil
}

func TestUnknownNotificationRestoresReceiptWithoutAnotherEnqueue(t *testing.T) {
	port := &committedNotificationReceiptPort{}
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, notificationPolicyResolver())
	m.SetNotificationToolPort(port)
	input := map[string]any{"name": "send_notification", "call_id": "committed-notification", "payload": map[string]any{"receiver_id": "reviewer", "title": "review", "text": "ready"}}
	approveNotificationFixture(t, m, capabilityContext(), input)
	first := capabilityRequest(t, m, "/internal/tool/invoke", capabilityContext(), input)
	if first.Code != http.StatusServiceUnavailable {
		t.Fatal("ambiguous acknowledgement hidden")
	}
	second := capabilityRequest(t, m, "/internal/tool/invoke", capabilityContext(), input)
	if second.Code != http.StatusOK || !strings.Contains(second.Body.String(), `"delivered":false`) || port.calls != 1 {
		t.Fatal("receipt recovery repeated enqueue or claimed delivery")
	}
	third := capabilityRequest(t, m, "/internal/tool/invoke", capabilityContext(), input)
	if third.Code != http.StatusOK || third.Body.String() != second.Body.String() || port.calls != 1 {
		t.Fatal("restored notification did not replay exactly")
	}
}

func (p *receiptBusinessPort) DescribeTool(name string) (RuntimeToolDescriptor, bool) {
	return RuntimeToolDescriptor{ExecutionType: "tool", Risk: "read_only", TimeoutSeconds: 3}, p.Supports(name)
}
