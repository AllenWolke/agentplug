package capability

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

type ambiguousNotificationPort struct{ calls int }

func (p *ambiguousNotificationPort) Enqueue(context.Context, NotificationToolCommand) (NotificationToolReceipt, error) {
	p.calls++
	// Simulate commit succeeded but acknowledgement was lost.
	// 模拟业务提交成功，但确认响应丢失。
	return NotificationToolReceipt{}, errors.New("commit acknowledgement lost with private payload")
}

func TestAmbiguousToolCommitCannotBeRetried(t *testing.T) {
	port := &ambiguousNotificationPort{}
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, notificationPolicyResolver())
	m.SetNotificationToolPort(port)
	in := map[string]any{"name": "send_notification", "call_id": "ambiguous", "payload": map[string]any{"receiver_id": "reviewer", "title": "review", "text": "ready"}}
	approveNotificationFixture(t, m, capabilityContext(), in)
	first := capabilityRequest(t, m, "/internal/tool/invoke", capabilityContext(), in)
	if first.Code != http.StatusServiceUnavailable {
		t.Fatal("downstream failure hidden")
	}
	second := capabilityRequest(t, m, "/internal/tool/invoke", capabilityContext(), in)
	if second.Code != http.StatusConflict || !strings.Contains(second.Body.String(), "TOOL_RESULT_UNKNOWN") || port.calls != 1 {
		t.Fatal("ambiguous commit was executed twice")
	}
	if strings.Contains(first.Body.String()+second.Body.String(), "private payload") {
		t.Fatal("downstream detail leaked")
	}
}

func TestToolPreflightDoesNotReserveLedger(t *testing.T) {
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, notificationPolicyResolver())
	in := map[string]any{"name": "send_notification", "call_id": "missing-port", "payload": map[string]any{"receiver_id": "reviewer", "title": "review", "text": "ready"}}
	if r := capabilityRequest(t, m, "/internal/tool/invoke", capabilityContext(), in); r.Code != http.StatusServiceUnavailable {
		t.Fatal("missing port accepted")
	}
	store := m.toolStore.(*memoryToolInvocationStore)
	store.mu.Lock()
	count := len(store.records)
	store.mu.Unlock()
	if count != 0 {
		t.Fatal("preflight left a stranded invocation")
	}
	m.SetNotificationToolPort(&fakeNotificationToolPort{})
	approveNotificationFixture(t, m, capabilityContext(), in)
	if r := capabilityRequest(t, m, "/internal/tool/invoke", capabilityContext(), in); r.Code != http.StatusOK {
		t.Fatal("preflight refusal prevented later legitimate call")
	}
}
