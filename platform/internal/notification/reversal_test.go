package notification

import "testing"

func reversalFixtureEvent() Event {
	return Event{ID: "event-reversal", TenantID: "tenant-reversal", DepartmentID: "dept-reversal", ApplicationID: "app-reversal", Topic: "platform.notification", EventType: "agent.notification.requested.v1", PartitionKey: "app-reversal", Payload: map[string]any{"recipient_id": "recipient-reversal", "tool_name": "notify.self", "tool_call_id": "call-reversal", "tool_fingerprint": reversalDigest("original call"), "run_id": "run-reversal", "session_id": "session-reversal", "installation_id": "install-reversal", "agent_version_id": "version-reversal", "principal_id": "recipient-reversal", "principal_type": "user", "title": "teaching notice", "text": "teaching text"}}
}
func TestReversalReceiptRequiresExactRecipientMessageAndClosedForward(t *testing.T) {
	binding, err := AgentReversalBinding(reversalFixtureEvent())
	if err != nil {
		t.Fatal(err)
	}
	request := ReversalRequest{Version: "notification-reversal/v1", Binding: binding, Key: reversalDigest("fixed inverse"), Action: "correct"}
	p := ReversalReceipt{Version: "notification-reversal-receipt/v1", Binding: binding, Key: request.Key, Action: request.Action, Disposition: "corrected", ForwardClosed: true, EvidenceDigest: reversalDigest("confirmed recipient correction")}
	if p.Validate(request) != nil {
		t.Fatal("valid correction denied")
	}
	for _, change := range []func(*ReversalReceipt){func(p *ReversalReceipt) { p.ForwardClosed = false }, func(p *ReversalReceipt) { p.Binding.RecipientDigest = reversalDigest("another recipient") }, func(p *ReversalReceipt) { p.Binding.MessageDigest = reversalDigest("another message") }, func(p *ReversalReceipt) { p.Key = reversalDigest("another inverse") }, func(p *ReversalReceipt) { p.Disposition = "published" }, func(p *ReversalReceipt) { p.Disposition = "queued" }, func(p *ReversalReceipt) { p.Disposition = "http_200" }, func(p *ReversalReceipt) { p.Disposition = "withdrawn" }} {
		copy := p
		change(&copy)
		if copy.Validate(request) == nil {
			t.Fatal("unconfirmed or different effect accepted")
		}
	}
	legacy := &HTTPAdapter{}
	if _, ok := any(legacy).(RevocableChannel); ok {
		t.Fatal("legacy webhook invented reversal capability")
	}
}
