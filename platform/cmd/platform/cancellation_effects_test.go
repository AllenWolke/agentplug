package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func cancellationCompositionScope() sharedkernel.Scope {
	return sharedkernel.Scope{TenantID: "tenant-e", DepartmentID: "dept-e", ApplicationID: "app-e", AgentInstanceID: "instance-e", AgentID: "agent-e", AgentVersionID: "version-e", InstallationID: "install-e", PrincipalType: "user", PrincipalID: "owner-e", SessionID: "session-e", RunID: "run-e", AuthorizationEpoch: 1, TraceID: "trace-e"}
}

func TestCancellationCoverageDoesNotConfuseLostResponseWithReversal(t *testing.T) {
	module := capability.NewModule("", "", nil, "", "")
	scope := cancellationCompositionScope()
	version := notification.InboxChannelVersion + ".withdraw"
	descriptor, found := module.RuntimeToolDescriptor("notify.self")
	if !found {
		t.Fatal("actual notification descriptor missing")
	}
	factory := func(q capability.ToolReceiptQuery) (compensation.Step, error) {
		return notificationCancellationStep(q, version)
	}
	c := &cancellationEffects{capabilities: module, bindings: map[string]cancellationToolBinding{"notify.self": {descriptor, factory}}}
	q := capability.ToolReceiptQuery{Scope: scope, Name: "notify.self", CallID: "call", Fingerprint: strings.Repeat("a", 64), RuntimeAudit: &capability.ToolRuntimeAuditBinding{Descriptor: descriptor, PolicyHash: strings.Repeat("b", 64)}}
	step, err := factory(q)
	if err != nil {
		t.Fatal(err)
	}
	lost := capability.CancellationToolFact{Query: q, Status: "unknown", Phase: "executing", LeaseExpired: true}
	if err := c.validateToolCoverage(scope, []capability.CancellationToolFact{lost}, nil); !errors.Is(err, compensation.ErrPending) {
		t.Fatal("unregistered lost effect passed", err)
	}
	if err := c.validateToolCoverage(scope, []capability.CancellationToolFact{lost}, []compensation.Step{step}); err != nil {
		t.Fatal("owned lost result could not enter receipt reconciliation", err)
	}
	if lost.Status != "unknown" {
		t.Fatal("coverage manufactured completed forward result")
	}
	wrong := step
	wrong.Fingerprint = strings.Repeat("c", 64)
	if err := c.validateToolCoverage(scope, []capability.CancellationToolFact{lost}, []compensation.Step{wrong}); err == nil {
		t.Fatal("different immutable effect substituted")
	}
	if err := c.validateToolCoverage(scope, nil, []compensation.Step{step}); err == nil {
		t.Fatal("orphan notification passed")
	}
	prepared := lost
	prepared.Phase = "preparing"
	if err := c.validateToolCoverage(scope, []capability.CancellationToolFact{prepared}, nil); err != nil {
		t.Fatal("never-submitted preparation required inverse", err)
	}
	if err := c.validateToolCoverage(scope, []capability.CancellationToolFact{prepared}, []compensation.Step{step}); err == nil {
		t.Fatal("non-atomic registration accepted")
	}
	other := scope
	other.RunID = "other-run"
	if err := c.validateToolCoverage(other, []capability.CancellationToolFact{lost}, []compensation.Step{step}); err == nil {
		t.Fatal("effect crossed Run boundary")
	}
}

func TestCancellationCoverageRejectsMissingMetadataAndUninstalledInverse(t *testing.T) {
	module := capability.NewModule("", "", nil, "", "")
	c := &cancellationEffects{capabilities: module}
	q := capability.ToolReceiptQuery{Scope: cancellationCompositionScope(), Name: "notify.self", CallID: "call", Fingerprint: strings.Repeat("a", 64)}
	if _, _, err := c.toolStep(q); err == nil {
		t.Fatal("missing evidence became read-only")
	}
	descriptor, _ := module.RuntimeToolDescriptor(q.Name)
	q.RuntimeAudit = &capability.ToolRuntimeAuditBinding{Descriptor: descriptor, PolicyHash: strings.Repeat("b", 64)}
	if _, _, err := c.toolStep(q); !errors.Is(err, compensation.ErrUnavailable) {
		t.Fatal("uninstalled inverse admitted write", err)
	}
	q.RuntimeAudit.Descriptor.Risk = "read_only"
	if _, _, err := c.toolStep(q); err == nil {
		t.Fatal("write downgraded to read")
	}
}

type cancellationChannelFixture struct{ calls int }

func (f *cancellationChannelFixture) Send(context.Context, notification.Event) error {
	f.calls++
	return nil
}

func TestCancellationChannelNeverFallsBackForAgentOrMalformedBinding(t *testing.T) {
	legacy, inbox := &cancellationChannelFixture{}, &cancellationChannelFixture{}
	c := &agentNotificationChannel{fallback: legacy}
	scope := cancellationCompositionScope()
	store := &recordingNotificationOutbox{}
	adapter := platformNotificationToolAdapter{outbox: store}
	_, err := adapter.Enqueue(context.Background(), capability.NotificationToolCommand{Scope: scope, ToolName: "notify.self", CallID: "call", Fingerprint: strings.Repeat("a", 64), EventID: "event-c", RecipientID: scope.PrincipalID, Title: "title", Text: "text"})
	if err != nil {
		t.Fatal(err)
	}
	event := store.events[0]
	if err := c.Send(context.Background(), event); !errors.Is(err, notification.ErrAdapterUnavailable) || legacy.calls != 0 {
		t.Fatal("missing inbox fell back to external channel", err)
	}
	if err := c.installInbox(inbox); err != nil {
		t.Fatal(err)
	}
	if err := c.installInbox(inbox); !errors.Is(err, notification.ErrConflict) {
		t.Fatal("live inbox replaced", err)
	}
	if err := c.Send(context.Background(), event); err != nil || inbox.calls != 1 || legacy.calls != 0 {
		t.Fatal("controlled delivery failed", err)
	}
	event.Topic = "platform.audit"
	if err := c.Send(context.Background(), event); err == nil || legacy.calls != 0 || inbox.calls != 1 {
		t.Fatal("malformed event bypassed inbox")
	}
	if err := c.Send(context.Background(), notification.Event{EventType: "identity.authorization.changed.v1"}); err != nil || legacy.calls != 1 {
		t.Fatal("identity event routed to compensation", err)
	}
}

func TestNotificationCompensationCannotSilentlyUseNontransactionalOutbox(t *testing.T) {
	store := &recordingNotificationOutbox{}
	adapter := platformNotificationToolAdapter{outbox: store, compensationVersion: notification.InboxChannelVersion + ".withdraw"}
	_, err := adapter.Enqueue(context.Background(), capability.NotificationToolCommand{Scope: cancellationCompositionScope(), EventID: "event", CallID: "call", Fingerprint: strings.Repeat("a", 64), RecipientID: "owner-e", Title: "title", Text: "text"})
	if !errors.Is(err, compensation.ErrUnavailable) || len(store.events) != 0 {
		t.Fatal("compensated forward operation committed without transaction", err)
	}
}
