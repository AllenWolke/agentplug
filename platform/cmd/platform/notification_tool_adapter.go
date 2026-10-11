package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/notification"
)

type notificationOutboxEnqueuer interface {
	Enqueue(notification.Event) (notification.Event, error)
}

// platformNotificationToolAdapter is a composition-root adapter: Capability
// owns the Agent-facing port while Notification owns the durable Outbox.
// 平台组合根 Adapter：Capability 定义 Agent 端口，Notification 模块拥有持久化 Outbox。
type platformNotificationToolAdapter struct {
	outbox       notificationOutboxEnqueuer
	db           *sql.DB
	guard        capability.ToolCommitGuard
	compensation interface {
		RegisterAgentEffectTx(context.Context, *sql.Tx, compensation.Step, notification.Event) error
	}
	compensationVersion string
}

func notificationCancellationStep(q capability.ToolReceiptQuery, version string) (compensation.Step, error) {
	if (q.Name != "send_notification" && q.Name != "notify.self") || q.Scope.ValidateTrusted() != nil || q.CallID == "" || !cancellationDigest(q.Fingerprint) || (version != notification.InboxChannelVersion+".withdraw" && version != notification.InboxChannelVersion+".correct") {
		return compensation.Step{}, compensation.ErrInvalid
	}
	id := sha256.Sum256([]byte(capability.ToolReceiptScopeHash(q.Scope) + "\x00" + q.CallID))
	step := compensation.Step{Root: q.Scope, Scope: q.Scope, Kind: "notification", Tool: q.Name, Provider: notification.NotificationCompensationProvider, ProviderVersion: version, CallID: q.CallID, Fingerprint: q.Fingerprint, Ref: "agent-tool-" + fmt.Sprintf("%x", id)}
	step.ID = compensation.StepID(q.Scope, step.Kind, q.CallID)
	return step, step.Validate()
}

func (a platformNotificationToolAdapter) Enqueue(ctx context.Context, command capability.NotificationToolCommand) (capability.NotificationToolReceipt, error) {
	if a.outbox == nil {
		return capability.NotificationToolReceipt{}, errors.New("notification outbox is unavailable")
	}
	if ctx == nil {
		return capability.NotificationToolReceipt{}, errors.New("notification context is required")
	}
	if err := ctx.Err(); err != nil {
		return capability.NotificationToolReceipt{}, err
	}
	scope := command.Scope
	toolName := command.ToolName
	if toolName == "" {
		// Keep direct legacy Port callers bound to the original public tool.
		toolName = "send_notification"
	}
	if toolName != "send_notification" && toolName != "notify.self" {
		return capability.NotificationToolReceipt{}, errors.New("notification tool name is invalid")
	}
	if toolName == "notify.self" && (scope.PrincipalType != "user" || scope.PrincipalID == "" || strings.TrimSpace(scope.PrincipalID) != scope.PrincipalID || command.RecipientID != scope.PrincipalID) {
		return capability.NotificationToolReceipt{}, errors.New("self notification recipient does not match the human scope")
	}
	event := notification.Event{
		ID: command.EventID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID,
		ApplicationID: scope.ApplicationID, Topic: "platform.notification",
		EventType: "agent.notification.requested.v1", PartitionKey: scope.ApplicationID,
		Payload: map[string]any{
			"tool_name":         toolName,
			"tool_call_id":      command.CallID,
			"tool_fingerprint":  command.Fingerprint,
			"recipient_id":      command.RecipientID,
			"title":             command.Title,
			"text":              command.Text,
			"agent_id":          scope.AgentID,
			"agent_instance_id": scope.AgentInstanceID,
			"agent_version_id":  scope.AgentVersionID,
			"installation_id":   scope.InstallationID,
			"principal_type":    scope.PrincipalType,
			"principal_id":      scope.PrincipalID,
			"session_id":        scope.SessionID,
			"run_id":            scope.RunID,
			"trace_id":          scope.TraceID,
		},
	}
	stored, err := a.enqueueGuarded(ctx, command, event)
	if err != nil {
		return capability.NotificationToolReceipt{}, err
	}
	if strings.TrimSpace(stored.ID) == "" {
		return capability.NotificationToolReceipt{}, errors.New("notification outbox returned an empty event ID")
	}
	return capability.NotificationToolReceipt{EventID: stored.ID, Status: string(notification.Pending)}, nil
}

// The local composition root coordinates two owned Ports in one transaction.
// 本地组合根协调两个模块Port原子提交，不读取任何模块的私有表。
func (a platformNotificationToolAdapter) enqueueGuarded(ctx context.Context, command capability.NotificationToolCommand, event notification.Event) (notification.Event, error) {
	if a.db == nil {
		if a.compensation != nil || a.compensationVersion != "" {
			return notification.Event{}, compensation.ErrUnavailable
		}
		return a.outbox.Enqueue(event)
	}
	writer, ok := a.outbox.(interface {
		EnqueueTx(context.Context, *sql.Tx, notification.Event) (notification.Event, error)
	})
	if !ok || a.guard == nil {
		return notification.Event{}, errors.New("notification transaction guard unavailable")
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return notification.Event{}, err
	}
	defer tx.Rollback()
	toolName := command.ToolName
	if toolName == "" {
		toolName = "send_notification"
	}
	q := capability.ToolReceiptQuery{Scope: command.Scope, CallID: command.CallID, Name: toolName, Fingerprint: command.Fingerprint}
	if err := a.guard.GuardToolCommit(ctx, tx, q); err != nil {
		return notification.Event{}, err
	}
	if a.compensation != nil || a.compensationVersion != "" {
		if a.compensation == nil {
			return notification.Event{}, compensation.ErrUnavailable
		}
		step, err := notificationCancellationStep(q, a.compensationVersion)
		if err != nil || event.ID != step.Ref {
			return notification.Event{}, compensation.ErrConflict
		}
		if err := a.compensation.RegisterAgentEffectTx(ctx, tx, step, event); err != nil {
			return notification.Event{}, err
		}
	}
	stored, err := writer.EnqueueTx(ctx, tx, event)
	if err != nil {
		return notification.Event{}, err
	}
	if err := a.guard.GuardToolCommit(ctx, tx, q); err != nil {
		return notification.Event{}, err
	}
	if err := tx.Commit(); err != nil {
		return notification.Event{}, err
	}
	return stored, nil
}

func (a platformNotificationToolAdapter) LookupToolReceipt(ctx context.Context, q capability.ToolReceiptQuery) (map[string]any, bool, error) {
	reader, ok := a.outbox.(interface {
		FindCommittedEvent(context.Context, string) (notification.Event, bool, error)
	})
	if !ok {
		return nil, false, errors.New("notification receipt reader unavailable")
	}
	if (q.Name != "send_notification" && q.Name != "notify.self") || q.CallID == "" || q.Fingerprint == "" {
		return nil, false, capability.ErrToolInvocationConflict
	}
	digest := sha256.Sum256([]byte(capability.ToolReceiptScopeHash(q.Scope) + "\x00" + q.CallID))
	id := "agent-tool-" + fmt.Sprintf("%x", digest)
	event, found, err := reader.FindCommittedEvent(ctx, id)
	if err != nil || !found {
		return nil, false, err
	}
	s := q.Scope
	if event.ID != id || event.TenantID != s.TenantID || event.DepartmentID != s.DepartmentID || event.ApplicationID != s.ApplicationID || event.Topic != "platform.notification" || event.EventType != "agent.notification.requested.v1" {
		return nil, false, capability.ErrToolInvocationConflict
	}
	if value, exists := event.Payload["tool_name"]; exists {
		toolName, ok := value.(string)
		if !ok || toolName != q.Name {
			return nil, false, capability.ErrToolInvocationConflict
		}
	} else if q.Name == "notify.self" {
		// Legacy send_notification receipts may predate the explicit name field;
		// a self receipt always requires its own name binding.
		return nil, false, capability.ErrToolInvocationConflict
	}
	for key, value := range map[string]string{"tool_call_id": q.CallID, "tool_fingerprint": q.Fingerprint, "agent_id": s.AgentID, "agent_instance_id": s.AgentInstanceID, "agent_version_id": s.AgentVersionID, "installation_id": s.InstallationID, "principal_type": s.PrincipalType, "principal_id": s.PrincipalID, "session_id": s.SessionID, "run_id": s.RunID} {
		if event.Payload[key] != value {
			return nil, false, capability.ErrToolInvocationConflict
		}
	}
	recipientID, recipientOK := event.Payload["recipient_id"].(string)
	_, titleOK := event.Payload["title"].(string)
	_, textOK := event.Payload["text"].(string)
	if !recipientOK || !titleOK || !textOK {
		return nil, false, capability.ErrToolInvocationConflict
	}
	if q.Name == "notify.self" {
		if s.PrincipalType != "user" || s.PrincipalID == "" || strings.TrimSpace(s.PrincipalID) != s.PrincipalID || recipientID != s.PrincipalID {
			return nil, false, capability.ErrToolInvocationConflict
		}
	}
	// Recover original acceptance, not the mutable delivery status.
	// 回放最初受理结果，不把后续消息状态当作工具完成或送达证明。
	return map[string]any{"message_id": id, "delivery_status": string(notification.Pending), "accepted": true, "delivered": false}, true, nil
}
