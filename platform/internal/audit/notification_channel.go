package audit

import (
	"context"
	"database/sql"
	"strings"

	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sqlutil"
)

// NotificationChannel confirms an audit event already committed by this owner.
// It does not accept business messages or send an external notification. IAM
// invalidations continue through the separate versioned-authorization adapter.
func (s *SQLStore) NotificationChannel() notification.ChannelAdapter {
	return auditNotificationChannel{store: s}
}

type auditNotificationChannel struct{ store *SQLStore }

func (a auditNotificationChannel) Send(ctx context.Context, event notification.Event) error {
	if ctx == nil || ctx.Err() != nil || a.store == nil || a.store.db == nil {
		return notification.ErrAdapterUnavailable
	}
	if event.ValidateForDelivery() != nil || event.Topic != "platform.audit" || !strings.HasPrefix(event.EventType, "audit.") || len(event.Payload) != 6 {
		return notification.ErrInvalidEvent
	}
	values := make(map[string]string, 6)
	for _, key := range []string{"event_id", "digest", "action", "aggregate_type", "aggregate_id", "outcome"} {
		value, ok := event.Payload[key].(string)
		if !ok || value == "" {
			return notification.ErrInvalidEvent
		}
		values[key] = value
	}
	if event.ID != "audit-"+values["event_id"] || event.EventType != "audit."+values["action"] || event.PartitionKey != values["aggregate_id"] {
		return notification.ErrInvalidEvent
	}
	var tenant, department, application, aggregateType, aggregateID, action, outcome, digest string
	err := a.store.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT tenant_id,department_id,application_id,aggregate_type,aggregate_id,action,outcome,digest FROM platform_audit_event WHERE event_id=?`), values["event_id"]).Scan(&tenant, &department, &application, &aggregateType, &aggregateID, &action, &outcome, &digest)
	if err == sql.ErrNoRows {
		return notification.ErrInvalidEvent
	}
	if err != nil {
		return notification.ErrAdapterUnavailable
	}
	if tenant != event.TenantID || department != event.DepartmentID || application != event.ApplicationID || aggregateType != values["aggregate_type"] || aggregateID != values["aggregate_id"] || action != values["action"] || outcome != values["outcome"] || digest != values["digest"] {
		return notification.ErrInvalidEvent
	}
	return nil
}

var _ notification.ChannelAdapter = auditNotificationChannel{}
