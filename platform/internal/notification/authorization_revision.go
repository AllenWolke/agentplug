package notification

import (
	"context"
	"errors"
	"strconv"
)

const AuthorizationChangedV1 = "identity.authorization.changed.v1"

var ErrAuthorizationRevision = errors.New("authorization event revision unavailable or inconsistent")

// AuthorizationRevisionReader reads durable principal revisions. Events are
// invalidation hints, never permission grants or a substitute for live IAM.
type AuthorizationRevisionReader func(context.Context, string, string, string) (uint64, error)

func NewAuthorizationChangedEvent(id, tenant, department, application, subjectType, subjectID string, revision uint64) (Event, error) {
	e := Event{ID: "authorization-" + id, TenantID: tenant, DepartmentID: department, ApplicationID: application,
		Topic: "agent-platform.identity.v1", EventType: AuthorizationChangedV1,
		PartitionKey: tenant + ":" + subjectType + ":" + subjectID,
		Payload: map[string]any{"change_id": id, "subject_type": subjectType, "subject_id": subjectID,
			// Decimal strings survive JSON transports without float64 precision loss.
			"aggregate_revision": strconv.FormatUint(revision, 10)}}
	if _, _, _, err := authorizationRevision(e); err != nil {
		return Event{}, err
	}
	return e, nil
}

func authorizationRevision(e Event) (string, string, uint64, error) {
	if e.ValidateForDelivery() != nil || e.EventType != AuthorizationChangedV1 || e.Topic != "agent-platform.identity.v1" || len(e.Payload) != 4 {
		return "", "", 0, ErrInvalidEvent
	}
	change, _ := e.Payload["change_id"].(string)
	kind, _ := e.Payload["subject_type"].(string)
	id, _ := e.Payload["subject_id"].(string)
	encoded, _ := e.Payload["aggregate_revision"].(string)
	revision, err := strconv.ParseUint(encoded, 10, 64)
	if change == "" || id == "" || (kind != "user" && kind != "service_principal") || err != nil || revision == 0 || strconv.FormatUint(revision, 10) != encoded || e.ID != "authorization-"+change || e.PartitionKey != e.TenantID+":"+kind+":"+id {
		return "", "", 0, ErrInvalidEvent
	}
	return kind, id, revision, nil
}

// VersionedAuthorizationAdapter acknowledges current/stale invalidations only
// after a successful authoritative read. Future versions and outages retry.
// Duplicate IDs remain protected by the module's durable delivery ledger.
type VersionedAuthorizationAdapter struct {
	ReadRevision AuthorizationRevisionReader
	Inner        ChannelAdapter
}

func (a VersionedAuthorizationAdapter) Send(ctx context.Context, e Event) error {
	if e.EventType != AuthorizationChangedV1 {
		if a.Inner == nil {
			return ErrAdapterUnavailable
		}
		return a.Inner.Send(ctx, e)
	}
	kind, id, version, err := authorizationRevision(e)
	if err != nil {
		return err
	}
	if a.ReadRevision == nil {
		return ErrAuthorizationRevision
	}
	current, err := a.ReadRevision(ctx, e.TenantID, kind, id)
	if err != nil {
		return err
	}
	if current == 0 || version > current {
		return ErrAuthorizationRevision
	}
	// No permission cache exists: acknowledging cannot restore old grants.
	return nil
}
