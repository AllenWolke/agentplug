package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type authorizationAuditRecorder interface {
	RecordTx(*sql.Tx, audit.Event) error
}

type authorizationTransactionVersionReader interface {
	AuthorizationVersionTx(context.Context, *sql.Tx, string, identity.PrincipalType, string) (uint64, error)
}

func recordVersionedAdministration(auditor authorizationAuditRecorder, outbox notification.TxEnqueuer, versions authorizationTransactionVersionReader) identity.AdministrativeRecorder {
	return func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, event identity.AdministrativeEvent) error {
		if event.DetailsDigest != "" {
			event.Reason += " [details_sha256=" + event.DetailsDigest + "]"
		}
		if err := auditor.RecordTx(tx, audit.Event{ID: event.ID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorType: "user", ActorID: event.ActorID, TraceID: scope.TraceID, AggregateType: "identity_administration", AggregateID: event.SubjectID, Action: event.Action, Outcome: "success", Summary: event.Reason, CreatedAt: event.OccurredAt}); err != nil {
			return err
		}
		if event.SubjectType == "" {
			return nil // Requests and step-up do not change principal permissions.
		}
		version, err := versions.AuthorizationVersionTx(ctx, tx, scope.TenantID, event.SubjectType, event.SubjectID)
		if err != nil {
			return err
		}
		invalidation, err := notification.NewAuthorizationChangedEvent(event.ID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, string(event.SubjectType), event.SubjectID, version)
		if err != nil {
			return err
		}
		_, err = outbox.EnqueueTx(ctx, tx, invalidation)
		return err
	}
}

func recordVersionedPrincipalLifecycle(auditor authorizationAuditRecorder, outbox notification.TxEnqueuer) identity.PrincipalLifecycleRecorder {
	return func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, decision identity.PrincipalLifecycleDecision) error {
		digest := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", decision.PrincipalType, decision.PrincipalID, decision.Revision)))
		key := hex.EncodeToString(digest[:])
		eventID := "identity-principal-" + key
		if err := auditor.RecordTx(tx, audit.Event{ID: eventID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorType: string(identity.PrincipalUser), ActorID: scope.PrincipalID, TraceID: scope.TraceID, AggregateType: "identity_principal", AggregateID: decision.PrincipalID, Action: "identity_principal." + decision.Status, Outcome: decision.Status, Summary: "Identity principal " + decision.Status, CreatedAt: decision.OccurredAt}); err != nil {
			return err
		}
		if _, err := outbox.EnqueueTx(ctx, tx, notification.Event{ID: "identity-principal-notify-" + key, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, Topic: "agent-platform.identity.v1", EventType: "identity.principal-" + decision.Status + ".v1", PartitionKey: scope.TenantID + ":" + decision.PrincipalID, Payload: map[string]any{"principal_id": decision.PrincipalID, "principal_type": decision.PrincipalType, "status": decision.Status, "revision": decision.Revision}}); err != nil {
			return err
		}
		invalidation, err := notification.NewAuthorizationChangedEvent(eventID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, string(decision.PrincipalType), decision.PrincipalID, decision.Revision)
		if err != nil {
			return err
		}
		_, err = outbox.EnqueueTx(ctx, tx, invalidation)
		return err
	}
}

func recordVersionedAuthorizationChange(auditor authorizationAuditRecorder, outbox notification.TxEnqueuer) identity.AuthorizationChangeRecorder {
	return func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, receipt identity.AuthorizationChangeReceipt) error {
		event, err := notification.NewAuthorizationChangedEvent(receipt.ID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, string(receipt.Change.SubjectType), receipt.SubjectID, receipt.Revision)
		if err != nil {
			return err
		}
		if err := auditor.RecordTx(tx, audit.Event{
			ID: receipt.ID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
			ActorType: "user", ActorID: receipt.ActorID, TraceID: scope.TraceID,
			AggregateType: "identity_authorization_change", AggregateID: receipt.SubjectID,
			Action: "authorization.changed", Outcome: "success", Summary: receipt.Reason, CreatedAt: receipt.OccurredAt,
		}); err != nil {
			return err
		}
		_, err = outbox.EnqueueTx(ctx, tx, event)
		return err
	}
}

type authorizationPrincipalReader interface {
	GetPrincipal(context.Context, identity.PrincipalType, string) (identity.Principal, error)
}

func readAuthorizationRevision(store authorizationPrincipalReader) notification.AuthorizationRevisionReader {
	return func(ctx context.Context, tenant, kind, id string) (uint64, error) {
		principal, err := store.GetPrincipal(ctx, identity.PrincipalType(kind), id)
		if err != nil {
			return 0, err
		}
		if principal.TenantID != tenant || string(principal.Type) != kind || principal.ID != id || principal.Revision == 0 {
			return 0, notification.ErrAuthorizationRevision
		}
		return principal.Revision, nil
	}
}
