package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type deadLetterBrowserBinding struct {
	Scope    sharedkernel.Scope
	Session  string
	Revision uint64
}
type deadLetterBrowserKey struct{}
type deadLetterAuthority struct {
	iam          *identity.SQLStore
	outbox       *notification.SQLStore
	audit        audit.TxRecorder
	cancellation *agentNotificationChannel
}

func (a deadLetterAuthority) ResolveBrowser(r *http.Request) (sharedkernel.Scope, error) {
	actor := sharedkernel.Scope{PrincipalType: r.Header.Get("X-Principal-Type"), PrincipalID: r.Header.Get("X-Principal-ID"), TenantID: r.Header.Get("X-Tenant-ID"), DepartmentID: r.Header.Get("X-Department-ID"), ApplicationID: r.Header.Get("X-Application-ID"), TraceID: r.Header.Get("X-Trace-ID")}
	revision, e := strconv.ParseUint(r.Header.Get("X-Authentication-Revision"), 10, 64)
	session := r.Header.Get("X-Authentication-Session")
	if a.iam == nil || r.Header.Get("X-Browser-Module") == "" || e != nil || revision == 0 || session == "" || actor.Validate() != nil || actor.PrincipalType != "user" || actor.TraceID == "" || a.iam.ValidateBrowserSession(r.Context(), actor, session, revision) != nil {
		return sharedkernel.Scope{}, identity.ErrPermissionDenied
	}
	*r = *r.WithContext(context.WithValue(r.Context(), deadLetterBrowserKey{}, deadLetterBrowserBinding{actor, session, revision}))
	return actor, nil
}
func (a deadLetterAuthority) Authorize(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, action string) error {
	b, ok := ctx.Value(deadLetterBrowserKey{}).(deadLetterBrowserBinding)
	if !ok || b.Scope != scope || a.iam == nil || tx == nil {
		return notification.ErrDeadLetterForbidden
	}
	if e := a.iam.AcquirePermissionReadContinuity(ctx, tx); e != nil {
		return e
	}
	if a.iam.ValidateBrowserSession(ctx, b.Scope, b.Session, b.Revision) != nil || a.iam.ValidateApplicationScope(ctx, scope.TenantID, scope.DepartmentID, scope.ApplicationID) != nil {
		return notification.ErrDeadLetterForbidden
	}
	permission := "platform.monitor"
	kind := "application"
	switch action {
	case "inspect":
	case "inspect.unscoped":
		kind = "global"
	case "close.unscoped":
		permission, kind = "tool.manage", "global"
	case "close", "redrive":
		permission = "tool.manage"
	default:
		return notification.ErrDeadLetterForbidden
	}
	target := identity.ManagementScope{Type: kind, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID}
	if kind == "global" {
		target = identity.ManagementScope{Type: "global"}
	}
	err := a.iam.AuthorizeManagementTx(ctx, tx, scope, identity.PermissionQuery{Action: permission, Scope: target})
	if errors.Is(err, identity.ErrPermissionDenied) {
		return notification.ErrDeadLetterForbidden
	}
	return err
}

// Personal inbox reads require a live authenticated workspace, not platform
// administrator rights. Current session/membership and revocation are checked
// while holding the same IAM continuity lock as the feed query.
func (a deadLetterAuthority) AuthorizeInbox(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
	b, ok := ctx.Value(deadLetterBrowserKey{}).(deadLetterBrowserBinding)
	if !ok || b.Scope != scope || a.iam == nil || tx == nil || scope.PrincipalType != "user" {
		return identity.ErrPermissionDenied
	}
	if err := a.iam.AcquirePermissionReadContinuity(ctx, tx); err != nil {
		return err
	}
	if a.iam.ValidateBrowserSession(ctx, scope, b.Session, b.Revision) != nil || a.iam.ValidateApplicationScope(ctx, scope.TenantID, scope.DepartmentID, scope.ApplicationID) != nil {
		return identity.ErrPermissionDenied
	}
	return nil
}
func (a deadLetterAuthority) Record(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, c notification.DeadLetterCommand, m notification.DeadLetterMetadata) error {
	if a.audit == nil {
		return notification.ErrDeadLetterUnavailable
	}
	h := sha256.Sum256([]byte(scope.TenantID + "\x00" + scope.DepartmentID + "\x00" + scope.ApplicationID + "\x00" + scope.PrincipalID + "\x00" + m.ID + "\x00" + c.IdempotencyKey))
	return a.audit.RecordTx(tx, audit.Event{ID: "kafka-dlq-" + hex.EncodeToString(h[:]), TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorType: scope.PrincipalType, ActorID: scope.PrincipalID, TraceID: scope.TraceID, AggregateType: "kafka_dead_letter", AggregateID: m.ID, Action: "kafka.dead_letter." + c.Action, Outcome: "success", Summary: "version=" + m.Version + ";reason=" + c.ReasonCode + ";revision=" + strconv.FormatInt(m.Revision, 10), CreatedAt: time.Now().UTC()})
}
func (a deadLetterAuthority) Redrive(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, e notification.Event) error {
	if a.outbox == nil || a.iam == nil {
		return notification.ErrDeadLetterUnavailable
	}
	if e.EventType == "agent.notification.requested.v1" {
		return a.cancellation.prepareRedrive(ctx, tx, e)
	}
	return a.outbox.PrepareControlEventRedriveTx(ctx, tx, e, func(ctx context.Context, tx *sql.Tx, tenant, kind, id string) (uint64, error) {
		return a.iam.AuthorizationVersionTx(ctx, tx, tenant, identity.PrincipalType(kind), id)
	})
}
