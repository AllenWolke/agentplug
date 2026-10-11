package main

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type authorizationEventRecorderStub struct {
	tx                     *sql.Tx
	auditCalls, eventCalls int
	auditErr, eventErr     error
	event                  notification.Event
}

type authorizationVersionTxStub struct {
	tx    *sql.Tx
	err   error
	calls int
}

func (s *authorizationVersionTxStub) AuthorizationVersionTx(_ context.Context, tx *sql.Tx, tenant string, kind identity.PrincipalType, id string) (uint64, error) {
	s.calls++
	if tx != s.tx || tenant != "tenant" || kind != identity.PrincipalServicePrincipal || id != "subject" {
		return 0, errors.New("transaction scope changed")
	}
	return 27, s.err
}

func TestAuthorizationAdministrationUsesPrincipalVersionAndPreservesOrdinaryAudit(t *testing.T) {
	tx := new(sql.Tx)
	scope := sharedkernel.Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application"}
	for _, stage := range []string{"versioned", "ordinary", "audit failure", "authority failure", "outbox failure"} {
		t.Run(stage, func(t *testing.T) {
			s := &authorizationEventRecorderStub{}
			v := &authorizationVersionTxStub{tx: tx}
			fault := errors.New(stage)
			e := identity.AdministrativeEvent{ID: "event", SubjectID: "subject", SubjectType: identity.PrincipalServicePrincipal, Revision: 2, Action: "machine.manage"}
			switch stage {
			case "ordinary":
				e.SubjectType = ""
			case "audit failure":
				s.auditErr = fault
			case "authority failure":
				v.err = fault
			case "outbox failure":
				s.eventErr = fault
			}
			err := recordVersionedAdministration(s, s, v)(context.Background(), tx, scope, e)
			if stage == "versioned" || stage == "ordinary" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, fault) {
				t.Fatal("failure hidden")
			}
			if stage == "ordinary" || stage == "audit failure" {
				if v.calls != 0 || s.eventCalls != 0 {
					t.Fatal("ordinary/audit failure emitted invalidation")
				}
				return
			}
			if stage == "authority failure" {
				if s.eventCalls != 0 {
					t.Fatal("failed authority emitted event")
				}
				return
			}
			if s.event.Payload["aggregate_revision"] != "27" {
				t.Fatal("credential/binding revision substituted for principal version")
			}
		})
	}
}

func TestAuthorizationPrincipalLifecycleRetainsNotificationAndAddsInvalidation(t *testing.T) {
	s := &authorizationEventRecorderStub{}
	scope := sharedkernel.Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application"}
	err := recordVersionedPrincipalLifecycle(s, s)(context.Background(), new(sql.Tx), scope, identity.PrincipalLifecycleDecision{PrincipalType: identity.PrincipalUser, PrincipalID: "subject", Status: "disabled", Revision: 7})
	if err != nil || s.auditCalls != 1 || s.eventCalls != 2 || s.event.EventType != notification.AuthorizationChangedV1 || s.event.Payload["aggregate_revision"] != "7" {
		t.Fatal("principal lifecycle lost original notification or version event", err)
	}
}

func (s *authorizationEventRecorderStub) RecordTx(tx *sql.Tx, _ audit.Event) error {
	s.tx = tx
	s.auditCalls++
	return s.auditErr
}
func (s *authorizationEventRecorderStub) EnqueueTx(_ context.Context, tx *sql.Tx, e notification.Event) (notification.Event, error) {
	if s.tx != tx {
		return notification.Event{}, errors.New("transaction changed")
	}
	s.eventCalls++
	s.event = e
	return e, s.eventErr
}

func TestAuthorizationChangeRecorderUsesSameTransactionAndPropagatesFailures(t *testing.T) {
	receipt := identity.AuthorizationChangeReceipt{ID: "change", SubjectID: "subject", Revision: 7, Change: identity.AuthorizationChangeCommand{SubjectType: identity.PrincipalUser}}
	scope := sharedkernel.Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application"}
	tx := new(sql.Tx)
	for _, stage := range []string{"success", "audit", "outbox"} {
		t.Run(stage, func(t *testing.T) {
			s := &authorizationEventRecorderStub{}
			fault := errors.New(stage)
			if stage == "audit" {
				s.auditErr = fault
			}
			if stage == "outbox" {
				s.eventErr = fault
			}
			err := recordVersionedAuthorizationChange(s, s)(context.Background(), tx, scope, receipt)
			if stage == "success" && err != nil {
				t.Fatal(err)
			}
			if stage != "success" && !errors.Is(err, fault) {
				t.Fatal("recorder failure hidden")
			}
			if s.auditCalls != 1 {
				t.Fatal("audit missing")
			}
			if stage == "audit" && s.eventCalls != 0 {
				t.Fatal("outbox attempted after audit failure")
			}
			if stage != "audit" && (s.eventCalls != 1 || s.event.Payload["aggregate_revision"] != "7" || len(s.event.Payload) != 4) {
				t.Fatal("versioned event missing or oversized")
			}
		})
	}
}

type authorizationPrincipalStub struct {
	principal identity.Principal
	err       error
}

func (s authorizationPrincipalStub) GetPrincipal(context.Context, identity.PrincipalType, string) (identity.Principal, error) {
	return s.principal, s.err
}
func TestAuthorizationRevisionReaderRejectsMismatchedAuthority(t *testing.T) {
	p := identity.Principal{ID: "subject", Type: identity.PrincipalUser, TenantID: "tenant", Revision: 7}
	for _, field := range []string{"valid", "tenant", "type", "id", "revision", "outage"} {
		t.Run(field, func(t *testing.T) {
			s := authorizationPrincipalStub{principal: p}
			switch field {
			case "tenant":
				s.principal.TenantID = "other"
			case "type":
				s.principal.Type = identity.PrincipalServicePrincipal
			case "id":
				s.principal.ID = "other"
			case "revision":
				s.principal.Revision = 0
			case "outage":
				s.err = errors.New("unavailable")
			}
			v, err := readAuthorizationRevision(s)(context.Background(), "tenant", "user", "subject")
			if field == "valid" {
				if err != nil || v != 7 {
					t.Fatal("valid revision unavailable")
				}
			} else if err == nil || v != 0 {
				t.Fatal("mismatched authority accepted")
			}
		})
	}
}
