package execution

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type denyingMachineRunAuthority struct{ machineAuthenticatorFunc }

func (denyingMachineRunAuthority) AuthorizeMachineRun(context.Context, string, string, string, sharedkernel.Scope, string) error {
	return errors.New("current object permission denied")
}

func TestMachineRunObjectDenialPrecedesDisclosureAndMutation(t *testing.T) {
	m := NewModule("internal")
	scope := testScope("object-denied").domain()
	scope.PrincipalType = "service_principal"
	created, err := m.store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: "object-denied-key", Fingerprint: "object-denied-body"})
	if err != nil {
		t.Fatal(err)
	}
	m.SetMachineAccessPorts(denyingMachineRunAuthority{machineAuthenticatorFunc(func(context.Context, string, string, string) (MachineAccess, error) {
		return MachineAccess{Scope: scope, AuthorizationEpoch: 1}, nil
	})}, nil)
	for _, endpoint := range []struct{ method, suffix, body string }{
		{http.MethodGet, "", ""}, {http.MethodGet, "/events", ""},
		{http.MethodPost, "/cancel", `{"expected_revision":1}`}, {http.MethodPost, "/resume", `{"input":{"approved":true}}`},
	} {
		r := httptest.NewRequest(endpoint.method, "/agent-runs/"+scope.RunID+endpoint.suffix, strings.NewReader(endpoint.body))
		r.Header.Set("Authorization", "Bearer machine-token")
		w := httptest.NewRecorder()
		m.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "MACHINE_ACCESS_DENIED") {
			t.Fatal("object denial bypassed", endpoint.suffix, w.Code, w.Body.String())
		}
	}
	current, err := m.store.Get(scope.RunID)
	if err != nil || current.Revision != created.Run.Revision || current.Status != created.Run.Status || len(current.ResumeInputJSON) != 0 {
		t.Fatal("denied machine request changed run state", err)
	}
}

func TestMachineCannotResumeHumanReviewForAnyBusinessAgent(t *testing.T) {
	for _, agent := range []string{"document-assistant", "ticket-assistant"} {
		m := NewModule("internal")
		scope := testScope("review-" + agent).domain()
		scope.PrincipalType, scope.AgentID = "service_principal", agent
		if _, err := m.store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: agent, Fingerprint: agent}); err != nil {
			t.Fatal(err)
		}
		run, err := m.store.Get(scope.RunID)
		if err != nil {
			t.Fatal(err)
		}
		run, err = m.store.Transition(run.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, run.Revision)
		if err != nil {
			t.Fatal(err)
		}
		lease, err := m.store.AcquireLease(run.ID, "review-lease", time.Now().UTC(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = m.store.FinalizeLeased(run.ID, platformruntime.StatusWaiting, lease.Revision, lease.LeaseToken, map[string]any{"stage": "waiting_review"}, map[string]any{"source": "fixture"}); err != nil {
			t.Fatal(err)
		}
		m.SetMachineAccessPorts(machineAuthenticatorFunc(func(context.Context, string, string, string) (MachineAccess, error) {
			return MachineAccess{Scope: scope, AuthorizationEpoch: 1}, nil
		}), nil)
		r := httptest.NewRequest(http.MethodPost, "/agent-runs/"+scope.RunID+"/resume", strings.NewReader(`{"input":{"approved":true}}`))
		r.Header.Set("Authorization", "Bearer machine-token")
		w := httptest.NewRecorder()
		m.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "HUMAN_REVIEW_REQUIRED") {
			t.Fatal("machine substituted for human reviewer", agent, w.Code, w.Body.String())
		}
	}
}
