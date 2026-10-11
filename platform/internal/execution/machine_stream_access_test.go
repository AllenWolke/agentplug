package execution

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func TestMachineSSERechecksCredentialAndOwnerBeforeEveryEvent(t *testing.T) {
	for _, changedOwner := range []bool{false, true} {
		t.Run(map[bool]string{false: "credential or grant revoked", true: "scope changed"}[changedOwner], func(t *testing.T) {
			m := NewModule("secret")
			scope := testScope("machine-stream").domain()
			scope.PrincipalType = "service_principal"
			if _, err := m.store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: "stream-key", Fingerprint: "stream-body"}); err != nil {
				t.Fatal(err)
			}
			if _, err := m.store.AppendEvent(scope.RunID, "private_progress", map[string]any{"private": "must not escape"}); err != nil {
				t.Fatal(err)
			}
			checks := 0
			m.SetMachineAccessPorts(machineAuthenticatorFunc(func(_ context.Context, token, remote, action string) (MachineAccess, error) {
				checks++
				if token != "private-machine-bearer" || action != "events" {
					t.Fatal("wrong verified stream identity", action)
				}
				current := scope
				// Both credential and durable-object checks precede disclosure.
				if checks >= 9 {
					if !changedOwner {
						return MachineAccess{}, errors.New("credential revoked")
					}
					current.PrincipalID = "other-machine"
				}
				return MachineAccess{Scope: current, AuthorizationEpoch: 1}, nil
			}), nil)
			r := httptest.NewRequest(http.MethodGet, "/agent-runs/"+scope.RunID+"/events", nil)
			r.Header.Set("Authorization", "Bearer private-machine-bearer")
			w := httptest.NewRecorder()
			m.Handler().ServeHTTP(w, r)
			body := w.Body.String()
			if !strings.Contains(body, "event: accepted") || strings.Contains(body, "private_progress") || strings.Contains(body, "private-machine-bearer") || !strings.Contains(body, `"code":"MACHINE_ACCESS_DENIED"`) {
				t.Fatal("revocation did not fence machine events", checks, body)
			}
		})
	}
}
