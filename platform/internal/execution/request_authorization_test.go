package execution

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func TestRunAuthorizationPreservesImmutableScopeAndRejectsIdentityChanges(t *testing.T) {
	for _, variant := range []string{"original", "epoch projection", "foreign user", "other version", "other endpoint identity", "zero", "future", "delegated"} {
		t.Run(variant, func(t *testing.T) {
			scope := testScope("authorization-projection")
			var request contract.ExecuteRequest
			if err := json.Unmarshal(gatewayRequest(t, scope, "run"), &request); err != nil {
				t.Fatal(err)
			}
			input, _ := json.Marshal(request.Input)
			run := platformruntime.Run{ID: scope.RunID, Scope: scope.domain()}
			switch variant {
			case "epoch projection":
				run.Scope.AuthorizationEpoch = 2
			case "foreign user":
				request.Scope.PrincipalID = "foreign"
			case "other version":
				request.Scope.AgentVersionID = "v2"
			case "other endpoint identity":
				request.Scope.InstallationID = "foreign"
			case "zero":
				request.Scope.AuthorizationEpoch = 0
			case "future":
				request.Scope.AuthorizationEpoch = 3
			case "delegated":
				run.Scope.ParentRunID = "parent"
			}
			err := bindRunAuthorization(run, &request)
			if variant != "original" {
				if err == nil {
					t.Fatal("scope drift accepted")
				}
				return
			}
			actual, _ := json.Marshal(request.Input)
			if err != nil || request.Scope.AuthorizationEpoch != scope.AuthorizationEpoch || !bytes.Equal(actual, input) {
				t.Fatal("authorization projection changed immutable input", err)
			}
		})
	}
}
