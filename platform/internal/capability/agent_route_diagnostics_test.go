package capability

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestAgentCoordinationAuthoritySeparatesBoundContextLiveCheckAndPolicy(t *testing.T) {
	scope := sharedkernel.Scope{RunID: "route-run", TraceID: "trace-route"}
	delegation := &policyasset.AgentDelegationPolicy{AllowedAgentIDs: []string{"python-agent"}, TaskTypes: []string{"documents.answer"}, MaxDepth: 1, MaxChildren: 1}
	validPolicy := policyasset.Snapshot{Runtime: policyasset.RuntimePolicy{Delegation: delegation}}
	assertReason := func(name string, ctx context.Context, gotScope sharedkernel.Scope, want agentcoordination.RouteDenialReason) {
		t.Helper()
		_, _, err := AgentCoordinationAuthority(ctx, gotScope)
		stage, reason, ok := agentcoordination.RouteErrorClassification(err)
		if !ok || stage != agentcoordination.RouteDenialParent || reason != want {
			t.Fatalf("%s classified as stage=%q reason=%q ok=%v err=%v", name, stage, reason, ok, err)
		}
		if !errors.Is(err, agentcoordination.ErrDenied) {
			t.Fatalf("%s stopped matching ErrDenied", name)
		}
	}

	assertReason("missing bound context", context.Background(), scope, agentcoordination.RouteReasonParentBoundContext)

	makeContext := func(bound skillRuntimeContext) context.Context {
		return context.WithValue(context.Background(), agentRouteContextKey{}, bound)
	}
	valid := skillRuntimeContext{Scope: scope, Policy: validPolicy, Lease: sharedkernel.ExecutionLeaseBinding{Revision: 1, TokenHash: strings.Repeat("a", 64)}, Check: func(context.Context) error { return nil }}
	assertReason("scope mismatch", makeContext(valid), sharedkernel.Scope{RunID: "other-run"}, agentcoordination.RouteReasonParentBoundContext)
	noCheck := valid
	noCheck.Check = nil
	assertReason("missing live check", makeContext(noCheck), scope, agentcoordination.RouteReasonParentBoundContext)
	failedCheck := valid
	failedCheck.Check = func(context.Context) error { return errors.New("private live authority detail") }
	assertReason("live check denied", makeContext(failedCheck), scope, agentcoordination.RouteReasonParentLiveCheck)
	badPolicy := valid
	badPolicy.Policy.Runtime.Delegation = nil
	assertReason("delegation policy absent", makeContext(badPolicy), scope, agentcoordination.RouteReasonParentPolicy)
}

func TestAgentCoordinationDenialLogContainsOnlySafeFields(t *testing.T) {
	var output bytes.Buffer
	oldOutput, oldFlags, oldPrefix := log.Writer(), log.Flags(), log.Prefix()
	log.SetOutput(&output)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() {
		log.SetOutput(oldOutput)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
	}()

	err := agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialTargetAuthorization, agentcoordination.RouteReasonParentMachineDelegate, errors.New("private principal, grant row, request body, and token"))
	logAgentCoordinationDenial("route-run", "trace-route", err)
	line := output.String()
	for _, safe := range []string{"agent_coordination_denied", `run_id="route-run"`, `trace_id="trace-route"`, "stage=target_authorization", "reason=parent_machine_target_delegate"} {
		if !strings.Contains(line, safe) {
			t.Fatalf("safe log field %q missing: %q", safe, line)
		}
	}
	for _, private := range []string{"private principal", "grant row", "request body", "token", "password", "endpoint", "manifest"} {
		if strings.Contains(line, private) {
			t.Fatalf("private detail %q escaped in route log: %q", private, line)
		}
	}

	output.Reset()
	logAgentCoordinationDenial("route-run", "trace-route", agentcoordination.ErrDenied)
	if !strings.Contains(output.String(), "stage=unclassified reason=denied") || strings.Contains(output.String(), "agent coordination denied") {
		t.Fatalf("unclassified denial log was unsafe: %q", output.String())
	}
}
