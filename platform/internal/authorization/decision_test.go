package authorization

import (
	"testing"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func accessContext() identity.AccessContext {
	return identity.AccessContext{
		Scope:     sharedkernel.Scope{TenantID: "tenant-a", DepartmentID: "compliance", ApplicationID: "business-app", AgentInstanceID: "validation-installation", PrincipalID: "alice"},
		Principal: identity.Principal{Type: identity.PrincipalUser, ID: "alice", TenantID: "tenant-a", IsActive: true},
		Action:    "run",
	}
}

func TestEvaluatorDenyOverridesAllow(t *testing.T) {
	ctx := accessContext()
	rules := []Rule{
		{TenantID: "tenant-a", DepartmentID: "compliance", ApplicationID: "business-app", AgentInstanceID: "validation-installation", SubjectType: identity.PrincipalUser, SubjectID: "alice", Action: "run", Effect: EffectAllow, Enabled: true},
		{TenantID: "tenant-a", DepartmentID: "compliance", ApplicationID: "business-app", AgentInstanceID: "validation-installation", SubjectType: identity.PrincipalUser, SubjectID: "alice", Action: "run", Effect: EffectDeny, Enabled: true},
	}
	decision, err := (Evaluator{}).Evaluate(ctx, rules)
	if err != nil || decision.Allowed || decision.Reason != "explicit_deny" {
		t.Fatalf("deny did not override allow: %+v, %v", decision, err)
	}
}

func TestEvaluatorRejectsCrossApplicationAndMachineMixup(t *testing.T) {
	ctx := accessContext()
	rule := Rule{TenantID: "tenant-a", DepartmentID: "compliance", ApplicationID: "aml", AgentInstanceID: "validation-installation", SubjectType: identity.PrincipalUser, SubjectID: "alice", Action: "run", Effect: EffectAllow, Enabled: true}
	decision, err := (Evaluator{}).Evaluate(ctx, []Rule{rule})
	if err != nil || decision.Allowed {
		t.Fatalf("cross-application rule unexpectedly allowed: %+v, %v", decision, err)
	}
	rule.ApplicationID = "business-app"
	rule.SubjectType = identity.PrincipalServicePrincipal
	decision, err = (Evaluator{}).Evaluate(ctx, []Rule{rule})
	if err != nil || decision.Allowed {
		t.Fatalf("machine rule unexpectedly matched user: %+v, %v", decision, err)
	}
}
