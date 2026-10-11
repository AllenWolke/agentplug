package authorization

import (
	"errors"
	"strings"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Rule is a persistence-neutral authorization rule. Repository adapters map
// database rows into this type; the evaluator never performs database I/O.
// Rule 是与持久化无关的授权规则，Repository Adapter 负责映射数据库记录。
type Rule struct {
	TenantID        string
	DepartmentID    string
	ApplicationID   string
	AgentInstanceID string
	SubjectType     identity.PrincipalType
	SubjectID       string
	Action          string
	Effect          Effect
	Enabled         bool
}

type Decision struct {
	Allowed bool
	Reason  string
}

var ErrInvalidRule = errors.New("invalid authorization rule")

// Evaluator implements deterministic deny-overrides semantics.
// Evaluator 实现确定性的 Deny 优先语义。
type Evaluator struct{}

func (Evaluator) Evaluate(ctx identity.AccessContext, rules []Rule) (Decision, error) {
	if err := ctx.Validate(); err != nil {
		return Decision{}, err
	}
	var matched bool
	for _, rule := range rules {
		if err := validateRule(rule); err != nil {
			return Decision{}, err
		}
		if !matches(ctx, rule) {
			continue
		}
		matched = true
		if rule.Effect == EffectDeny {
			return Decision{Allowed: false, Reason: "explicit_deny"}, nil
		}
	}
	if matched {
		return Decision{Allowed: true, Reason: "explicit_allow"}, nil
	}
	return Decision{Allowed: false, Reason: "no_matching_grant"}, nil
}

func validateRule(rule Rule) error {
	if strings.TrimSpace(rule.TenantID) == "" || strings.TrimSpace(rule.DepartmentID) == "" || strings.TrimSpace(rule.ApplicationID) == "" || strings.TrimSpace(rule.AgentInstanceID) == "" || strings.TrimSpace(rule.SubjectID) == "" || strings.TrimSpace(rule.Action) == "" {
		return ErrInvalidRule
	}
	if rule.SubjectType != identity.PrincipalUser && rule.SubjectType != identity.PrincipalServicePrincipal {
		return ErrInvalidRule
	}
	if rule.Effect != EffectAllow && rule.Effect != EffectDeny {
		return ErrInvalidRule
	}
	return nil
}

func matches(ctx identity.AccessContext, rule Rule) bool {
	scope := ctx.Scope
	if !rule.Enabled || !keepScopeMatch(scope, rule) || rule.Action != ctx.Action {
		return false
	}
	if rule.SubjectType != ctx.Principal.Type || rule.SubjectID != ctx.Principal.ID {
		return false
	}
	return true
}

// keepScopeMatch is split out to make the full tenant/application boundary
// visible to reviewers and static checks.
func keepScopeMatch(scope sharedkernel.Scope, rule Rule) bool {
	return rule.TenantID == scope.TenantID && rule.DepartmentID == scope.DepartmentID && rule.ApplicationID == scope.ApplicationID && rule.AgentInstanceID == scope.AgentInstanceID
}
