package main

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type skillAuthority struct {
	identity  *identity.SQLStore
	runs      *execution.SQLStore
	resources capabilityExecutionAuthority
}

type skillBrowserKey struct{}
type skillBrowserSession struct {
	Scope        sharedkernel.Scope
	SessionScope sharedkernel.Scope
	Session      string
	Revision     uint64
}

func (a skillAuthority) ResolveBrowser(r *http.Request, target *capability.SkillManagementNamespace) (sharedkernel.Scope, error) {
	if a.identity == nil {
		return sharedkernel.Scope{}, capability.ErrSkillDenied
	}
	revision, err := strconv.ParseUint(r.Header.Get("X-Authentication-Revision"), 10, 64)
	actor := sharedkernel.Scope{PrincipalType: r.Header.Get("X-Principal-Type"), PrincipalID: r.Header.Get("X-Principal-ID"), TenantID: r.Header.Get("X-Tenant-ID"), DepartmentID: r.Header.Get("X-Department-ID"), ApplicationID: r.Header.Get("X-Application-ID"), TraceID: r.Header.Get("X-Trace-ID")}
	session := r.Header.Get("X-Authentication-Session")
	if err != nil || revision == 0 || session == "" || actor.Validate() != nil || actor.PrincipalType != "user" || a.identity.ValidateBrowserSession(r.Context(), actor, session, revision) != nil {
		return sharedkernel.Scope{}, capability.ErrSkillDenied
	}
	sessionScope := actor
	if target != nil {
		if target.TenantID != sessionScope.TenantID || a.identity.ValidateApplicationScope(r.Context(), target.TenantID, target.DepartmentID, target.ApplicationID) != nil {
			return sharedkernel.Scope{}, capability.ErrSkillDenied
		}
		actor.TenantID, actor.DepartmentID, actor.ApplicationID = target.TenantID, target.DepartmentID, target.ApplicationID
	}
	*r = *r.WithContext(context.WithValue(r.Context(), skillBrowserKey{}, skillBrowserSession{Scope: actor, SessionScope: sessionScope, Session: session, Revision: revision}))
	return actor, nil
}

// skillLockOrDenied keeps an ancestor lock wait retryable. A finished skill
// denial stays the stable sentinel; a 2s row-lock wait is not that denial.
func skillLockOrDenied(err error) error {
	if err == nil || ancestryLockWait(err) {
		return err
	}
	return capability.ErrSkillDenied
}

// AcquireTransactionFence fixes lock order for every SQL Skill operation:
// IAM continuity and, for runtime disclosures, the Run/session lease precede
// the registry namespace advisory lock. Human control-plane transactions keep
// their browser-session continuity check and do not require a Run lease.
func (a skillAuthority) AcquireTransactionFence(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
	if a.identity == nil || a.runs == nil || tx == nil {
		return capability.ErrSkillDenied
	}
	if b, ok := ctx.Value(skillBrowserKey{}).(skillBrowserSession); ok {
		if err := a.identity.AcquirePermissionReadContinuity(ctx, tx); err != nil {
			return skillLockOrDenied(err)
		}
		if b.Scope != scope || scope.PrincipalType != "user" || a.identity.ValidateBrowserSession(ctx, b.SessionScope, b.Session, b.Revision) != nil || a.identity.ValidateApplicationScope(ctx, scope.TenantID, scope.DepartmentID, scope.ApplicationID) != nil {
			return capability.ErrSkillDenied
		}
		return nil
	}
	lease, _, err := capability.SkillRuntimeAuthority(ctx, scope)
	if err != nil {
		return skillLockOrDenied(err)
	}
	if err := a.identity.AcquirePermissionReadContinuity(ctx, tx); err != nil {
		return skillLockOrDenied(err)
	}
	// Runtime Skill validation reads execution facts and writes registry/audit
	// rows only. Never upgrade a model/checkpoint owner's shared execution
	// fence; the Skill namespace lock serializes its own registry transitions.
	if err := a.runs.CheckCapabilityReadLeaseTx(ctx, tx, scope, lease); err != nil {
		return skillLockOrDenied(err)
	}
	return nil
}

func (a skillAuthority) Authorize(ctx context.Context, tx *sql.Tx, action string, scope sharedkernel.Scope, skill, target string) error {
	if a.identity == nil || a.runs == nil || tx == nil {
		return capability.ErrSkillDenied
	}
	if err := a.identity.AcquirePermissionReadContinuity(ctx, tx); err != nil {
		return skillLockOrDenied(err)
	}
	if b, ok := ctx.Value(skillBrowserKey{}).(skillBrowserSession); ok {
		if b.Scope != scope || scope.PrincipalType != "user" || a.identity.ValidateBrowserSession(ctx, b.SessionScope, b.Session, b.Revision) != nil || a.identity.ValidateApplicationScope(ctx, scope.TenantID, scope.DepartmentID, scope.ApplicationID) != nil {
			return capability.ErrSkillDenied
		}
		permission := ""
		switch action {
		case "skill.inspect":
			for _, permission := range []string{"policy.manage", "release.approve"} {
				versioned, err := authorizeVersionedControl(ctx, a.identity, scope.PrincipalID, permission, scope.TenantID, scope.DepartmentID, scope.ApplicationID)
				if err == nil && versioned {
					return nil
				}
			}
			return capability.ErrSkillDenied
		case "skill.register", "skill.revoked":
			permission = "policy.manage"
		case "skill.approved", "skill.rejected", "skill.publish":
			permission = "release.approve"
		default:
			return capability.ErrSkillDenied
		}
		versioned, err := authorizeVersionedControl(ctx, a.identity, scope.PrincipalID, permission, scope.TenantID, scope.DepartmentID, scope.ApplicationID)
		if err != nil || !versioned {
			return capability.ErrSkillDenied
		}
		return nil
	}
	lease, policy, err := capability.SkillRuntimeAuthority(ctx, scope)
	if err != nil {
		return skillLockOrDenied(err)
	}
	if err := a.runs.CheckCapabilityReadLeaseTx(ctx, tx, scope, lease); err != nil {
		return skillLockOrDenied(err)
	}
	snapshot, err := a.identity.PermissionSnapshot(ctx, identity.PrincipalType(scope.PrincipalType), scope.PrincipalID)
	if err != nil {
		return skillLockOrDenied(err)
	}
	if snapshot.Mode != "v2" {
		return capability.ErrSkillDenied
	}
	allowed := false
	for _, id := range policy.Runtime.AllowedSkills {
		if id == skill {
			allowed = true
		}
	}
	if !allowed {
		return capability.ErrSkillDenied
	}
	access := capability.CapabilityResourceAccess{Action: "skill.load", ResourceType: "skill", ResourceID: skill}
	switch action {
	case "skill.discover", "skill.load":
	case "skill.require_tool":
		if !policy.AllowsTool(target) {
			return capability.ErrSkillDenied
		}
		access = capability.CapabilityResourceAccess{Action: "tool.invoke", ResourceType: "tool", ResourceID: target}
	case "skill.require_knowledge":
		known := false
		for _, id := range policy.Knowledge.AllowedScopes {
			if id == target {
				known = true
			}
		}
		if !known {
			return capability.ErrSkillDenied
		}
		access = capability.CapabilityResourceAccess{Action: "knowledge.search", ResourceType: "knowledge", ResourceID: target}
	default:
		// Human lifecycle authority is separately wired; runtime context never
		// authorizes registration, approval, release or revocation.
		return capability.ErrSkillDenied
	}
	if err := a.resources.AuthorizeCapabilityResource(ctx, scope, access); err != nil {
		return skillLockOrDenied(err)
	}
	return nil
}
