package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type toolApprovalBrowserBinding struct {
	Actor    sharedkernel.Scope
	Session  string
	Revision uint64
}
type toolApprovalBrowserKey struct{}

type toolApprovalRunReader interface {
	ResolveToolApprovalRun(context.Context, sharedkernel.Scope, string) (execution.ToolApprovalRun, error)
}

type toolApprovalAdapter struct {
	identity        *identity.SQLStore
	runs            toolApprovalRunReader
	policy          policyasset.Resolver
	resources       capabilityExecutionAuthority
	tools           *capability.Module
	checkpoints     capability.CheckpointStore
	runSQL          *execution.SQLStore
	waitingAncestry func(context.Context, *sql.Tx, sharedkernel.Scope) error
	execution       *execution.Module
}

func (a toolApprovalAdapter) checkSession(ctx context.Context, b toolApprovalBrowserBinding) error {
	if a.identity == nil || b.Session == "" || b.Revision == 0 {
		return identity.ErrRefreshSessionRejected
	}
	return a.identity.ValidateBrowserSession(ctx, b.Actor, b.Session, b.Revision)
}

func (a toolApprovalAdapter) resolve(ctx context.Context, b toolApprovalBrowserBinding, operation capability.ToolApprovalOperation, active bool) (sharedkernel.Scope, string, error) {
	if err := a.checkSession(ctx, b); err != nil {
		return sharedkernel.Scope{}, "", err
	}
	return a.resolveExecution(ctx, b.Actor, operation, active)
}

func (a toolApprovalAdapter) resolveExecution(ctx context.Context, actor sharedkernel.Scope, operation capability.ToolApprovalOperation, active bool) (sharedkernel.Scope, string, error) {
	if a.runs == nil || a.policy == nil {
		return sharedkernel.Scope{}, "", capability.ErrToolApprovalDenied
	}
	run, err := a.runs.ResolveToolApprovalRun(ctx, actor, operation.RunID)
	if err != nil {
		return sharedkernel.Scope{}, "", errors.Join(capability.ErrToolApprovalDenied, err)
	}
	if err != nil || (active && !run.Active) {
		return sharedkernel.Scope{}, "", capability.ErrToolApprovalDenied
	}
	snapshot, err := a.identity.PermissionSnapshot(ctx, identity.PrincipalUser, run.Scope.PrincipalID)
	if err != nil {
		return sharedkernel.Scope{}, "", errors.Join(capability.ErrToolApprovalDenied, err)
	}
	if err != nil || snapshot.Mode != "v2" || a.tools == nil || !a.tools.HasRegisteredTool(operation.Name) {
		return sharedkernel.Scope{}, "", capability.ErrToolApprovalDenied
	}
	owner := any(a.runs)
	if a.runSQL != nil {
		owner = a.runSQL
	}
	expected, proofErr := expectedExecutionEpoch(ctx, owner, run.Scope)
	epoch, err := a.identity.CurrentAuthorizationEpoch(ctx, run.Scope, "run")
	if proofErr != nil || err != nil {
		return sharedkernel.Scope{}, "", errors.Join(capability.ErrToolApprovalDenied, proofErr, err)
	}
	if proofErr != nil || err != nil || epoch != expected {
		return sharedkernel.Scope{}, "", capability.ErrToolApprovalDenied
	}
	requested := policyasset.SnapshotFromContext(run.PolicyIDs)
	policy, err := a.policy.Resolve(ctx, run.Scope, run.Scope.AgentVersionID)
	if err != nil {
		return sharedkernel.Scope{}, "", errors.Join(capability.ErrToolApprovalDenied, err)
	}
	if err != nil || requested.ValidateIDs() != nil || !policy.SameIDs(requested) || !policy.SameRuleBinding(requested) || policy.Hash != run.PolicyHash || !policy.AllowsTool(operation.Name) {
		return sharedkernel.Scope{}, "", capability.ErrToolApprovalDenied
	}
	if err = a.resources.AuthorizeCapabilityResource(ctx, run.Scope, capability.CapabilityResourceAccess{Action: "tool.invoke", ResourceType: "tool", ResourceID: operation.Name}); err != nil {
		return sharedkernel.Scope{}, "", err
	}
	if operation.Payload != nil {
		body, err := json.Marshal(operation.Payload)
		if err != nil {
			return sharedkernel.Scope{}, "", err
		}
		for _, function := range policy.Tool.Functions {
			if function.ToolName == operation.Name {
				if _, err = policy.Tool.ValidateFunctionArguments(function.Name, body); err != nil {
					return sharedkernel.Scope{}, "", err
				}
				break
			}
		}
	}
	return run.Scope, policy.Hash, nil
}

func (a toolApprovalAdapter) Resolve(r *http.Request, operation capability.ToolApprovalOperation) (sharedkernel.Scope, string, error) {
	revision, err := strconv.ParseUint(r.Header.Get("X-Authentication-Revision"), 10, 64)
	if err != nil {
		return sharedkernel.Scope{}, "", err
	}
	b := toolApprovalBrowserBinding{Actor: sharedkernel.Scope{PrincipalType: r.Header.Get("X-Principal-Type"), PrincipalID: r.Header.Get("X-Principal-ID"), TenantID: r.Header.Get("X-Tenant-ID"), DepartmentID: r.Header.Get("X-Department-ID"), ApplicationID: r.Header.Get("X-Application-ID")}, Session: r.Header.Get("X-Authentication-Session"), Revision: revision}
	scope, hash, err := a.resolve(r.Context(), b, operation, strings.HasSuffix(r.URL.Path, "/preview") || strings.HasSuffix(r.URL.Path, "/approve"))
	if err == nil {
		*r = *r.WithContext(context.WithValue(r.Context(), toolApprovalBrowserKey{}, b))
	}
	return scope, hash, err
}

func (a toolApprovalAdapter) StepUp(ctx context.Context, r *http.Request, scope sharedkernel.Scope, operation capability.ToolApprovalOperation, action, digest, password string) (string, time.Time, error) {
	b, ok := ctx.Value(toolApprovalBrowserKey{}).(toolApprovalBrowserBinding)
	if !ok {
		return "", time.Time{}, capability.ErrToolApprovalDenied
	}
	proof, err := a.identity.CreateToolStepUp(ctx, scope, identity.StepUpRequest{CurrentPassword: password, Action: action, RequestDigest: digest}, func(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, action, digest string) error {
		fingerprint, err := capability.ToolCommandFingerprint(operation.Name, operation.Payload)
		if err != nil {
			return errors.Join(capability.ErrToolApprovalDenied, err)
		}
		if err := a.fencePending(ctx, tx, scope, operation.Name, operation.CallID, fingerprint, action); err != nil {
			return errors.Join(capability.ErrToolApprovalDenied, err)
		}
		actual, _, err := a.resolve(ctx, b, operation, action == "tool.approval.approve")
		if err != nil {
			return errors.Join(capability.ErrToolApprovalDenied, err)
		}
		if err != nil || actual != scope {
			return capability.ErrToolApprovalDenied
		}
		return nil
	})
	return proof.Token, proof.ExpiresAt, err
}

func (a toolApprovalAdapter) Authorize(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, claims capability.ToolConfirmationClaims, action, proof string) error {
	if claims.PendingKey != "" || claims.CheckpointRevision != 0 {
		pending, ok := ctx.Value(pendingToolApprovalKey{}).(pendingToolApprovalBinding)
		if !ok || pending.Key != claims.PendingKey || pending.Checkpoint.Revision != claims.CheckpointRevision {
			return capability.ErrToolApprovalDenied
		}
	}
	b, ok := ctx.Value(toolApprovalBrowserKey{}).(toolApprovalBrowserBinding)
	if !ok || b.Actor.PrincipalID != scope.PrincipalID || b.Actor.TenantID != scope.TenantID {
		return capability.ErrToolApprovalDenied
	}
	if err := a.identity.ConsumeToolStepUpTx(ctx, tx, scope, b.Session, b.Revision, proof, action, capability.ToolApprovalDigest(claims)); err != nil {
		return err
	}
	if err := a.fencePending(ctx, tx, scope, claims.ToolName, claims.CallID, claims.Fingerprint, action); err != nil {
		return err
	}
	actual, hash, err := a.resolve(ctx, b, capability.ToolApprovalOperation{RunID: scope.RunID, Name: claims.ToolName, CallID: claims.CallID}, action == "tool.approval.approve")
	if err != nil {
		return errors.Join(capability.ErrToolApprovalDenied, err)
	}
	if err != nil || actual != scope || hash != claims.PolicyHash || claims.ScopeHash != capability.ToolReceiptScopeHash(scope) {
		return errors.New("current tool approval authorization denied")
	}
	return nil
}
