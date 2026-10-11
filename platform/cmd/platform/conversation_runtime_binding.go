package main

import (
	"context"
	"errors"
	"net/url"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type conversationCatalogTargetResolver interface {
	ResolveEvaluationAgentTarget(context.Context, sharedkernel.Scope, string, string) (catalog.EvaluationAgentTarget, error)
}

type conversationAgentRunAuthorizer interface {
	AuthorizeConversationRun(context.Context, sharedkernel.Scope) (bool, error)
	CurrentAuthorizationEpoch(context.Context, sharedkernel.Scope, string) (uint64, error)
}

// catalogConversationRuntimeBindings resolves browser runs from the same
// scoped Catalog deployment plane used by machine and evaluation execution.
// 会话运行与机器调用、评测统一从按租户/部门/应用隔离的 Catalog 部署面解析目标。
type catalogConversationRuntimeBindings struct {
	targets   conversationCatalogTargetResolver
	authorize conversationAgentRunAuthorizer
}

func (r catalogConversationRuntimeBindings) Resolve(ctx context.Context, scope conversation.Scope, agentID, versionID string) (conversation.RuntimeBinding, error) {
	if r.targets == nil || r.authorize == nil || scope.Validate() != nil || agentID == "" || versionID == "" {
		return conversation.RuntimeBinding{}, conversation.ErrRuntimeBinding
	}
	lookupScope := sharedkernel.Scope{
		TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
		PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID,
	}
	target, err := r.targets.ResolveEvaluationAgentTarget(ctx, lookupScope, agentID, versionID)
	if err != nil || target.AgentID != agentID || target.AgentVersionID != versionID || target.InstallationID == "" || target.Revision == 0 || target.Endpoint == "" {
		return conversation.RuntimeBinding{}, conversation.ErrRuntimeBinding
	}
	inputSchema, schemaErr := url.Parse(target.InputSchemaURI)
	if schemaErr != nil || inputSchema == nil || inputSchema.Scheme != "schema" || inputSchema.Host == "" || inputSchema.Path == "" || inputSchema.User != nil || inputSchema.RawQuery != "" || inputSchema.Fragment != "" || inputSchema.Opaque != "" {
		return conversation.RuntimeBinding{}, conversation.ErrRuntimeBinding
	}
	// Conversation targets must have a transport that the Platform AgentGateway
	// can route, and the registered endpoint scheme must match its Catalog value.
	// 会话目标必须使用 Platform AgentGateway 支持的传输，且 endpoint scheme
	// 必须与 Catalog 中的 transport 完全一致。
	endpoint, parseErr := url.Parse(target.Endpoint)
	transportMatchesScheme := false
	if endpoint != nil {
		switch target.Transport {
		case "http":
			transportMatchesScheme = endpoint.Scheme == "http" || endpoint.Scheme == "https"
		case "grpc":
			transportMatchesScheme = endpoint.Scheme == "grpc" || endpoint.Scheme == "grpcs"
		}
	}
	if parseErr != nil || endpoint == nil || endpoint.Host == "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || !transportMatchesScheme {
		return conversation.RuntimeBinding{}, conversation.ErrRuntimeBinding
	}
	runScope := sharedkernel.Scope{
		TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
		AgentInstanceID: target.InstallationID, AgentID: target.AgentID,
		PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID,
		InstallationID: target.InstallationID, AgentVersionID: target.AgentVersionID,
	}
	// Epoch lookup also checks access. Resolve an explicit denial first so it
	// remains a permission response rather than an unavailable binding. Check
	// again with the epoch below to close a revocation race during lookup.
	allowed, err := r.authorize.AuthorizeConversationRun(ctx, runScope)
	if err != nil {
		return conversation.RuntimeBinding{}, conversation.ErrRuntimeBinding
	}
	if !allowed {
		return conversation.RuntimeBinding{}, conversation.ErrForbidden
	}
	epoch, err := r.authorize.CurrentAuthorizationEpoch(ctx, runScope, "run")
	if err != nil || epoch == 0 {
		return conversation.RuntimeBinding{}, conversation.ErrRuntimeBinding
	}
	runScope.AuthorizationEpoch = epoch
	allowed, err = r.authorize.AuthorizeConversationRun(ctx, runScope)
	if err != nil {
		return conversation.RuntimeBinding{}, conversation.ErrRuntimeBinding
	}
	if !allowed {
		return conversation.RuntimeBinding{}, conversation.ErrForbidden
	}
	return conversation.RuntimeBinding{
		AgentEndpoint: target.Endpoint, AgentInstanceID: target.InstallationID,
		InstallationID: target.InstallationID, AgentVersionID: target.AgentVersionID,
		InputSchemaURI:     target.InputSchemaURI,
		AuthorizationEpoch: epoch,
	}, nil
}

type identityConversationAgentRunAuthorizer struct{ store identity.Store }

func (a identityConversationAgentRunAuthorizer) CurrentAuthorizationEpoch(ctx context.Context, scope sharedkernel.Scope, action string) (uint64, error) {
	authority, ok := a.store.(identity.AuthorizationVersionPort)
	if !ok {
		return 0, errors.New("IAM authorization version unavailable")
	}
	return authority.CurrentAuthorizationEpoch(ctx, scope, action)
}

func (a identityConversationAgentRunAuthorizer) AuthorizeConversationRun(ctx context.Context, scope sharedkernel.Scope) (bool, error) {
	if a.store == nil {
		return false, errors.New("identity store is unavailable")
	}
	decision, err := identity.CheckPrincipalAccess(ctx, a.store, scope, identity.PrincipalType(scope.PrincipalType), scope.PrincipalID, "run")
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}
