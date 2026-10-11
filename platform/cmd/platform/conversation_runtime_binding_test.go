package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type stubConversationCatalogTargets struct {
	target catalog.EvaluationAgentTarget
	err    error
	scope  sharedkernel.Scope
}

func (s *stubConversationCatalogTargets) ResolveEvaluationAgentTarget(_ context.Context, scope sharedkernel.Scope, agentID, versionID string) (catalog.EvaluationAgentTarget, error) {
	s.scope = scope
	if s.err != nil {
		return catalog.EvaluationAgentTarget{}, s.err
	}
	if s.target.AgentID != agentID || s.target.AgentVersionID != versionID {
		return catalog.EvaluationAgentTarget{}, errors.New("unexpected agent target")
	}
	return s.target, nil
}

type stubConversationRunAuthorizer struct {
	allowed       bool
	err           error
	scope         sharedkernel.Scope
	epochCalls    int
	denyWithEpoch bool
}

func (s *stubConversationRunAuthorizer) AuthorizeConversationRun(_ context.Context, scope sharedkernel.Scope) (bool, error) {
	s.scope = scope
	if s.denyWithEpoch && scope.AuthorizationEpoch != 0 {
		return false, nil
	}
	return s.allowed, s.err
}

func (s *stubConversationRunAuthorizer) CurrentAuthorizationEpoch(_ context.Context, _ sharedkernel.Scope, _ string) (uint64, error) {
	s.epochCalls++
	return 99, s.err
}

func TestCatalogConversationRuntimeBindingsResolveAndAuthorizeExactScopedTarget(t *testing.T) {
	targets := &stubConversationCatalogTargets{target: catalog.EvaluationAgentTarget{
		AgentID: "document-assistant", AgentVersionID: "qa-v2", InstallationID: "install-app-a",
		Endpoint: "http://qa-agent:8002", Transport: "http", Revision: 7, InputSchemaURI: "schema://document-assistant/input/v2",
	}}
	authorizer := &stubConversationRunAuthorizer{allowed: true}
	resolver := catalogConversationRuntimeBindings{targets: targets, authorize: authorizer}
	scope := conversation.Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", PrincipalType: "user", PrincipalID: "alice", TraceID: "0123456789abcdef0123456789abcdef"}
	binding, err := resolver.Resolve(context.Background(), scope, "document-assistant", "qa-v2")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if binding.AgentEndpoint != "http://qa-agent:8002" || binding.InstallationID != "install-app-a" || binding.AgentInstanceID != "install-app-a" || binding.AgentVersionID != "qa-v2" || binding.AuthorizationEpoch != 99 || binding.InputSchemaURI != "schema://document-assistant/input/v2" {
		t.Fatalf("unexpected resolved binding: %+v", binding)
	}
	if targets.scope.TenantID != "tenant-a" || targets.scope.DepartmentID != "dept-a" || targets.scope.ApplicationID != "app-a" || targets.scope.PrincipalID != "alice" {
		t.Fatalf("Catalog lookup lost trusted scope: %+v", targets.scope)
	}
	if authorizer.scope.AgentInstanceID != "install-app-a" || authorizer.scope.InstallationID != "install-app-a" || authorizer.scope.AgentVersionID != "qa-v2" || authorizer.scope.AuthorizationEpoch != 99 || authorizer.scope.PrincipalID != "alice" {
		t.Fatalf("Grant check was not bound to resolved installation: %+v", authorizer.scope)
	}
}

func TestCatalogConversationRuntimeBindingsFailClosed(t *testing.T) {
	scope := conversation.Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", PrincipalType: "user", PrincipalID: "alice"}
	target := catalog.EvaluationAgentTarget{AgentID: "qa", AgentVersionID: "v1", InstallationID: "install", Endpoint: "http://qa:8000", Transport: "http", Revision: 1, InputSchemaURI: "schema://qa/input/v1"}
	missingSchema := target
	missingSchema.InputSchemaURI = ""
	for _, tc := range []struct {
		name       string
		targets    *stubConversationCatalogTargets
		authorizer *stubConversationRunAuthorizer
		wantErr    bool
	}{
		{name: "missing catalog", authorizer: &stubConversationRunAuthorizer{allowed: true}, wantErr: true},
		{name: "catalog unavailable", targets: &stubConversationCatalogTargets{err: errors.New("db unavailable")}, authorizer: &stubConversationRunAuthorizer{allowed: true}, wantErr: true},
		{name: "grant denied", targets: &stubConversationCatalogTargets{target: target}, authorizer: &stubConversationRunAuthorizer{}, wantErr: true},
		{name: "grant store failure", targets: &stubConversationCatalogTargets{target: target}, authorizer: &stubConversationRunAuthorizer{err: errors.New("identity unavailable")}, wantErr: true},
		{name: "transport mismatch", targets: &stubConversationCatalogTargets{target: catalog.EvaluationAgentTarget{AgentID: "qa", AgentVersionID: "v1", InstallationID: "install", Endpoint: "grpc://qa:9000", Transport: "http", Revision: 1}}, authorizer: &stubConversationRunAuthorizer{allowed: true}, wantErr: true},
		{name: "unsupported transport", targets: &stubConversationCatalogTargets{target: catalog.EvaluationAgentTarget{AgentID: "qa", AgentVersionID: "v1", InstallationID: "install", Endpoint: "ftp://qa:9000", Transport: "ftp", Revision: 1}}, authorizer: &stubConversationRunAuthorizer{allowed: true}, wantErr: true},
		{name: "missing published input schema", targets: &stubConversationCatalogTargets{target: missingSchema}, authorizer: &stubConversationRunAuthorizer{allowed: true}, wantErr: true},
		{name: "http schema is not a schema URI", targets: &stubConversationCatalogTargets{target: catalog.EvaluationAgentTarget{AgentID: "qa", AgentVersionID: "v1", InstallationID: "install", Endpoint: "http://qa:8000", Transport: "http", Revision: 1, InputSchemaURI: "https://example.com/input"}}, authorizer: &stubConversationRunAuthorizer{allowed: true}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var targets conversationCatalogTargetResolver
			if tc.targets != nil {
				targets = tc.targets
			}
			resolver := catalogConversationRuntimeBindings{targets: targets, authorize: tc.authorizer}
			_, err := resolver.Resolve(context.Background(), scope, "qa", "v1")
			if (err != nil) != tc.wantErr {
				t.Fatalf("Resolve() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.name == "grant denied" && !errors.Is(err, conversation.ErrForbidden) {
				t.Fatal("a proven permission denial must retain its authorization classification", err)
			}
			if tc.name == "grant denied" && tc.authorizer.epochCalls != 0 {
				t.Fatal("a denied caller must not reach access-checked epoch lookup")
			}
			if tc.name == "grant store failure" && !errors.Is(err, conversation.ErrRuntimeBinding) {
				t.Fatal("an unavailable authority must not masquerade as a completed permission decision", err)
			}
		})
	}
}

func TestCatalogConversationRuntimeBindingsRejectRevocationDuringEpochLookup(t *testing.T) {
	scope := conversation.Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", PrincipalType: "user", PrincipalID: "alice"}
	targets := &stubConversationCatalogTargets{target: catalog.EvaluationAgentTarget{AgentID: "qa", AgentVersionID: "v1", InstallationID: "install", Endpoint: "http://qa:8000", Transport: "http", Revision: 1, InputSchemaURI: "schema://qa/input/v1"}}
	authorizer := &stubConversationRunAuthorizer{allowed: true, denyWithEpoch: true}
	binding, err := (catalogConversationRuntimeBindings{targets: targets, authorize: authorizer}).Resolve(context.Background(), scope, "qa", "v1")
	if !errors.Is(err, conversation.ErrForbidden) || binding.AuthorizationEpoch != 0 || authorizer.epochCalls != 1 {
		t.Fatalf("revocation during epoch lookup must prevent session binding: binding=%+v err=%v", binding, err)
	}
}

func TestCatalogConversationRuntimeBindingsAcceptCatalogApprovedGRPCTarget(t *testing.T) {
	scope := conversation.Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", PrincipalType: "user", PrincipalID: "alice"}
	targets := &stubConversationCatalogTargets{target: catalog.EvaluationAgentTarget{
		AgentID: "qa", AgentVersionID: "v1", InstallationID: "install", Endpoint: "grpcs://qa.internal:9443", Transport: "grpc", Revision: 3, InputSchemaURI: "schema://qa/input/v2",
	}}
	authorizer := &stubConversationRunAuthorizer{allowed: true}
	binding, err := (catalogConversationRuntimeBindings{targets: targets, authorize: authorizer}).Resolve(context.Background(), scope, "qa", "v1")
	if err != nil {
		t.Fatalf("Resolve() rejected gRPC target: %v", err)
	}
	if binding.AgentEndpoint != targets.target.Endpoint || binding.InstallationID != "install" || binding.AgentVersionID != "v1" || binding.AuthorizationEpoch != 99 || binding.InputSchemaURI != "schema://qa/input/v2" {
		t.Fatalf("unexpected gRPC binding: %+v", binding)
	}
	if authorizer.scope.InstallationID != "install" || authorizer.scope.AuthorizationEpoch != 99 {
		t.Fatalf("authorization was not bound to the resolved gRPC installation: %+v", authorizer.scope)
	}
}
