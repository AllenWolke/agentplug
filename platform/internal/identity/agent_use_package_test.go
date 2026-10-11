package identity

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func agentUseFixtureResources() []AgentUseResource {
	resources := []AgentUseResource{}
	for _, action := range []string{"discover", "run", "cancel", "history.read", "history.continue"} {
		resources = append(resources, AgentUseResource{Type: "agent_installation", ID: "fixture-installation", Action: action})
	}
	for _, entry := range []AgentUseResource{{"model", "model-fixture", "model.generate"}, {"model", "model-fixture", "model.embed"}, {"tool", "tool-fixture", "tool.invoke"}, {"knowledge", "knowledge-fixture", "knowledge.search"}, {"memory", "memory-fixture", "memory.read"}, {"memory", "memory-fixture", "memory.write"}, {"skill", "skill-fixture", "skill.load"}} {
		resources = append(resources, entry)
	}
	return resources
}

type agentUseFixtureResolver struct {
	capabilityFixtureResolver
	version, policyDigest string
	calls                 int
	packageFailure        error
}

func (r *agentUseFixtureResolver) ResolveAgentUsePackage(_ context.Context, scope sharedkernel.Scope) (AgentUsePackage, error) {
	r.calls++
	if r.packageFailure != nil {
		return AgentUsePackage{}, r.packageFailure
	}
	version, digest := r.version, r.policyDigest
	if version == "" {
		version = "fixture-version"
	}
	if digest == "" {
		digest = strings.Repeat("a", 64)
	}
	return NewAgentUsePackage(ManagementScope{Type: "agent_installation", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ResourceID: scope.InstallationID}, "fixture-agent", version, digest, agentUseFixtureResources())
}

func TestAgentUsePackageCanonicalDigestAndRestrictedActions(t *testing.T) {
	scope := ManagementScope{Type: "agent_installation", TenantID: "t", DepartmentID: "d", ApplicationID: "a", ResourceID: "fixture-installation"}
	resources := agentUseFixtureResources()
	pack, err := NewAgentUsePackage(scope, "agent", "version", strings.Repeat("a", 64), resources)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(resources)
	reordered, err := NewAgentUsePackage(scope, "agent", "version", strings.Repeat("a", 64), resources)
	if err != nil || reordered.Digest != pack.Digest {
		t.Fatal("catalog enumeration order changed immutable package", err)
	}
	resources[0].ID = "changed-skill"
	if pack.Resources[0] == resources[0] {
		t.Fatal("package aliases provider-owned resources")
	}
	changed, err := NewAgentUsePackage(scope, "agent", "version", strings.Repeat("a", 64), resources)
	if err != nil || changed.Digest == pack.Digest {
		t.Fatal("changed dependency did not invalidate package review", err)
	}
	for _, extra := range []AgentUseResource{{"agent_installation", scope.ResourceID, "history.export"}, {"agent_installation", scope.ResourceID, "history.share"}, {"model", "*", "model.generate"}, {"tool", "tool-fixture", "model.generate"}, {"agent_installation", "other-installation", "run"}, pack.Resources[0]} {
		if _, err := NewAgentUsePackage(scope, "agent", "version", strings.Repeat("a", 64), append(append([]AgentUseResource(nil), pack.Resources...), extra)); err == nil {
			t.Fatal("package accepted unsupported, wildcard or duplicate resource", extra)
		}
	}
	if _, err := NewAgentUsePackage(scope, "agent", "version", strings.Repeat("A", 64), pack.Resources); err == nil {
		t.Fatal("noncanonical policy checksum accepted")
	}
	if _, err := NewAgentUsePackage(scope, "agent", "version", strings.Repeat("a", 64), pack.Resources[1:]); err == nil {
		t.Fatal("incomplete basic Agent actions accepted")
	}
}

func TestAgentUseScopedRoleKeepsExistingSensitiveGrantDormant(t *testing.T) {
	snapshot, query := permissionFixture()
	snapshot.Bindings[0].RoleVersion = 2
	snapshot.Bindings[0].Scope.Type, snapshot.Bindings[0].Scope.ResourceID = "agent_installation", query.ResourceID
	if decision, err := EvaluatePermission(snapshot, query); err != nil || !decision.Allowed {
		t.Fatal("installation role cannot use its exact Agent through an application API", decision, err)
	}
	other := snapshot.Grants[0]
	other.ID, other.AgentInstanceID, other.ResourceID = "other-grant", "other-agent", "other-agent"
	snapshot.Grants = append(snapshot.Grants, other)
	query.ResourceID = other.ResourceID
	if decision, err := EvaluatePermission(snapshot, query); err != nil || decision.Allowed {
		t.Fatal("installation role became an application-wide business role", decision, err)
	}
	query.ResourceID = "i"
	for _, action := range []string{"history.export", "history.share", "history.revise", "history.regenerate", "history.delete.request"} {
		grant := snapshot.Grants[0]
		grant.ID, grant.Action = "existing-sensitive-"+action, action
		candidate := snapshot
		candidate.Grants = append(append([]Grant(nil), snapshot.Grants...), grant)
		query.Action = action
		if decision, err := EvaluatePermission(candidate, query); err != nil || decision.Allowed {
			t.Fatal("ordinary package identity activated existing additional authority", action, decision, err)
		}
	}
}
