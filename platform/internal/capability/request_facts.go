/**Request-scoped capability admission facts, verified once per HTTP request.*/

package capability

import (
	"context"
	"slices"
	"sync"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type capabilityFactsCaptureKey struct{}

type capabilityFactsCapture struct {
	mu    sync.Mutex
	facts *capabilityAdmissionFacts
	epoch uint64
}

// capabilityAdmissionFacts retains only facts already verified during this
// request's entry authorize() check. They never survive the request. The
// mutable facts (run/lease state, approval row, policy hash, IAM epoch) are
// NOT retained here; each later recheck revalidates them fresh through
// recheckCapabilityFacts below.
type capabilityAdmissionFacts struct {
	scope      sharedkernel.Scope
	epoch      uint64
	snapshot   identity.PermissionSnapshot
	executor   identity.PermissionSnapshot
	binding    identity.WorkloadBinding
	credential identity.MachineCredential
}

// CapabilityAdmissionFacts is an opaque, request-scoped snapshot created only
// after the joined live-authority and resource checks succeed. It is useful
// only while the exact Run scope and IAM epoch remain current.
type CapabilityAdmissionFacts = capabilityAdmissionFacts

func cloneAdmissionValidity(value identity.Validity) identity.Validity {
	if value.StartsAt != nil {
		v := *value.StartsAt
		value.StartsAt = &v
	}
	if value.ExpiresAt != nil {
		v := *value.ExpiresAt
		value.ExpiresAt = &v
	}
	return value
}

func cloneAdmissionDataScope(value identity.DataScope) identity.DataScope {
	value.IDs = slices.Clone(value.IDs)
	return value
}

func cloneAdmissionSnapshot(value identity.PermissionSnapshot) identity.PermissionSnapshot {
	value.Principal.Roles = slices.Clone(value.Principal.Roles)
	value.Principal.Groups = slices.Clone(value.Principal.Groups)
	value.Memberships = slices.Clone(value.Memberships)
	for i := range value.Memberships {
		value.Memberships[i].Validity = cloneAdmissionValidity(value.Memberships[i].Validity)
	}
	value.Bindings = slices.Clone(value.Bindings)
	for i := range value.Bindings {
		value.Bindings[i].Validity = cloneAdmissionValidity(value.Bindings[i].Validity)
	}
	value.Roles = slices.Clone(value.Roles)
	for i := range value.Roles {
		value.Roles[i].ScopeTypes = slices.Clone(value.Roles[i].ScopeTypes)
		value.Roles[i].Actions = slices.Clone(value.Roles[i].Actions)
	}
	value.Grants = slices.Clone(value.Grants)
	for i := range value.Grants {
		value.Grants[i].Validity = cloneAdmissionValidity(value.Grants[i].Validity)
		value.Grants[i].DataScope = cloneAdmissionDataScope(value.Grants[i].DataScope)
	}
	value.Delegations = slices.Clone(value.Delegations)
	for i := range value.Delegations {
		item := &value.Delegations[i]
		item.Roles = slices.Clone(item.Roles)
		item.Actions = slices.Clone(item.Actions)
		item.Resources = slices.Clone(item.Resources)
		item.ResourceBindings = slices.Clone(item.ResourceBindings)
		item.DataScopeTypes = slices.Clone(item.DataScopeTypes)
		item.DataIDs = slices.Clone(item.DataIDs)
		item.ManagementActions = slices.Clone(item.ManagementActions)
		item.Validity = cloneAdmissionValidity(item.Validity)
	}
	value.Assignments = slices.Clone(value.Assignments)
	for i := range value.Assignments {
		item := &value.Assignments[i]
		item.Validity = cloneAdmissionValidity(item.Validity)
		if item.TaskObject != nil {
			object := *item.TaskObject
			object.AssignedTo = slices.Clone(object.AssignedTo)
			object.Participants = slices.Clone(object.Participants)
			item.TaskObject = &object
		}
	}
	value.AgentPackages = slices.Clone(value.AgentPackages)
	for i := range value.AgentPackages {
		item := &value.AgentPackages[i]
		item.Validity = cloneAdmissionValidity(item.Validity)
		item.Requirements.Requirements = slices.Clone(item.Requirements.Requirements)
		for j := range item.Requirements.Requirements {
			item.Requirements.Requirements[j].DataScope = cloneAdmissionDataScope(item.Requirements.Requirements[j].DataScope)
		}
	}
	return value
}

func cloneAdmissionBinding(value identity.WorkloadBinding) identity.WorkloadBinding {
	value.AllowedAgentVersionIDs = slices.Clone(value.AllowedAgentVersionIDs)
	return value
}

func cloneAdmissionCredential(value identity.MachineCredential) identity.MachineCredential {
	value.NetworkCIDRs = slices.Clone(value.NetworkCIDRs)
	return value
}

func NewCapabilityAdmissionFacts(scope sharedkernel.Scope, epoch uint64, snapshot, executor identity.PermissionSnapshot, binding identity.WorkloadBinding, credential identity.MachineCredential) *CapabilityAdmissionFacts {
	if scope.Validate() != nil || epoch == 0 || snapshot.Mode != "v2" ||
		snapshot.Principal.ID != scope.PrincipalID || snapshot.Principal.Type != identity.PrincipalType(scope.PrincipalType) ||
		snapshot.Principal.TenantID != scope.TenantID || executor.Mode != "v2" ||
		executor.Principal.Type != identity.PrincipalServicePrincipal || executor.Principal.ID == "" ||
		executor.Principal.ID != binding.PrincipalID || executor.Principal.TenantID != scope.TenantID ||
		binding.TenantID != scope.TenantID || binding.DepartmentID != scope.DepartmentID ||
		binding.ApplicationID != scope.ApplicationID || binding.InstallationID != scope.InstallationID ||
		binding.AgentID != scope.AgentID || binding.AgentVersionID != scope.AgentVersionID ||
		binding.Status != "active" || binding.Revision == 0 || credential.TenantID != scope.TenantID ||
		credential.PrincipalID != binding.PrincipalID || credential.Status != "active" || credential.Revision == 0 {
		return nil
	}
	return &capabilityAdmissionFacts{scope: scope, epoch: epoch, snapshot: cloneAdmissionSnapshot(snapshot),
		executor: cloneAdmissionSnapshot(executor), binding: cloneAdmissionBinding(binding), credential: cloneAdmissionCredential(credential)}
}

// CaptureCapabilityAdmissionFacts transfers only facts produced by the
// composition-root live-authority check into the current HTTP request's
// capture slot. It is a no-op outside requests that explicitly opened one.
func CaptureCapabilityAdmissionFacts(ctx context.Context, facts *CapabilityAdmissionFacts) bool {
	if ctx == nil || facts == nil {
		return false
	}
	capture, ok := ctx.Value(capabilityFactsCaptureKey{}).(*capabilityFactsCapture)
	if !ok || capture == nil {
		return false
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if capture.facts != nil {
		return false
	}
	capture.facts = facts
	return true
}

// CaptureCapabilityAdmissionEpoch records the IAM epoch checked inside the
// joined entry fence. The full facts are attached only after its resource
// checks and transaction commit both succeed.
func CaptureCapabilityAdmissionEpoch(ctx context.Context, epoch uint64) bool {
	if ctx == nil || epoch == 0 {
		return false
	}
	capture, ok := ctx.Value(capabilityFactsCaptureKey{}).(*capabilityFactsCapture)
	if !ok || capture == nil {
		return false
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if capture.epoch != 0 && capture.epoch != epoch {
		return false
	}
	capture.epoch = epoch
	return true
}

func CapabilityAdmissionEpoch(ctx context.Context) uint64 {
	if ctx == nil {
		return 0
	}
	capture, ok := ctx.Value(capabilityFactsCaptureKey{}).(*capabilityFactsCapture)
	if !ok || capture == nil {
		return 0
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.epoch
}

func (c *capabilityFactsCapture) forScope(scope sharedkernel.Scope) *capabilityAdmissionFacts {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.facts == nil || c.facts.scope != scope || c.facts.epoch != scope.AuthorizationEpoch {
		return nil
	}
	return c.facts
}

func (f *CapabilityAdmissionFacts) SnapshotValues() (sharedkernel.Scope, uint64, identity.PermissionSnapshot, identity.PermissionSnapshot, identity.WorkloadBinding, identity.MachineCredential, bool) {
	if f == nil || f.scope.Validate() != nil || f.epoch == 0 {
		return sharedkernel.Scope{}, 0, identity.PermissionSnapshot{}, identity.PermissionSnapshot{}, identity.WorkloadBinding{}, identity.MachineCredential{}, false
	}
	return f.scope, f.epoch, cloneAdmissionSnapshot(f.snapshot), cloneAdmissionSnapshot(f.executor),
		cloneAdmissionBinding(f.binding), cloneAdmissionCredential(f.credential), true
}
