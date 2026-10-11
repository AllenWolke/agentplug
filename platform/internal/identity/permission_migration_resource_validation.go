package identity

import (
	"context"
	"encoding/json"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// ValidateMigrationMappingResources validates an existing read-only preview
// through Identity's organization checks and owning-module resource ports.
// It is not an authorization to apply, appoint administrators or change users.
func (s *SQLStore) ValidateMigrationMappingResources(ctx context.Context, plan MigrationMappingPreview) (MigrationMappingPreview, error) {
	if s == nil || s.db == nil || !plan.PreviewOnly || plan.ResourceOwnershipVerified {
		return MigrationMappingPreview{}, ErrInvalidResource
	}
	checksum := plan.Digest
	plan.Digest = ""
	raw, err := json.Marshal(plan)
	if err != nil || checksum == "" || permissionHash(raw) != checksum {
		return MigrationMappingPreview{}, ErrPermissionPlanStale
	}
	batch, err := s.InspectMigrationSources(ctx, plan.Target.Principal.TenantID, []MigrationSubject{{Type: plan.Target.Principal.Type, ID: plan.Target.Principal.ID}})
	if err != nil {
		return MigrationMappingPreview{}, err
	}
	if batch.Sources[0].SourceDigest != plan.SourceDigest {
		return MigrationMappingPreview{}, ErrPermissionPlanStale
	}
	// A checksum is not a signature. Rebuild the diagnostic plan from current
	// trusted facts so recomputing a hash cannot hide review issues or change
	// immutable subject/role/assignment facts in a detached report.
	queries := make([]PermissionQuery, 0, len(plan.Samples))
	for _, sample := range plan.Samples {
		queries = append(queries, sample.Query)
	}
	rebuilt, err := PreviewMigrationMapping(batch.Sources[0], MigrationMapping{ExpectedSourceDigest: plan.SourceDigest, Basis: plan.Basis, Target: plan.Target}, queries, plan.EvaluatedAt)
	if err != nil {
		return MigrationMappingPreview{}, err
	}
	if rebuilt.Digest != checksum {
		return MigrationMappingPreview{}, ErrPermissionPlanStale
	}
	for _, m := range plan.Target.Memberships {
		if m.Status == "active" {
			if err := s.validateMigrationScope(ctx, m.Scope); err != nil {
				return MigrationMappingPreview{}, err
			}
		}
	}
	for _, b := range plan.Target.Bindings {
		if b.Status == "active" {
			if err := s.validateMigrationScope(ctx, b.Scope); err != nil {
				return MigrationMappingPreview{}, err
			}
		}
	}
	for _, g := range plan.Target.Grants {
		if g.Status != "active" {
			continue
		}
		scope := ManagementScope{Type: "application", TenantID: g.TenantID, DepartmentID: g.DepartmentID, ApplicationID: g.ApplicationID}
		if err := validatePermissionScope(ctx, s.db, scope); err != nil {
			return MigrationMappingPreview{}, err
		}
		if err := s.validateGrantResource(ctx, g); err != nil {
			return MigrationMappingPreview{}, err
		}
	}
	// Source facts might change while another module resolves published assets.
	// Recheck instead of returning a report based on a known stale IAM source.
	batch, err = s.InspectMigrationSources(ctx, plan.Target.Principal.TenantID, []MigrationSubject{{Type: plan.Target.Principal.Type, ID: plan.Target.Principal.ID}})
	if err != nil {
		return MigrationMappingPreview{}, err
	}
	if batch.Sources[0].SourceDigest != plan.SourceDigest {
		return MigrationMappingPreview{}, ErrPermissionPlanStale
	}
	plan.ResourceOwnershipVerified = true
	raw, err = json.Marshal(plan)
	if err != nil {
		return MigrationMappingPreview{}, err
	}
	plan.Digest = permissionHash(raw)
	return plan, nil
}

func (s *SQLStore) validateMigrationScope(ctx context.Context, scope ManagementScope) error {
	if err := validatePermissionScope(ctx, s.db, scope); err != nil {
		return err
	}
	if scope.Type != "agent_installation" {
		return nil
	}
	if s.permissionResourceResolver == nil {
		return ErrInvalidResource
	}
	_, err := s.permissionResourceResolver.ResolveAgentInstallation(ctx, sharedkernel.Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentInstanceID: scope.ResourceID, InstallationID: scope.ResourceID}, scope.ResourceID)
	return err
}
