package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

var (
	ErrAgentPackageApprovalRequired = errors.New("company approval is required for complete agent use")
	ErrAgentPackageStale            = errors.New("company agent approval no longer matches the published version")
)

type DepartmentAgentPackage struct {
	ID             string               `json:"id"`
	Scope          ManagementScope      `json:"scope"`
	InstallationID string               `json:"installation_id"`
	Requirements   AgentUseRequirements `json:"requirements"`
	Status         string               `json:"status"`
	Revision       uint64               `json:"revision"`
	ApprovedBy     string               `json:"approved_by"`
	Reason         string               `json:"reason"`
	Validity
	UpdatedAt time.Time `json:"updated_at"`
}

type DepartmentAgentPackageEntry struct {
	ApplicationID      string                  `json:"application_id"`
	Requirements       AgentUseRequirements    `json:"requirements"`
	Approval           *DepartmentAgentPackage `json:"approval,omitempty"`
	Approved           bool                    `json:"approved"`
	AvailabilityReason string                  `json:"availability_reason,omitempty"`
}

type DepartmentAgentPackageInspection struct {
	Scope      ManagementScope               `json:"scope"`
	Entries    []DepartmentAgentPackageEntry `json:"entries"`
	CanApprove bool                          `json:"can_approve"`
}

func departmentAgentPackageID(scope ManagementScope, installation string) string {
	raw, _ := json.Marshal([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, installation})
	return "department-agent-package-" + permissionHash(raw)
}

func validatePackageSelection(selection DepartmentAgentSelection) error {
	if selection.Scope.Type != "department" || selection.Scope.Validate() != nil || len(selection.Targets) < 1 || len(selection.Targets) > 16 {
		return ErrInvalidResource
	}
	seen, apps, total := map[string]bool{}, map[string]bool{}, 0
	for _, target := range selection.Targets {
		if !validPermissionResourceID(target.ApplicationID) || apps[target.ApplicationID] || len(target.InstallationIDs) < 1 {
			return ErrInvalidResource
		}
		apps[target.ApplicationID] = true
		for _, id := range target.InstallationIDs {
			if !validPermissionResourceID(id) || seen[id] {
				return ErrInvalidResource
			}
			seen[id] = true
			total++
		}
	}
	if total > 16 {
		return ErrInvalidResource
	}
	return nil
}

func readDepartmentAgentPackage(ctx context.Context, reader permissionReader, scope ManagementScope, id string) (*DepartmentAgentPackage, error) {
	var raw []byte
	var revision uint64
	var status string
	err := reader.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,status,payload FROM platform_identity_department_agent_package WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND installation_id=?`), departmentAgentPackageID(scope, id), scope.TenantID, scope.DepartmentID, scope.ApplicationID, id).Scan(&revision, &status, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var value DepartmentAgentPackage
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if value.ID != departmentAgentPackageID(scope, id) || value.Scope != scope || value.InstallationID != id || value.Revision != revision || value.Status != status {
		return nil, ErrInvalidResource
	}
	digest := value.Requirements.Digest
	if value.Validity.Validate() != nil || value.Requirements.InstallationID != id || value.Requirements.Seal() != nil || value.Requirements.Digest != digest || revision == 0 || status != "active" && status != "suspended" {
		return nil, ErrInvalidResource
	}
	return &value, nil
}

func (s *SQLStore) inspectDepartmentAgentPackages(ctx context.Context, reader permissionReader, actor sharedkernel.Scope, selection DepartmentAgentSelection) (DepartmentAgentPackageInspection, error) {
	result := DepartmentAgentPackageInspection{Scope: selection.Scope, Entries: []DepartmentAgentPackageEntry{}}
	if err := validatePackageSelection(selection); err != nil {
		return result, err
	}
	owner, err := permissionRequestOwner(ctx, reader, actor)
	if err != nil {
		return result, err
	}
	now := s.clock().UTC()
	allowed, err := canManageDepartmentAgentAccess(owner, selection.Scope, now)
	if err != nil {
		return result, err
	}
	if !allowed {
		return result, ErrPermissionDenied
	}
	if err := validatePermissionScope(ctx, reader, selection.Scope); err != nil {
		return result, err
	}
	result.CanApprove = canApproveDepartmentAgentPackage(owner, selection.Scope, now)
	resolver, ok := s.capabilityResourceResolver.(AgentUseRequirementsResolver)
	if !ok {
		return result, ErrPermissionResourceResolverUnavailable
	}
	for _, target := range selection.Targets {
		scope := ManagementScope{Type: "application", TenantID: selection.Scope.TenantID, DepartmentID: selection.Scope.DepartmentID, ApplicationID: target.ApplicationID}
		if err := validatePermissionScope(ctx, reader, scope); err != nil {
			return result, err
		}
		for _, id := range target.InstallationIDs {
			execution := sharedkernel.Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, PrincipalType: "user", PrincipalID: actor.PrincipalID, InstallationID: id, AgentInstanceID: id}
			approval, err := readDepartmentAgentPackage(ctx, reader, scope, id)
			if err != nil {
				return result, err
			}
			requirements, err := resolver.ResolveAgentUseRequirements(ctx, execution)
			availabilityReason := ""
			if err != nil {
				// An unavailable Agent must remain suspendable. Only Catalog's
				// exact-owned availability result permits showing the stored approval;
				// provider failures or a different scope never enable this fallback.
				availability, ok := s.capabilityResourceResolver.(PermissionRunAvailabilityResolver)
				if !ok || approval == nil {
					return result, err
				}
				reason, availabilityErr := availability.ResolvePermissionRunAvailability(ctx, execution)
				if availabilityErr != nil || reason != "RESOURCE_UNAVAILABLE" && reason != "RESOURCE_NOT_PUBLISHED" {
					return result, err
				}
				requirements, availabilityReason = approval.Requirements, reason
			}
			if requirements.InstallationID != id {
				return result, ErrInvalidResource
			}
			oldDigest := requirements.Digest
			if err := requirements.Seal(); err != nil || requirements.Digest != oldDigest {
				return result, ErrInvalidResource
			}
			entry := DepartmentAgentPackageEntry{ApplicationID: scope.ApplicationID, Requirements: requirements, Approval: approval, AvailabilityReason: availabilityReason}
			entry.Approved = availabilityReason == "" && approval != nil && approval.Status == "active" && approval.Effective(now) && approval.Requirements.Digest == requirements.Digest
			result.Entries = append(result.Entries, entry)
		}
	}
	slices.SortFunc(result.Entries, func(a, b DepartmentAgentPackageEntry) int {
		return strings.Compare(a.Requirements.InstallationID, b.Requirements.InstallationID)
	})
	return result, nil
}

func (s *SQLStore) InspectDepartmentAgentPackages(ctx context.Context, actor sharedkernel.Scope, selection DepartmentAgentSelection) (DepartmentAgentPackageInspection, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return DepartmentAgentPackageInspection{}, err
	}
	defer tx.Rollback()
	result, err := s.inspectDepartmentAgentPackages(ctx, tx, actor, selection)
	if err != nil {
		return result, err
	}
	return result, tx.Commit()
}

func canApproveDepartmentAgentPackage(owner PermissionSnapshot, scope ManagementScope, now time.Time) bool {
	return requireSuperAdministrator(owner, "delegation.manage", now) == nil || companyAdministrationAllows(owner, scope, "delegation.manage", now)
}
