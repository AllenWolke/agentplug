package identity

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type LegacyRequestMigrationEntry struct {
	Source      LegacyPermissionRequestSource `json:"source"`
	SubjectID   string                        `json:"subject_id"`
	Disposition string                        `json:"disposition"`
}

type LegacyRequestMigrationPlan struct {
	Version   int                           `json:"version"`
	ActorID   string                        `json:"actor_id"`
	Scope     ManagementScope               `json:"scope"`
	CreatedAt time.Time                     `json:"created_at"`
	Entries   []LegacyRequestMigrationEntry `json:"entries"`
	Digest    string                        `json:"digest"`
}

func (s *SQLStore) AuthorizeLegacyRequestMigration(ctx context.Context, actor sharedkernel.Scope) error {
	if actor.Validate() != nil || actor.PrincipalType != "user" {
		return ErrPermissionDenied
	}
	owner, err := s.PermissionSnapshot(ctx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return err
	}
	if owner.Mode != "v2" || !owner.Principal.IsActive || owner.Principal.TenantID != actor.TenantID {
		return ErrPermissionDenied
	}
	scope := ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	return authorizePermissionRequestDecision(owner, actor, PermissionRequest{Scope: scope}, s.clock().UTC())
}

func validPermissionDigest(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 32
}

func (p LegacyRequestMigrationPlan) calculatedDigest() (string, error) {
	p.Digest = ""
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return permissionHash(raw), nil
}

func (p LegacyRequestMigrationPlan) Validate() error {
	if p.Version != 1 || p.ActorID == "" || p.Scope.Validate() != nil || p.Scope.Type != "application" || p.CreatedAt.IsZero() || len(p.Entries) > 100000 || !validPermissionDigest(p.Digest) {
		return ErrInvalidResource
	}
	previous := ""
	for _, e := range p.Entries {
		if e.Source.ID == "" || len(e.Source.ID) > 128 || e.Source.ID <= previous || e.Source.Revision == 0 || !validPermissionDigest(e.Source.Digest) || e.SubjectID == "" {
			return ErrInvalidResource
		}
		switch e.Disposition {
		case "ready", "self_request", "unsupported_subject", "subject_not_v2", "invalid_actions":
		default:
			return ErrInvalidResource
		}
		previous = e.Source.ID
	}
	digest, err := p.calculatedDigest()
	if err != nil || digest != p.Digest {
		return ErrInvalidResource
	}
	return nil
}

// A repeatable-read snapshot and keyset pages give one bounded, consistent
// pending-source inventory. No source, grant, role, request or audit is written.
func (s *SQLStore) PlanLegacyPermissionRequests(ctx context.Context, actor sharedkernel.Scope, pageSize int) (LegacyRequestMigrationPlan, error) {
	if s == nil || s.db == nil || actor.Validate() != nil || actor.PrincipalType != "user" || pageSize < 1 || pageSize > 1000 {
		return LegacyRequestMigrationPlan{}, ErrInvalidResource
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return LegacyRequestMigrationPlan{}, err
	}
	defer tx.Rollback()
	owner, err := permissionRequestOwner(ctx, tx, actor)
	if err != nil {
		return LegacyRequestMigrationPlan{}, err
	}
	scope := ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	if err := authorizePermissionRequestDecision(owner, actor, PermissionRequest{Scope: scope}, s.clock().UTC()); err != nil {
		return LegacyRequestMigrationPlan{}, err
	}
	plan := LegacyRequestMigrationPlan{Version: 1, ActorID: actor.PrincipalID, Scope: scope, CreatedAt: s.clock().UTC(), Entries: []LegacyRequestMigrationEntry{}}
	cursor := ""
	for {
		rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT id,tenant_id,department_id,application_id,agent_id,agent_instance_id,subject_type,subject_id,actions_json,reason,status,reviewer_id,comment,revision,created_at,updated_at FROM platform_identity_agent_access_request WHERE tenant_id=? AND department_id=? AND application_id=? AND status='pending' AND id COLLATE "C">? COLLATE "C" ORDER BY id COLLATE "C" LIMIT ?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, cursor, pageSize)
		if err != nil {
			return LegacyRequestMigrationPlan{}, err
		}
		sources := []AgentAccessRequest{}
		for rows.Next() {
			source, scanErr := scanAgentAccessRequest(rows)
			if scanErr != nil {
				rows.Close()
				return LegacyRequestMigrationPlan{}, scanErr
			}
			sources = append(sources, source)
		}
		rowErr := rows.Err()
		rows.Close()
		if rowErr != nil {
			return LegacyRequestMigrationPlan{}, rowErr
		}
		for _, source := range sources {
			if len(plan.Entries) >= 100000 {
				return LegacyRequestMigrationPlan{}, ErrInvalidResource
			}
			raw, err := json.Marshal(source)
			if err != nil {
				return LegacyRequestMigrationPlan{}, err
			}
			entry := LegacyRequestMigrationEntry{Source: LegacyPermissionRequestSource{ID: source.ID, Revision: source.Revision, Digest: permissionHash(raw)}, SubjectID: source.SubjectID, Disposition: "ready"}
			switch {
			case source.SubjectID == actor.PrincipalID:
				entry.Disposition = "self_request"
			case source.SubjectType != PrincipalUser:
				entry.Disposition = "unsupported_subject"
			default:
				target, targetErr := loadPermissionSnapshot(ctx, tx, PrincipalUser, source.SubjectID)
				if targetErr != nil {
					return LegacyRequestMigrationPlan{}, targetErr
				}
				if target.Mode != "v2" || target.Principal.TenantID != scope.TenantID {
					entry.Disposition = "subject_not_v2"
				}
			}
			if _, valid := normalizeAgentAccessActions(source.Actions); !valid || source.AgentInstanceID == "" {
				entry.Disposition = "invalid_actions"
			}
			plan.Entries = append(plan.Entries, entry)
			cursor = source.ID
		}
		if len(sources) < pageSize {
			break
		}
	}
	plan.Digest, err = plan.calculatedDigest()
	if err != nil {
		return LegacyRequestMigrationPlan{}, err
	}
	return plan, tx.Commit()
}
