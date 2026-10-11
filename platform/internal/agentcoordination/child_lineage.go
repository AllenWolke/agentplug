package agentcoordination

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// lockWaitError is an unfinished row-lock wait. A caller's own context.Canceled
// is a stop, not a wait, and must stay distinguishable from a denial.
func lockWaitError(err error) bool {
	if err == nil {
		return false
	}
	switch sqlutil.SQLState(err) {
	case "55P03", "57014":
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// CheckChildEdgeTx proves a real coordination-owned edge. A signed or stored
// ParentRunID alone is insufficient. Unknown/preparing reservations cannot
// authorize a descendant; only an accepted exact child Run binding can.
func (s *SQLRouteStore) CheckChildEdgeTx(ctx context.Context, tx *sql.Tx, parent, child sharedkernel.Scope, depth int) error {
	return s.checkChildEdgeTx(ctx, tx, parent, child, depth, false)
}

// CheckRecordedChildEdgeTx permits a proven admitted edge after termination
// for accounting only. It grants no execution or result-disclosure authority.
func (s *SQLRouteStore) CheckRecordedChildEdgeTx(ctx context.Context, tx *sql.Tx, parent, child sharedkernel.Scope, depth int) error {
	return s.checkChildEdgeTx(ctx, tx, parent, child, depth, true)
}

func (s *SQLRouteStore) checkChildEdgeTx(ctx context.Context, tx *sql.Tx, parent, child sharedkernel.Scope, depth int, accounting bool) error {
	if tx == nil || parent.ValidateTrusted() != nil || child.ValidateTrusted() != nil || depth < 1 || depth > 4 || child.ParentRunID != parent.RunID || parent.TenantID != child.TenantID || parent.DepartmentID != child.DepartmentID || parent.ApplicationID != child.ApplicationID || parent.PrincipalType != child.PrincipalType || parent.PrincipalID != child.PrincipalID || parent.SessionID != child.SessionID {
		return ErrDenied
	}
	var raw string
	var ordinal, declaredDepth int
	var installation, version, manifest, status string
	var requestFingerprint sql.NullString
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT r.plan_json,r.child_depth,c.ordinal,c.target_installation_id,c.target_version_id,c.target_manifest_hash,c.status,c.request_fingerprint FROM platform_agent_child_reservation c JOIN platform_agent_route r ON r.parent_key=c.parent_key AND r.operation_key=c.operation_key WHERE c.parent_key=? AND r.parent_run_id=? AND c.child_run_id=? FOR SHARE OF r,c`), routeScopeKey(parent), parent.RunID, child.RunID).Scan(&raw, &declaredDepth, &ordinal, &installation, &version, &manifest, &status, &requestFingerprint)
	if lockWaitError(err) {
		return err
	}
	validStatus := status == "accepted" || status == "running"
	if accounting {
		validStatus = validStatus || status == "completed" || status == "failed" || status == "cancelled" || status == "uncertain"
	}
	if err != nil || len(raw) > 65536 || declaredDepth != depth || installation != child.InstallationID || version != child.AgentVersionID || !validStatus {
		return ErrDenied
	}
	if !requestFingerprint.Valid || !hashValue(requestFingerprint.String) {
		return ErrDenied
	}
	var plan RoutePlan
	if json.Unmarshal([]byte(raw), &plan) != nil || plan.Version != "agent-route/v1" || plan.ParentRunID != parent.RunID || plan.ChildDepth != depth || ordinal < 0 || ordinal >= len(plan.Targets) || plan.EvidenceDigest != digest(plan.Targets) {
		return ErrDenied
	}
	target := plan.Targets[ordinal]
	if target.AgentID != child.AgentID || target.InstallationID != installation || target.VersionID != version || target.ManifestHash != manifest {
		return ErrDenied
	}
	return nil
}
