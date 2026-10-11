package agentcoordination

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type ChildRoutingFacts struct {
	Target             Target
	TaskType           string
	PolicyHash         string
	RequestFingerprint string
}

// ChildRoutingFactsTx returns the fixed original target for current admission,
// so callers compare current publication against the saved deployment rather
// than accidentally accepting a replacement latest-ready deployment.
func (s *SQLRouteStore) ChildRoutingFactsTx(ctx context.Context, tx *sql.Tx, parent, child sharedkernel.Scope, depth int) (ChildRoutingFacts, error) {
	return s.childRoutingFactsTx(ctx, tx, parent, child, depth, false)
}

// RecordedChildRoutingFactsTx proves original target metadata for accounting
// and stop/lifecycle control only; terminal records cannot grant execution.
func (s *SQLRouteStore) RecordedChildRoutingFactsTx(ctx context.Context, tx *sql.Tx, parent, child sharedkernel.Scope, depth int) (ChildRoutingFacts, error) {
	return s.childRoutingFactsTx(ctx, tx, parent, child, depth, true)
}

func (s *SQLRouteStore) childRoutingFactsTx(ctx context.Context, tx *sql.Tx, parent, child sharedkernel.Scope, depth int, historical bool) (ChildRoutingFacts, error) {
	empty := ChildRoutingFacts{}
	if s == nil {
		return empty, ErrDenied
	}
	check := s.CheckChildEdgeTx
	if historical {
		check = s.CheckRecordedChildEdgeTx
	}
	if err := check(ctx, tx, parent, child, depth); err != nil {
		if lockWaitError(err) {
			return empty, err
		}
		return empty, ErrDenied
	}
	var raw, installation, version, manifest, status, policyHash, evidence, fingerprint, task, key, runID, operation string
	var ordinal, declaredDepth, count int
	var revision uint64
	var requestFingerprint sql.NullString
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT r.plan_json,r.child_depth,c.ordinal,c.target_installation_id,c.target_version_id,c.target_manifest_hash,c.status,c.request_fingerprint,r.policy_hash,r.evidence_digest,r.fingerprint,r.task_type,r.reserved_children,c.child_key,c.child_run_id,c.revision,r.operation_key FROM platform_agent_child_reservation c JOIN platform_agent_route r ON r.parent_key=c.parent_key AND r.operation_key=c.operation_key WHERE c.parent_key=? AND r.parent_run_id=? AND c.child_run_id=? FOR SHARE OF r,c`), routeScopeKey(parent), parent.RunID, child.RunID).Scan(&raw, &declaredDepth, &ordinal, &installation, &version, &manifest, &status, &requestFingerprint, &policyHash, &evidence, &fingerprint, &task, &count, &key, &runID, &revision, &operation)
	if err != nil {
		return empty, err
	}
	validStatus := status == "accepted" || status == "running"
	if historical {
		validStatus = validStatus || status == "completed" || status == "failed" || status == "cancelled" || status == "uncertain"
	}
	if len(raw) > 65536 || declaredDepth != depth || installation != child.InstallationID || version != child.AgentVersionID || !validStatus || !requestFingerprint.Valid || !hashValue(requestFingerprint.String) || revision < 3 || runID != child.RunID || !hashValue(key) || runID != "child-"+key[:48] {
		return empty, ErrDenied
	}
	var plan RoutePlan
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&plan) != nil || decoder.Decode(new(any)) != io.EOF || plan.Version != "agent-route/v1" || plan.ParentRunID != parent.RunID || plan.ChildDepth != depth || ordinal < 0 || ordinal >= len(plan.Targets) || count != len(plan.Targets) || count < 1 || count > 16 || plan.PolicyHash != policyHash || !hashValue(policyHash) || plan.TaskType != task || !identifier(task) || plan.OperationKey != operation || !identifier(operation) || plan.Fingerprint != fingerprint || plan.EvidenceDigest != evidence || evidence != digest(plan.Targets) || fingerprint != digest([]any{routeScopeKey(parent), policyHash, RouteRequest{OperationKey: operation, TaskType: task, Count: count}}) || key != digest([]any{routeScopeKey(parent), operation, ordinal, fingerprint}) {
		return empty, ErrDenied
	}
	target := plan.Targets[ordinal]
	if target.AgentID != child.AgentID || child.AgentInstanceID != installation || target.InstallationID != installation || target.VersionID != version || target.ManifestHash != manifest || target.TenantID != parent.TenantID || target.DepartmentID != parent.DepartmentID || target.ApplicationID != parent.ApplicationID {
		return empty, ErrDenied
	}
	return ChildRoutingFacts{Target: target, TaskType: task, PolicyHash: policyHash, RequestFingerprint: requestFingerprint.String}, nil
}
