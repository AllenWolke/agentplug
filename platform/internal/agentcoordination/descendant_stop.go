package agentcoordination

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

const (
	descendantStopBatchSize = 128
	maxAgentRouteChildren   = 16
	maxAgentRouteDepth      = 4
)

type descendantStopNode struct {
	scope                 sharedkernel.Scope
	depth                 int
	ancestorAgents        []string
	ancestorInstallations []string
}

type descendantStopRouteRow struct {
	parentKey      string
	operationKey   string
	fingerprint    string
	policyHash     string
	evidenceDigest string
	reservedCount  int
	childDepth     int
	taskType       string
	parentRunID    string
	planJSON       string
}

type descendantStopReservation struct {
	parentKey                string
	operationKey             string
	ordinal                  int
	childKey                 string
	targetInstallationID     string
	targetVersionID          string
	targetManifestHash       string
	status                   string
	revision                 int64
	childRunID               sql.NullString
	requestFingerprint       sql.NullString
	preparedInputSchema      string
	preparedInputBytes       sql.NullInt64
	preparedInputFingerprint sql.NullString
}

type descendantStopRoute struct {
	plan  RoutePlan
	slots []descendantStopReservation
}

// CheckDescendantStopTx checks the complete recorded descendant tree without
// mutating route reservations, Run projections or budget/model accounting.
// The caller owns the transaction and has already locked the cancelling root
// Run. Execution facts and model settlement are read through the existing
// child lifecycle ports, never through cross-module SQL.
func (s *SQLRouteStore) CheckDescendantStopTx(ctx context.Context, tx *sql.Tx, parentScope sharedkernel.Scope) error {
	_, err := s.ReadStoppedTreeScopesTx(ctx, tx, parentScope)
	return err
}

// ReadStoppedTreeScopesTx returns the exact immutable scopes proven by the
// routing owner. It validates durable reservations, admission fingerprints,
// terminal outcomes and quiescence across the complete recorded tree.
// Cancellation uses these owner facts to enroll effects; caller ParentRunID
// alone cannot nominate a descendant. It neither authorizes nor replays work.
func (s *SQLRouteStore) ReadStoppedTreeScopesTx(ctx context.Context, tx *sql.Tx, parentScope sharedkernel.Scope) ([]sharedkernel.Scope, error) {
	return s.readStoppedTreeScopesTx(ctx, tx, parentScope, nil)
}

// This control-only reader retains the same recorded ancestry and terminal
// outcome checks. Its composition-supplied callback verifies settled charges
// and registered effect coverage without replaying or rewriting lost results.
// Ordinary recovery and successful completion keep the stricter original port.
func (s *SQLRouteStore) ReadCancellationTreeScopesTx(ctx context.Context, tx *sql.Tx, parentScope sharedkernel.Scope, check func(context.Context, *sql.Tx, sharedkernel.Scope) error) ([]sharedkernel.Scope, error) {
	if check == nil {
		return nil, ErrUnavailable
	}
	return s.readStoppedTreeScopesTx(ctx, tx, parentScope, check)
}

func (s *SQLRouteStore) readStoppedTreeScopesTx(ctx context.Context, tx *sql.Tx, parentScope sharedkernel.Scope, cancellationCheck func(context.Context, *sql.Tx, sharedkernel.Scope) error) ([]sharedkernel.Scope, error) {
	if s == nil || s.db == nil || tx == nil || ctx == nil || ctx.Err() != nil || parentScope.ValidateTrusted() != nil {
		return nil, ErrDenied
	}
	scopes := []sharedkernel.Scope{parentScope}
	rootDepth, err := s.recordedDescendantScopeDepthTx(ctx, tx, parentScope)
	if err != nil {
		return nil, err
	}
	maxNodes := maxRecordedDescendantCount(rootDepth)
	if maxNodes < 0 {
		return nil, ErrConflict
	}
	queue := []descendantStopNode{{
		scope: parentScope, depth: rootDepth,
		ancestorAgents:        []string{parentScope.AgentID},
		ancestorInstallations: []string{parentScope.InstallationID},
	}}
	seenRuns := map[string]struct{}{parentScope.RunID: {}}
	visited := 0
	allTerminal := true
	var observer ChildExecutionLifecycleObserver
	var barrier ChildExecutionStopBarrier

	for len(queue) > 0 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		nextLevel := make([]descendantStopNode, 0)
		for batchStart := 0; batchStart < len(queue); batchStart += descendantStopBatchSize {
			batchEnd := batchStart + descendantStopBatchSize
			if batchEnd > len(queue) {
				batchEnd = len(queue)
			}
			batch := queue[batchStart:batchEnd]
			snapshots, err := s.readDescendantStopBatchTx(ctx, tx, batch)
			if err != nil {
				return nil, err
			}
			for _, node := range batch {
				parentKey := routeScopeKey(node.scope)
				for _, route := range snapshots[parentKey] {
					depth := route.plan.ChildDepth
					for _, slot := range route.slots {
						admitted, err := validateDescendantStopReservation(slot, route.plan, node.scope)
						if err != nil {
							return nil, err
						}
						if !admitted {
							// reserved/preparing is a real reservation, but atomic
							// admission has not created a child Run yet.
							continue
						}
						if observer == nil || barrier == nil {
							observer, barrier, err = descendantStopLifecyclePorts(s.children)
							if err != nil {
								return nil, err
							}
						}
						if ctx.Err() != nil {
							return nil, ctx.Err()
						}
						target := route.plan.Targets[slot.ordinal]
						if _, duplicate := seenRuns[slot.childRunID.String]; duplicate ||
							contains(node.ancestorAgents, target.AgentID) ||
							contains(node.ancestorInstallations, target.InstallationID) {
							return nil, ErrConflict
						}
						visited++
						if visited > maxNodes {
							return nil, ErrConflict
						}
						seenRuns[slot.childRunID.String] = struct{}{}

						observed, err := observer.ObserveChildLifecycle(ctx, tx, ChildExecutionRead{
							Parent: ParentFacts{Scope: node.scope}, Target: target, Depth: depth, RunID: slot.childRunID.String,
						})
						if err != nil {
							return nil, err
						}
						if ctx.Err() != nil {
							return nil, ctx.Err()
						}
						child := observed.Scope
						if child.ValidateTrusted() != nil || child.RunID != slot.childRunID.String ||
							child.ParentRunID != node.scope.RunID || observed.Revision == 0 ||
							!hashValue(observed.RequestFingerprint) || observed.RequestFingerprint != slot.requestFingerprint.String {
							return nil, ErrConflict
						}
						facts, err := s.RecordedChildRoutingFactsTx(ctx, tx, node.scope, child, depth)
						if err != nil || facts.RequestFingerprint != observed.RequestFingerprint || digest(facts.Target) != digest(target) {
							return nil, ErrConflict
						}

						terminalStatus := observed.Status == "completed" || observed.Status == "failed" || observed.Status == "cancelled"
						if observed.TerminalVerified && !terminalStatus {
							return nil, ErrConflict
						}
						if !observed.TerminalVerified || !terminalStatus {
							allTerminal = false
						} else {
							if cancellationCheck != nil {
								err = cancellationCheck(ctx, tx, child)
							} else {
								err = barrier.CheckChildStopQuiescence(ctx, child)
							}
							if err != nil {
								return nil, err
							}
						}
						if ctx.Err() != nil {
							return nil, ctx.Err()
						}
						scopes = append(scopes, child)
						childAgents := append(append([]string(nil), node.ancestorAgents...), child.AgentID)
						childInstallations := append(append([]string(nil), node.ancestorInstallations...), child.InstallationID)
						nextLevel = append(nextLevel, descendantStopNode{
							scope: child, depth: depth,
							ancestorAgents: childAgents, ancestorInstallations: childInstallations,
						})
					}
				}
			}
		}
		queue = nextLevel
	}
	if !allTerminal {
		return nil, ErrConflict
	}
	return scopes, nil
}

// descendantStopLifecyclePorts is required only once durable storage proves
// there is an admitted child to inspect. Roots with no recorded descendants
// can be fenced from the same SQL rows alone; an admitted child still fails
// closed unless both trusted lifecycle ports are wired.
func descendantStopLifecyclePorts(children ChildExecutionAdmitter) (ChildExecutionLifecycleObserver, ChildExecutionStopBarrier, error) {
	observer, ok := children.(ChildExecutionLifecycleObserver)
	if !ok {
		return nil, nil, ErrUnavailable
	}
	barrier, ok := children.(ChildExecutionStopBarrier)
	if !ok {
		return nil, nil, ErrUnavailable
	}
	return observer, barrier, nil
}

func maxRecordedDescendantCount(parentDepth int) int {
	if parentDepth < 0 || parentDepth > maxAgentRouteDepth {
		return -1
	}
	// RouteStore enforces MaxChildren across all operations for each parent;
	// policyassets cap it at 16 and the maximum route depth is four.
	total, level := 0, 1
	for depth := parentDepth + 1; depth <= maxAgentRouteDepth; depth++ {
		level *= maxAgentRouteChildren
		total += level
	}
	return total
}

func (s *SQLRouteStore) recordedDescendantScopeDepthTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) (int, error) {
	if scope.ParentRunID == "" {
		return 0, nil
	}
	var row descendantStopRouteRow
	var slot descendantStopReservation
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT r.parent_key,r.operation_key,r.fingerprint,r.policy_hash,r.evidence_digest,r.reserved_children,r.child_depth,r.task_type,r.parent_run_id,r.plan_json,
		c.ordinal,c.child_key,c.target_installation_id,c.target_version_id,c.target_manifest_hash,c.status,c.revision,c.child_run_id,c.request_fingerprint,c.prepared_input_schema,
		CASE WHEN c.prepared_input_json IS NULL THEN NULL ELSE octet_length(c.prepared_input_json) END,c.prepared_input_fingerprint
		FROM platform_agent_child_reservation c JOIN platform_agent_route r ON r.parent_key=c.parent_key AND r.operation_key=c.operation_key
		WHERE r.parent_run_id=? AND c.child_run_id=?`), scope.ParentRunID, scope.RunID).Scan(
		&row.parentKey, &row.operationKey, &row.fingerprint, &row.policyHash, &row.evidenceDigest,
		&row.reservedCount, &row.childDepth, &row.taskType, &row.parentRunID, &row.planJSON,
		&slot.ordinal, &slot.childKey, &slot.targetInstallationID, &slot.targetVersionID, &slot.targetManifestHash,
		&slot.status, &slot.revision, &slot.childRunID, &slot.requestFingerprint, &slot.preparedInputSchema,
		&slot.preparedInputBytes, &slot.preparedInputFingerprint)
	if err != nil {
		if err == sql.ErrNoRows {
			if s.externalRootVerifier != nil {
				if verifyErr := s.externalRootVerifier(ctx, tx, scope); verifyErr != nil {
					return 0, verifyErr
				}
				return 0, nil
			}
			return 0, ErrConflict
		}
		return 0, err
	}
	plan, err := decodeDescendantStopPlan(row)
	if err != nil || plan.ChildDepth < 1 || plan.ChildDepth > maxAgentRouteDepth ||
		row.parentRunID != scope.ParentRunID || slot.ordinal < 0 || slot.ordinal >= len(plan.Targets) {
		return 0, ErrConflict
	}
	target := plan.Targets[slot.ordinal]
	for _, plannedTarget := range plan.Targets {
		if !validDescendantStopTargetData(plannedTarget, scope, plan.TaskType) {
			return 0, ErrConflict
		}
	}
	admitted, reservationErr := validateDescendantStopReservationWithParentKey(slot, plan, scope, row.parentKey)
	if target.AgentID != scope.AgentID ||
		target.InstallationID != scope.InstallationID || target.VersionID != scope.AgentVersionID ||
		reservationErr != nil || !admitted {
		return 0, ErrConflict
	}
	return plan.ChildDepth, nil
}

func (s *SQLRouteStore) readDescendantStopBatchTx(ctx context.Context, tx *sql.Tx, nodes []descendantStopNode) (map[string][]descendantStopRoute, error) {
	result := make(map[string][]descendantStopRoute, len(nodes))
	if len(nodes) == 0 {
		return result, nil
	}
	byKey := make(map[string]descendantStopNode, len(nodes))
	keys := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if node.depth < 0 || node.depth > maxAgentRouteDepth || node.scope.ValidateTrusted() != nil {
			return nil, ErrConflict
		}
		key := routeScopeKey(node.scope)
		if _, exists := byKey[key]; exists {
			return nil, ErrConflict
		}
		byKey[key] = node
		keys = append(keys, key)
	}
	placeholders, args := descendantStopInClause(keys)

	routeQuery := `SELECT parent_key,operation_key,fingerprint,policy_hash,evidence_digest,reserved_children,child_depth,task_type,parent_run_id,plan_json
		FROM platform_agent_route WHERE parent_key IN (` + placeholders + `) ORDER BY parent_key,operation_key FOR SHARE`
	routeRows, err := tx.QueryContext(ctx, sqlutil.Bind(routeQuery), args...)
	if err != nil {
		return nil, err
	}
	routesByKey := make(map[string]map[string]*descendantStopRoute, len(nodes))
	for routeRows.Next() {
		var row descendantStopRouteRow
		if err := routeRows.Scan(&row.parentKey, &row.operationKey, &row.fingerprint, &row.policyHash, &row.evidenceDigest,
			&row.reservedCount, &row.childDepth, &row.taskType, &row.parentRunID, &row.planJSON); err != nil {
			_ = routeRows.Close()
			return nil, err
		}
		node, known := byKey[row.parentKey]
		if !known {
			_ = routeRows.Close()
			return nil, ErrConflict
		}
		plan, err := decodeDescendantStopPlan(row)
		if err != nil || plan.ParentRunID != node.scope.RunID || plan.ChildDepth != node.depth+1 ||
			plan.ChildDepth > maxAgentRouteDepth {
			_ = routeRows.Close()
			return nil, ErrConflict
		}
		seenInstallations := map[string]struct{}{}
		for _, target := range plan.Targets {
			if !validDescendantStopTarget(target, node.scope, plan.TaskType) {
				_ = routeRows.Close()
				return nil, ErrConflict
			}
			if _, duplicate := seenInstallations[target.InstallationID]; duplicate {
				_ = routeRows.Close()
				return nil, ErrConflict
			}
			seenInstallations[target.InstallationID] = struct{}{}
		}
		perKey := routesByKey[row.parentKey]
		if perKey == nil {
			perKey = make(map[string]*descendantStopRoute)
			routesByKey[row.parentKey] = perKey
		}
		if _, duplicate := perKey[row.operationKey]; duplicate {
			_ = routeRows.Close()
			return nil, ErrConflict
		}
		perKey[row.operationKey] = &descendantStopRoute{plan: plan, slots: make([]descendantStopReservation, 0, len(plan.Targets))}
	}
	if err := routeRows.Err(); err != nil {
		_ = routeRows.Close()
		return nil, err
	}
	if err := routeRows.Close(); err != nil {
		return nil, err
	}

	reservationQuery := `SELECT parent_key,operation_key,ordinal,child_key,target_installation_id,target_version_id,target_manifest_hash,status,revision,child_run_id,request_fingerprint,prepared_input_schema,
		CASE WHEN prepared_input_json IS NULL THEN NULL ELSE octet_length(prepared_input_json) END,prepared_input_fingerprint
		FROM platform_agent_child_reservation WHERE parent_key IN (` + placeholders + `) ORDER BY parent_key,operation_key,ordinal FOR SHARE`
	reservationRows, err := tx.QueryContext(ctx, sqlutil.Bind(reservationQuery), args...)
	if err != nil {
		return nil, err
	}
	for reservationRows.Next() {
		var row descendantStopReservation
		if err := reservationRows.Scan(&row.parentKey, &row.operationKey, &row.ordinal, &row.childKey,
			&row.targetInstallationID, &row.targetVersionID, &row.targetManifestHash, &row.status, &row.revision,
			&row.childRunID, &row.requestFingerprint, &row.preparedInputSchema, &row.preparedInputBytes,
			&row.preparedInputFingerprint); err != nil {
			_ = reservationRows.Close()
			return nil, err
		}
		perKey := routesByKey[row.parentKey]
		route := perKey[row.operationKey]
		if route == nil || row.ordinal < 0 || row.ordinal >= len(route.plan.Targets) ||
			validateDescendantStopReservationShape(row, route.plan, byKey[row.parentKey].scope) != nil {
			_ = reservationRows.Close()
			return nil, ErrConflict
		}
		route.slots = append(route.slots, row)
	}
	if err := reservationRows.Err(); err != nil {
		_ = reservationRows.Close()
		return nil, err
	}
	if err := reservationRows.Close(); err != nil {
		return nil, err
	}

	for _, key := range keys {
		perKey := routesByKey[key]
		var total int
		for _, route := range perKey {
			if len(route.slots) != len(route.plan.Targets) {
				return nil, ErrConflict
			}
			for ordinal, slot := range route.slots {
				if slot.ordinal != ordinal {
					return nil, ErrConflict
				}
			}
			total += len(route.slots)
		}
		if total > maxAgentRouteChildren {
			return nil, ErrConflict
		}
		operations := make([]string, 0, len(perKey))
		for operation := range perKey {
			operations = append(operations, operation)
		}
		// SQL already returns stable order, but a map is used while validating
		// joins. Sort here so observer lock acquisition is deterministic too.
		sort.Strings(operations)
		for _, operation := range operations {
			result[key] = append(result[key], *perKey[operation])
		}
	}
	return result, nil
}

func descendantStopInClause(keys []string) (string, []any) {
	var placeholders strings.Builder
	args := make([]any, len(keys))
	for index, key := range keys {
		if index > 0 {
			placeholders.WriteByte(',')
		}
		placeholders.WriteByte('?')
		args[index] = key
	}
	return placeholders.String(), args
}

func decodeDescendantStopPlan(row descendantStopRouteRow) (RoutePlan, error) {
	var plan RoutePlan
	if len(row.planJSON) == 0 || len(row.planJSON) > 65536 || !hashValue(row.parentKey) ||
		!identifier(row.operationKey) || !hashValue(row.fingerprint) || !hashValue(row.policyHash) ||
		!hashValue(row.evidenceDigest) || row.reservedCount < 1 || row.reservedCount > maxAgentRouteChildren ||
		row.childDepth < 1 || row.childDepth > maxAgentRouteDepth || !identifier(row.taskType) || row.parentRunID == "" {
		return plan, ErrConflict
	}
	decoder := json.NewDecoder(bytes.NewBufferString(row.planJSON))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&plan) != nil || decoder.Decode(new(any)) != io.EOF || plan.Version != "agent-route/v1" ||
		plan.OperationKey != row.operationKey || plan.Fingerprint != row.fingerprint || plan.PolicyHash != row.policyHash ||
		plan.EvidenceDigest != row.evidenceDigest || row.evidenceDigest != digest(plan.Targets) ||
		plan.ChildDepth != row.childDepth || plan.TaskType != row.taskType || plan.ParentRunID != row.parentRunID ||
		len(plan.Targets) != row.reservedCount || row.fingerprint != digest([]any{row.parentKey, row.policyHash,
		RouteRequest{OperationKey: row.operationKey, TaskType: row.taskType, Count: row.reservedCount}}) {
		return RoutePlan{}, ErrConflict
	}
	return plan, nil
}

func validDescendantStopTarget(target Target, parent sharedkernel.Scope, task string) bool {
	return validDescendantStopTargetData(target, parent, task) && target.InstallationID != parent.InstallationID && target.AgentID != parent.AgentID
}

func validDescendantStopTargetData(target Target, owner sharedkernel.Scope, task string) bool {
	if target.TenantID != owner.TenantID || target.DepartmentID != owner.DepartmentID || target.ApplicationID != owner.ApplicationID ||
		!identifier(target.AgentID) || !identifier(target.InstallationID) || target.InstallationRevision == 0 ||
		!identifier(target.VersionID) || !identifier(target.DeploymentID) || target.DeploymentRevision == 0 ||
		!strings.HasPrefix(target.ManifestHash, "sha256:") || !hashValue(strings.TrimPrefix(target.ManifestHash, "sha256:")) ||
		!validDescendantStopSchema(target.InputSchema) || !validDescendantStopSchema(target.OutputSchema) ||
		!target.Published || !target.Ready ||
		len(target.TaskTypes) < 1 || len(target.TaskTypes) > 16 || !contains(target.TaskTypes, task) {
		return false
	}
	seen := map[string]struct{}{}
	for _, taskType := range target.TaskTypes {
		if !identifier(taskType) {
			return false
		}
		if _, duplicate := seen[taskType]; duplicate {
			return false
		}
		seen[taskType] = struct{}{}
	}
	return true
}

func validDescendantStopSchema(value string) bool {
	return len(value) > len("schema://") && len(value) <= 256 && strings.HasPrefix(value, "schema://") &&
		strings.TrimSpace(value) == value && !strings.ContainsAny(value, "*\x00\r\n\t ")
}

func validateDescendantStopReservation(row descendantStopReservation, plan RoutePlan, parent sharedkernel.Scope) (bool, error) {
	return validateDescendantStopReservationWithParentKey(row, plan, parent, routeScopeKey(parent))
}

func validateDescendantStopReservationWithParentKey(row descendantStopReservation, plan RoutePlan, parent sharedkernel.Scope, parentKey string) (bool, error) {
	if err := validateDescendantStopReservationShapeWithParentKey(row, plan, parent, parentKey); err != nil {
		return false, err
	}
	return row.childRunID.Valid, nil
}

func validateDescendantStopReservationShape(row descendantStopReservation, plan RoutePlan, parent sharedkernel.Scope) error {
	return validateDescendantStopReservationShapeWithParentKey(row, plan, parent, routeScopeKey(parent))
}

func validateDescendantStopReservationShapeWithParentKey(row descendantStopReservation, plan RoutePlan, parent sharedkernel.Scope, parentKey string) error {
	if row.ordinal < 0 || row.ordinal >= len(plan.Targets) || !hashValue(row.childKey) ||
		!hashValue(parentKey) || row.childKey != digest([]any{parentKey, plan.OperationKey, row.ordinal, plan.Fingerprint}) {
		return ErrConflict
	}
	target := plan.Targets[row.ordinal]
	if row.targetInstallationID != target.InstallationID || row.targetVersionID != target.VersionID || row.targetManifestHash != target.ManifestHash {
		return ErrConflict
	}
	preparedShape := row.preparedInputSchema == target.InputSchema && row.preparedInputBytes.Valid &&
		row.preparedInputBytes.Int64 > 0 && row.preparedInputBytes.Int64 <= 65536 &&
		row.preparedInputFingerprint.Valid && hashValue(row.preparedInputFingerprint.String)
	noPreparedInput := row.preparedInputSchema == "" && !row.preparedInputBytes.Valid && !row.preparedInputFingerprint.Valid
	noAdmissionBinding := !row.childRunID.Valid && !row.requestFingerprint.Valid
	if row.revision < 1 {
		return ErrConflict
	}
	switch row.status {
	case "reserved":
		if row.revision != 1 || !noAdmissionBinding || !noPreparedInput {
			return ErrConflict
		}
	case "preparing":
		if row.revision != 2 || !noAdmissionBinding || !preparedShape {
			return ErrConflict
		}
	case "accepted", "running", "completed", "failed", "cancelled", "uncertain":
		if row.revision < 3 || !row.childRunID.Valid || row.childRunID.String != "child-"+row.childKey[:48] ||
			!row.requestFingerprint.Valid || !hashValue(row.requestFingerprint.String) || !preparedShape {
			return ErrConflict
		}
	default:
		return ErrConflict
	}
	return nil
}
