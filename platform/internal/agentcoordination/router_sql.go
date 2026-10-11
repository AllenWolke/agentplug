package agentcoordination

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Authority must check the active execution fence and hold current IAM read
// continuity in this transaction. Catalog and execution facts come through
// their own module Ports; this store owns only coordination tables.
type SQLRouteAuthority interface {
	Parent(context.Context, *sql.Tx, sharedkernel.Scope) (ParentFacts, error)
	Candidates(context.Context, *sql.Tx, ParentFacts, string) ([]Target, error)
	AuthorizeTarget(context.Context, *sql.Tx, ParentFacts, Target) error
}
type SQLRouteStore struct {
	db                   *sql.DB
	authority            SQLRouteAuthority
	audit                audit.TxRecorder
	children             ChildExecutionAdmitter
	externalRootVerifier func(context.Context, *sql.Tx, sharedkernel.Scope) error
}

// SetExternalRootVerifier wires provenance for roots owned by another platform
// module, such as Evaluation cases. A parent ID alone never establishes a root.
// This stop-only port grants no execution authority and repairs no receipts.
func (s *SQLRouteStore) SetExternalRootVerifier(verify func(context.Context, *sql.Tx, sharedkernel.Scope) error) {
	s.externalRootVerifier = verify
}

func NewSQLRouteStore(db *sql.DB) (*SQLRouteStore, error) {
	if db == nil {
		return nil, ErrUnavailable
	}
	return &SQLRouteStore{db: db}, nil
}
func (s *SQLRouteStore) SetAuthority(authority SQLRouteAuthority)   { s.authority = authority }
func (s *SQLRouteStore) SetAuditRecorder(recorder audit.TxRecorder) { s.audit = recorder }

// Only explicit deployment migration may call EnsureSchema.
func (s *SQLRouteStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS platform_agent_route (
 parent_key VARCHAR(64) NOT NULL, operation_key VARCHAR(128) NOT NULL,
 parent_run_id VARCHAR(128) NOT NULL, fingerprint VARCHAR(64) NOT NULL,
 policy_hash VARCHAR(64) NOT NULL, task_type VARCHAR(128) NOT NULL,
 child_depth INTEGER NOT NULL CHECK(child_depth BETWEEN 1 AND 4),
 reserved_children INTEGER NOT NULL CHECK(reserved_children BETWEEN 1 AND 16),
 plan_json TEXT NOT NULL CHECK(octet_length(plan_json)<=65536), evidence_digest VARCHAR(64) NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(parent_key,operation_key));
CREATE INDEX IF NOT EXISTS platform_agent_route_parent_run ON platform_agent_route(parent_run_id);
CREATE TABLE IF NOT EXISTS platform_agent_child_reservation (
 parent_key VARCHAR(64) NOT NULL, operation_key VARCHAR(128) NOT NULL,
 ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 15),
 child_key VARCHAR(64) NOT NULL UNIQUE, target_installation_id VARCHAR(128) NOT NULL,
 target_version_id VARCHAR(128) NOT NULL, target_manifest_hash VARCHAR(71) NOT NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'reserved' CHECK(status IN ('reserved','preparing','accepted','running','completed','cancelled','uncertain')),
 revision BIGINT NOT NULL DEFAULT 1 CHECK(revision>0),
	 child_run_id VARCHAR(128) UNIQUE, request_fingerprint VARCHAR(64),
	 prepared_input_schema VARCHAR(256) NOT NULL DEFAULT '',
	 prepared_input_json TEXT CHECK(octet_length(prepared_input_json)<=65536), prepared_input_fingerprint VARCHAR(64),
	 delegation_authority_json TEXT CHECK(octet_length(delegation_authority_json)<=32768),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(parent_key,operation_key,ordinal),
	 FOREIGN KEY(parent_key,operation_key) REFERENCES platform_agent_route(parent_key,operation_key),
	 CHECK(status NOT IN ('accepted','running','completed') OR (child_run_id IS NOT NULL AND request_fingerprint IS NOT NULL)));`)
	return err
}

func routeScopeKey(scope sharedkernel.Scope) string {
	// Dynamic authorization epoch and trace do not create a second parent
	// budget or fan-out namespace. They are checked through current authority.
	return digest([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentInstanceID, scope.InstallationID, scope.AgentVersionID, scope.PrincipalType, scope.PrincipalID, scope.SessionID, scope.RunID})
}

type sqlRouteTransaction struct {
	ctx              context.Context
	tx               *sql.Tx
	store            *SQLRouteStore
	scope            sharedkernel.Scope
	key              string
	parent           *ParentFacts
	targetChecks     []Target
	reservationCount int
	auditCount       int
	auditAction      string
}

func (s *SQLRouteStore) Transact(ctx context.Context, scope sharedkernel.Scope, operation func(RouteTransaction) error) error {
	if scope.ValidateTrusted() != nil || s.authority == nil || s.audit == nil || operation == nil {
		return ErrDenied
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	key := routeScopeKey(scope)
	lock := sha256.Sum256([]byte("agent-route/v1\x00" + key))
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`SELECT pg_advisory_xact_lock(?)`), int64(binary.BigEndian.Uint64(lock[:8]))); err != nil {
		return err
	}
	unit := &sqlRouteTransaction{ctx: ctx, tx: tx, store: s, scope: scope, key: key}
	if err = operation(unit); err != nil {
		return err
	}
	if unit.parent == nil || unit.auditCount != 1 {
		return ErrDenied
	}
	current, err := s.authority.Parent(ctx, tx, scope)
	if err != nil {
		return err
	}
	if !current.Active || current.Scope != scope || current.PolicyHash != unit.parent.PolicyHash || current.Depth != unit.parent.Depth || digest(current.Policy) != digest(unit.parent.Policy) || digest(current.AncestorInstallations) != digest(unit.parent.AncestorInstallations) || digest(current.AncestorAgentIDs) != digest(unit.parent.AncestorAgentIDs) {
		return ErrDenied
	}
	for _, target := range unit.targetChecks {
		if s.authority.AuthorizeTarget(ctx, tx, current, target) != nil {
			return ErrDenied
		}
	}
	return tx.Commit()
}
func (u *sqlRouteTransaction) Parent(ctx context.Context, scope sharedkernel.Scope) (ParentFacts, error) {
	if scope != u.scope || u.parent != nil {
		return ParentFacts{}, ErrDenied
	}
	facts, err := u.store.authority.Parent(ctx, u.tx, scope)
	if err != nil {
		return ParentFacts{}, err
	}
	if facts.Scope != scope || !facts.Active {
		return ParentFacts{}, ErrDenied
	}
	if err = u.tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COALESCE(SUM(reserved_children),0) FROM platform_agent_route WHERE parent_key=?`), u.key).Scan(&facts.CurrentChildren); err != nil {
		return ParentFacts{}, err
	}
	if facts.CurrentChildren < 0 || facts.CurrentChildren > 16 {
		return ParentFacts{}, ErrConflict
	}
	u.parent = &facts
	return facts, nil
}
func (u *sqlRouteTransaction) Candidates(ctx context.Context, parent ParentFacts, task string) ([]Target, error) {
	if u.parent == nil || parent.Scope != u.scope || parent.PolicyHash != u.parent.PolicyHash {
		return nil, ErrDenied
	}
	return u.store.authority.Candidates(ctx, u.tx, parent, task)
}
func (u *sqlRouteTransaction) AuthorizeTarget(ctx context.Context, parent ParentFacts, target Target) error {
	if u.parent == nil || parent.Scope != u.scope || parent.PolicyHash != u.parent.PolicyHash || len(u.targetChecks) >= 144 {
		return ErrDenied
	}
	if err := u.store.authority.AuthorizeTarget(ctx, u.tx, parent, target); err != nil {
		return err
	}
	u.targetChecks = append(u.targetChecks, target)
	return nil
}
func (u *sqlRouteTransaction) Existing(operation string) (RoutePlan, bool, error) {
	return u.existing(operation, " FOR UPDATE")
}

// ExistingShared is the read used while a child is still running. FOR UPDATE
// here blocks the child's own ancestor share of the same route row.
func (u *sqlRouteTransaction) ExistingShared(operation string) (RoutePlan, bool, error) {
	return u.existing(operation, " FOR SHARE")
}

func (u *sqlRouteTransaction) existing(operation, lock string) (RoutePlan, bool, error) {
	if (lock != " FOR UPDATE" && lock != " FOR SHARE") || !identifier(operation) || u.parent == nil {
		return RoutePlan{}, false, ErrDenied
	}
	var raw string
	var fingerprint, policyHash, evidenceDigest, taskType, parentRunID string
	var count, depth int
	err := u.tx.QueryRowContext(u.ctx, sqlutil.Bind(`SELECT plan_json,fingerprint,policy_hash,evidence_digest,reserved_children,child_depth,task_type,parent_run_id FROM platform_agent_route WHERE parent_key=? AND operation_key=?`+lock), u.key, operation).Scan(&raw, &fingerprint, &policyHash, &evidenceDigest, &count, &depth, &taskType, &parentRunID)
	if errors.Is(err, sql.ErrNoRows) {
		return RoutePlan{}, false, nil
	}
	if err != nil {
		return RoutePlan{}, false, err
	}
	if len(raw) > 65536 {
		return RoutePlan{}, false, ErrConflict
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	var plan RoutePlan
	if decoder.Decode(&plan) != nil || decoder.Decode(new(any)) != io.EOF {
		return RoutePlan{}, false, ErrConflict
	}
	if plan.OperationKey != operation || plan.Fingerprint != fingerprint || plan.PolicyHash != policyHash || plan.EvidenceDigest != evidenceDigest || len(plan.Targets) != count || plan.ChildDepth != depth || plan.TaskType != taskType || plan.ParentRunID != parentRunID {
		return RoutePlan{}, false, ErrConflict
	}
	return plan, true, nil
}
func (u *sqlRouteTransaction) Reserve(plan RoutePlan) error {
	if u.parent == nil || u.parent.Policy == nil || u.reservationCount != 0 || plan.ParentRunID != u.scope.RunID || plan.PolicyHash != u.parent.PolicyHash || !identifier(plan.OperationKey) || len(plan.Targets) < 1 || len(plan.Targets) > 16 || u.parent.CurrentChildren+len(plan.Targets) > u.parent.Policy.MaxChildren || plan.EvidenceDigest != digest(plan.Targets) {
		return ErrDenied
	}
	if plan.Version != "agent-route/v1" || plan.ChildDepth != u.parent.Depth+1 || plan.ChildDepth > u.parent.Policy.MaxDepth || !contains(u.parent.Policy.TaskTypes, plan.TaskType) || plan.Fingerprint != digest([]any{u.key, plan.PolicyHash, RouteRequest{OperationKey: plan.OperationKey, TaskType: plan.TaskType, Count: len(plan.Targets)}}) {
		return ErrDenied
	}
	// Only selected targets remain dependencies of the committed plan.
	u.targetChecks = nil
	seen := map[string]bool{}
	for _, target := range plan.Targets {
		if seen[target.InstallationID] || !eligible(*u.parent, target, plan.TaskType) || u.AuthorizeTarget(u.ctx, *u.parent, target) != nil {
			return ErrDenied
		}
		seen[target.InstallationID] = true
	}
	raw, err := json.Marshal(plan)
	if err != nil || len(raw) > 65536 {
		return ErrConflict
	}
	_, err = u.tx.ExecContext(u.ctx, sqlutil.Bind(`INSERT INTO platform_agent_route(parent_key,operation_key,parent_run_id,fingerprint,policy_hash,task_type,child_depth,reserved_children,plan_json,evidence_digest) VALUES(?,?,?,?,?,?,?,?,?,?)`), u.key, plan.OperationKey, plan.ParentRunID, plan.Fingerprint, plan.PolicyHash, plan.TaskType, plan.ChildDepth, len(plan.Targets), string(raw), plan.EvidenceDigest)
	if err != nil {
		return err
	}
	for ordinal, target := range plan.Targets {
		childKey := digest([]any{u.key, plan.OperationKey, ordinal, plan.Fingerprint})
		_, err = u.tx.ExecContext(u.ctx, sqlutil.Bind(`INSERT INTO platform_agent_child_reservation(parent_key,operation_key,ordinal,child_key,target_installation_id,target_version_id,target_manifest_hash) VALUES(?,?,?,?,?,?,?)`), u.key, plan.OperationKey, ordinal, childKey, target.InstallationID, target.VersionID, target.ManifestHash)
		if err != nil {
			return err
		}
	}
	u.reservationCount = 1
	return nil
}
func (u *sqlRouteTransaction) Audit(plan RoutePlan) error {
	if u.parent == nil || u.auditCount != 0 || plan.ParentRunID != u.scope.RunID || plan.PolicyHash != u.parent.PolicyHash || !hashValue(plan.EvidenceDigest) {
		return ErrDenied
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	action := "agent.route_planned"
	if u.auditAction == "agent.child_prepared" || u.auditAction == "agent.child_accepted" || u.auditAction == "agent.child_read" || u.auditAction == "agent.child_cancel_requested" || u.auditAction == "agent.group_read" {
		action = u.auditAction
	}
	event := audit.Event{ID: "route-" + hex.EncodeToString(nonce[:]), TenantID: u.scope.TenantID, DepartmentID: u.scope.DepartmentID, ApplicationID: u.scope.ApplicationID, ActorType: u.scope.PrincipalType, ActorID: u.scope.PrincipalID, TraceID: u.scope.TraceID, AggregateType: "agent_route", AggregateID: u.scope.RunID, Action: action, Outcome: "success", Summary: fmt.Sprintf("children=%d depth=%d evidence_digest=%s", len(plan.Targets), plan.ChildDepth, plan.EvidenceDigest)}
	if err := u.tx.QueryRowContext(u.ctx, `SELECT clock_timestamp()`).Scan(&event.CreatedAt); err != nil {
		return err
	}
	if err := u.store.audit.RecordTx(u.tx, event); err != nil {
		return err
	}
	u.auditCount = 1
	return nil
}
