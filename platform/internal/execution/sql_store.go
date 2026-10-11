package execution

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// SQLStore is the production-oriented Local Repository for one platform
// process. The schema is owned by the platform module and can later be moved
// behind a remote repository without changing the HTTP contract.
// SQLStore 是单平台进程使用的生产持久化仓储；表由平台模块拥有。
type SQLStore struct {
	db                         *sql.DB
	recoveryCheckpoints        func(context.Context, *sql.Tx, sharedkernel.Scope, uint64) ([]contract.RecoveryCheckpointReference, error)
	groupWaitCheckpoint        func(context.Context, *sql.Tx, sharedkernel.Scope, contract.AgentGroupHandoff) ([]contract.RecoveryCheckpointReference, error)
	groupWaitPlan              func(context.Context, *sql.Tx, sharedkernel.Scope, contract.AgentGroupHandoff) error
	groupStopBarrier           func(context.Context, *sql.Tx, sharedkernel.Scope, contract.AgentGroupHandoff) error
	groupWaitFence             func(context.Context, *sql.Tx, sharedkernel.Scope) error
	groupResumeQuiescence      func(context.Context, sharedkernel.Scope) error
	recoveryDescendants        func(context.Context, *sql.Tx, sharedkernel.Scope) error
	recoveryStateLost          func(error) bool
	recoverySettlement         func(context.Context, sharedkernel.Scope) error
	terminalOutcomeFence       func(context.Context, *sql.Tx, sharedkernel.Scope) error
	cancellationFence          func(context.Context, *sql.Tx, sharedkernel.Scope) error
	cancellationSaga           compensation.Coordinator
	cancellationPorts          CancellationCompensationPorts
	synchronousCreation        func(context.Context, *sql.Tx, platformruntime.CreateRequest) error
	completedEvaluationControl func(context.Context, *sql.Tx, platformruntime.Run) error
}

// SetTerminalOutcomeFence installs the production settlement/descendant guard.
// It runs while the execution row is locked, before outcome or FIFO release.
func (s *SQLStore) SetTerminalOutcomeFence(check func(context.Context, *sql.Tx, sharedkernel.Scope) error) {
	s.terminalOutcomeFence = check
}

// Only a positively classified missing/expired State lineage can become a
// stopped, non-recoverable failure. Database or transport errors stay pending.
func (s *SQLStore) SetRecoveryFailureDisposition(classify func(error) bool, settled func(context.Context, sharedkernel.Scope) error) {
	s.recoveryStateLost, s.recoverySettlement = classify, settled
}

// SetRecoveryDescendantBarrier fences the complete admitted tree before an
// ordinary recovery clears its old lease. It grants no new child admission.
func (s *SQLStore) SetRecoveryDescendantBarrier(check func(context.Context, *sql.Tx, sharedkernel.Scope) error) {
	s.recoveryDescendants = check
}

func (s *SQLStore) SetAgentGroupStopBarrier(check func(context.Context, *sql.Tx, sharedkernel.Scope, contract.AgentGroupHandoff) error) {
	s.groupStopBarrier = check
}

func (s *SQLStore) SetAgentGroupWaitFence(fence func(context.Context, *sql.Tx, sharedkernel.Scope) error) {
	s.groupWaitFence = fence
}

func (s *SQLStore) SetAgentGroupResumeQuiescence(check func(context.Context, sharedkernel.Scope) error) {
	s.groupResumeQuiescence = check
}

// Group waiting uses independent State and coordination-owned transaction
// ports. Missing wiring cannot establish a waiting execution proof.
func (s *SQLStore) SetAgentGroupWaitPorts(capture func(context.Context, *sql.Tx, sharedkernel.Scope, contract.AgentGroupHandoff) ([]contract.RecoveryCheckpointReference, error), plan func(context.Context, *sql.Tx, sharedkernel.Scope, contract.AgentGroupHandoff) error) {
	s.groupWaitCheckpoint, s.groupWaitPlan = capture, plan
}

// SetRecoveryCheckpointCapture is composition wiring installed before workers
// start. It reads public State inside the stop transaction, never a second DB
// snapshot. An absent port provides audit provenance only, not SDK recovery.
func (s *SQLStore) SetRecoveryCheckpointCapture(capture func(context.Context, *sql.Tx, sharedkernel.Scope, uint64) ([]contract.RecoveryCheckpointReference, error)) {
	s.recoveryCheckpoints = capture
}

func OpenSQLStore(ctx context.Context, driver, dsn string) (*SQLStore, error) {
	store, err := ConnectSQLStore(ctx, driver, dsn)
	if err != nil {
		return nil, err
	}
	return store, nil
}

// ConnectSQLStore only connects; it never creates or alters schema.
// ConnectSQLStore仅连接和探活，不创建或修改Schema。
func ConnectSQLStore(ctx context.Context, driver, dsn string) (*SQLStore, error) {
	if (driver != "pgx" && driver != "postgres") || dsn == "" {
		return nil, errors.New("execution requires PostgreSQL driver and DSN")
	}
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("open execution database: %w", err)
	}
	store := &SQLStore{db: db}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLStore) Close() error { return s.db.Close() }

// DB exposes the already-open connection to other platform-owned modules.
// DB 只把平台已打开的连接交给同一进程内模块，避免各模块重复建连接池。
func (s *SQLStore) DB() *sql.DB { return s.db }

// MigrateSchema is the explicit migration seam, using the migration-owned pool.
func MigrateSchema(ctx context.Context, db *sql.DB) error { return (&SQLStore{db: db}).Migrate(ctx) }

func (s *SQLStore) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, sqlutil.Bind(`CREATE TABLE IF NOT EXISTS platform_execution_session_lease (
 session_key VARCHAR(64) NOT NULL PRIMARY KEY,
 run_id VARCHAR(128) NOT NULL,
 lease_token VARCHAR(128) NOT NULL,
 lease_until TIMESTAMPTZ(6) NULL
);
`)); err != nil {
		return fmt.Errorf("migrate execution session lease: %w", err)
	}
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`
CREATE TABLE IF NOT EXISTS platform_execution_run (
  run_id VARCHAR(128) NOT NULL PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  department_id VARCHAR(128) NOT NULL,
  application_id VARCHAR(128) NOT NULL,
  agent_instance_id VARCHAR(128) NOT NULL,
  agent_id VARCHAR(128) NOT NULL,
  principal_id VARCHAR(128) NOT NULL,
  principal_type VARCHAR(32) NOT NULL,
  installation_id VARCHAR(128) NOT NULL,
  agent_version_id VARCHAR(128) NOT NULL,
  session_id VARCHAR(128) NOT NULL,
  authorization_epoch NUMERIC(20,0) CHECK (authorization_epoch>=0 AND authorization_epoch<=18446744073709551615) NOT NULL DEFAULT 0,
  trace_id VARCHAR(128) NOT NULL,
  idempotency_key VARCHAR(128) NOT NULL,
  scope_idem_hash VARCHAR(64) NOT NULL,
  fingerprint VARCHAR(64) NOT NULL,
  request_json TEXT NULL,
  trace_context VARCHAR(1024) NOT NULL DEFAULT '',
  resume_input_json TEXT NULL,
  agent_endpoint VARCHAR(512) NOT NULL DEFAULT '',
  status VARCHAR(32) NOT NULL,
  revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
  lease_token VARCHAR(128) NOT NULL DEFAULT '',
  lease_until TIMESTAMPTZ(6) NULL,
  created_at TIMESTAMPTZ(6) NOT NULL,
  updated_at TIMESTAMPTZ(6) NOT NULL,
	CONSTRAINT uq_platform_execution_idem_hash UNIQUE (scope_idem_hash));
CREATE INDEX IF NOT EXISTS idx_platform_execution_scope ON platform_execution_run (tenant_id, department_id, application_id, principal_id, run_id);
CREATE INDEX IF NOT EXISTS idx_platform_execution_recovery ON platform_execution_run (status, updated_at);`),
	)
	if err != nil {
		return fmt.Errorf("migrate platform execution run: %w", err)
	}
	// PostgreSQL is a new schema lineage; old vendor-specific volume upgrades
	// are not applied to the rebuilt public database.
	_, err = s.db.ExecContext(ctx, sqlutil.Bind(`
CREATE TABLE IF NOT EXISTS platform_execution_event (
  seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  run_id VARCHAR(128) NOT NULL,
  event_type VARCHAR(64) NOT NULL,
  payload JSON NOT NULL,
  occurred_at TIMESTAMPTZ(6) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_platform_execution_event_run ON platform_execution_event (run_id, seq);`),
	)
	if err != nil {
		return fmt.Errorf("migrate platform execution event: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, sqlutil.Bind(`CREATE TABLE IF NOT EXISTS platform_execution_outcome (
 run_id VARCHAR(128) NOT NULL PRIMARY KEY,
 revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
 output_json JSON NOT NULL,
 event_type VARCHAR(64) NOT NULL,
 event_payload JSON NOT NULL,
 projection_pending BOOLEAN NOT NULL);
CREATE INDEX IF NOT EXISTS idx_execution_outcome_pending ON platform_execution_outcome (projection_pending, run_id);`)); err != nil {
		return fmt.Errorf("migrate execution outcome: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, sqlutil.Bind(`CREATE TABLE IF NOT EXISTS platform_execution_creation_projection (
 run_id VARCHAR(128) NOT NULL PRIMARY KEY,
 message_id VARCHAR(128) NOT NULL,
 conversation_pending BOOLEAN NOT NULL,
 task_pending BOOLEAN NOT NULL);
CREATE INDEX IF NOT EXISTS idx_execution_creation_pending ON platform_execution_creation_projection (conversation_pending, task_pending, run_id);`)); err != nil {
		return fmt.Errorf("migrate creation projection: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, sqlutil.Bind(`CREATE TABLE IF NOT EXISTS platform_execution_dispatch_command (
 run_id VARCHAR(128) PRIMARY KEY, revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
 operation VARCHAR(16) NOT NULL, body_hash VARCHAR(64) NOT NULL, policy_hash VARCHAR(64) NOT NULL
);
`)); err != nil {
		return fmt.Errorf("migrate dispatch command: %w", err)
	}
	if err := s.EnsureGenerationJournalSchema(ctx); err != nil {
		return fmt.Errorf("migrate execution generation journal: %w", err)
	}
	return nil
}

func (s *SQLStore) Create(req platformruntime.CreateRequest) (platformruntime.CreateResult, error) {
	if err := req.Scope.Validate(); err != nil {
		return platformruntime.CreateResult{}, err
	}
	if req.ID == "" || req.AgentVersionID == "" || req.IdempotencyKey == "" || req.Fingerprint == "" {
		return platformruntime.CreateResult{}, platformruntime.ErrIdempotencyConflict
	}
	scopeHash := fmt.Sprintf("%x", sha256.Sum256([]byte(platformruntime.ScopeIdempotencyHash(req.Scope, req.IdempotencyKey))))
	// Retry transient transaction failures only after the previous transaction
	// has rolled back. The unique scope hash remains the idempotency authority.
	for attempt := 0; attempt < 5; attempt++ {
		result, err := s.createOnce(req, scopeHash)
		if err == nil || !retryableCreateError(err) || attempt == 4 {
			return result, err
		}
		time.Sleep(time.Duration(1<<attempt)*25*time.Millisecond + time.Duration(attempt)*7*time.Millisecond)
	}
	return platformruntime.CreateResult{}, fmt.Errorf("create execution run retries exhausted")
}

func retryableCreateError(err error) bool {
	state := sqlutil.SQLState(err)
	return errors.Is(err, errConcurrentCreate) || state == "40001" || state == "40P01" || state == "55P03"
}

var errConcurrentCreate = errors.New("concurrent execution idempotency winner committed")

func (s *SQLStore) createOnce(req platformruntime.CreateRequest, scopeHash string) (platformruntime.CreateResult, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return platformruntime.CreateResult{}, err
	}
	defer tx.Rollback()
	result, err := s.createRunTx(ctx, tx, req, scopeHash, false)
	if err != nil {
		return platformruntime.CreateResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return platformruntime.CreateResult{}, err
	}
	return result, nil
}

// createRunTx shares canonical execution idempotency/events with internal
// tasks while keeping the caller's authorization/audit transaction atomic.
func (s *SQLStore) createRunTx(ctx context.Context, tx *sql.Tx, req platformruntime.CreateRequest, scopeHash string, internal bool) (platformruntime.CreateResult, error) {
	// A concurrent first insert is resolved by the unique scope hash. A losing
	// insert rolls back and retries to read the committed winner and fingerprint.
	var existing platformruntime.Run
	var existingFingerprint string
	var existingLeaseUntil sql.NullTime
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id, tenant_id, department_id, application_id, agent_instance_id, agent_id, principal_id, principal_type, installation_id, agent_version_id, session_id, authorization_epoch, trace_id, idempotency_key, fingerprint, request_json, trace_context, resume_input_json, agent_endpoint, status, revision, lease_token, lease_until, created_at, updated_at FROM platform_execution_run WHERE scope_idem_hash=? FOR UPDATE`), scopeHash).Scan(
		&existing.ID, &existing.Scope.TenantID, &existing.Scope.DepartmentID, &existing.Scope.ApplicationID, &existing.Scope.AgentInstanceID, &existing.Scope.AgentID, &existing.Scope.PrincipalID, &existing.Scope.PrincipalType, &existing.Scope.InstallationID, &existing.Scope.AgentVersionID, &existing.Scope.SessionID, &existing.Scope.AuthorizationEpoch, &existing.Scope.TraceID, &existing.IdempotencyKey, &existingFingerprint, &existing.RequestJSON, &existing.TraceContext, &existing.ResumeInputJSON, &existing.AgentEndpoint, &existing.Status, &existing.Revision, &existing.LeaseToken, &existingLeaseUntil, &existing.CreatedAt, &existing.UpdatedAt,
	)
	if err == nil {
		if existingFingerprint != req.Fingerprint {
			return platformruntime.CreateResult{}, platformruntime.ErrIdempotencyConflict
		}
		if existingLeaseUntil.Valid {
			existing.LeaseUntil = existingLeaseUntil.Time
		}
		existing.Scope.RunID = existing.ID
		restoreParentRunID(&existing)
		existing.AgentVersionID = existing.Scope.AgentVersionID
		return platformruntime.CreateResult{Run: existing, Replayed: true}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return platformruntime.CreateResult{}, err
	}
	// Normalize duplicated identity fields at the persistence boundary. This
	// keeps old callers compatible while guaranteeing projections and recovery
	// reads see the same version/run identity as the top-level request.
	// 在持久化边界归一化重复身份字段，兼容旧调用方并保证投影与恢复读取
	// 使用和顶层请求一致的版本及运行 ID。
	if req.Scope.AgentVersionID == "" {
		req.Scope.AgentVersionID = req.AgentVersionID
	}
	if req.Scope.RunID == "" {
		req.Scope.RunID = req.ID
	}
	if !internal && s.synchronousCreation != nil && req.Scope.ParentRunID != "" {
		var request contract.ExecuteRequest
		if json.Unmarshal(req.RequestJSON, &request) != nil {
			return platformruntime.CreateResult{}, platformruntime.ErrInvalidRequest
		}
		if request.Scope.DelegationDepth == 0 {
			guardCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if err := s.synchronousCreation(guardCtx, tx, req); err != nil {
				return platformruntime.CreateResult{}, err
			}
		}
	}
	now := time.Now().UTC()
	run := platformruntime.Run{ID: req.ID, Scope: req.Scope, AgentVersionID: req.AgentVersionID, IdempotencyKey: req.IdempotencyKey, RequestJSON: append([]byte(nil), req.RequestJSON...), TraceContext: req.TraceContext, AgentEndpoint: req.AgentEndpoint, Status: platformruntime.StatusAccepted, Revision: 1, CreatedAt: now, UpdatedAt: now}
	inserted, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_run (run_id, tenant_id, department_id, application_id, agent_instance_id, agent_id, principal_id, principal_type, installation_id, agent_version_id, session_id, authorization_epoch, trace_id, idempotency_key, scope_idem_hash, fingerprint, request_json, trace_context, resume_input_json, agent_endpoint, status, revision, lease_token, lease_until, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (scope_idem_hash) DO NOTHING`), run.ID, run.Scope.TenantID, run.Scope.DepartmentID, run.Scope.ApplicationID, run.Scope.AgentInstanceID, run.Scope.AgentID, run.Scope.PrincipalID, run.Scope.PrincipalType, run.Scope.InstallationID, run.AgentVersionID, run.Scope.SessionID, run.Scope.AuthorizationEpoch, run.Scope.TraceID, run.IdempotencyKey, scopeHash, req.Fingerprint, req.RequestJSON, req.TraceContext, nil, req.AgentEndpoint, run.Status, run.Revision, run.LeaseToken, nil, run.CreatedAt, run.UpdatedAt)
	if err != nil {
		return platformruntime.CreateResult{}, err
	}
	count, err := inserted.RowsAffected()
	if err != nil {
		return platformruntime.CreateResult{}, err
	}
	if count == 0 {
		return platformruntime.CreateResult{}, errConcurrentCreate
	}
	payload, _ := json.Marshal(map[string]any{"status": string(platformruntime.StatusAccepted)})
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event (run_id, event_type, payload, occurred_at) VALUES (?,?,?,?)`), run.ID, "accepted", payload, now); err != nil {
		return platformruntime.CreateResult{}, err
	}
	if !internal {
		if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_creation_projection (run_id, message_id, conversation_pending, task_pending) VALUES (?,?,TRUE,TRUE)`), run.ID, req.MessageID); err != nil {
			return platformruntime.CreateResult{}, err
		}
	}
	return platformruntime.CreateResult{Run: run}, nil
}

// Install before serving. New Evaluation children share the product-head
// lock with cancellation, so a successful preflight cannot race a later
// cancelled parent into accepting an untracked child.
func (s *SQLStore) SetSynchronousCreationGuard(guard func(context.Context, *sql.Tx, platformruntime.CreateRequest) error) error {
	if s == nil || guard == nil || s.synchronousCreation != nil {
		return platformruntime.ErrInvalidRequest
	}
	s.synchronousCreation = guard
	return nil
}

func (s *SQLStore) Get(id string) (platformruntime.Run, error) {
	return s.GetContext(context.Background(), id)
}

// restoreParentRunID rebuilds immutable evaluation lineage from the durable
// signed request. The child Run keeps its own execution ID; no mutable header
// or caller-supplied lookup is allowed to change billing attribution.
// 从持久化签名请求恢复父评测 Run；子 Run 仍保留独立执行 ID。
func restoreParentRunID(run *platformruntime.Run) {
	if run == nil || len(run.RequestJSON) == 0 {
		return
	}
	var request struct {
		Scope struct {
			ParentRunID string `json:"parent_run_id"`
		} `json:"scope"`
	}
	if json.Unmarshal(run.RequestJSON, &request) == nil {
		run.Scope.ParentRunID = request.Scope.ParentRunID
	}
}

// GetContext follows the caller's cancellation and bounded read budget.
// GetContext 遵守调用方取消及读取预算。
func (s *SQLStore) GetContext(ctx context.Context, id string) (platformruntime.Run, error) {
	return readExecutionRun(ctx, s.db, id, "")
}

type executionRunQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Recovery uses the same complete projection under its UPDATE lock, rather
// than copying request or lease facts from a read before the transaction.
func readExecutionRun(ctx context.Context, queryer executionRunQueryer, id, lock string) (platformruntime.Run, error) {
	if queryer == nil || (lock != "" && lock != " FOR UPDATE") {
		return platformruntime.Run{}, platformruntime.ErrInvalidRequest
	}
	var run platformruntime.Run
	var status string
	var leaseUntil sql.NullTime
	err := queryer.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id, tenant_id, department_id, application_id, agent_instance_id, agent_id, principal_id, principal_type, installation_id, agent_version_id, session_id, authorization_epoch, trace_id, idempotency_key, request_json, trace_context, resume_input_json, agent_endpoint, status, revision, lease_token, lease_until, created_at, updated_at FROM platform_execution_run WHERE run_id=?`+lock), id).Scan(&run.ID, &run.Scope.TenantID, &run.Scope.DepartmentID, &run.Scope.ApplicationID, &run.Scope.AgentInstanceID, &run.Scope.AgentID, &run.Scope.PrincipalID, &run.Scope.PrincipalType, &run.Scope.InstallationID, &run.Scope.AgentVersionID, &run.Scope.SessionID, &run.Scope.AuthorizationEpoch, &run.Scope.TraceID, &run.IdempotencyKey, &run.RequestJSON, &run.TraceContext, &run.ResumeInputJSON, &run.AgentEndpoint, &status, &run.Revision, &run.LeaseToken, &leaseUntil, &run.CreatedAt, &run.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return platformruntime.Run{}, platformruntime.ErrRunNotFound
	}
	if err != nil {
		return platformruntime.Run{}, err
	}
	run.Scope.RunID = run.ID
	restoreParentRunID(&run)
	run.AgentVersionID = run.Scope.AgentVersionID
	if leaseUntil.Valid {
		run.LeaseUntil = leaseUntil.Time
	}
	run.Status = platformruntime.Status(status)
	return run, nil
}

// ListPending lets the single-instance dispatcher recover accepted rows after
// restart. The query is bounded and returns only rows carrying a complete
// signed request and a trusted Agent endpoint.
// ListPending 让单实例 Dispatcher 在重启后恢复 accepted；查询有界且只返回
// 同时具备完整签名请求和受信 Agent Endpoint 的记录。
func (s *SQLStore) ListPending(limit int) ([]platformruntime.Run, error) {
	if limit < 1 {
		return nil, nil
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.Query(sqlutil.Bind(`SELECT run_id, tenant_id, department_id, application_id, agent_instance_id, agent_id, principal_id, principal_type, installation_id, agent_version_id, session_id, authorization_epoch, trace_id, idempotency_key, request_json, trace_context, resume_input_json, agent_endpoint, status, revision, lease_token, lease_until, created_at, updated_at FROM platform_execution_run WHERE (status='accepted' OR (status='running' AND lease_token='')) AND request_json IS NOT NULL AND request_json<>'' AND agent_endpoint<>'' ORDER BY created_at LIMIT ?`), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]platformruntime.Run, 0, limit)
	for rows.Next() {
		var run platformruntime.Run
		var status string
		var leaseUntil sql.NullTime
		if err := rows.Scan(&run.ID, &run.Scope.TenantID, &run.Scope.DepartmentID, &run.Scope.ApplicationID, &run.Scope.AgentInstanceID, &run.Scope.AgentID, &run.Scope.PrincipalID, &run.Scope.PrincipalType, &run.Scope.InstallationID, &run.Scope.AgentVersionID, &run.Scope.SessionID, &run.Scope.AuthorizationEpoch, &run.Scope.TraceID, &run.IdempotencyKey, &run.RequestJSON, &run.TraceContext, &run.ResumeInputJSON, &run.AgentEndpoint, &status, &run.Revision, &run.LeaseToken, &leaseUntil, &run.CreatedAt, &run.UpdatedAt); err != nil {
			return nil, err
		}
		run.Scope.RunID = run.ID
		restoreParentRunID(&run)
		run.AgentVersionID = run.Scope.AgentVersionID
		run.Status = platformruntime.Status(status)
		if leaseUntil.Valid {
			run.LeaseUntil = leaseUntil.Time
		}
		result = append(result, run)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// ListRunningExpired finds durable running work whose previous dispatcher
// lease is no longer valid. The caller must confirm the old generation stopped
// before acquiring another lease; expiry alone is not a shutdown guarantee.
// ListRunningExpired 查找旧 Dispatcher 租约已失效的 durable running 工作，
// 必须先停止确认旧世代，再领取新租约；过期不是远程停止证明。
func (s *SQLStore) ListRunningExpired(now time.Time, limit int) ([]platformruntime.Run, error) {
	if limit < 1 {
		return nil, nil
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.Query(sqlutil.Bind(`SELECT run_id, tenant_id, department_id, application_id, agent_instance_id, agent_id, principal_id, principal_type, installation_id, agent_version_id, session_id, authorization_epoch, trace_id, idempotency_key, request_json, trace_context, resume_input_json, agent_endpoint, status, revision, lease_token, lease_until, created_at, updated_at FROM platform_execution_run WHERE status=? AND lease_until IS NOT NULL AND lease_until<=? AND request_json IS NOT NULL AND request_json<>'' AND agent_endpoint<>'' ORDER BY updated_at LIMIT ?`), platformruntime.StatusRunning, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]platformruntime.Run, 0, limit)
	for rows.Next() {
		var run platformruntime.Run
		var status string
		var leaseUntil sql.NullTime
		if err := rows.Scan(&run.ID, &run.Scope.TenantID, &run.Scope.DepartmentID, &run.Scope.ApplicationID, &run.Scope.AgentInstanceID, &run.Scope.AgentID, &run.Scope.PrincipalID, &run.Scope.PrincipalType, &run.Scope.InstallationID, &run.Scope.AgentVersionID, &run.Scope.SessionID, &run.Scope.AuthorizationEpoch, &run.Scope.TraceID, &run.IdempotencyKey, &run.RequestJSON, &run.TraceContext, &run.ResumeInputJSON, &run.AgentEndpoint, &status, &run.Revision, &run.LeaseToken, &leaseUntil, &run.CreatedAt, &run.UpdatedAt); err != nil {
			return nil, err
		}
		run.Scope.RunID = run.ID
		restoreParentRunID(&run)
		run.AgentVersionID = run.Scope.AgentVersionID
		run.Status = platformruntime.Status(status)
		if leaseUntil.Valid {
			run.LeaseUntil = leaseUntil.Time
		}
		result = append(result, run)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *SQLStore) Transition(id string, from, to platformruntime.Status, expectedRevision uint64) (platformruntime.Run, error) {
	return s.transition(id, from, to, expectedRevision, "")
}

// TransitionLeased validates lease ownership inside the state transaction.
// TransitionLeased 在状态事务内校验租约，避免先检查再更新的竞争窗口。
func (s *SQLStore) TransitionLeased(id string, from, to platformruntime.Status, revision uint64, token string) (platformruntime.Run, error) {
	if token == "" {
		return platformruntime.Run{}, platformruntime.ErrLeaseConflict
	}
	return s.transition(id, from, to, revision, token)
}

func (s *SQLStore) transition(id string, from, to platformruntime.Status, expectedRevision uint64, token string) (platformruntime.Run, error) {
	return s.transitionOutcome(id, from, to, expectedRevision, token, nil)
}

func (s *SQLStore) transitionOutcome(id string, from, to platformruntime.Status, expectedRevision uint64, token string, outcome *platformruntime.Outcome) (platformruntime.Run, error) {
	if s.cancellationSaga != nil && to == platformruntime.StatusCancelled {
		// A generic transition or Agent response cannot bypass stop/effect
		// verification. Cancellation must use the dedicated durable operation.
		return platformruntime.Run{}, platformruntime.ErrInvalidTransition
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return platformruntime.Run{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if outcome != nil && outcome.EventPayload["agent_group_handoff"] != nil {
		if s.groupWaitFence == nil {
			return platformruntime.Run{}, platformruntime.ErrInvalidTransition
		}
		preliminary, err := readExecutionRun(context.Background(), tx, id, "")
		if err != nil {
			return platformruntime.Run{}, err
		}
		if err := s.groupWaitFence(context.Background(), tx, preliminary.Scope); err != nil {
			return platformruntime.Run{}, err
		}
	}
	var run platformruntime.Run
	var status string
	var leaseUntil sql.NullTime
	err = tx.QueryRow(sqlutil.Bind(`SELECT run_id, tenant_id, department_id, application_id, agent_instance_id, agent_id, principal_id, principal_type, installation_id, agent_version_id, session_id, authorization_epoch, trace_id, idempotency_key, request_json, trace_context, resume_input_json, agent_endpoint, status, revision, lease_token, lease_until, created_at, updated_at FROM platform_execution_run WHERE run_id=? FOR UPDATE`), id).Scan(&run.ID, &run.Scope.TenantID, &run.Scope.DepartmentID, &run.Scope.ApplicationID, &run.Scope.AgentInstanceID, &run.Scope.AgentID, &run.Scope.PrincipalID, &run.Scope.PrincipalType, &run.Scope.InstallationID, &run.Scope.AgentVersionID, &run.Scope.SessionID, &run.Scope.AuthorizationEpoch, &run.Scope.TraceID, &run.IdempotencyKey, &run.RequestJSON, &run.TraceContext, &run.ResumeInputJSON, &run.AgentEndpoint, &status, &run.Revision, &run.LeaseToken, &leaseUntil, &run.CreatedAt, &run.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return platformruntime.Run{}, platformruntime.ErrRunNotFound
	}
	if err != nil {
		return platformruntime.Run{}, err
	}
	run.Scope.RunID = run.ID
	restoreParentRunID(&run)
	run.AgentVersionID = run.Scope.AgentVersionID
	if leaseUntil.Valid {
		run.LeaseUntil = leaseUntil.Time
	}
	run.Status = platformruntime.Status(status)
	if run.Revision != expectedRevision {
		return platformruntime.Run{}, platformruntime.ErrRevisionConflict
	}
	if token != "" && (run.LeaseToken != token || !run.LeaseUntil.After(time.Now().UTC())) {
		return platformruntime.Run{}, platformruntime.ErrLeaseConflict
	}
	if !transitionAllowed(from, to) || run.Status != from {
		return platformruntime.Run{}, platformruntime.ErrInvalidTransition
	}
	if (to == platformruntime.StatusSucceeded || to == platformruntime.StatusFailed || to == platformruntime.StatusCancelled) && s.terminalOutcomeFence != nil {
		if err := s.terminalOutcomeFence(ctx, tx, run.Scope); err != nil {
			return platformruntime.Run{}, fmt.Errorf("%w: %w", ErrExecutionOutcomeUnconfirmed, err)
		}
	}
	if token != "" {
		var matched int
		if err = tx.QueryRow(sqlutil.Bind(`SELECT 1 FROM platform_execution_session_lease WHERE session_key=? AND run_id=? AND lease_token=? AND lease_until>? FOR UPDATE`), platformruntime.SessionExecutionKey(run.Scope), run.ID, token, time.Now().UTC()).Scan(&matched); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return platformruntime.Run{}, platformruntime.ErrLeaseConflict
			}
			return platformruntime.Run{}, err
		}
	}
	if err = validateWaitingHandoffTx(context.Background(), tx, run, outcome); err != nil {
		return platformruntime.Run{}, err
	}
	if err = s.validateGroupWaitingTx(context.Background(), tx, run, outcome); err != nil {
		return platformruntime.Run{}, err
	}
	run.Status = to
	run.Revision++
	run.UpdatedAt = time.Now().UTC()
	updateStatus := `UPDATE platform_execution_run SET status=?, revision=?, updated_at=? WHERE run_id=?`
	clearTerminalLease := to == platformruntime.StatusSucceeded || to == platformruntime.StatusFailed
	if clearTerminalLease {
		// The terminal outcome fence has already confirmed settled effects.
		// Release the Run lease in the same transaction as its durable outcome;
		// retain the old token in memory until session ownership is released.
		updateStatus = `UPDATE platform_execution_run SET status=?, revision=?, updated_at=?, lease_token='', lease_until=NULL WHERE run_id=?`
	}
	if _, err = tx.Exec(sqlutil.Bind(updateStatus), run.Status, run.Revision, run.UpdatedAt, run.ID); err != nil {
		return platformruntime.Run{}, err
	}
	payload, _ := json.Marshal(map[string]any{"from": string(from), "to": string(to), "revision": run.Revision})
	if _, err = tx.Exec(sqlutil.Bind(`INSERT INTO platform_execution_event (run_id, event_type, payload, occurred_at) VALUES (?,?,?,?)`), run.ID, "status", payload, run.UpdatedAt); err != nil {
		return platformruntime.Run{}, err
	}
	if outcome != nil {
		// Only admission of a business run creates a conversation projection.
		// Internal index jobs have synthetic session IDs for lease isolation,
		// not conversation sessions, so they must not enqueue result projection.
		if outcome.ProjectionPending {
			var businessAdmission bool
			if err = tx.QueryRow(sqlutil.Bind(`SELECT EXISTS (SELECT 1 FROM platform_execution_creation_projection WHERE run_id=?)`), run.ID).Scan(&businessAdmission); err != nil {
				return platformruntime.Run{}, err
			}
			outcome.ProjectionPending = businessAdmission
		}
		eventPayload, marshalErr := json.Marshal(outcome.EventPayload)
		if marshalErr != nil {
			return platformruntime.Run{}, marshalErr
		}
		// One transaction owns status, response, terminal event and projection
		// intent. No cross-module business table is written here.
		// 同一事务保存状态、响应、终结事件和投影待办；不越界写业务模块表。
		if _, err = tx.Exec(sqlutil.Bind(`INSERT INTO platform_execution_outcome (run_id, revision, output_json, event_type, event_payload, projection_pending) VALUES (?,?,?,?,?,?) ON CONFLICT (run_id) DO UPDATE SET revision=EXCLUDED.revision, output_json=EXCLUDED.output_json, event_type=EXCLUDED.event_type, event_payload=EXCLUDED.event_payload, projection_pending=EXCLUDED.projection_pending`), run.ID, run.Revision, outcome.OutputJSON, outcome.EventType, eventPayload, outcome.ProjectionPending); err != nil {
			return platformruntime.Run{}, err
		}
		if _, err = tx.Exec(sqlutil.Bind(`INSERT INTO platform_execution_event (run_id, event_type, payload, occurred_at) VALUES (?,?,?,?)`), run.ID, outcome.EventType, eventPayload, run.UpdatedAt); err != nil {
			return platformruntime.Run{}, err
		}
	}
	if err = s.releaseSessionTx(tx, run); err != nil {
		return platformruntime.Run{}, err
	}
	if clearTerminalLease {
		run.LeaseToken = ""
		run.LeaseUntil = time.Time{}
	}
	if err = tx.Commit(); err != nil {
		return platformruntime.Run{}, err
	}
	return run, nil
}

// Cancel atomically fences the current Run, clears its lease and appends both
// status and audit events.  Keeping this operation transactional is important
// for cancellation: a caller must never observe cancelled without the durable
// task_cancelled event required by audit/replay consumers.
// Cancel 以事务完成 CAS、租约清理和审计事件追加，避免业务状态与审计脱节。
func (s *SQLStore) Cancel(id string, expectedRevision uint64) (platformruntime.Run, error) {
	return s.cancelWithEvidence(id, expectedRevision, nil, nil, nil)
}

func (s *SQLStore) CancelWithStopEvidence(id string, revision uint64, proof StopEvidence) (platformruntime.Run, error) {
	if proof.Source != "runtime-process-stop/v1" || len(proof.Digest) != 64 || len(proof.RuntimeID) != 64 {
		return platformruntime.Run{}, platformruntime.ErrInvalidRequest
	}
	return s.cancelWithEvidence(id, revision, &proof, nil, nil)
}

func (s *SQLStore) CancelWithWaitingHandoff(id string, revision uint64, receipt contract.HandlerHandoff) (platformruntime.Run, error) {
	return s.cancelWithEvidence(id, revision, nil, &receipt, nil)
}

func (s *SQLStore) CancelWithAgentGroupHandoff(id string, revision uint64, receipt contract.AgentGroupHandoff) (platformruntime.Run, error) {
	return s.cancelWithEvidence(id, revision, nil, nil, &receipt)
}

func (s *SQLStore) cancelWithEvidence(id string, expectedRevision uint64, proof *StopEvidence, handoff *contract.HandlerHandoff, group *contract.AgentGroupHandoff) (platformruntime.Run, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.cancelWithGuard(ctx, id, expectedRevision, proof, handoff, group, nil)
}

// A guard verifies a stop proof while the same transaction owns the Run lock.
// It cannot turn a read followed by a racing dispatch into a terminal outcome.
func (s *SQLStore) cancelWithGuard(ctx context.Context, id string, expectedRevision uint64, proof *StopEvidence, handoff *contract.HandlerHandoff, group *contract.AgentGroupHandoff, guard func(context.Context, *sql.Tx, platformruntime.Run) error) (platformruntime.Run, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return platformruntime.Run{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var run platformruntime.Run
	var status string
	var leaseUntil sql.NullTime
	err = tx.QueryRow(sqlutil.Bind(`SELECT run_id, tenant_id, department_id, application_id, agent_instance_id, agent_id, principal_id, principal_type, installation_id, agent_version_id, session_id, authorization_epoch, trace_id, idempotency_key, request_json, trace_context, resume_input_json, agent_endpoint, status, revision, lease_token, lease_until, created_at, updated_at FROM platform_execution_run WHERE run_id=? FOR UPDATE`), id).Scan(&run.ID, &run.Scope.TenantID, &run.Scope.DepartmentID, &run.Scope.ApplicationID, &run.Scope.AgentInstanceID, &run.Scope.AgentID, &run.Scope.PrincipalID, &run.Scope.PrincipalType, &run.Scope.InstallationID, &run.Scope.AgentVersionID, &run.Scope.SessionID, &run.Scope.AuthorizationEpoch, &run.Scope.TraceID, &run.IdempotencyKey, &run.RequestJSON, &run.TraceContext, &run.ResumeInputJSON, &run.AgentEndpoint, &status, &run.Revision, &run.LeaseToken, &leaseUntil, &run.CreatedAt, &run.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return platformruntime.Run{}, platformruntime.ErrRunNotFound
	}
	if err != nil {
		return platformruntime.Run{}, err
	}
	run.Scope.RunID = run.ID
	restoreParentRunID(&run)
	run.AgentVersionID = run.Scope.AgentVersionID
	if leaseUntil.Valid {
		run.LeaseUntil = leaseUntil.Time
	}
	run.Status = platformruntime.Status(status)
	if run.Status == platformruntime.StatusCancelled {
		if guard != nil {
			return platformruntime.Run{}, platformruntime.ErrRevisionConflict
		}
		if err = tx.Commit(); err != nil {
			return platformruntime.Run{}, err
		}
		return run, nil
	}
	if run.Status == platformruntime.StatusSucceeded || run.Status == platformruntime.StatusFailed {
		return platformruntime.Run{}, platformruntime.ErrInvalidTransition
	}
	if expectedRevision != 0 && run.Revision != expectedRevision {
		return platformruntime.Run{}, platformruntime.ErrRevisionConflict
	}
	if !transitionAllowed(run.Status, platformruntime.StatusCancelled) {
		return platformruntime.Run{}, platformruntime.ErrInvalidTransition
	}
	if guard != nil {
		if err := guard(ctx, tx, run); err != nil {
			return platformruntime.Run{}, err
		}
	}
	if group != nil {
		if run.Status != platformruntime.StatusCancelling || expectedRevision < 3 || run.LeaseToken == "" || proof != nil || handoff != nil || s.groupStopBarrier == nil {
			return platformruntime.Run{}, platformruntime.ErrInvalidTransition
		}
		ref, err := s.AgentGroupWaitReferenceTx(context.Background(), tx, run.ID, expectedRevision-1, run.LeaseToken)
		if err != nil {
			return platformruntime.Run{}, err
		}
		a, _ := json.Marshal(ref.Handoff)
		b, _ := json.Marshal(group)
		if string(a) != string(b) {
			return platformruntime.Run{}, platformruntime.ErrLeaseConflict
		}
		if err := s.groupStopBarrier(context.Background(), tx, run.Scope, ref.Handoff); err != nil {
			return platformruntime.Run{}, err
		}
		payload, err := json.Marshal(map[string]any{"source": "platform_group_wait_handoff", "agent_group_handoff": ref.Handoff})
		if err != nil {
			return platformruntime.Run{}, err
		}
		if _, err := tx.Exec(sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES(?,?,?,?)`), run.ID, "handler_exit_stop_confirmed", payload, time.Now().UTC()); err != nil {
			return platformruntime.Run{}, err
		}
	}
	if handoff != nil {
		if run.Status != platformruntime.StatusCancelling || expectedRevision < 3 || run.LeaseToken == "" || proof != nil {
			return platformruntime.Run{}, platformruntime.ErrInvalidTransition
		}
		committed, err := persistedWaitingHandoffTx(context.Background(), tx, run.ID, expectedRevision-1, run.LeaseToken)
		if err != nil {
			return platformruntime.Run{}, err
		}
		if committed != *handoff {
			return platformruntime.Run{}, platformruntime.ErrLeaseConflict
		}
		payload, err := json.Marshal(map[string]any{"source": "platform_waiting_handoff", "handoff": committed})
		if err != nil {
			return platformruntime.Run{}, err
		}
		if _, err = tx.Exec(sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES (?,?,?,?)`), run.ID, "handler_exit_stop_confirmed", payload, time.Now().UTC()); err != nil {
			return platformruntime.Run{}, err
		}
	}
	if proof != nil {
		if run.Status != platformruntime.StatusCancelling || expectedRevision == 0 || run.LeaseToken == "" {
			return platformruntime.Run{}, platformruntime.ErrInvalidTransition
		}
		payload, err := json.Marshal(proof)
		if err != nil {
			return platformruntime.Run{}, err
		}
		if _, err = s.dbProofEvent(tx, run.ID, payload); err != nil {
			return platformruntime.Run{}, err
		}
	}
	if s.cancellationSaga != nil {
		staged, stageErr := s.stageCancellationCompensationTx(ctx, tx, run, proof, handoff, group, guard != nil)
		if stageErr != nil {
			return platformruntime.Run{}, stageErr
		}
		if err := tx.Commit(); err != nil {
			return platformruntime.Run{}, err
		}
		return staged, nil
	}
	run, err = s.finishCancelledTx(ctx, tx, run, map[string]any{"source": "platform_cancel"})
	if err != nil {
		return platformruntime.Run{}, err
	}
	if err = tx.Commit(); err != nil {
		return platformruntime.Run{}, err
	}
	return run, nil
}

// The compensation coordinator and legacy stop path use the same local
// outcome transaction. Only the caller commits; no nested transaction exists.
func (s *SQLStore) finishCancelledTx(ctx context.Context, tx *sql.Tx, run platformruntime.Run, cancellation map[string]any) (platformruntime.Run, error) {
	from := run.Status
	run.Status = platformruntime.StatusCancelled
	run.LeaseToken = ""
	run.LeaseUntil = time.Time{}
	run.Revision++
	run.UpdatedAt = time.Now().UTC()
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_run SET status=?, revision=?, lease_token='', lease_until=NULL, updated_at=? WHERE run_id=? AND revision=?`), run.Status, run.Revision, run.UpdatedAt, run.ID, run.Revision-1)
	if err != nil {
		return platformruntime.Run{}, err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return platformruntime.Run{}, platformruntime.ErrRevisionConflict
	}
	statusPayload, _ := json.Marshal(map[string]any{"from": string(from), "to": string(platformruntime.StatusCancelled), "revision": run.Revision})
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event (run_id, event_type, payload, occurred_at) VALUES (?,?,?,?)`), run.ID, "status", statusPayload, run.UpdatedAt); err != nil {
		return platformruntime.Run{}, err
	}
	cancelPayload, err := json.Marshal(cancellation)
	if err != nil {
		return platformruntime.Run{}, err
	}
	// Terminal response and cancellation event share the state transaction.
	// 终态响应、取消事件与状态同事务，恢复结果时不得重新执行 Agent。
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_outcome (run_id,revision,output_json,event_type,event_payload,projection_pending) VALUES (?,?,?,?,?,?) ON CONFLICT (run_id) DO UPDATE SET revision=EXCLUDED.revision,output_json=EXCLUDED.output_json,event_type=EXCLUDED.event_type,event_payload=EXCLUDED.event_payload,projection_pending=EXCLUDED.projection_pending`), run.ID, run.Revision, []byte(`{}`), "task_cancelled", cancelPayload, false); err != nil {
		return platformruntime.Run{}, err
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event (run_id, event_type, payload, occurred_at) VALUES (?,?,?,?)`), run.ID, "task_cancelled", cancelPayload, run.UpdatedAt); err != nil {
		return platformruntime.Run{}, err
	}
	if err = s.releaseSessionTx(tx, run); err != nil {
		return platformruntime.Run{}, err
	}
	return run, nil
}

// PrepareResume persists a resume command and changes waiting to running in
// one transaction. The dispatcher can therefore recover the exact command
// from request_json after a process restart without a second resume ledger.
// PrepareResume 在同一事务中持久化恢复命令并完成 waiting -> running；
// 进程重启后 Dispatcher 仍可从 request_json 恢复准确的命令。
func (s *SQLStore) PrepareResume(id string, input []byte) (platformruntime.Run, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return platformruntime.Run{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var status string
	var revision uint64
	err = tx.QueryRow(sqlutil.Bind(`SELECT status, revision FROM platform_execution_run WHERE run_id=? FOR UPDATE`), id).Scan(&status, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return platformruntime.Run{}, platformruntime.ErrRunNotFound
	}
	if err != nil {
		return platformruntime.Run{}, err
	}
	if platformruntime.Status(status) != platformruntime.StatusWaiting {
		return platformruntime.Run{}, platformruntime.ErrInvalidTransition
	}
	if len(input) == 0 || !json.Valid(input) {
		return platformruntime.Run{}, platformruntime.ErrInvalidRequest
	}
	now := time.Now().UTC()
	if _, err = tx.Exec(sqlutil.Bind(`UPDATE platform_execution_run SET resume_input_json=?, status=?, revision=?, updated_at=?, lease_token='', lease_until=NULL WHERE run_id=? AND status=? AND revision=?`), input, platformruntime.StatusRunning, revision+1, now, id, platformruntime.StatusWaiting, revision); err != nil {
		return platformruntime.Run{}, err
	}
	payload, _ := json.Marshal(map[string]any{"from": string(platformruntime.StatusWaiting), "to": string(platformruntime.StatusRunning), "revision": revision + 1})
	if _, err = tx.Exec(sqlutil.Bind(`INSERT INTO platform_execution_event (run_id, event_type, payload, occurred_at) VALUES (?,?,?,?)`), id, "status", payload, now); err != nil {
		return platformruntime.Run{}, err
	}
	if err = tx.Commit(); err != nil {
		return platformruntime.Run{}, err
	}
	return s.Get(id)
}

func (s *SQLStore) Events(id string, afterSeq uint64) ([]platformruntime.Event, error) {
	return s.EventsContext(context.Background(), id, afterSeq)
}

// EventsContext reads a bounded replay page and follows stream cancellation.
// EventsContext 分页读取重放事件，并遵守流请求取消与超时。
func (s *SQLStore) EventsContext(ctx context.Context, id string, afterSeq uint64) ([]platformruntime.Event, error) {
	if _, err := s.Get(id); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT seq, event_type, payload, occurred_at FROM platform_execution_event WHERE run_id=? AND seq>? ORDER BY seq LIMIT 256`), id, afterSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []platformruntime.Event
	for rows.Next() {
		var event platformruntime.Event
		var raw []byte
		if err := rows.Scan(&event.Seq, &event.Type, &raw, &event.OccurredAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &event.Payload); err != nil {
			return nil, fmt.Errorf("decode execution event: %w", err)
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func (s *SQLStore) AppendEvent(id, eventType string, payload map[string]any) (platformruntime.Event, error) {
	if eventType == "" || eventType == "cancellation_stop_verified" {
		return platformruntime.Event{}, platformruntime.ErrInvalidTransition
	}
	if _, err := s.Get(id); err != nil {
		return platformruntime.Event{}, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return platformruntime.Event{}, fmt.Errorf("encode execution event: %w", err)
	}
	now := time.Now().UTC()
	var seq uint64
	err = s.db.QueryRow(sqlutil.Bind(`INSERT INTO platform_execution_event (run_id, event_type, payload, occurred_at) VALUES (?,?,?,?) RETURNING seq`), id, eventType, encoded, now).Scan(&seq)
	if err != nil {
		return platformruntime.Event{}, err
	}
	return platformruntime.Event{Seq: seq, Type: eventType, Payload: payload, OccurredAt: now}, nil
}

func (s *SQLStore) AcquireLease(id, token string, now time.Time, ttl time.Duration) (platformruntime.Run, error) {
	if token == "" || ttl <= 0 {
		return platformruntime.Run{}, platformruntime.ErrLeaseConflict
	}
	tx, err := s.db.Begin()
	if err != nil {
		return platformruntime.Run{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var currentToken string
	var leaseUntil sql.NullTime
	var revision uint64
	var status string
	var run platformruntime.Run
	run.ID = id
	err = tx.QueryRow(sqlutil.Bind(`SELECT lease_token, lease_until, revision, status,tenant_id,department_id,application_id,installation_id,agent_instance_id,agent_id,principal_type,principal_id,session_id,agent_version_id FROM platform_execution_run WHERE run_id=? FOR UPDATE`), id).Scan(&currentToken, &leaseUntil, &revision, &status, &run.Scope.TenantID, &run.Scope.DepartmentID, &run.Scope.ApplicationID, &run.Scope.InstallationID, &run.Scope.AgentInstanceID, &run.Scope.AgentID, &run.Scope.PrincipalType, &run.Scope.PrincipalID, &run.Scope.SessionID, &run.Scope.AgentVersionID)
	if errors.Is(err, sql.ErrNoRows) {
		return platformruntime.Run{}, platformruntime.ErrRunNotFound
	}
	if err != nil {
		return platformruntime.Run{}, err
	}
	if (status != string(platformruntime.StatusAccepted) && status != string(platformruntime.StatusRunning)) || (currentToken != "" && currentToken != token) {
		return platformruntime.Run{}, platformruntime.ErrLeaseConflict
	}
	until := now.Add(ttl)
	if err = s.claimSessionTx(tx, run, token, now, until); err != nil {
		return platformruntime.Run{}, err
	}
	if _, err = tx.Exec(sqlutil.Bind(`UPDATE platform_execution_run SET lease_token=?, lease_until=?, revision=?, updated_at=? WHERE run_id=?`), token, until, revision+1, now, id); err != nil {
		return platformruntime.Run{}, err
	}
	if err = s.RecordGenerationClaimTx(context.Background(), tx, id, platformruntime.Status(status), revision); err != nil {
		return platformruntime.Run{}, err
	}
	if err = tx.Commit(); err != nil {
		return platformruntime.Run{}, err
	}
	return s.Get(id)
}

func (s *SQLStore) Heartbeat(id, token string, expectedRevision uint64, now time.Time, ttl time.Duration) (platformruntime.Run, error) {
	return s.HeartbeatContext(context.Background(), id, token, expectedRevision, now, ttl)
}

func (s *SQLStore) HeartbeatContext(ctx context.Context, id, token string, expectedRevision uint64, now time.Time, ttl time.Duration) (platformruntime.Run, error) {
	if token == "" || ttl <= 0 {
		return platformruntime.Run{}, platformruntime.ErrLeaseConflict
	}
	// Heartbeats retain the command revision; reacquisition advances fencing.
	// 心跳保持命令版本，重新领取租约时才推进 fencing 版本。
	run, err := s.GetContext(ctx, id)
	if err != nil {
		return platformruntime.Run{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return platformruntime.Run{}, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_run SET lease_until=?, updated_at=? WHERE run_id=? AND lease_token=? AND revision=? AND lease_until>? AND status='running'`), now.Add(ttl), now, id, token, expectedRevision, now)
	if err != nil {
		return platformruntime.Run{}, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return platformruntime.Run{}, err
	}
	if count != 1 {
		if _, getErr := s.GetContext(ctx, id); errors.Is(getErr, platformruntime.ErrRunNotFound) {
			return platformruntime.Run{}, getErr
		}
		return platformruntime.Run{}, platformruntime.ErrLeaseConflict
	}
	result, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_session_lease SET lease_until=? WHERE session_key=? AND run_id=? AND lease_token=? AND lease_until>?`), now.Add(ttl), platformruntime.SessionExecutionKey(run.Scope), id, token, now)
	if err != nil {
		return platformruntime.Run{}, err
	}
	count, err = result.RowsAffected()
	if err != nil {
		return platformruntime.Run{}, err
	}
	if count != 1 {
		return platformruntime.Run{}, platformruntime.ErrLeaseConflict
	}
	if err = tx.Commit(); err != nil {
		return platformruntime.Run{}, err
	}
	return s.GetContext(ctx, id)
}

func transitionAllowed(from, to platformruntime.Status) bool {
	return map[platformruntime.Status]map[platformruntime.Status]bool{
		platformruntime.StatusAccepted:   {platformruntime.StatusRunning: true, platformruntime.StatusCancelled: true, platformruntime.StatusFailed: true},
		platformruntime.StatusRunning:    {platformruntime.StatusWaiting: true, platformruntime.StatusSucceeded: true, platformruntime.StatusFailed: true, platformruntime.StatusCancelled: true},
		platformruntime.StatusWaiting:    {platformruntime.StatusRunning: true, platformruntime.StatusSucceeded: true, platformruntime.StatusFailed: true, platformruntime.StatusCancelled: true},
		platformruntime.StatusCancelling: {platformruntime.StatusCancelled: true},
	}[from][to]
}

var _ Repository = (*SQLStore)(nil)
