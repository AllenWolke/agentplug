package capability

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"sync"
	"time"
)

// ModelInvocation is the platform-owned idempotency record for one model call.
// ModelInvocation 是平台所有的单次模型调用幂等记录。
type ModelInvocation struct {
	ScopeHash        string
	Key              string
	Fingerprint      string
	Status           string
	Response         map[string]any
	CostCents        int64
	Recovery         *BillingRecovery
	RetryAt          time.Time
	AttemptToken     string
	PreparationUntil time.Time
	// RecoveryCorrupt is a safe diagnostic, never the raw persisted payload.
	// 仅传播安全诊断标志，不传播损坏记录中的原始敏感内容。
	RecoveryCorrupt bool
}

var (
	ErrModelInvocationConflict             = errors.New("model invocation idempotency conflict")
	ErrModelInvocationPending              = errors.New("model invocation is still running")
	ErrModelInvocationReconciliationNeeded = errors.New("model invocation requires reconciliation")
	ErrModelBudgetExceeded                 = errors.New("model budget exceeded")
)

// ModelInvocationStore is deliberately smaller than the SQL implementation so
// the modular monolith can later replace it with a remote usage service.
// ModelInvocationStore 是可替换 Port，后续可以迁移到远程用量服务。
type ModelInvocationStore interface {
	EnsureSchema(context.Context) error
	Reserve(context.Context, string, string, string, int64, int64) (ModelInvocation, bool, error)
	Complete(context.Context, string, string, string, map[string]any, int64) error
}

// ModelInvocationFailureStore is an optional terminal-state port used when a
// configured provider returns an error. Failed keys may then be safely retried.
type ModelInvocationFailureStore interface {
	Fail(context.Context, string, string, string) error
}

// ModelInvocationReconciliationStore persists that a provider may have
// produced a billable result even when the usage settlement could not commit.
type ModelInvocationReconciliationStore interface {
	MarkReconciliationNeeded(context.Context, string, string, string, map[string]any, int64) error
}

type memoryModelInvocationStore struct {
	mu      sync.Mutex
	records map[string]ModelInvocation
	spent   map[string]int64
}

// newMemoryModelInvocationStore is used only by unit tests and no-DB mode.
func newMemoryModelInvocationStore() *memoryModelInvocationStore {
	return &memoryModelInvocationStore{records: make(map[string]ModelInvocation), spent: make(map[string]int64)}
}

func (s *memoryModelInvocationStore) EnsureSchema(context.Context) error { return nil }

func (s *memoryModelInvocationStore) Reserve(_ context.Context, scopeHash, key, fingerprint string, budget, estimate int64) (ModelInvocation, bool, error) {
	return s.reserveModel(scopeHash, key, fingerprint, budget, estimate, "", time.Time{})
}

func (s *memoryModelInvocationStore) reserveModel(scopeHash, key, fingerprint string, budget, estimate int64, token string, until time.Time) (ModelInvocation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	compound := scopeHash + "\x00" + key
	if existing, ok := s.records[compound]; ok {
		if existing.Fingerprint != fingerprint {
			return ModelInvocation{}, false, ErrModelInvocationConflict
		}
		if existing.Status == "failed" {
			existing.Status = "running"
			existing.Response = nil
			existing.Recovery = nil
			existing.CostCents = 0
			existing.RetryAt = time.Time{}
			existing.AttemptToken, existing.PreparationUntil = token, until
			s.records[compound] = existing
			return cloneInvocation(existing), false, nil
		}
		if existing.Status == "reconcile" {
			return ModelInvocation{}, false, ErrModelInvocationReconciliationNeeded
		}
		if existing.Status != "completed" {
			return ModelInvocation{}, false, ErrModelInvocationPending
		}
		return cloneInvocation(existing), true, nil
	}
	if budget > 0 && s.spent[scopeHash]+estimate > budget {
		return ModelInvocation{}, false, ErrModelBudgetExceeded
	}
	record := ModelInvocation{ScopeHash: scopeHash, Key: key, Fingerprint: fingerprint, Status: "running", AttemptToken: token, PreparationUntil: until}
	s.records[compound] = record
	return cloneInvocation(record), false, nil
}

func (s *memoryModelInvocationStore) Fail(_ context.Context, scopeHash, key, fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	compound := scopeHash + "\x00" + key
	existing, ok := s.records[compound]
	if !ok || existing.Fingerprint != fingerprint || existing.Status != "running" {
		return ErrModelInvocationConflict
	}
	existing.Status = "failed"
	existing.Response = nil
	s.records[compound] = existing
	return nil
}

func (s *memoryModelInvocationStore) Complete(_ context.Context, scopeHash, key, fingerprint string, response map[string]any, cost int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	compound := scopeHash + "\x00" + key
	existing, ok := s.records[compound]
	if ok && existing.Status == "completed" && existing.Fingerprint == fingerprint && existing.CostCents == cost {
		a, errA := json.Marshal(existing.Response)
		b, errB := json.Marshal(response)
		if errA == nil && errB == nil && string(a) == string(b) {
			return nil
		}
	}
	if !ok || existing.Fingerprint != fingerprint || existing.Status != "running" && existing.Status != "reconcile" {
		return ErrModelInvocationConflict
	}
	existing.Status = "completed"
	existing.Response = cloneMap(response)
	existing.CostCents = cost
	s.records[compound] = existing
	s.spent[scopeHash] += cost
	return nil
}

func (s *memoryModelInvocationStore) MarkReconciliationNeeded(_ context.Context, scopeHash, key, fingerprint string, response map[string]any, cost int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	compound := scopeHash + "\x00" + key
	existing, ok := s.records[compound]
	if !ok || existing.Fingerprint != fingerprint || existing.Status != "running" && existing.Status != "reconcile" {
		return ErrModelInvocationConflict
	}
	existing.Status = "reconcile"
	existing.Response = cloneMap(response)
	existing.CostCents = cost
	s.records[compound] = existing
	return nil
}

func cloneInvocation(value ModelInvocation) ModelInvocation {
	value.Response = cloneMap(value.Response)
	if value.Recovery != nil {
		raw, err := json.Marshal(value.Recovery)
		if err == nil {
			var cloned BillingRecovery
			if json.Unmarshal(raw, &cloned) == nil {
				value.Recovery = &cloned
			}
		}
	}
	return value
}

func cloneMap(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

// SQLModelInvocationStore provides transactional idempotency and budget
// accounting for a single platform process. A remote store can implement the
// same Port when the platform becomes distributed.
type SQLModelInvocationStore struct{ db *sql.DB }

func NewSQLModelInvocationStore(db *sql.DB) (*SQLModelInvocationStore, error) {
	if db == nil {
		return nil, errors.New("model invocation database is required")
	}
	return &SQLModelInvocationStore{db: db}, nil
}

func (s *SQLModelInvocationStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`
CREATE TABLE IF NOT EXISTS platform_model_invocation (
  scope_hash VARCHAR(64) NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  fingerprint VARCHAR(64) NOT NULL,
  status VARCHAR(16) NOT NULL,
  response_json TEXT NULL,
  cost_cents BIGINT NOT NULL DEFAULT 0,
  billing_recovery_json TEXT NULL,
  billing_state VARCHAR(16) NOT NULL DEFAULT '',
  billing_retry_at TIMESTAMPTZ(6) NULL,
  invocation_token VARCHAR(32) NOT NULL DEFAULT '',
  preparation_deadline TIMESTAMPTZ(6) NULL,
  created_at TIMESTAMPTZ(6) NOT NULL,
  updated_at TIMESTAMPTZ(6) NOT NULL,
  PRIMARY KEY (scope_hash, idempotency_key));
CREATE INDEX IF NOT EXISTS idx_platform_model_invocation_scope ON platform_model_invocation (scope_hash, status);`))
	if err != nil {
		return fmt.Errorf("migrate model invocation: %w", err)
	}
	_, err = s.db.ExecContext(ctx, sqlutil.Bind(`CREATE TABLE IF NOT EXISTS platform_model_billing_decision (
scope_hash VARCHAR(64) NOT NULL,idempotency_key VARCHAR(255) NOT NULL,reservation_id VARCHAR(128) NOT NULL,
decision_id VARCHAR(64) NOT NULL,decision_json TEXT NOT NULL,status VARCHAR(16) NOT NULL,
created_at TIMESTAMPTZ(6) NOT NULL,applied_at TIMESTAMPTZ(6) NULL,
PRIMARY KEY(scope_hash,idempotency_key,reservation_id)
);
`))
	return err
}

func (s *SQLModelInvocationStore) Reserve(ctx context.Context, scopeHash, key, fingerprint string, budget, estimate int64) (ModelInvocation, bool, error) {
	return retryModelReservation(ctx, func() (ModelInvocation, bool, error) {
		return s.reserveModel(ctx, scopeHash, key, fingerprint, budget, estimate, "", time.Time{})
	})
}

func (s *SQLModelInvocationStore) reserveModel(ctx context.Context, scopeHash, key, fingerprint string, budget, estimate int64, token string, until time.Time) (ModelInvocation, bool, error) {
	state := ""
	var deadline any
	if token != "" {
		state, deadline = "preparing", until.UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ModelInvocation{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockLedgerScope(ctx, tx, "model-invocation", scopeHash); err != nil {
		return ModelInvocation{}, false, err
	}
	var existing ModelInvocation
	var responseJSON sql.NullString
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT fingerprint,status,response_json,cost_cents FROM platform_model_invocation WHERE scope_hash=? AND idempotency_key=? FOR UPDATE`), scopeHash, key).Scan(&existing.Fingerprint, &existing.Status, &responseJSON, &existing.CostCents)
	if err == nil {
		existing.ScopeHash, existing.Key = scopeHash, key
		if existing.Fingerprint != fingerprint {
			return ModelInvocation{}, false, ErrModelInvocationConflict
		}
		if existing.Status == "failed" {
			if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET status='running',response_json=NULL,cost_cents=0,billing_recovery_json=NULL,billing_state=?,billing_retry_at=NULL,invocation_token=?,preparation_deadline=?,updated_at=clock_timestamp() WHERE scope_hash=? AND idempotency_key=? AND fingerprint=? AND status='failed'`), state, token, deadline, scopeHash, key, fingerprint); err != nil {
				return ModelInvocation{}, false, err
			}
			if err = tx.Commit(); err != nil {
				return ModelInvocation{}, false, err
			}
			return ModelInvocation{ScopeHash: scopeHash, Key: key, Fingerprint: fingerprint, Status: "running", AttemptToken: token, PreparationUntil: until}, false, nil
		}
		if existing.Status == "reconcile" {
			return ModelInvocation{}, false, ErrModelInvocationReconciliationNeeded
		}
		if existing.Status != "completed" {
			return ModelInvocation{}, false, ErrModelInvocationPending
		}
		if responseJSON.Valid && responseJSON.String != "" && json.Unmarshal([]byte(responseJSON.String), &existing.Response) != nil {
			return ModelInvocation{}, false, errors.New("corrupt model invocation response")
		}
		if err = tx.Commit(); err != nil {
			return ModelInvocation{}, false, err
		}
		return existing, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ModelInvocation{}, false, err
	}
	if budget > 0 {
		var spent int64
		if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COALESCE(SUM(cost_cents),0) FROM platform_model_invocation WHERE scope_hash=? AND status='completed'`), scopeHash).Scan(&spent); err != nil {
			return ModelInvocation{}, false, err
		}
		if spent+estimate > budget {
			return ModelInvocation{}, false, ErrModelBudgetExceeded
		}
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_invocation(scope_hash,idempotency_key,fingerprint,status,cost_cents,billing_state,invocation_token,preparation_deadline,created_at,updated_at) VALUES(?,?,?,'running',0,?,?,?,clock_timestamp(),clock_timestamp())`), scopeHash, key, fingerprint, state, token, deadline)
	if err != nil {
		return ModelInvocation{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return ModelInvocation{}, false, err
	}
	return ModelInvocation{ScopeHash: scopeHash, Key: key, Fingerprint: fingerprint, Status: "running", AttemptToken: token, PreparationUntil: until}, false, nil
}

func (s *SQLModelInvocationStore) Fail(ctx context.Context, scopeHash, key, fingerprint string) error {
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET status='failed',response_json=NULL,updated_at=clock_timestamp() WHERE scope_hash=? AND idempotency_key=? AND fingerprint=? AND status='running'`), scopeHash, key, fingerprint)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrModelInvocationConflict
	}
	return nil
}

func (s *SQLModelInvocationStore) Complete(ctx context.Context, scopeHash, key, fingerprint string, response map[string]any, cost int64) error {
	raw, err := json.Marshal(response)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET status='completed',billing_state='done',billing_retry_at=NULL,response_json=?,cost_cents=?,updated_at=clock_timestamp() WHERE scope_hash=? AND idempotency_key=? AND fingerprint=? AND status IN ('running','reconcile')`), string(raw), cost, scopeHash, key, fingerprint)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		// Concurrent direct settlement and recovery may finish the same receipt.
		// 请求线程和对账线程可能同时提交同一响应；只允许完全相同的完成回放。
		var storedFingerprint, status, storedJSON string
		var storedCost int64
		if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT fingerprint,status,response_json,cost_cents FROM platform_model_invocation WHERE scope_hash=? AND idempotency_key=?`), scopeHash, key).Scan(&storedFingerprint, &status, &storedJSON, &storedCost); err != nil {
			return err
		}
		if storedFingerprint != fingerprint || status != "completed" || storedCost != cost || storedJSON != string(raw) {
			return ErrModelInvocationConflict
		}
	}
	return nil
}

func (s *SQLModelInvocationStore) MarkReconciliationNeeded(ctx context.Context, scopeHash, key, fingerprint string, response map[string]any, cost int64) error {
	var raw []byte
	var err error
	if response != nil {
		raw, err = json.Marshal(response)
		if err != nil {
			return err
		}
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET status='reconcile',response_json=?,cost_cents=?,updated_at=clock_timestamp() WHERE scope_hash=? AND idempotency_key=? AND fingerprint=? AND status IN ('running','reconcile')`), nullableJSON(raw), cost, scopeHash, key, fingerprint)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 1 {
		return nil
	}
	return ErrModelInvocationConflict
}

func nullableJSON(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
}

var _ ModelInvocationStore = (*SQLModelInvocationStore)(nil)
