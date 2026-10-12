package usagecost

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"strings"
	"sync"
	"time"
)

var (
	ErrBudgetExceeded = errors.New("usage budget exceeded")
	ErrUsageConflict  = errors.New("usage event conflicts with an existing event")
	ErrInvalidUsage   = errors.New("invalid usage event")
)

type Scope struct {
	TenantID       string `json:"tenant_id"`
	DepartmentID   string `json:"department_id"`
	ApplicationID  string `json:"application_id"`
	AgentID        string `json:"agent_id"`
	AgentVersionID string `json:"agent_version_id"`
	RunID          string `json:"run_id"`
}

// Recorder is the narrow boundary used by capability calls to publish durable
// usage. The implementation can stay local to the modular monolith today and
// be replaced by a remote Usage service later.
type Recorder interface {
	Apply(context.Context, Event) (Snapshot, error)
}

type Event struct {
	ID           string  `json:"id"`
	StepID       *string `json:"step_id,omitempty"`
	Scope        Scope   `json:"scope"`
	Provider     string  `json:"provider"`
	Model        string  `json:"model"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	CostMicros   int64   `json:"cost_micros"`
}

func (e Event) Validate() error {
	if e.ID == "" || !validScope(e.Scope) || e.InputTokens < 0 || e.OutputTokens < 0 || e.CostMicros < 0 {
		return ErrInvalidUsage
	}
	if e.StepID != nil && (*e.StepID == "" || len(*e.StepID) > 128 || strings.TrimSpace(*e.StepID) != *e.StepID || strings.ContainsAny(*e.StepID, "\x00\r\n")) {
		return ErrInvalidUsage
	}
	return nil
}

func validScope(scope Scope) bool {
	return scope.TenantID != "" && scope.DepartmentID != "" && scope.ApplicationID != "" &&
		scope.AgentID != "" && scope.AgentVersionID != "" && scope.RunID != ""
}

type Budget struct {
	ScopeKey    string `json:"scope_key"`
	LimitMicros int64  `json:"limit_micros"`
}

type Snapshot struct {
	ScopeKey     string                `json:"scope_key"`
	LastEventID  string                `json:"last_event_id"`
	UsedMicros   int64                 `json:"used_micros"`
	InputTokens  int64                 `json:"input_tokens"`
	OutputTokens int64                 `json:"output_tokens"`
	RunBudget    *RunTreeBudgetReceipt `json:"run_budget,omitempty"`
}

type Ledger struct {
	mu        sync.Mutex
	events    map[string]Event
	createdAt map[string]time.Time
	used      map[string]Snapshot
	budgets   map[string]Budget
}

func NewLedger() *Ledger {
	return &Ledger{events: make(map[string]Event), createdAt: make(map[string]time.Time), used: make(map[string]Snapshot), budgets: make(map[string]Budget)}
}

func ScopeKey(scope Scope) string {
	return scope.TenantID + ":" + scope.DepartmentID + ":" + scope.ApplicationID + ":" + scope.AgentID + ":" + scope.AgentVersionID
}

func (l *Ledger) SetBudget(b Budget) error {
	if b.ScopeKey == "" || b.LimitMicros < 0 {
		return ErrInvalidUsage
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.budgets[b.ScopeKey] = b
	return nil
}

func (l *Ledger) Apply(event Event) (Snapshot, error) {
	if err := event.Validate(); err != nil {
		return Snapshot{}, err
	}
	key := ScopeKey(event.Scope)
	l.mu.Lock()
	defer l.mu.Unlock()
	if prior, ok := l.events[event.ID]; ok {
		// The event ID is an immutable idempotency key.  Compare every billing
		// dimension, including provider/model and RunID, so an ID cannot be
		// replayed under another execution while retaining the old charge.
		if prior.CostMicros != event.CostMicros || prior.InputTokens != event.InputTokens || prior.OutputTokens != event.OutputTokens || prior.Provider != event.Provider || prior.Model != event.Model || prior.Scope != event.Scope || !compatibleStepID(prior.StepID, event.StepID) {
			return Snapshot{}, ErrUsageConflict
		}
		return l.used[key], nil
	}
	current := l.used[key]
	budget, hasBudget := l.budgets[key]
	// Subtraction avoids signed integer overflow turning an over-budget event
	// into a negative or otherwise apparently affordable total.
	if hasBudget && (current.UsedMicros > budget.LimitMicros || event.CostMicros > budget.LimitMicros-current.UsedMicros) {
		return current, ErrBudgetExceeded
	}
	if event.CostMicros > maxInt64-current.UsedMicros || event.InputTokens > maxInt64-current.InputTokens || event.OutputTokens > maxInt64-current.OutputTokens {
		return current, ErrInvalidUsage
	}
	eventCopy := event
	eventCopy.StepID = cloneStepID(event.StepID)
	l.events[event.ID] = eventCopy
	l.createdAt[event.ID] = time.Now().UTC()
	current.ScopeKey = key
	current.LastEventID = event.ID
	current.UsedMicros += event.CostMicros
	current.InputTokens += event.InputTokens
	current.OutputTokens += event.OutputTokens
	l.used[key] = current
	return current, nil
}

const maxInt64 = int64(^uint64(0) >> 1)

func (l *Ledger) Snapshot(scope Scope) Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.used[ScopeKey(scope)]
}

// SQLStore is the single-instance durable usage/cost ledger. Events are
// immutable idempotency records; the snapshot is updated in the same
// transaction so budget checks cannot race concurrent model calls.
type SQLStore struct {
	db  *sql.DB
	now func() time.Time
}

func NewSQLStore(db *sql.DB) *SQLStore { return &SQLStore{db: db} }

// ReconciliationSnapshot is read from the durable reservation ledger so a
// process restart cannot reset pending financial work to zero.
type ReconciliationSnapshot struct {
	Pending  int64
	OldestAt time.Time
}

func (s *SQLStore) ReconciliationSnapshot(ctx context.Context) (ReconciliationSnapshot, error) {
	if s == nil || s.db == nil {
		return ReconciliationSnapshot{}, errors.New("model budget database is required")
	}
	var result ReconciliationSnapshot
	var oldest sql.NullTime
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*),MIN(updated_at) FROM platform_model_budget_reservation WHERE status='reconcile'`)).Scan(&result.Pending, &oldest)
	if err != nil {
		return ReconciliationSnapshot{}, fmt.Errorf("read budget reconciliation snapshot: %w", err)
	}
	if oldest.Valid {
		result.OldestAt = oldest.Time.UTC()
	}
	return result, nil
}

func (s *SQLStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("usage database is required")
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS platform_usage_budget (
			scope_key VARCHAR(512) PRIMARY KEY, limit_micros BIGINT NOT NULL
		);
`,
		`CREATE TABLE IF NOT EXISTS platform_usage_event (
			event_id VARCHAR(128) PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL, application_id VARCHAR(128) NOT NULL,
			agent_id VARCHAR(128) NOT NULL, agent_version_id VARCHAR(128) NOT NULL,
			run_id VARCHAR(128) NOT NULL, provider VARCHAR(128) NOT NULL,
			model VARCHAR(255) NOT NULL, input_tokens BIGINT NOT NULL,
			output_tokens BIGINT NOT NULL, cost_micros BIGINT NOT NULL, step_id VARCHAR(128) NULL,
			created_at TIMESTAMPTZ(6) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_platform_usage_scope ON platform_usage_event (tenant_id,department_id,application_id,agent_id,agent_version_id,run_id);
CREATE INDEX IF NOT EXISTS idx_platform_usage_time ON platform_usage_event (tenant_id,department_id,application_id,created_at);
CREATE INDEX IF NOT EXISTS idx_platform_usage_run_time ON platform_usage_event (tenant_id,department_id,application_id,run_id,created_at);`,
		`ALTER TABLE platform_usage_event ADD COLUMN IF NOT EXISTS step_id VARCHAR(128) NULL;`,
		`CREATE TABLE IF NOT EXISTS platform_usage_snapshot (
			scope_key VARCHAR(512) PRIMARY KEY, last_event_id VARCHAR(128) NOT NULL,
			used_micros BIGINT NOT NULL, input_tokens BIGINT NOT NULL,
			output_tokens BIGINT NOT NULL, updated_at TIMESTAMPTZ(6) NOT NULL
		);
`,
		`CREATE TABLE IF NOT EXISTS platform_model_budget_window (
			window_id VARCHAR(64) PRIMARY KEY, scope_hash VARCHAR(64) NOT NULL,
			scope_json VARCHAR(1024) NOT NULL, window_start TIMESTAMPTZ(6) NOT NULL,
			window_end TIMESTAMPTZ(6) NOT NULL, budget_limit_micros BIGINT NOT NULL,
			actual_micros BIGINT NOT NULL, reserved_micros BIGINT NOT NULL,
			revision BIGINT NOT NULL, created_at TIMESTAMPTZ(6) NOT NULL,
			updated_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_model_budget_scope_window UNIQUE(scope_hash,window_start,window_end));
CREATE INDEX IF NOT EXISTS idx_model_budget_window_end ON platform_model_budget_window (window_end);`,
		`CREATE TABLE IF NOT EXISTS platform_model_budget_reservation (
			reservation_id VARCHAR(32) PRIMARY KEY, window_id VARCHAR(64) NOT NULL,
			tenant_id VARCHAR(128) NOT NULL, department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL, agent_id VARCHAR(128) NOT NULL,
			agent_version_id VARCHAR(128) NOT NULL, run_id VARCHAR(128) NOT NULL,
			request_id VARCHAR(128) NOT NULL, request_fingerprint VARCHAR(64) NOT NULL,
			price_version_id VARCHAR(128) NOT NULL, budget_limit_micros BIGINT NOT NULL,
			reserve_micros BIGINT NOT NULL, settled_micros BIGINT NOT NULL,
			status VARCHAR(16) NOT NULL, event_id VARCHAR(128) NOT NULL DEFAULT '',
			terminal_reason VARCHAR(32) NOT NULL DEFAULT '', expires_at TIMESTAMPTZ(6) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL, updated_at TIMESTAMPTZ(6) NOT NULL,
			settled_at TIMESTAMPTZ(6) NULL, released_at TIMESTAMPTZ(6) NULL,
			CONSTRAINT uq_model_budget_idempotency UNIQUE(window_id,request_id));
CREATE INDEX IF NOT EXISTS idx_model_budget_expiry ON platform_model_budget_reservation (window_id,status,expires_at);
CREATE INDEX IF NOT EXISTS idx_model_budget_run ON platform_model_budget_reservation (tenant_id,department_id,application_id,run_id);
CREATE INDEX IF NOT EXISTS idx_model_budget_reconcile ON platform_model_budget_reservation (status,updated_at);`,
		`CREATE TABLE IF NOT EXISTS platform_model_budget_settlement (
			reservation_id VARCHAR(32) PRIMARY KEY, event_id VARCHAR(128) NOT NULL,
			price_version_id VARCHAR(128) NOT NULL, settled_micros BIGINT NOT NULL,
			settled_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_model_budget_settlement_event UNIQUE(event_id)
		);
`,
		`CREATE TABLE IF NOT EXISTS platform_model_budget_manual_resolution (
			reservation_id VARCHAR(32) PRIMARY KEY, receipt_hash VARCHAR(64) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL
		);
`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, sqlutil.Bind(statement)); err != nil {
			return fmt.Errorf("usage schema: %w", err)
		}
	}
	return nil
}

func (s *SQLStore) SetBudget(ctx context.Context, budget Budget) error {
	if strings.TrimSpace(budget.ScopeKey) == "" || budget.LimitMicros < 0 {
		return ErrInvalidUsage
	}
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_usage_budget(scope_key,limit_micros) VALUES(?,?) ON CONFLICT (scope_key) DO UPDATE SET limit_micros=EXCLUDED.limit_micros`), budget.ScopeKey, budget.LimitMicros)
	if err != nil {
		return fmt.Errorf("set usage budget: %w", err)
	}
	return nil
}

// Apply records one immutable event and returns the current aggregate. Exact
// retries are safe; reusing an event ID with different billing dimensions is
// rejected.
func (s *SQLStore) Apply(ctx context.Context, event Event) (Snapshot, error) {
	if err := event.Validate(); err != nil {
		return Snapshot{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, fmt.Errorf("begin usage transaction: %w", err)
	}
	defer tx.Rollback()
	key := ScopeKey(event.Scope)
	// Materialize and lock the aggregate before any missing-row FOR UPDATE
	// read. Concurrent first events otherwise acquire compatible gap locks
	// and deadlock when each tries to insert the same aggregate afterward.
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_usage_snapshot(scope_key,last_event_id,used_micros,input_tokens,output_tokens,updated_at) VALUES(?,'',0,0,0,?) ON CONFLICT (scope_key) DO UPDATE SET scope_key=EXCLUDED.scope_key`), key, time.Now().UTC())
	if err != nil {
		return Snapshot{}, fmt.Errorf("initialize usage snapshot: %w", err)
	}
	var snapshot Snapshot
	var budget int64
	var hasBudget bool
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT limit_micros FROM platform_usage_budget WHERE scope_key=? FOR UPDATE`), key).Scan(&budget)
	if err == nil {
		hasBudget = true
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, fmt.Errorf("lock usage budget: %w", err)
	}
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT last_event_id,used_micros,input_tokens,output_tokens FROM platform_usage_snapshot WHERE scope_key=? FOR UPDATE`), key).Scan(&snapshot.LastEventID, &snapshot.UsedMicros, &snapshot.InputTokens, &snapshot.OutputTokens)
	if errors.Is(err, sql.ErrNoRows) {
		snapshot.ScopeKey = key
	} else if err != nil {
		return Snapshot{}, fmt.Errorf("lock usage snapshot: %w", err)
	} else {
		snapshot.ScopeKey = key
	}
	var existing Event
	var existingStepID sql.NullString
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT tenant_id,department_id,application_id,agent_id,agent_version_id,run_id,provider,model,input_tokens,output_tokens,cost_micros,step_id FROM platform_usage_event WHERE event_id=? FOR UPDATE`), event.ID).Scan(
		&existing.Scope.TenantID, &existing.Scope.DepartmentID, &existing.Scope.ApplicationID, &existing.Scope.AgentID, &existing.Scope.AgentVersionID, &existing.Scope.RunID, &existing.Provider, &existing.Model, &existing.InputTokens, &existing.OutputTokens, &existing.CostMicros, &existingStepID)
	if err == nil {
		if existingStepID.Valid {
			existing.StepID = &existingStepID.String
		}
		if existing.Scope != event.Scope || existing.Provider != event.Provider || existing.Model != event.Model || existing.InputTokens != event.InputTokens || existing.OutputTokens != event.OutputTokens || existing.CostMicros != event.CostMicros || !compatibleStepID(existing.StepID, event.StepID) {
			return Snapshot{}, ErrUsageConflict
		}
		if err = tx.Commit(); err != nil {
			return Snapshot{}, err
		}
		return snapshot, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, fmt.Errorf("lookup usage event: %w", err)
	}
	if hasBudget && (snapshot.UsedMicros > budget || event.CostMicros > budget-snapshot.UsedMicros) {
		return snapshot, ErrBudgetExceeded
	}
	if event.CostMicros > maxInt64-snapshot.UsedMicros || event.InputTokens > maxInt64-snapshot.InputTokens || event.OutputTokens > maxInt64-snapshot.OutputTokens {
		return snapshot, ErrInvalidUsage
	}
	created := time.Now().UTC()
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_usage_event(event_id,tenant_id,department_id,application_id,agent_id,agent_version_id,run_id,provider,model,input_tokens,output_tokens,cost_micros,step_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), event.ID, event.Scope.TenantID, event.Scope.DepartmentID, event.Scope.ApplicationID, event.Scope.AgentID, event.Scope.AgentVersionID, event.Scope.RunID, event.Provider, event.Model, event.InputTokens, event.OutputTokens, event.CostMicros, event.StepID, created)
	if err != nil {
		return Snapshot{}, fmt.Errorf("record usage event: %w", err)
	}
	snapshot.ScopeKey = key
	snapshot.LastEventID = event.ID
	snapshot.UsedMicros += event.CostMicros
	snapshot.InputTokens += event.InputTokens
	snapshot.OutputTokens += event.OutputTokens
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_usage_snapshot(scope_key,last_event_id,used_micros,input_tokens,output_tokens,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT (scope_key) DO UPDATE SET last_event_id=EXCLUDED.last_event_id,used_micros=EXCLUDED.used_micros,input_tokens=EXCLUDED.input_tokens,output_tokens=EXCLUDED.output_tokens,updated_at=EXCLUDED.updated_at`), snapshot.ScopeKey, snapshot.LastEventID, snapshot.UsedMicros, snapshot.InputTokens, snapshot.OutputTokens, created)
	if err != nil {
		return Snapshot{}, fmt.Errorf("update usage snapshot: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return Snapshot{}, fmt.Errorf("commit usage transaction: %w", err)
	}
	return snapshot, nil
}

func (s *SQLStore) GetSnapshot(ctx context.Context, scope Scope) (Snapshot, error) {
	if !validScope(scope) {
		return Snapshot{}, ErrInvalidUsage
	}
	var snapshot Snapshot
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT scope_key,last_event_id,used_micros,input_tokens,output_tokens FROM platform_usage_snapshot WHERE scope_key=?`), ScopeKey(scope)).Scan(&snapshot.ScopeKey, &snapshot.LastEventID, &snapshot.UsedMicros, &snapshot.InputTokens, &snapshot.OutputTokens)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{ScopeKey: ScopeKey(scope)}, nil
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("get usage snapshot: %w", err)
	}
	return snapshot, nil
}

var _ Recorder = (*SQLStore)(nil)
