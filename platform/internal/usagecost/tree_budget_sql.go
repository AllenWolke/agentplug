package usagecost

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// RunTreeBudgetFacts must be derived from Execution, coordination provenance
// and the immutable root policy. Admission additionally holds current IAM and
// execution-fence continuity. Accounting may outlive permission revocation:
// known provider charges still belong to the original verified execution.
type RunTreeBudgetFacts struct {
	ActorScope     sharedkernel.Scope
	RootScope      sharedkernel.Scope
	PolicyHash     string
	LimitMicros    int64
	LimitTokens    int64
	EvaluationRoot bool
}

type RunTreeBudgetCommand struct {
	Action             string
	RequestID          string
	Fingerprint        string
	Hold               RunTreeBudgetHold
	OutcomeFingerprint string
	ActualMicros       int64
	InputTokens        int64
	OutputTokens       int64
}

// Outcome verification must use an immutable actual provider receipt, not a
// client assertion. release_unbilled requires terminal proof of no billing.
type RunTreeBudgetAuthority interface {
	Facts(context.Context, *sql.Tx, sharedkernel.Scope, bool) (RunTreeBudgetFacts, error)
	VerifyOutcome(context.Context, *sql.Tx, sharedkernel.Scope, RunTreeBudgetCommand) error
}

// Optional live read fence. It retains current IAM, execution lease, ancestry
// and policy checks, but permits shared execution locks for a counter read.
// Reserve/settle/release must continue to use Facts and their write fences.
type RunTreeBudgetReadAuthority interface {
	ReadFacts(context.Context, *sql.Tx, sharedkernel.Scope) (RunTreeBudgetFacts, error)
}

type RunTreeBudgetReceipt struct {
	rootKey     string
	Version     string                `json:"version"`
	RootRunID   string                `json:"root_run_id"`
	RunID       string                `json:"run_id"`
	RequestID   string                `json:"request_id"`
	Fingerprint string                `json:"fingerprint"`
	Status      string                `json:"status"`
	Counters    RunTreeBudgetCounters `json:"counters"`
	Exceeded    bool                  `json:"exceeded"`
}

type SQLRunTreeBudgetStore struct {
	db        *sql.DB
	authority RunTreeBudgetAuthority
	audit     audit.TxRecorder
}

func NewSQLRunTreeBudgetStore(db *sql.DB) *SQLRunTreeBudgetStore {
	return &SQLRunTreeBudgetStore{db: db}
}
func (s *SQLRunTreeBudgetStore) SetAuthority(authority RunTreeBudgetAuthority) {
	s.authority = authority
}
func (s *SQLRunTreeBudgetStore) SetAuditRecorder(recorder audit.TxRecorder) { s.audit = recorder }

// Explicit migration only. No runtime or SDK method creates these tables.
func (s *SQLRunTreeBudgetStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrInvalidUsage
	}
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS platform_run_tree_budget (
 root_key VARCHAR(64) PRIMARY KEY, root_run_id VARCHAR(128) NOT NULL,
 policy_hash VARCHAR(64) NOT NULL, limit_micros BIGINT NOT NULL CHECK(limit_micros>=0),
 limit_tokens BIGINT NOT NULL CHECK(limit_tokens>=0), used_micros BIGINT NOT NULL DEFAULT 0 CHECK(used_micros>=0),
 used_tokens BIGINT NOT NULL DEFAULT 0 CHECK(used_tokens>=0), held_micros BIGINT NOT NULL DEFAULT 0 CHECK(held_micros>=0),
 held_tokens BIGINT NOT NULL DEFAULT 0 CHECK(held_tokens>=0), revision BIGINT NOT NULL DEFAULT 1 CHECK(revision>0));
CREATE TABLE IF NOT EXISTS platform_run_tree_budget_request (
 root_key VARCHAR(64) NOT NULL REFERENCES platform_run_tree_budget(root_key), actor_key VARCHAR(64) NOT NULL,
 request_id VARCHAR(128) NOT NULL, fingerprint VARCHAR(64) NOT NULL, run_id VARCHAR(128) NOT NULL,
 hold_micros BIGINT NOT NULL CHECK(hold_micros>=0), hold_tokens BIGINT NOT NULL CHECK(hold_tokens>=0),
 status VARCHAR(16) NOT NULL CHECK(status IN ('held','uncertain','settled','released')),
 outcome_fingerprint VARCHAR(64) NOT NULL DEFAULT '', actual_micros BIGINT NOT NULL DEFAULT 0 CHECK(actual_micros>=0),
 input_tokens BIGINT NOT NULL DEFAULT 0 CHECK(input_tokens>=0), output_tokens BIGINT NOT NULL DEFAULT 0 CHECK(output_tokens>=0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(root_key,actor_key,request_id));
CREATE INDEX IF NOT EXISTS idx_run_tree_budget_active ON platform_run_tree_budget_request (root_key,run_id)
 WHERE status NOT IN ('settled','released');
CREATE TABLE IF NOT EXISTS platform_run_tree_model_binding (
 binding_key VARCHAR(64) PRIMARY KEY, root_key VARCHAR(64) NOT NULL, actor_key VARCHAR(64) NOT NULL,
 request_id VARCHAR(128) NOT NULL, scope_json TEXT NOT NULL CHECK(octet_length(scope_json)<=16384),
 request_json TEXT NOT NULL CHECK(octet_length(request_json)<=16384), hold_tokens BIGINT NOT NULL CHECK(hold_tokens>=0),
 reservation_id VARCHAR(128) UNIQUE, reservation_json TEXT CHECK(octet_length(reservation_json)<=16384),
 UNIQUE(root_key,actor_key,request_id),
 FOREIGN KEY(root_key,actor_key,request_id) REFERENCES platform_run_tree_budget_request(root_key,actor_key,request_id));`)
	return err
}

func treeScopeKey(scope sharedkernel.Scope) string {
	raw, _ := json.Marshal([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID, scope.SessionID, scope.AgentID, scope.AgentInstanceID, scope.InstallationID, scope.AgentVersionID, scope.RunID, scope.ParentRunID})
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}
func treeHash(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && value == hex.EncodeToString(raw)
}
func validTreeFacts(facts RunTreeBudgetFacts, scope sharedkernel.Scope) bool {
	root := facts.RootScope
	if facts.EvaluationRoot {
		if root.RunID != scope.RunID || scope.ParentRunID == "" || root.ParentRunID != scope.ParentRunID || treeScopeKey(root) != treeScopeKey(scope) {
			return false
		}
	} else if root.RunID == scope.RunID {
		if scope.ParentRunID != "" || treeScopeKey(root) != treeScopeKey(scope) {
			return false
		}
	} else if scope.ParentRunID == "" {
		return false
	}
	return facts.ActorScope == scope && root.ValidateTrusted() == nil && (!facts.EvaluationRoot && root.ParentRunID == "" || facts.EvaluationRoot && root.ParentRunID == scope.ParentRunID) && treeHash(facts.PolicyHash) && facts.LimitMicros >= 0 && facts.LimitTokens >= 0 &&
		root.TenantID == scope.TenantID && root.DepartmentID == scope.DepartmentID && root.ApplicationID == scope.ApplicationID && root.PrincipalType == scope.PrincipalType && root.PrincipalID == scope.PrincipalID && root.SessionID == scope.SessionID
}

func (s *SQLRunTreeBudgetStore) Apply(ctx context.Context, scope sharedkernel.Scope, command RunTreeBudgetCommand) (RunTreeBudgetReceipt, error) {
	if s == nil || s.db == nil {
		return RunTreeBudgetReceipt{}, ErrInvalidUsage
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RunTreeBudgetReceipt{}, err
	}
	defer tx.Rollback()
	receipt, err := s.ApplyTx(ctx, tx, scope, command)
	if err != nil {
		return RunTreeBudgetReceipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return RunTreeBudgetReceipt{}, err
	}
	return receipt, nil
}

// ApplyTx is the composition boundary for atomic root AND existing model-price
// window accounting. The caller owns commit; errors must roll back its whole
// transaction. Nothing here sends a model request or grants dispatch authority.
func (s *SQLRunTreeBudgetStore) ApplyTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, command RunTreeBudgetCommand) (RunTreeBudgetReceipt, error) {
	empty := RunTreeBudgetReceipt{}
	if s == nil || tx == nil || s.authority == nil || s.audit == nil || scope.ValidateTrusted() != nil || command.Hold.Validate() != nil || !treeHash(command.Fingerprint) ||
		command.RequestID == "" || len(command.RequestID) > 128 || strings.TrimSpace(command.RequestID) != command.RequestID || strings.ContainsAny(command.RequestID, "*\x00\r\n") {
		return empty, ErrInvalidUsage
	}
	admission := command.Action == "reserve"
	switch command.Action {
	case "reserve", "unknown":
		if command.OutcomeFingerprint != "" || command.ActualMicros != 0 || command.InputTokens != 0 || command.OutputTokens != 0 {
			return empty, ErrInvalidUsage
		}
	case "settle", "release_unbilled":
		if !treeHash(command.OutcomeFingerprint) || command.ActualMicros < 0 || command.InputTokens < 0 || command.OutputTokens < 0 || command.OutputTokens > maxInt64-command.InputTokens {
			return empty, ErrInvalidUsage
		}
		if command.Action == "release_unbilled" && (command.ActualMicros != 0 || command.InputTokens != 0 || command.OutputTokens != 0) {
			return empty, ErrInvalidUsage
		}
	default:
		return empty, ErrInvalidUsage
	}
	facts, err := s.authority.Facts(ctx, tx, scope, admission)
	if err != nil {
		return empty, err
	}
	if !validTreeFacts(facts, scope) {
		return empty, ErrBudgetScopeMismatch
	}
	rootKey, actorKey := treeScopeKey(facts.RootScope), treeScopeKey(scope)
	if admission {
		_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_run_tree_budget(root_key,root_run_id,policy_hash,limit_micros,limit_tokens) VALUES(?,?,?,?,?) ON CONFLICT(root_key) DO NOTHING`), rootKey, facts.RootScope.RunID, facts.PolicyHash, facts.LimitMicros, facts.LimitTokens)
		if err != nil {
			return empty, err
		}
	}
	var current RunTreeBudgetCounters
	var rootID, policyHash string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT root_run_id,policy_hash,limit_micros,limit_tokens,used_micros,used_tokens,held_micros,held_tokens FROM platform_run_tree_budget WHERE root_key=? FOR UPDATE`), rootKey).Scan(&rootID, &policyHash, &current.LimitMicros, &current.LimitTokens, &current.UsedMicros, &current.UsedTokens, &current.HeldMicros, &current.HeldTokens)
	if err != nil {
		return empty, err
	}
	if rootID != facts.RootScope.RunID || policyHash != facts.PolicyHash || current.LimitMicros != facts.LimitMicros || current.LimitTokens != facts.LimitTokens || current.Validate() != nil {
		return empty, ErrBudgetReservationConflict
	}
	var fingerprint, runID, status, outcome string
	var hold RunTreeBudgetHold
	var micros, input, output int64
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT fingerprint,run_id,hold_micros,hold_tokens,status,outcome_fingerprint,actual_micros,input_tokens,output_tokens FROM platform_run_tree_budget_request WHERE root_key=? AND actor_key=? AND request_id=? FOR UPDATE`), rootKey, actorKey, command.RequestID).Scan(&fingerprint, &runID, &hold.Micros, &hold.Tokens, &status, &outcome, &micros, &input, &output)
	missing := errors.Is(err, sql.ErrNoRows)
	if err != nil && !missing {
		return empty, err
	}
	if missing && !admission {
		return empty, ErrBudgetReservationNotFound
	}
	if !missing && (fingerprint != command.Fingerprint || runID != scope.RunID || hold != command.Hold) {
		return empty, ErrBudgetReservationConflict
	}
	next := current
	changed := false
	if missing {
		next, err = ReserveRunTreeBudget(current, command.Hold)
		if err != nil {
			if errors.Is(err, ErrBudgetExceeded) {
				log.Print(formatRunTreeBudgetDenied(scope, current, command.Hold))
			}
			return empty, err
		}
		status = "held"
		_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_run_tree_budget_request(root_key,actor_key,request_id,fingerprint,run_id,hold_micros,hold_tokens,status) VALUES(?,?,?,?,?,?,?,'held')`), rootKey, actorKey, command.RequestID, command.Fingerprint, scope.RunID, command.Hold.Micros, command.Hold.Tokens)
		changed = true
	} else if command.Action == "unknown" {
		if status == "held" {
			status = "uncertain"
			changed = true
		} else if status != "uncertain" {
			return empty, ErrBudgetReservationClosed
		}
	} else if command.Action == "settle" || command.Action == "release_unbilled" {
		if err = s.authority.VerifyOutcome(ctx, tx, scope, command); err != nil {
			return empty, err
		}
		terminal := "settled"
		if command.Action == "release_unbilled" {
			terminal = "released"
		}
		if status == "settled" || status == "released" {
			if status != terminal || outcome != command.OutcomeFingerprint || micros != command.ActualMicros || input != command.InputTokens || output != command.OutputTokens {
				return empty, ErrBudgetReservationConflict
			}
		} else {
			if status != "held" && status != "uncertain" {
				return empty, ErrBudgetReservationClosed
			}
			if terminal == "settled" {
				next, _, err = SettleRunTreeBudget(current, hold, command.ActualMicros, command.InputTokens, command.OutputTokens)
			} else {
				next, err = ReleaseRunTreeBudget(current, hold)
			}
			if err != nil {
				return empty, err
			}
			status = terminal
			outcome, micros, input, output = command.OutcomeFingerprint, command.ActualMicros, command.InputTokens, command.OutputTokens
			changed = true
		}
	}
	if err != nil {
		return empty, err
	}
	if changed {
		_, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_run_tree_budget SET used_micros=?,used_tokens=?,held_micros=?,held_tokens=?,revision=revision+1 WHERE root_key=?`), next.UsedMicros, next.UsedTokens, next.HeldMicros, next.HeldTokens, rootKey)
		if err != nil {
			return empty, err
		}
		_, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_run_tree_budget_request SET status=?,outcome_fingerprint=?,actual_micros=?,input_tokens=?,output_tokens=?,updated_at=clock_timestamp() WHERE root_key=? AND actor_key=? AND request_id=?`), status, outcome, micros, input, output, rootKey, actorKey, command.RequestID)
		if err != nil {
			return empty, err
		}
	}
	// Re-check the same authority and policy before giving control back to the
	// owning transaction. Facts must retain IAM/fence locks through commit.
	check, err := s.authority.Facts(ctx, tx, scope, admission)
	if err != nil {
		return empty, err
	}
	if !validTreeFacts(check, scope) || treeScopeKey(check.RootScope) != rootKey || check.PolicyHash != facts.PolicyHash || check.LimitMicros != facts.LimitMicros || check.LimitTokens != facts.LimitTokens {
		return empty, ErrBudgetScopeMismatch
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return empty, err
	}
	event := audit.Event{ID: "tree-budget-" + hex.EncodeToString(nonce[:]), TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorType: scope.PrincipalType, ActorID: scope.PrincipalID, TraceID: scope.TraceID, AggregateType: "run_tree_budget", AggregateID: scope.RunID, Action: "budget.tree_" + command.Action, Outcome: "success", Summary: "status=" + status}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&event.CreatedAt); err != nil {
		return empty, err
	}
	if err = s.audit.RecordTx(tx, event); err != nil {
		return empty, err
	}
	return RunTreeBudgetReceipt{rootKey: rootKey, Version: "run-tree-budget/v1", RootRunID: rootID, RunID: scope.RunID, RequestID: command.RequestID, Fingerprint: command.Fingerprint, Status: status, Counters: next, Exceeded: next.UsedMicros+next.HeldMicros > next.LimitMicros || next.UsedTokens+next.HeldTokens > next.LimitTokens}, nil
}

func formatRunTreeBudgetDenied(scope sharedkernel.Scope, current RunTreeBudgetCounters, hold RunTreeBudgetHold) string {
	costExceeded := hold.Micros > current.LimitMicros-current.UsedMicros-current.HeldMicros
	tokensExceeded := hold.Tokens > current.LimitTokens-current.UsedTokens-current.HeldTokens
	dimension := "none"
	switch {
	case costExceeded && tokensExceeded:
		dimension = "cost_and_tokens"
	case costExceeded:
		dimension = "cost"
	case tokensExceeded:
		dimension = "tokens"
	}
	return fmt.Sprintf("event=run_tree_budget_denied stage=root_reserve run_id=%q trace_id=%q dimension=%s limit_micros=%d used_micros=%d held_micros=%d attempt_micros=%d limit_tokens=%d used_tokens=%d held_tokens=%d attempt_tokens=%d",
		scope.RunID, scope.TraceID, dimension,
		current.LimitMicros, current.UsedMicros, current.HeldMicros, hold.Micros,
		current.LimitTokens, current.UsedTokens, current.HeldTokens, hold.Tokens)
}
