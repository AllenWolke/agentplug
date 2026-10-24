package capability

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sqlutil"
)

func decodeModelRouteExecution(raw string) (ModelRouteExecution, error) {
	var s ModelRouteExecution
	d := json.NewDecoder(bytes.NewBufferString(raw))
	d.DisallowUnknownFields()
	if len(raw) > 16384 || d.Decode(&s) != nil || d.Decode(new(any)) != io.EOF || !validModelRouteExecution(s) {
		return s, ErrModelRouteUnavailable
	}
	return s, nil
}

func cloneModelRouteExecution(s ModelRouteExecution) ModelRouteExecution {
	s.Steps = append([]ModelRouteExecutionStep(nil), s.Steps...)
	if s.RecoveryPolicy != nil {
		raw, _ := json.Marshal(s.RecoveryPolicy)
		var policy policyasset.ModelRoutingPolicy
		_ = json.Unmarshal(raw, &policy)
		s.RecoveryPolicy = &policy
	}
	return s
}

func (s *SQLModelInvocationStore) ensureModelRouteExecutionSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS platform_model_route_execution (
scope_hash VARCHAR(64) NOT NULL, logical_key VARCHAR(255) NOT NULL,
state_json TEXT NOT NULL, revision BIGINT NOT NULL, updated_at TIMESTAMPTZ(6) NOT NULL,
PRIMARY KEY(scope_hash,logical_key));`)
	return err
}

func (s *SQLModelInvocationStore) LookupModelRouteExecution(ctx context.Context, scope, logical string) (ModelRouteExecution, bool, error) {
	if !validRouteStoreKey(scope, logical) {
		return ModelRouteExecution{}, false, ErrModelInvocationConflict
	}
	var raw string
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT state_json FROM platform_model_route_execution WHERE scope_hash=? AND logical_key=?`), scope, logical).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ModelRouteExecution{}, false, nil
	}
	if err != nil {
		return ModelRouteExecution{}, false, err
	}
	value, err := decodeModelRouteExecution(raw)
	return value, err == nil, err
}

func (s *SQLModelInvocationStore) BeginModelRouteExecution(ctx context.Context, scope, logical string, proposal ModelRouteExecution) (ModelRouteExecution, error) {
	if !validRouteStoreKey(scope, logical) || !validModelRouteExecution(proposal) || proposal.Revision != 1 || proposal.Status != "active" {
		return ModelRouteExecution{}, ErrModelInvocationConflict
	}
	raw, _ := json.Marshal(proposal)
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_route_execution(scope_hash,logical_key,state_json,revision,updated_at) VALUES(?,?,?,1,clock_timestamp()) ON CONFLICT(scope_hash,logical_key) DO NOTHING`), scope, logical, string(raw))
	if err != nil {
		return ModelRouteExecution{}, err
	}
	actual, found, err := s.LookupModelRouteExecution(ctx, scope, logical)
	if err != nil || !found {
		return ModelRouteExecution{}, ErrModelRouteUnavailable
	}
	if !sameModelExecutionRequest(actual, proposal) {
		return ModelRouteExecution{}, ErrModelInvocationConflict
	}
	return actual, nil
}

func sameModelExecutionRequest(a, b ModelRouteExecution) bool {
	return a.RequestFingerprint == b.RequestFingerprint && a.PolicySHA256 == b.PolicySHA256 && a.MaxAttempts == b.MaxAttempts
}

// Lock the business choice and original physical record together. A racing
// completion either wins before this transition, or stays accounting-only.
func (s *SQLModelInvocationStore) AdvanceModelRouteExecution(ctx context.Context, scope, logical string, expected ModelRouteExecution,
	route StoredModelRoute, fingerprint string, p policyasset.ModelRoutingPolicy) (ModelRouteExecution, error) {
	if !validRouteStoreKey(scope, logical) || !validModelRouteExecution(expected) {
		return ModelRouteExecution{}, ErrModelInvocationConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ModelRouteExecution{}, err
	}
	defer tx.Rollback()
	var raw string
	var revision int64
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT state_json,revision FROM platform_model_route_execution WHERE scope_hash=? AND logical_key=? FOR UPDATE`), scope, logical).Scan(&raw, &revision)
	if err != nil {
		return ModelRouteExecution{}, err
	}
	actual, err := decodeModelRouteExecution(raw)
	if err != nil || actual.Revision != revision || !sameModelExecutionRequest(actual, expected) {
		return ModelRouteExecution{}, ErrModelInvocationConflict
	}
	if actual.Revision != expected.Revision {
		return actual, tx.Commit()
	}
	if modelRouteHash(actual) != modelRouteHash(expected) {
		return ModelRouteExecution{}, ErrModelInvocationConflict
	}
	key := physicalRouteAttemptKey(logical, len(actual.Steps))
	var routeHash, requestHash string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT decision_sha256,request_fingerprint FROM platform_model_route_decision WHERE scope_hash=? AND idempotency_key=?`), scope, key).Scan(&routeHash, &requestHash)
	if err != nil || routeHash != route.DecisionSHA256 || requestHash != actual.RequestFingerprint {
		return ModelRouteExecution{}, ErrModelInvocationConflict
	}
	record := ModelInvocation{ScopeHash: scope, Key: key}
	var response, recovery sql.NullString
	var billing string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT fingerprint,status,response_json,cost_cents,billing_recovery_json,billing_state FROM platform_model_invocation WHERE scope_hash=? AND idempotency_key=? FOR UPDATE`), scope, key).
		Scan(&record.Fingerprint, &record.Status, &response, &record.CostCents, &recovery, &billing)
	if errors.Is(err, sql.ErrNoRows) {
		return ModelRouteExecution{}, ErrModelRouteOutcomePending
	}
	if err != nil {
		return ModelRouteExecution{}, err
	}
	if response.Valid && json.Unmarshal([]byte(response.String), &record.Response) != nil ||
		recovery.Valid && json.Unmarshal([]byte(recovery.String), &record.Recovery) != nil {
		return ModelRouteExecution{}, ErrModelRouteUnavailable
	}
	if record.Status == "reconcile" && billing != "manual" {
		return ModelRouteExecution{}, ErrModelRouteOutcomePending
	}
	if record.Status == "completed" && billing != "done" {
		return ModelRouteExecution{}, ErrModelRouteOutcomePending
	}
	next, err := advanceModelRouteExecution(actual, logical, route, fingerprint, p, record)
	if err != nil {
		return ModelRouteExecution{}, err
	}
	encoded, _ := json.Marshal(next)
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_route_execution SET state_json=?,revision=?,updated_at=clock_timestamp() WHERE scope_hash=? AND logical_key=? AND revision=?`), string(encoded), next.Revision, scope, logical, revision)
	if err != nil {
		return ModelRouteExecution{}, err
	}
	return next, tx.Commit()
}

func (s *memoryModelInvocationStore) LookupModelRouteExecution(ctx context.Context, scope, logical string) (ModelRouteExecution, bool, error) {
	if err := ctx.Err(); err != nil {
		return ModelRouteExecution{}, false, err
	}
	if !validRouteStoreKey(scope, logical) {
		return ModelRouteExecution{}, false, ErrModelInvocationConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, found := s.routeExecutions[scope+"\x00"+logical]
	if found && !validModelRouteExecution(state) {
		return ModelRouteExecution{}, false, ErrModelRouteUnavailable
	}
	return cloneModelRouteExecution(state), found, nil
}

func (s *memoryModelInvocationStore) BeginModelRouteExecution(ctx context.Context, scope, logical string, proposal ModelRouteExecution) (ModelRouteExecution, error) {
	if err := ctx.Err(); err != nil {
		return ModelRouteExecution{}, err
	}
	if !validRouteStoreKey(scope, logical) || !validModelRouteExecution(proposal) || proposal.Revision != 1 || proposal.Status != "active" {
		return ModelRouteExecution{}, ErrModelInvocationConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.routeExecutions == nil {
		s.routeExecutions = make(map[string]ModelRouteExecution)
	}
	key := scope + "\x00" + logical
	if actual, found := s.routeExecutions[key]; found {
		if !validModelRouteExecution(actual) || !sameModelExecutionRequest(actual, proposal) {
			return ModelRouteExecution{}, ErrModelInvocationConflict
		}
		return cloneModelRouteExecution(actual), nil
	}
	s.routeExecutions[key] = cloneModelRouteExecution(proposal)
	return cloneModelRouteExecution(proposal), nil
}

func (s *memoryModelInvocationStore) AdvanceModelRouteExecution(ctx context.Context, scope, logical string, expected ModelRouteExecution,
	route StoredModelRoute, fingerprint string, p policyasset.ModelRoutingPolicy) (ModelRouteExecution, error) {
	if err := ctx.Err(); err != nil {
		return ModelRouteExecution{}, err
	}
	if !validRouteStoreKey(scope, logical) || !validModelRouteExecution(expected) {
		return ModelRouteExecution{}, ErrModelInvocationConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	compound := scope + "\x00" + logical
	actual, found := s.routeExecutions[compound]
	if !found || !validModelRouteExecution(actual) || !sameModelExecutionRequest(actual, expected) {
		return ModelRouteExecution{}, ErrModelInvocationConflict
	}
	if actual.Revision != expected.Revision {
		return cloneModelRouteExecution(actual), nil
	}
	if modelRouteHash(actual) != modelRouteHash(expected) {
		return ModelRouteExecution{}, ErrModelInvocationConflict
	}
	key := physicalRouteAttemptKey(logical, len(actual.Steps))
	stored, found := s.routes[scope+"\x00"+key]
	if !found || stored.DecisionSHA256 != route.DecisionSHA256 || stored.RequestFingerprint != actual.RequestFingerprint {
		return ModelRouteExecution{}, ErrModelInvocationConflict
	}
	record, found := s.records[scope+"\x00"+key]
	if !found {
		return ModelRouteExecution{}, ErrModelRouteOutcomePending
	}
	next, err := advanceModelRouteExecution(actual, logical, route, fingerprint, p, record)
	if err != nil {
		return ModelRouteExecution{}, err
	}
	s.routeExecutions[compound] = cloneModelRouteExecution(next)
	return cloneModelRouteExecution(next), nil
}

var _ ModelRouteExecutionStore = (*SQLModelInvocationStore)(nil)
var _ ModelRouteExecutionStore = (*memoryModelInvocationStore)(nil)
