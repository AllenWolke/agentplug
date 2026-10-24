package capability

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Recovery advances only already-persisted physical outcomes. It has no gateway
// or budget mutation port, so it cannot resend, refund, or start an alternate.
type modelRouteDispositionReader interface {
	ListActiveModelRouteExecutions(context.Context, string) (map[string]ModelRouteExecution, error)
	GetBillingRecord(context.Context, string, string) (ModelInvocation, error)
}

func (s *SQLModelInvocationStore) ListActiveModelRouteExecutions(ctx context.Context, scope string) (map[string]ModelRouteExecution, error) {
	if !isRouteSHA(scope) {
		return nil, ErrModelRouteUnavailable
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT logical_key,state_json FROM platform_model_route_execution
 WHERE scope_hash=? AND state_json::jsonb->>'status'='active' ORDER BY logical_key LIMIT 10001`), scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ModelRouteExecution{}
	physicalKeys := map[string]string{}
	for rows.Next() {
		var key, raw string
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, err
		}
		state, err := decodeModelRouteExecution(raw)
		if err != nil || !validRouteStoreKey(scope, key) || len(out) >= 10000 {
			return nil, ErrModelRouteUnavailable
		}
		out[key] = state
		physical := physicalRouteAttemptKey(key, len(state.Steps))
		if _, duplicate := physicalKeys[physical]; duplicate {
			return nil, ErrModelInvocationConflict
		}
		physicalKeys[physical] = key
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Close the first cursor before obtaining another connection. Bulk-filter
	// absent next attempts, so successive bounded passes do not spend their
	// entire allowance re-reading already-retained logical calls.
	if err := rows.Close(); err != nil || len(out) == 0 {
		return out, err
	}
	keys := make([]string, 0, len(physicalKeys))
	for physical := range physicalKeys {
		keys = append(keys, physical)
	}
	sort.Strings(keys)
	keyJSON, _ := json.Marshal(keys)
	existing, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT idempotency_key FROM platform_model_invocation
 WHERE scope_hash=? AND idempotency_key IN (SELECT jsonb_array_elements_text(?::jsonb))`), scope, string(keyJSON))
	if err != nil {
		return nil, err
	}
	defer existing.Close()
	recoverable := map[string]ModelRouteExecution{}
	for existing.Next() {
		var key string
		if err := existing.Scan(&key); err != nil {
			return nil, err
		}
		logical, found := physicalKeys[key]
		if !found {
			return nil, ErrModelInvocationConflict
		}
		recoverable[logical] = out[logical]
	}
	return recoverable, existing.Err()
}

func (s *memoryModelInvocationStore) ListActiveModelRouteExecutions(ctx context.Context, scope string) (map[string]ModelRouteExecution, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !isRouteSHA(scope) {
		return nil, ErrModelRouteUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]ModelRouteExecution{}
	for key, state := range s.routeExecutions {
		if strings.HasPrefix(key, scope+"\x00") && state.Status == "active" {
			if !validModelRouteExecution(state) || len(out) >= 10000 {
				return nil, ErrModelRouteUnavailable
			}
			logical := strings.TrimPrefix(key, scope+"\x00")
			if _, found := s.records[scope+"\x00"+physicalRouteAttemptKey(logical, len(state.Steps))]; found {
				out[logical] = cloneModelRouteExecution(state)
			}
		}
	}
	return out, nil
}

// Called only by the system stop/quiescence composition after owner fencing.
// A saved policy is authoritative across publication changes. For an existing
// state without it, the resolver may supply only a byte-hash-equivalent policy.
func (m *Module) recoverStoppedModelRouteDispositions(ctx context.Context, scope sharedkernel.Scope) error {
	reader, ok := m.modelStore.(modelRouteDispositionReader)
	if !ok {
		return ErrModelRouteUnavailable
	}
	store, ok := m.modelStore.(ModelRouteExecutionStore)
	if !ok {
		return ErrModelRouteUnavailable
	}
	routes, ok := m.modelStore.(ModelRouteDecisionStore)
	if !ok {
		return ErrModelRouteUnavailable
	}
	recoveryCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer stop()
	hash := modelSelectionScopeHash(scope)
	states, err := reader.ListActiveModelRouteExecutions(recoveryCtx, hash)
	if err != nil || len(states) == 0 {
		return err
	}
	var fallback *policyasset.ModelRoutingPolicy
	if m.policy != nil {
		if snapshot, err := m.policy.Resolve(recoveryCtx, scope, scope.AgentVersionID); err == nil {
			fallback = snapshot.Model.Routing
		}
	}
	keys := make([]string, 0, len(states))
	for key := range states {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, logical := range keys {
		state := states[logical]
		p := state.RecoveryPolicy
		if p == nil {
			p = fallback
		}
		if p == nil || p.Validate() != nil || modelRouteHash(*p) != state.PolicySHA256 {
			continue // Changed or unavailable policy never grants disposition.
		}
		key := physicalRouteAttemptKey(logical, len(state.Steps))
		route, found, err := routes.LookupModelRoute(recoveryCtx, hash, key)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		record, err := reader.GetBillingRecord(recoveryCtx, hash, key)
		if errors.Is(err, ErrModelInvocationConflict) {
			continue // No physical admission is not a no-send/refund proof.
		}
		if err != nil {
			return err
		}
		_, err = store.AdvanceModelRouteExecution(recoveryCtx, hash, logical, state, route, record.Fingerprint, *p)
		if err != nil && !errors.Is(err, ErrModelRouteOutcomePending) {
			return err
		}
	}
	return nil
}
