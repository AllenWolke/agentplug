package capability

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

// StoredModelRoute fixes selection before any invocation admission or send.
// Its immutable request fingerprint uses the original published policy, so a
// concurrent winner or resumed call cannot reselect a different model/price.
type StoredModelRoute struct {
	RequestFingerprint string             `json:"request_fingerprint"`
	Decision           ModelRouteDecision `json:"decision"`
	DecisionSHA256     string             `json:"decision_sha256"`
}

type ModelRouteDecisionStore interface {
	LookupModelRoute(context.Context, string, string) (StoredModelRoute, bool, error)
	PersistModelRoute(context.Context, string, string, StoredModelRoute) (StoredModelRoute, error)
}

func validRouteStoreKey(scope, key string) bool {
	return isRouteSHA(scope) && key != "" && len(key) <= 255 && strings.TrimSpace(key) == key && !strings.ContainsAny(key, "\x00\r\n")
}

func isRouteSHA(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && strings.ToLower(value) == value
}

func validStoredModelRoute(value StoredModelRoute) bool {
	d := value.Decision
	return (d.SelectionMode == "" || d.SelectionMode == "manual") && validModelRouteFallback(d.Fallback) && isRouteSHA(value.RequestFingerprint) && isRouteSHA(value.DecisionSHA256) && value.DecisionSHA256 == modelRouteHash(d) &&
		d.Version == "model-route-decision/v1" && isRouteSHA(d.PolicySHA256) && isRouteSHA(d.FeaturesSHA256) &&
		d.FeaturesSHA256 == modelRouteHash(d.Features) && isRouteSHA(d.CapabilitySHA256) && isRouteSHA(d.QualityEvidenceSHA256) &&
		d.ModelVersionID != "" && d.ModelKey != "" && len(d.ModelKey) <= 128 && d.EstimatedMicros >= 0 && len(d.Excluded) <= 8 &&
		validRuntimeModelPrice(d.Price, d.ModelVersionID, d.Price.EffectiveFrom)
}

func cloneStoredModelRoute(value StoredModelRoute) StoredModelRoute {
	raw, _ := json.Marshal(value)
	var copy StoredModelRoute
	_ = json.Unmarshal(raw, &copy)
	return copy
}

func (s *SQLModelInvocationStore) ensureModelRouteSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS platform_model_route_decision (
scope_hash VARCHAR(64) NOT NULL,idempotency_key VARCHAR(255) NOT NULL,
request_fingerprint VARCHAR(64) NOT NULL,decision_json TEXT NOT NULL,
decision_sha256 VARCHAR(64) NOT NULL,created_at TIMESTAMPTZ(6) NOT NULL,
PRIMARY KEY(scope_hash,idempotency_key));`)
	if err != nil {
		return err
	}
	if err := s.ensureModelSelectionSchema(ctx); err != nil {
		return err
	}
	if err := s.ensureModelAvailabilitySchema(ctx); err != nil {
		return err
	}
	return s.ensureModelRouteExecutionSchema(ctx)
}

func (s *SQLModelInvocationStore) LookupModelRoute(ctx context.Context, scope, key string) (StoredModelRoute, bool, error) {
	if !validRouteStoreKey(scope, key) {
		return StoredModelRoute{}, false, ErrModelInvocationConflict
	}
	var result StoredModelRoute
	var raw string
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT request_fingerprint,decision_json,decision_sha256 FROM platform_model_route_decision WHERE scope_hash=? AND idempotency_key=?`), scope, key).Scan(&result.RequestFingerprint, &raw, &result.DecisionSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredModelRoute{}, false, nil
	}
	if err != nil {
		return StoredModelRoute{}, false, err
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > 16384 || decoder.Decode(&result.Decision) != nil || decoder.Decode(new(any)) != io.EOF || !validStoredModelRoute(result) {
		return StoredModelRoute{}, false, ErrModelRouteUnavailable
	}
	return result, true, nil
}

func (s *SQLModelInvocationStore) PersistModelRoute(ctx context.Context, scope, key string, proposal StoredModelRoute) (StoredModelRoute, error) {
	if !validRouteStoreKey(scope, key) || !validStoredModelRoute(proposal) {
		return StoredModelRoute{}, ErrModelInvocationConflict
	}
	raw, err := json.Marshal(proposal.Decision)
	if err != nil || len(raw) > 16384 {
		return StoredModelRoute{}, ErrModelRouteUnavailable
	}
	_, err = s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_route_decision(scope_hash,idempotency_key,request_fingerprint,decision_json,decision_sha256,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(scope_hash,idempotency_key) DO NOTHING`), scope, key, proposal.RequestFingerprint, string(raw), proposal.DecisionSHA256, time.Now().UTC())
	if err != nil {
		return StoredModelRoute{}, err
	}
	// Read the persisted winner. Never send from the in-memory proposal after CAS.
	actual, found, err := s.LookupModelRoute(ctx, scope, key)
	if err != nil || !found {
		return StoredModelRoute{}, ErrModelRouteUnavailable
	}
	if actual.RequestFingerprint != proposal.RequestFingerprint {
		return StoredModelRoute{}, ErrModelInvocationConflict
	}
	return actual, nil
}

func (s *memoryModelInvocationStore) LookupModelRoute(ctx context.Context, scope, key string) (StoredModelRoute, bool, error) {
	if err := ctx.Err(); err != nil {
		return StoredModelRoute{}, false, err
	}
	if !validRouteStoreKey(scope, key) {
		return StoredModelRoute{}, false, ErrModelInvocationConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	value, found := s.routes[scope+"\x00"+key]
	if found && !validStoredModelRoute(value) {
		return StoredModelRoute{}, false, ErrModelRouteUnavailable
	}
	return cloneStoredModelRoute(value), found, nil
}

func (s *memoryModelInvocationStore) PersistModelRoute(ctx context.Context, scope, key string, proposal StoredModelRoute) (StoredModelRoute, error) {
	if err := ctx.Err(); err != nil {
		return StoredModelRoute{}, err
	}
	if !validRouteStoreKey(scope, key) || !validStoredModelRoute(proposal) {
		return StoredModelRoute{}, ErrModelInvocationConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.routes == nil {
		s.routes = map[string]StoredModelRoute{}
	}
	compound := scope + "\x00" + key
	if previous, found := s.routes[compound]; found {
		if !validStoredModelRoute(previous) {
			return StoredModelRoute{}, ErrModelRouteUnavailable
		}
		if previous.RequestFingerprint != proposal.RequestFingerprint {
			return StoredModelRoute{}, ErrModelInvocationConflict
		}
		return cloneStoredModelRoute(previous), nil
	}
	s.routes[compound] = cloneStoredModelRoute(proposal)
	return cloneStoredModelRoute(proposal), nil
}

var _ ModelRouteDecisionStore = (*SQLModelInvocationStore)(nil)
var _ ModelRouteDecisionStore = (*memoryModelInvocationStore)(nil)
