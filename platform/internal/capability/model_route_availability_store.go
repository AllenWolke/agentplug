package capability

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

// One bounded health row per application/model. No prompts, responses, keys or
// authorization decisions are stored here. Revision fences recovery probes.
type ModelRouteAvailabilityState struct {
	Revision       int64     `json:"revision"`
	Failures       int       `json:"failures"`
	OpenUntil      time.Time `json:"open_until"`
	ProbeOwner     string    `json:"probe_owner"`
	ProbeUntil     time.Time `json:"probe_until"`
	LastAttempt    string    `json:"last_attempt"`
	LastStartedAt  time.Time `json:"last_started_at"`
	LastFinishedAt time.Time `json:"last_finished_at"`
}

type ModelRouteAvailabilityStore interface {
	LookupModelAvailability(context.Context, string, string) (ModelRouteAvailabilityState, bool, error)
	CompareAndSwapModelAvailability(context.Context, string, string, int64, ModelRouteAvailabilityState) (bool, error)
}

func validAvailabilityKey(partition, model string) bool {
	return isRouteSHA(partition) && model != "" && len(model) <= 128 && strings.TrimSpace(model) == model && !strings.ContainsAny(model, "\x00\r\n")
}

func validAvailabilityState(s ModelRouteAvailabilityState) bool {
	return s.Revision > 0 && s.Failures >= 0 && s.Failures <= 10 &&
		(s.ProbeOwner == "" && s.ProbeUntil.IsZero() || isRouteSHA(s.ProbeOwner) && !s.OpenUntil.IsZero() && !s.ProbeUntil.IsZero()) &&
		(s.LastAttempt == "" && s.LastStartedAt.IsZero() && s.LastFinishedAt.IsZero() ||
			isRouteSHA(s.LastAttempt) && !s.LastStartedAt.IsZero() && !s.LastFinishedAt.Before(s.LastStartedAt))
}

func (s *SQLModelInvocationStore) ensureModelAvailabilitySchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS platform_model_route_availability (
partition_hash VARCHAR(64) NOT NULL,model_version_id VARCHAR(128) NOT NULL,
revision BIGINT NOT NULL,state_json TEXT NOT NULL,
PRIMARY KEY(partition_hash,model_version_id));`)
	return err
}

func (s *SQLModelInvocationStore) LookupModelAvailability(ctx context.Context, partition, model string) (ModelRouteAvailabilityState, bool, error) {
	if !validAvailabilityKey(partition, model) {
		return ModelRouteAvailabilityState{}, false, ErrModelRouteUnavailable
	}
	var state ModelRouteAvailabilityState
	var revision int64
	var raw string
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,state_json FROM platform_model_route_availability WHERE partition_hash=? AND model_version_id=?`), partition, model).Scan(&revision, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return state, false, nil
	}
	if err != nil {
		return state, false, err
	}
	d := json.NewDecoder(bytes.NewBufferString(raw))
	d.DisallowUnknownFields()
	if len(raw) > 2048 || d.Decode(&state) != nil || d.Decode(new(any)) != io.EOF || state.Revision != revision || !validAvailabilityState(state) {
		return ModelRouteAvailabilityState{}, false, ErrModelRouteUnavailable
	}
	return state, true, nil
}

func (s *SQLModelInvocationStore) CompareAndSwapModelAvailability(ctx context.Context, partition, model string, expected int64, state ModelRouteAvailabilityState) (bool, error) {
	if !validAvailabilityKey(partition, model) || expected < 0 || state.Revision != expected+1 || !validAvailabilityState(state) {
		return false, ErrModelRouteUnavailable
	}
	raw, err := json.Marshal(state)
	if err != nil || len(raw) > 2048 {
		return false, ErrModelRouteUnavailable
	}
	var result sql.Result
	if expected == 0 {
		result, err = s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_route_availability(partition_hash,model_version_id,revision,state_json) VALUES(?,?,?,?) ON CONFLICT(partition_hash,model_version_id) DO NOTHING`), partition, model, state.Revision, string(raw))
	} else {
		result, err = s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_route_availability SET revision=?,state_json=? WHERE partition_hash=? AND model_version_id=? AND revision=?`), state.Revision, string(raw), partition, model, expected)
	}
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

func (s *memoryModelInvocationStore) LookupModelAvailability(ctx context.Context, partition, model string) (ModelRouteAvailabilityState, bool, error) {
	if err := ctx.Err(); err != nil {
		return ModelRouteAvailabilityState{}, false, err
	}
	if !validAvailabilityKey(partition, model) {
		return ModelRouteAvailabilityState{}, false, ErrModelRouteUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, found := s.availability[partition+"\x00"+model]
	if found && !validAvailabilityState(state) {
		return ModelRouteAvailabilityState{}, false, ErrModelRouteUnavailable
	}
	return state, found, nil
}

func (s *memoryModelInvocationStore) CompareAndSwapModelAvailability(ctx context.Context, partition, model string, expected int64, state ModelRouteAvailabilityState) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !validAvailabilityKey(partition, model) || expected < 0 || state.Revision != expected+1 || !validAvailabilityState(state) {
		return false, ErrModelRouteUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := partition + "\x00" + model
	previous := s.availability[key]
	if previous.Revision != expected {
		return false, nil
	}
	if s.availability == nil {
		s.availability = map[string]ModelRouteAvailabilityState{}
	}
	s.availability[key] = state
	return true, nil
}

var _ ModelRouteAvailabilityStore = (*SQLModelInvocationStore)(nil)
var _ ModelRouteAvailabilityStore = (*memoryModelInvocationStore)(nil)
