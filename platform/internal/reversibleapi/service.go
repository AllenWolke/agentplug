// Package reversibleapi provides an operator-owned, durable reference API.
// It demonstrates compensable business writes, not arbitrary HTTP rollback.
package reversibleapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/sqlutil"
)

const Protocol = "reversible-business-api/v1"
const Provider = "platform.api.reversible"

type Request struct {
	Version string            `json:"version"`
	Action  string            `json:"action"`
	Step    compensation.Step `json:"step"`
	Payload map[string]any    `json:"payload,omitempty"`
}
type Response struct {
	Version        string                `json:"version"`
	StepDigest     string                `json:"step_digest"`
	State          string                `json:"state"`
	ForwardClosed  bool                  `json:"forward_closed"`
	EvidenceDigest string                `json:"evidence_digest,omitempty"`
	Receipt        *compensation.Receipt `json:"receipt,omitempty"`
}
type Config struct {
	ToolName, TenantID, ApplicationID string
	AgentIDs                          []string
	ForwardToken, ControlToken        []byte
}
type Server struct {
	db     *sql.DB
	config Config
	slots  chan struct{}
}

const schema = `CREATE SCHEMA IF NOT EXISTS reversible_api;
CREATE TABLE IF NOT EXISTS reversible_api.value (resource_id TEXT PRIMARY KEY,value_json JSONB NOT NULL,owner_stamp TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reversible_api.operation (step_id TEXT PRIMARY KEY,spec_digest TEXT NOT NULL,spec_json JSONB NOT NULL,state TEXT NOT NULL,forward_closed BOOLEAN NOT NULL DEFAULT FALSE,resource_id TEXT NOT NULL DEFAULT '',before_json JSONB NULL,before_stamp TEXT NULL,after_stamp TEXT NOT NULL DEFAULT '',receipt_json JSONB NULL,updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());`

// Run only as an explicit migration; runtime startup never applies DDL.
func Migrate(ctx context.Context, db *sql.DB) error {
	if ctx == nil || db == nil {
		return compensation.ErrInvalid
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(20261009,1617)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, schema); err != nil {
		return err
	}
	return tx.Commit()
}
func New(ctx context.Context, db *sql.DB, c Config) (*Server, error) {
	if ctx == nil || db == nil || !strings.HasPrefix(c.ToolName, "api.") || c.TenantID == "" || c.ApplicationID == "" || len(c.AgentIDs) == 0 || len(c.AgentIDs) > 32 || len(c.ForwardToken) < 32 || len(c.ControlToken) < 32 || bytes.Equal(c.ForwardToken, c.ControlToken) {
		return nil, compensation.ErrInvalid
	}
	for _, token := range [][]byte{c.ForwardToken, c.ControlToken} {
		if len(token) > 8192 || strings.ContainsAny(string(token), "\r\n\x00") {
			return nil, compensation.ErrInvalid
		}
	}
	var found bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('reversible_api.operation') IS NOT NULL AND to_regclass('reversible_api.value') IS NOT NULL`).Scan(&found); err != nil || !found {
		return nil, compensation.ErrUnavailable
	}
	c.AgentIDs = append([]string(nil), c.AgentIDs...)
	c.ForwardToken = bytes.Clone(c.ForwardToken)
	c.ControlToken = bytes.Clone(c.ControlToken)
	return &Server{db: db, config: c, slots: make(chan struct{}, 8)}, nil
}
func Hash(v any) string {
	raw, _ := json.Marshal(v)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func Fingerprint(tool string, payload map[string]any) string {
	return Hash(struct {
		Name    string         `json:"name"`
		Payload map[string]any `json:"payload"`
	}{tool, payload})
}
func (s *Server) permitted(step compensation.Step) bool {
	if step.Validate() != nil || step.Root != step.Scope || step.Kind != "api" || step.Provider != Provider || step.Tool != s.config.ToolName || step.Scope.TenantID != s.config.TenantID || step.Scope.ApplicationID != s.config.ApplicationID {
		return false
	}
	for _, id := range s.config.AgentIDs {
		if id == step.Scope.AgentID {
			return true
		}
	}
	return false
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	fail := func(status int, code string) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": code})
	}
	if s == nil || r.Method != "POST" || r.URL.Path != "/v1/effects" || r.URL.RawQuery != "" {
		fail(404, "NOT_FOUND")
		return
	}
	var q Request
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF || q.Version != Protocol || !s.permitted(q.Step) {
		fail(400, "INVALID_BINDING")
		return
	}
	key := s.config.ControlToken
	if q.Action == "apply" {
		key = s.config.ForwardToken
	} else if q.Action != "lookup" && q.Action != "close" && q.Action != "undo" {
		fail(400, "INVALID_ACTION")
		return
	}
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(header, "Bearer ")), key) != 1 {
		fail(403, "SERVICE_AUTHORITY_DENIED")
		return
	}
	if q.Action != "apply" && q.Payload != nil {
		fail(400, "CONTROL_PAYLOAD_DENIED")
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		fail(429, "CAPACITY_EXCEEDED")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	result, err := s.execute(ctx, q)
	if err != nil {
		fail(409, "EFFECT_UNCONFIRMED")
		return
	}
	json.NewEncoder(w).Encode(result)
}
func (s *Server) execute(ctx context.Context, q Request) (Response, error) {
	result := Response{Version: Protocol, StepDigest: q.Step.Digest(), State: "unknown"}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,1617))`, q.Step.ID); err != nil {
		return result, err
	}
	var saved, state, resource, after string
	var closed bool
	var before, receipt []byte
	var beforeStamp sql.NullString
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT spec_digest,state,forward_closed,resource_id,before_json,before_stamp,after_stamp,receipt_json FROM reversible_api.operation WHERE step_id=? FOR UPDATE`), q.Step.ID).Scan(&saved, &state, &closed, &resource, &before, &beforeStamp, &after, &receipt)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}
	if exists && saved != q.Step.Digest() {
		return result, compensation.ErrConflict
	}
	if q.Action == "lookup" {
		if exists {
			result.State, result.ForwardClosed = state, closed
			if len(receipt) > 0 {
				var r compensation.Receipt
				if json.Unmarshal(receipt, &r) != nil || r.Validate(q.Step) != nil {
					return result, compensation.ErrConflict
				}
				result.Receipt = &r
				result.EvidenceDigest = r.EvidenceDigest
			}
		}
		return result, tx.Commit()
	}
	if q.Action == "apply" {
		if len(q.Payload) != 2 || Fingerprint(q.Step.Tool, q.Payload) != q.Step.Fingerprint {
			return result, compensation.ErrInvalid
		}
		key, keyOK := q.Payload["key"].(string)
		value, valOK := q.Payload["value"].(string)
		if !keyOK || !valOK || key == "" || len(key) > 128 || len(value) > 16384 || strings.ContainsAny(key, "\r\n\x00") {
			return result, compensation.ErrInvalid
		}
		if exists {
			if closed {
				return result, compensation.ErrPending
			}
			result.State = state
			return result, tx.Commit()
		}
		// Scope includes recipient: an Agent cannot overwrite another user's
		// resource by choosing an identical business key.
		resource = Hash([]string{q.Step.Scope.TenantID, q.Step.Scope.ApplicationID, q.Step.Scope.PrincipalType, q.Step.Scope.PrincipalID, key})
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,1618))`, resource); err != nil {
			return result, err
		}
		err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT value_json,owner_stamp FROM reversible_api.value WHERE resource_id=? FOR UPDATE`), resource).Scan(&before, &beforeStamp)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return result, err
		}
		after = q.Step.ID
		valueJSON, _ := json.Marshal(value)
		if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO reversible_api.value VALUES(?,?::jsonb,?) ON CONFLICT(resource_id) DO UPDATE SET value_json=EXCLUDED.value_json,owner_stamp=EXCLUDED.owner_stamp`), resource, string(valueJSON), after); err != nil {
			return result, err
		}
		spec, _ := json.Marshal(q.Step)
		var beforeValue any
		if len(before) > 0 {
			beforeValue = string(before)
		}
		_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO reversible_api.operation(step_id,spec_digest,spec_json,state,resource_id,before_json,before_stamp,after_stamp) VALUES(?,?,?::jsonb,'applied',?,?::jsonb,?,?)`), q.Step.ID, q.Step.Digest(), string(spec), resource, beforeValue, beforeStamp, after)
		if err != nil {
			return result, err
		}
		result.State = "applied"
		return result, tx.Commit()
	}
	// Close persists a tombstone before reporting no-effect. This fences a
	// delayed forward request even when it had not reached this API at cancel.
	if !exists {
		spec, _ := json.Marshal(q.Step)
		if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO reversible_api.operation(step_id,spec_digest,spec_json,state,forward_closed) VALUES(?,?,?::jsonb,'no_effect',TRUE)`), q.Step.ID, q.Step.Digest(), string(spec)); err != nil {
			return result, err
		}
		state, closed = "no_effect", true
	} else if !closed {
		if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE reversible_api.operation SET forward_closed=TRUE,updated_at=clock_timestamp() WHERE step_id=?`), q.Step.ID); err != nil {
			return result, err
		}
		closed = true
	}
	result.State, result.ForwardClosed = state, true
	if len(receipt) > 0 {
		var r compensation.Receipt
		if json.Unmarshal(receipt, &r) != nil || r.Validate(q.Step) != nil {
			return result, compensation.ErrConflict
		}
		result.Receipt = &r
		result.EvidenceDigest = r.EvidenceDigest
		return result, tx.Commit()
	}
	if q.Action == "close" && state == "applied" {
		result.EvidenceDigest = Hash([]string{Protocol, q.Step.Digest(), "applied", "forward_closed"})
		return result, tx.Commit()
	}
	action := "no_effect"
	if state == "applied" {
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,1618))`, resource); err != nil {
			return result, err
		}
		var stamp string
		if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT owner_stamp FROM reversible_api.value WHERE resource_id=? FOR UPDATE`), resource).Scan(&stamp); err != nil || stamp != after {
			return result, compensation.ErrConflict
		}
		if beforeStamp.Valid {
			_, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE reversible_api.value SET value_json=?::jsonb,owner_stamp=? WHERE resource_id=? AND owner_stamp=?`), string(before), beforeStamp.String, resource, after)
		} else {
			_, err = tx.ExecContext(ctx, sqlutil.Bind(`DELETE FROM reversible_api.value WHERE resource_id=? AND owner_stamp=?`), resource, after)
		}
		if err != nil {
			return result, err
		}
		action = "rolled_back"
		state = "rolled_back"
	} else if state != "no_effect" {
		return result, compensation.ErrConflict
	}
	r := compensation.Receipt{Version: compensation.ContractVersion, StepDigest: q.Step.Digest(), Key: q.Step.CompensationKey(), Action: action, EvidenceDigest: Hash([]string{Protocol, q.Step.Digest(), state, "forward_closed"})}
	raw, _ := json.Marshal(r)
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE reversible_api.operation SET state=?,receipt_json=?::jsonb,updated_at=clock_timestamp() WHERE step_id=?`), state, string(raw), q.Step.ID); err != nil {
		return result, err
	}
	result.State, result.Receipt, result.EvidenceDigest = state, &r, r.EvidenceDigest
	return result, tx.Commit()
}
