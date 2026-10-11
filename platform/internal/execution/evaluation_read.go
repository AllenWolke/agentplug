package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	agenteval "github.com/lexagent/agent-evaluation"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// ReadEvaluationTrajectory is read-only and repeats the same history policy as
// the public Run API. It never releases signed envelopes or lease credentials.
func (m *Module) ReadEvaluationTrajectory(ctx context.Context, actor BrowserRunActor, id string) (agenteval.Trajectory, error) {
	get := func(id string) (platformruntime.Run, error) {
		if reader, ok := m.store.(interface {
			GetContext(context.Context, string) (platformruntime.Run, error)
		}); ok {
			return reader.GetContext(ctx, id)
		}
		return m.store.Get(id)
	}
	run, err := get(id)
	if err != nil {
		return agenteval.Trajectory{}, platformruntime.ErrRunNotFound
	}
	if m.browserRunAuthorizer == nil {
		return agenteval.Trajectory{}, ErrRunPermissionDenied
	}
	if err = m.browserRunAuthorizer(ctx, run.Scope, actor, "history.read"); err != nil {
		return agenteval.Trajectory{}, err
	}
	t := agenteval.Trajectory{Version: agenteval.TrajectoryVersion, Source: "platform", RunID: run.ID, ParentRunID: run.Scope.ParentRunID,
		Agent:  agenteval.Agent{AgentID: run.Scope.AgentID, InstallationID: run.Scope.InstallationID, VersionID: run.AgentVersionID},
		Status: string(run.Status), StartedAt: run.CreatedAt.UTC().Format(time.RFC3339Nano), TraceID: run.Scope.TraceID, Events: []agenteval.Event{}, Missing: []string{}, Children: []string{}}
	terminal := run.Status == platformruntime.StatusSucceeded || run.Status == platformruntime.StatusFailed || run.Status == platformruntime.StatusCancelled
	if terminal {
		t.FinishedAt = run.UpdatedAt.UTC().Format(time.RFC3339Nano)
		duration := float64(run.UpdatedAt.Sub(run.CreatedAt).Milliseconds())
		if duration >= 0 {
			t.Measurements.LatencyMS = &duration
		}
	}
	hash := sha256.Sum256(run.RequestJSON)
	t.InputHash = hex.EncodeToString(hash[:])
	var envelope struct {
		Input map[string]json.RawMessage `json:"input"`
	}
	if json.Unmarshal(run.RequestJSON, &envelope) == nil && envelope.Input != nil {
		delete(envelope.Input, "policy_snapshot")
		canonical, _ := json.Marshal(envelope.Input)
		var business any
		decoder := json.NewDecoder(bytes.NewReader(canonical))
		decoder.UseNumber()
		if decoder.Decode(&business) == nil {
			canonical, _ = json.Marshal(business)
			hash = sha256.Sum256(canonical)
			t.BusinessInputHash = hex.EncodeToString(hash[:])
		}
	}
	outcome, outcomeErr := m.store.GetOutcome(id)
	if outcomeErr == nil {
		hash = sha256.Sum256(outcome.OutputJSON)
		t.OutputHash = hex.EncodeToString(hash[:])
		var value any
		decoder := json.NewDecoder(bytes.NewReader(outcome.OutputJSON))
		decoder.UseNumber()
		if len(outcome.OutputJSON) <= 1<<20 && decoder.Decode(&value) == nil {
			t.Output, _ = json.Marshal(agenteval.Sanitize(value))
		} else {
			t.Missing = append(t.Missing, "output_too_large_or_invalid")
		}
	} else {
		t.Missing = append(t.Missing, "output")
	}
	cursor := uint64(0)
	complete := true
	for len(t.Events) < 10000 {
		events, e := m.store.Events(id, cursor)
		if e != nil {
			return agenteval.Trajectory{}, e
		}
		if len(events) == 0 {
			break
		}
		for _, event := range events {
			if event.Seq <= cursor {
				return agenteval.Trajectory{}, errors.New("evaluation event cursor invalid")
			}
			cursor = event.Seq
			projected := agenteval.Event{Seq: event.Seq, RunID: id, Kind: event.Type, StartedAt: event.OccurredAt.UTC().Format(time.RFC3339Nano)}
			// Stable error codes are sufficient for diagnosis. Never expose the
			// remote error message or free-form event payload through evaluation.
			if code, ok := event.Payload["code"].(string); ok && len(code) <= 128 {
				valid := code != ""
				for _, r := range code {
					valid = valid && (r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_')
				}
				if valid {
					projected.ErrorType = code
				}
			}
			t.Events = append(t.Events, projected)
		}
		if len(t.Events) >= 10000 {
			complete = false
			t.Missing = append(t.Missing, "events_truncated")
			break
		}
	}
	if reader, ok := m.store.(interface {
		EvaluationChildren(context.Context, sharedkernel.Scope) ([]string, error)
	}); ok {
		t.Children, err = reader.EvaluationChildren(ctx, run.Scope)
		if err != nil {
			return agenteval.Trajectory{}, err
		}
		visible := []string{}
		for _, childID := range t.Children {
			child, e := get(childID)
			if e != nil {
				return agenteval.Trajectory{}, e
			}
			if e = m.browserRunAuthorizer(ctx, child.Scope, actor, "history.read"); e == nil {
				visible = append(visible, childID)
			} else {
				t.Missing = append(t.Missing, "child_history_permission")
			}
		}
		t.Children = visible
	} else {
		t.Missing = append(t.Missing, "children")
	}
	t.Complete = terminal && complete && len(t.Missing) == 0
	t.Coverage = map[string]bool{"events": terminal && complete}
	if err = m.browserRunAuthorizer(ctx, run.Scope, actor, "history.read"); err != nil {
		return agenteval.Trajectory{}, err
	}
	return t, nil
}

func (s *SQLStore) EvaluationChildren(ctx context.Context, scope sharedkernel.Scope) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT run_id FROM platform_execution_run WHERE tenant_id=? AND department_id=? AND application_id=? AND COALESCE(NULLIF(request_json,'')::jsonb->'scope'->>'parent_run_id','')=? ORDER BY created_at,run_id LIMIT 201`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.RunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	if len(out) > 200 {
		return nil, errors.New("evaluation children limit exceeded")
	}
	return out, rows.Err()
}

// Counts only the authenticated owner's work; it cannot disclose another user's
// presence through a deployment-level count.
func (s *SQLStore) EvaluationActiveCount(ctx context.Context, scope sharedkernel.Scope) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_execution_run WHERE tenant_id=? AND department_id=? AND application_id=? AND installation_id=? AND principal_id=? AND principal_type=? AND status IN ('running','recovering','cancelling') AND lease_token<>'' AND lease_until>CURRENT_TIMESTAMP`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.InstallationID, scope.PrincipalID, scope.PrincipalType).Scan(&count)
	return count, err
}
