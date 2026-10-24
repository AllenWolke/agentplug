package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/lexagent/platform/internal/compensation"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

const CancellationProjectionVersion = "cancellation-state/v1"

// No before-image, lease, credential or user output is projected. A historical
// terminal status alone cannot establish a verified business cancellation.
type CancellationProjection struct {
	Version     string                 `json:"version"`
	Disposition string                 `json:"disposition"`
	Progress    *compensation.Progress `json:"progress,omitempty"`
}

func (s *SQLStore) readCancellationOutcomeProofTx(ctx context.Context, tx *sql.Tx, run platformruntime.Run) (bool, error) {
	proof, err := s.cancellationSaga.CompletionProofTx(ctx, tx, run.Scope)
	if err != nil {
		return false, err
	}
	if proof.Revision == ^uint64(0) || run.Revision != proof.Revision+1 || run.LeaseToken != "" {
		return false, compensation.ErrConflict
	}
	var revision uint64
	var event string
	var raw, stoppedRaw []byte
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,event_type,event_payload FROM platform_execution_outcome WHERE run_id=?`), run.ID).Scan(&revision, &event, &raw); err != nil {
		return false, err
	}
	var outcome struct {
		Source      string `json:"source"`
		Version     string `json:"compensation_version"`
		ScopeDigest string `json:"scope_digest"`
		StopDigest  string `json:"stop_evidence_digest"`
	}
	if len(raw) > 2048 || json.Unmarshal(raw, &outcome) != nil || revision != run.Revision || event != "task_cancelled" ||
		outcome.Source != "platform_cancel" || outcome.Version != compensation.ContractVersion || outcome.ScopeDigest != proof.ScopeDigest || outcome.StopDigest != proof.EvidenceDigest {
		return false, compensation.ErrConflict
	}
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_execution_event WHERE run_id=? AND event_type='cancellation_stop_verified' ORDER BY seq DESC LIMIT 1`), run.ID).Scan(&stoppedRaw); err != nil {
		return false, err
	}
	return stopHash(stoppedRaw) == proof.EvidenceDigest, nil
}

func legacyCancellationProjection(run platformruntime.Run) *CancellationProjection {
	if run.Status != platformruntime.StatusCancelling && run.Status != platformruntime.StatusCancelled {
		return nil
	}
	disposition := "pending_unverified"
	if run.Status == platformruntime.StatusCancelled {
		disposition = "historical_unverified"
	}
	return &CancellationProjection{Version: CancellationProjectionVersion, Disposition: disposition}
}

func (s *SQLStore) ReadCancellationProjection(ctx context.Context, scope sharedkernel.Scope) (platformruntime.Run, *CancellationProjection, error) {
	if ctx == nil || scope.ValidateTrusted() != nil {
		return platformruntime.Run{}, nil, compensation.ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return platformruntime.Run{}, nil, err
	}
	defer tx.Rollback()
	run, err := readExecutionRun(ctx, tx, scope.RunID, " FOR UPDATE")
	if err != nil {
		return platformruntime.Run{}, nil, err
	}
	if run.Scope != scope {
		return platformruntime.Run{}, nil, compensation.ErrConflict
	}
	projection := legacyCancellationProjection(run)
	if projection != nil && s.cancellationSaga != nil {
		p, found, err := s.cancellationSaga.ProgressTx(ctx, tx, scope)
		if err != nil {
			return platformruntime.Run{}, nil, err
		}
		if found {
			projection.Progress = &p
			projection.Disposition = "in_progress"
			if (p.Phase == "complete") != (run.Status == platformruntime.StatusCancelled) {
				return platformruntime.Run{}, nil, compensation.ErrConflict
			}
			if run.Status == platformruntime.StatusCancelled {
				outcome, err := s.readCancellationOutcomeProofTx(ctx, tx, run)
				if err != nil || !outcome {
					return platformruntime.Run{}, nil, compensation.ErrConflict
				}
				projection.Disposition = "verified"
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return platformruntime.Run{}, nil, err
	}
	return run, projection, nil
}

// Permission is checked by the caller before using the owner Scope. The
// repository then returns one consistent Run/compensation snapshot.
func (m *Module) writeCancellationAwareRun(w http.ResponseWriter, r *http.Request, status int, run platformruntime.Run, replayed bool) {
	projection := legacyCancellationProjection(run)
	if reader, ok := m.store.(interface {
		ReadCancellationProjection(context.Context, sharedkernel.Scope) (platformruntime.Run, *CancellationProjection, error)
	}); ok && projection != nil {
		current, p, err := reader.ReadCancellationProjection(r.Context(), run.Scope)
		if err != nil {
			m.writeError(w, http.StatusServiceUnavailable, "CANCELLATION_STATE_UNCONFIRMED")
			return
		}
		run, projection = current, p
		if status == http.StatusAccepted && run.Status == platformruntime.StatusCancelled {
			status = http.StatusOK
		}
	}
	response := runResponseFrom(run, replayed)
	response.Cancellation = projection
	if m.modelRoutingSummary != nil {
		summary, err := m.modelRoutingSummary.ReadRunModelRouting(r.Context(), run.Scope)
		if err != nil {
			m.writeError(w, http.StatusServiceUnavailable, "MODEL_ROUTING_STATE_UNCONFIRMED")
			return
		}
		response.ModelRouting = &summary
	}
	m.writeJSON(w, status, response)
}
