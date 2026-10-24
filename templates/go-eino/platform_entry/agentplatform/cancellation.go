package agentplatform

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
)

var ErrCancellationEvidence = errors.New("platform cancellation evidence unconfirmed")

type CancellationProgress struct {
	Version        string `json:"version"`
	CancellationID string `json:"cancellation_id"`
	Phase          string `json:"phase"`
	StopConfirmed  *bool  `json:"stop_confirmed"`
	Total          *int   `json:"total"`
	Compensated    *int   `json:"compensated"`
	NoEffect       *int   `json:"no_effect"`
	Unresolved     *int   `json:"unresolved"`
	Attention      *int   `json:"needs_attention"`
}
type CancellationState struct {
	Version     string                `json:"version"`
	Disposition string                `json:"disposition"`
	Progress    *CancellationProgress `json:"progress,omitempty"`
	complete    bool
}

// Complete refers to the PLATFORM business outcome, not the Agent gateway's
// execution-stop acknowledgement. It is true only for validated proof read
// through the authenticated platform API.
func (s CancellationState) Complete() bool { return s.complete }

func ReadCancellationState(status string, raw json.RawMessage) (*CancellationState, error) {
	empty := len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
	if status != "cancelling" && status != "cancelled" {
		if !empty {
			return nil, ErrCancellationEvidence
		}
		return nil, nil
	}
	if empty {
		disposition := "pending_unverified"
		if status == "cancelled" {
			disposition = "historical_unverified"
		}
		return &CancellationState{Version: "cancellation-state/v1", Disposition: disposition}, nil
	}
	if len(raw) > 8192 {
		return nil, ErrCancellationEvidence
	}
	var s CancellationState
	if json.Unmarshal(raw, &s) != nil || s.Version != "cancellation-state/v1" {
		return nil, ErrCancellationEvidence
	}
	if s.Disposition == "historical_unverified" || s.Disposition == "pending_unverified" {
		expected := "cancelling"
		if s.Disposition == "historical_unverified" {
			expected = "cancelled"
		}
		if status != expected || s.Progress != nil {
			return nil, ErrCancellationEvidence
		}
		return &s, nil
	}
	if s.Disposition != "verified" && s.Disposition != "in_progress" {
		return nil, ErrCancellationEvidence
	}
	p := s.Progress
	if p == nil || p.Version != "cancellation-compensation/v1" || p.StopConfirmed == nil {
		return nil, ErrCancellationEvidence
	}
	id, err := hex.DecodeString(p.CancellationID)
	if err != nil || len(id) != 32 || p.CancellationID != hex.EncodeToString(id) {
		return nil, ErrCancellationEvidence
	}
	for _, n := range []*int{p.Total, p.Compensated, p.NoEffect, p.Unresolved, p.Attention} {
		if n == nil || *n < 0 || *n > 16384 {
			return nil, ErrCancellationEvidence
		}
	}
	if *p.Compensated+*p.NoEffect+*p.Unresolved != *p.Total || *p.Attention > *p.Unresolved {
		return nil, ErrCancellationEvidence
	}
	if p.Phase != "stopping" && p.Phase != "compensating" && p.Phase != "needs_attention" && p.Phase != "complete" {
		return nil, ErrCancellationEvidence
	}
	if (p.Phase == "stopping") == *p.StopConfirmed || (p.Phase == "needs_attention") != (*p.Attention > 0) {
		return nil, ErrCancellationEvidence
	}
	if s.Disposition == "verified" {
		if status != "cancelled" || p.Phase != "complete" || *p.Unresolved != 0 || !*p.StopConfirmed {
			return nil, ErrCancellationEvidence
		}
		s.complete = true
	} else if status != "cancelling" || p.Phase == "complete" {
		return nil, ErrCancellationEvidence
	}
	return &s, nil
}
