package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

var ErrInvalidEvent = errors.New("invalid audit event")

type Event struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	DepartmentID  string    `json:"department_id"`
	ApplicationID string    `json:"application_id"`
	ActorType     string    `json:"actor_type"`
	ActorID       string    `json:"actor_id"`
	TraceID       string    `json:"trace_id"`
	AggregateType string    `json:"aggregate_type"`
	AggregateID   string    `json:"aggregate_id"`
	Action        string    `json:"action"`
	Outcome       string    `json:"outcome"`
	Summary       string    `json:"summary"`
	CreatedAt     time.Time `json:"created_at"`
}

func (e Event) Validate() error {
	if e.ID == "" || e.TenantID == "" || e.DepartmentID == "" || e.ApplicationID == "" || e.ActorID == "" || e.Action == "" || e.AggregateType == "" || e.AggregateID == "" || e.CreatedAt.IsZero() {
		return ErrInvalidEvent
	}
	return nil
}

// Digest creates a stable redacted audit fingerprint; raw secrets and payloads
// never enter the audit event. / Digest 只生成稳定摘要，原始密钥和大载荷
// 永不写入审计事件。
func (e Event) Digest() (string, error) {
	if err := e.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(struct {
		ID, TenantID, DepartmentID, ApplicationID string
		ActorType, ActorID, TraceID               string
		AggregateType, AggregateID, Action        string
		Outcome, Summary                          string
	}{e.ID, e.TenantID, e.DepartmentID, e.ApplicationID, e.ActorType, e.ActorID, e.TraceID, e.AggregateType, e.AggregateID, e.Action, e.Outcome, e.Summary})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
