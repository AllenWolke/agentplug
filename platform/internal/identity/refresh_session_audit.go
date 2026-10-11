package identity

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var ErrRefreshRecorderRequired = errors.New("refresh session audit recorder is required")

type RefreshSessionEvent struct {
	ID         string
	FamilyID   string
	Identity   LocalIdentity
	Action     string
	OccurredAt time.Time
}

type RefreshSessionRecorder func(context.Context, *sql.Tx, RefreshSessionEvent) error

func (s *SQLStore) SetRefreshSessionRecorder(recorder RefreshSessionRecorder) {
	s.refreshSessionRecorder = recorder
}

func (s *SQLStore) recordRefreshSession(ctx context.Context, tx *sql.Tx, family string, identity LocalIdentity, action string) error {
	if s.refreshSessionRecorder == nil {
		return ErrRefreshRecorderRequired
	}
	_, eventID, err := refreshSecret()
	if err != nil {
		return err
	}
	return s.refreshSessionRecorder(ctx, tx, RefreshSessionEvent{ID: "refresh-" + eventID, FamilyID: family, Identity: identity, Action: action, OccurredAt: s.clock().UTC()})
}
