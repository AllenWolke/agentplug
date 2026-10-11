package notification

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
)

// FindCommittedEvent is a read-only Port, not enqueue or delivery.
// 只读查询已提交Outbox事件，不执行入队或消息投递。
func (s *SQLStore) FindCommittedEvent(ctx context.Context, id string) (Event, bool, error) {
	if s == nil || s.db == nil {
		return Event{}, false, errors.New("notification database required")
	}
	event, err := scanEvent(s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT event_id,tenant_id,department_id,application_id,topic,event_type,partition_key,payload_json,status,attempts,next_attempt_at,claim_owner,claim_until FROM platform_notification_outbox WHERE event_id=?`), id))
	if errors.Is(err, sql.ErrNoRows) {
		return Event{}, false, nil
	}
	if err != nil {
		return Event{}, false, err
	}
	return event, true, nil
}

func (s *Store) FindCommittedEvent(ctx context.Context, id string) (Event, bool, error) {
	if err := ctx.Err(); err != nil {
		return Event{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	event, ok := s.events[id]
	if !ok {
		return Event{}, false, nil
	}
	// Deep copy isolates callers from mutable dispatcher state.
	// 深拷贝隔离查询者与消息Dispatcher的可变状态。
	raw, err := json.Marshal(event)
	if err != nil {
		return Event{}, false, err
	}
	var result Event
	if err := json.Unmarshal(raw, &result); err != nil {
		return Event{}, false, err
	}
	return result, true, nil
}
