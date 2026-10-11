package runtime

import (
	"encoding/json"
	"sort"
)

// Outcome is the durable execution result and projection intent, not another
// Agent invocation. Revision fences acknowledgments against a subsequent resume.
// Outcome 是持久化结果及投影待办，不触发新的 Agent 调用；revision 隔离后续恢复结果。
type Outcome struct {
	RunID             string
	Revision          uint64
	OutputJSON        []byte
	EventType         string
	EventPayload      map[string]any
	ProjectionPending bool
}

func NewOutcome(status Status, output map[string]any, payload map[string]any) (Outcome, error) {
	eventTypes := map[Status]string{StatusSucceeded: "task_completed", StatusFailed: "task_failed", StatusCancelled: "task_cancelled", StatusWaiting: "waiting"}
	eventType, ok := eventTypes[status]
	if !ok {
		return Outcome{}, ErrInvalidTransition
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		return Outcome{}, err
	}
	// Check serialization before entering the state transaction. / 入事务前检查序列化。
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		return Outcome{}, err
	}
	var copied map[string]any
	if err := json.Unmarshal(encodedPayload, &copied); err != nil {
		return Outcome{}, err
	}
	return Outcome{OutputJSON: encoded, EventType: eventType, EventPayload: copied, ProjectionPending: status == StatusSucceeded}, nil
}

func (s *Store) FinalizeLeased(id string, status Status, revision uint64, token string, output map[string]any, payload map[string]any) (Run, error) {
	if token == "" {
		return Run{}, ErrLeaseConflict
	}
	outcome, err := NewOutcome(status, output, payload)
	if err != nil {
		return Run{}, err
	}
	return s.transitionOutcome(id, StatusRunning, status, revision, token, &outcome)
}

func (s *Store) PendingOutcomes(limit int) ([]Outcome, error) {
	return s.PendingOutcomesAfter("", limit)
}

func (s *Store) PendingOutcomesAfter(after string, limit int) ([]Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := []Outcome{}
	if limit <= 0 {
		return result, nil
	}
	for _, outcome := range s.outcomes {
		if outcome.ProjectionPending && outcome.RunID > after {
			outcome.OutputJSON = append([]byte(nil), outcome.OutputJSON...)
			result = append(result, outcome)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RunID < result[j].RunID })
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (s *Store) GetOutcome(id string) (Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	outcome, ok := s.outcomes[id]
	if !ok {
		return Outcome{}, ErrRunNotFound
	}
	outcome.OutputJSON = append([]byte(nil), outcome.OutputJSON...)
	encoded, err := json.Marshal(outcome.EventPayload)
	if err != nil {
		return Outcome{}, err
	}
	outcome.EventPayload = nil
	if err := json.Unmarshal(encoded, &outcome.EventPayload); err != nil {
		return Outcome{}, err
	}
	return outcome, nil
}

func (s *Store) AcknowledgeOutcome(id string, revision uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	outcome, ok := s.outcomes[id]
	if !ok {
		return ErrRunNotFound
	}
	if outcome.Revision != revision {
		return ErrRevisionConflict
	}
	outcome.ProjectionPending = false
	s.outcomes[id] = outcome
	return nil
}
