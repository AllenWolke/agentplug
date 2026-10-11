package runtime

import "sort"

// CreationProjection is atomically created with the Run. Each consumer owns
// its acknowledgment, so a task outage cannot erase a conversation repair.
// CreationProjection 与 Run 原子创建；各消费者独立确认，避免一项失败丢失另一项待办。
type CreationProjection struct {
	RunID               string
	MessageID           string
	ConversationPending bool
	TaskPending         bool
}

func (s *Store) PendingCreations(limit int) ([]CreationProjection, error) {
	return s.PendingCreationsAfter("", limit)
}

func (s *Store) PendingCreationsAfter(after string, limit int) ([]CreationProjection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := []CreationProjection{}
	if limit <= 0 {
		return result, nil
	}
	for _, projection := range s.creations {
		if (projection.ConversationPending || projection.TaskPending) && projection.RunID > after {
			result = append(result, projection)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RunID < result[j].RunID })
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (s *Store) GetCreation(id string) (CreationProjection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.creations[id]
	if !ok {
		return CreationProjection{}, ErrRunNotFound
	}
	return p, nil
}

func (s *Store) AcknowledgeCreation(id, kind string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.creations[id]
	if !ok {
		return ErrRunNotFound
	}
	switch kind {
	case "conversation":
		p.ConversationPending = false
	case "task":
		p.TaskPending = false
	default:
		return ErrInvalidRequest
	}
	s.creations[id] = p
	return nil
}
