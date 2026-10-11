package runtime

import (
	"encoding/hex"
	"time"
)

// DispatchCommand records what the current fenced worker actually signed.
// No bearer token is needed for recovery or capability authorization.
// DispatchCommand 保存当前受 fencing 保护的 Worker 实际签名摘要，不依赖持久化 Bearer。
type DispatchCommand struct {
	RunID      string
	Revision   uint64
	Operation  string
	BodyHash   string
	PolicyHash string
}

func (c DispatchCommand) Validate() error {
	if c.RunID == "" || c.Revision == 0 || (c.Operation != "run" && c.Operation != "invoke" && c.Operation != "resume") {
		return ErrInvalidRequest
	}
	for _, value := range []string{c.BodyHash, c.PolicyHash} {
		raw, err := hex.DecodeString(value)
		if err != nil || len(raw) != 32 {
			return ErrInvalidRequest
		}
	}
	return nil
}

func (s *Store) RecordDispatchCommand(command DispatchCommand, token string) error {
	if err := command.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[command.RunID]
	if !ok {
		return ErrRunNotFound
	}
	if run.Status != StatusRunning || run.Revision != command.Revision || token == "" || run.LeaseToken != token || !run.LeaseUntil.After(time.Now().UTC()) {
		return ErrLeaseConflict
	}
	if err := s.checkSessionLeaseLocked(run, time.Now().UTC()); err != nil {
		return err
	}
	s.commands[command.RunID] = command
	return nil
}

func (s *Store) GetDispatchCommand(id string) (DispatchCommand, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.commands[id]
	if !ok {
		return DispatchCommand{}, ErrRunNotFound
	}
	return c, nil
}
