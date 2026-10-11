package capability

import (
	"context"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type toolQuiescenceStore interface {
	CheckToolQuiescence(context.Context, string) error
}

// CheckTaskEffectQuiescence grants no execution or receipt repair. Both model
// settlement and actual tool ledger completion must precede lease release.
func (m *Module) CheckTaskEffectQuiescence(ctx context.Context, scope sharedkernel.Scope) error {
	if err := m.CheckTaskModelQuiescence(ctx, scope); err != nil {
		return err
	}
	store, ok := m.toolStore.(toolQuiescenceStore)
	if !ok {
		return ErrToolResultUnknown
	}
	return store.CheckToolQuiescence(ctx, ToolReceiptScopeHash(scope))
}

func (s *SQLToolInvocationStore) CheckToolQuiescence(ctx context.Context, scopeHash string) error {
	if s == nil || s.db == nil || len(scopeHash) != 64 {
		return ErrToolResultUnknown
	}
	var pending bool
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS(SELECT 1 FROM platform_tool_invocation WHERE scope_hash=? AND status NOT IN ('completed','failed'))`), scopeHash).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return ErrToolResultUnknown
	}
	return nil
}

func (s *memoryToolInvocationStore) CheckToolQuiescence(ctx context.Context, scopeHash string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.records {
		if record.ScopeHash == scopeHash && record.Status != "completed" && record.Status != "failed" {
			return ErrToolResultUnknown
		}
	}
	return nil
}

var _ toolQuiescenceStore = (*SQLToolInvocationStore)(nil)
var _ toolQuiescenceStore = (*memoryToolInvocationStore)(nil)
