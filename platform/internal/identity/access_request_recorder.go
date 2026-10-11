package identity

// Transactional Access Decision Recorders
// 授权申请决策的事务记录边界

import (
	"context"
	"database/sql"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// AgentAccessDecisionRecorder is composed at the process boundary. It writes
// audit and integration events using the exact transaction that changes the
// request and creates its grants.
// AgentAccessDecisionRecorder 在进程组合根注入，并复用变更申请与授权的同一事务写入审计及集成事件。
type AgentAccessDecisionRecorder func(context.Context, *sql.Tx, sharedkernel.Scope, AgentAccessRequest) error

// SetAgentAccessDecisionRecorder configures the required atomic side effects
// before the module starts serving requests.
// SetAgentAccessDecisionRecorder 在模块开始服务前配置必须的原子副作用。
func (s *SQLStore) SetAgentAccessDecisionRecorder(recorder AgentAccessDecisionRecorder) {
	if s != nil {
		s.accessDecisionRecorder = recorder
	}
}
