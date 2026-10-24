package compensation

import (
	"context"
	"database/sql"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// EffectLedger 只公开副作用登记及事务围栏，不公开连接、迁移或 SQL 实现。
// 调用者的业务写入和这些操作必须使用同一个事务。
type EffectLedger interface {
	RegisterTx(context.Context, *sql.Tx, Step) error
	GuardRegisteredStopTx(context.Context, *sql.Tx, Step) error
	GuardLeaseTx(context.Context, *sql.Tx, Lease) error
	ReadEffectReferenceTx(context.Context, *sql.Tx, string, string) (Step, error)
}

// Coordinator 是组合根注入执行模块的补偿端口。数据库构造和只读启动
// 检查属于组合根；执行模块仅提交控制意图、核对覆盖及读取完成证明。
type Coordinator interface {
	EffectLedger
	Queue
	WorkerStore
	BeginTx(context.Context, *sql.Tx, sharedkernel.Scope, uint64) (string, error)
	ConfirmStoppedTx(context.Context, *sql.Tx, sharedkernel.Scope, StopProof) error
	FinalizeTx(context.Context, *sql.Tx, sharedkernel.Scope) error
	Progress(context.Context, sharedkernel.Scope) (Progress, bool, error)
	ProgressTx(context.Context, *sql.Tx, sharedkernel.Scope) (Progress, bool, error)
	CompletionProofTx(context.Context, *sql.Tx, sharedkernel.Scope) (StopProof, error)
	EnrollStoppedTreeTx(context.Context, *sql.Tx, sharedkernel.Scope, []sharedkernel.Scope) error
	VerifyStoppedTreeCoverageTx(context.Context, *sql.Tx, sharedkernel.Scope, []sharedkernel.Scope) error
}

// LocalEffects 是资源所有者使用的前镜像端口。资源模块只能提供自己的
// RestoreEffectTx，不能借用补偿仓储执行其他模块的 SQL。
type LocalEffects interface {
	AppliedTx(context.Context, *sql.Tx, Step) (bool, error)
	RecordTx(context.Context, *sql.Tx, Step, LocalEffect) error
	BindOwner(string, string, LocalEffectOwner) (Port, error)
}

func (s *LocalEffectLedger) BindOwner(provider, version string, owner LocalEffectOwner) (Port, error) {
	return s.Port(provider, version, owner)
}

var _ Coordinator = (*SQLStore)(nil)
var _ LocalEffects = (*LocalEffectLedger)(nil)
