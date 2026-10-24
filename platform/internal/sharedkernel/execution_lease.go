package sharedkernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// ExecutionLeaseBinding is signed proof of the current worker generation.
// Revision is the Run execution generation, not a business checkpoint revision,
// authorization epoch or tool attempt fence. Tokens are scoped to one Run and
// may never be compared across Runs or used as external operation identities.
// 执行租约绑定是当前 Worker 世代的签名证明，不向 Agent 暴露原始租约密钥。
type ExecutionLeaseBinding struct {
	Revision  uint64
	TokenHash string
}
type executionLeaseKey struct{}

func BindExecutionLease(ctx context.Context, revision uint64, token string) context.Context {
	digest := sha256.Sum256([]byte(token))
	return WithExecutionLease(ctx, ExecutionLeaseBinding{Revision: revision, TokenHash: hex.EncodeToString(digest[:])})
}
func WithExecutionLease(ctx context.Context, binding ExecutionLeaseBinding) context.Context {
	return context.WithValue(ctx, executionLeaseKey{}, binding)
}
func ExecutionLeaseFromContext(ctx context.Context) (ExecutionLeaseBinding, bool) {
	if ctx == nil {
		return ExecutionLeaseBinding{}, false
	}
	binding, ok := ctx.Value(executionLeaseKey{}).(ExecutionLeaseBinding)
	return binding, ok && binding.Revision > 0 && len(binding.TokenHash) == 64
}
