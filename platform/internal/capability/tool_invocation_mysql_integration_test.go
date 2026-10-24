package capability

import "testing"

// 失败回执重试及重开连接场景保留；不再加载已退役的MySQL驱动。
func TestToolInvocationFailedAttemptCanRetryMySQLIntegration(t *testing.T) {
	TestToolInvocationFailedAttemptCanRetryPostgresIntegration(t)
}
