package capability

import "testing"

// 保留历史用例名；底层改用相同账本场景的原生PostgreSQL集成用例。
func TestGovernedModelBillingMySQLIntegration(t *testing.T) {
	testGovernedModelBillingPostgres(t, false)
}
