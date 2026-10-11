package capability

// RegisterRuntimeExecutor 在启动组合时追加业务工具执行器。
// 注册不替换已有工具；执行继续经过公共权限、预算、租约与Observation边界。
// 此方法不提供HTTP注册入口，调用方必须在启动监听前完成组合。
func (m *Module) RegisterRuntimeExecutor(provider RegisteredRuntimeExecutor) error {
	return m.installRuntimeExecutor(provider)
}
