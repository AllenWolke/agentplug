package execution

import "context"

// Test setup is explicit; connecting the production repository never migrates.
// 测试夹具显式迁移，生产仓储连接绝不能隐式改库。
func openMigratedSQLFixture(ctx context.Context, driver, dsn string) (*SQLStore, error) {
	s, err := OpenSQLStore(ctx, driver, dsn)
	if err != nil {
		return nil, err
	}
	if err := s.Migrate(ctx); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}
