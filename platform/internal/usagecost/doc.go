// Package usagecost owns usage, pricing, quota and budget application logic.
// ModelBudgetStore adds a reservation ledger whose canonical tenant/department/
// application/agent/version window is serialized by SQL transaction locks.
// usagecost 管理用量、价格、配额和预算；ModelBudgetStore 以事务锁原子预占和结算模型费用。
package usagecost
