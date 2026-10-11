package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/lexagent/platform/internal/identity"
)

type demoIdentityRepository interface {
	ListTenants(context.Context, string, string) ([]identity.Tenant, error)
	ListDepartments(context.Context, string, string, string) ([]identity.Department, error)
	ListApplications(context.Context, string, string, string, string) ([]identity.Application, error)
	CreateTenant(context.Context, identity.Tenant) error
	CreateDepartment(context.Context, identity.Department) error
	CreateApplication(context.Context, identity.Application) error
	CreatePrincipal(context.Context, identity.Principal) error
	GetPrincipal(context.Context, identity.PrincipalType, string) (identity.Principal, error)
}

type demoIdentitySeed struct {
	principal   identity.Principal
	department  identity.Department
	application identity.Application
}

// Initial demo principals receive no implicit legacy roles; versioned roles and
// resource grants are provisioned explicitly by the reviewed demo setup.
var modularDemoIdentities = []demoIdentitySeed{
	{principal: identity.Principal{Type: identity.PrincipalUser, ID: "system.admin", TenantID: "tenant-demo", IsActive: true}, department: identity.Department{ID: "dept-platform", TenantID: "tenant-demo", Code: "platform", Name: "平台管理", Status: "active", Revision: 1}, application: identity.Application{ID: "app-platform-admin", TenantID: "tenant-demo", DepartmentID: "dept-platform", Code: "platform-admin", Name: "平台管理", Status: "active", Revision: 1}},
	{principal: identity.Principal{Type: identity.PrincipalUser, ID: "permission.admin", TenantID: "tenant-demo", IsActive: true}, department: identity.Department{ID: "dept-platform", TenantID: "tenant-demo", Code: "platform", Name: "平台管理", Status: "active", Revision: 1}, application: identity.Application{ID: "app-platform-admin", TenantID: "tenant-demo", DepartmentID: "dept-platform", Code: "platform-admin", Name: "平台管理", Status: "active", Revision: 1}},
	{principal: identity.Principal{Type: identity.PrincipalUser, ID: "demo.go.user", TenantID: "tenant-demo", IsActive: true}, department: identity.Department{ID: "dept-demo", TenantID: "tenant-demo", Code: "examples", Name: "SDK示例", Status: "active", Revision: 1}, application: identity.Application{ID: "app-demo", TenantID: "tenant-demo", DepartmentID: "dept-demo", Code: "sdk-examples", Name: "SDK业务示例", Status: "active", Revision: 1}},
	{principal: identity.Principal{Type: identity.PrincipalUser, ID: "demo.python.user", TenantID: "tenant-demo", IsActive: true}, department: identity.Department{ID: "dept-demo", TenantID: "tenant-demo", Code: "examples", Name: "SDK示例", Status: "active", Revision: 1}, application: identity.Application{ID: "app-demo", TenantID: "tenant-demo", DepartmentID: "dept-demo", Code: "sdk-examples", Name: "SDK业务示例", Status: "active", Revision: 1}},
	{principal: identity.Principal{Type: identity.PrincipalUser, ID: "demo.java.user", TenantID: "tenant-demo", IsActive: true}, department: identity.Department{ID: "dept-demo", TenantID: "tenant-demo", Code: "examples", Name: "SDK示例", Status: "active", Revision: 1}, application: identity.Application{ID: "app-demo", TenantID: "tenant-demo", DepartmentID: "dept-demo", Code: "sdk-examples", Name: "SDK业务示例", Status: "active", Revision: 1}},
}

// seedModularDemoIdentities creates development-only organization and user
// records when they are absent. It never updates an existing tenant, role, or
// principal, so a restart cannot silently restore revoked permissions.
// seedModularDemoIdentities 仅为开发环境补齐缺失的演示组织和用户；绝不更新既有角色，
// 因此重启不会静默恢复已撤销的权限。
func seedModularDemoIdentities(ctx context.Context, store demoIdentityRepository) error {
	if store == nil {
		return errors.New("demo identity bootstrap store is required")
	}
	if err := ensureDemoTenant(ctx, store); err != nil {
		return err
	}
	departments := map[string]identity.Department{}
	applications := map[string]identity.Application{}
	for _, seed := range modularDemoIdentities {
		departments[seed.department.ID] = seed.department
		applications[seed.application.ID] = seed.application
	}
	for _, department := range departments {
		if err := ensureDemoDepartment(ctx, store, department); err != nil {
			return err
		}
	}
	for _, application := range applications {
		if err := ensureDemoApplication(ctx, store, application); err != nil {
			return err
		}
	}
	for _, seed := range modularDemoIdentities {
		_, err := store.GetPrincipal(ctx, identity.PrincipalUser, seed.principal.ID)
		switch {
		case errors.Is(err, identity.ErrPrincipalNotFound):
			if err := store.CreatePrincipal(ctx, seed.principal); err != nil {
				return fmt.Errorf("seed demo principal %q: %w", seed.principal.ID, err)
			}
		case err != nil:
			return fmt.Errorf("read demo principal %q: %w", seed.principal.ID, err)
		default:
			// Existing principal state is authoritative, including disabled state.
			// 已存在的主体状态为权威状态，包括停用状态。
		}
	}
	return nil
}

func ensureDemoTenant(ctx context.Context, store demoIdentityRepository) error {
	items, err := store.ListTenants(ctx, "tenant-demo", "")
	if err != nil {
		return fmt.Errorf("read demo tenant: %w", err)
	}
	if len(items) != 0 {
		if items[0].Status != "active" {
			return errors.New("demo tenant exists but is not active")
		}
		return nil
	}
	if err := store.CreateTenant(ctx, identity.Tenant{ID: "tenant-demo", Code: "demo", Name: "演示租户", Status: "active", Revision: 1}); err != nil {
		return fmt.Errorf("seed demo tenant: %w", err)
	}
	return nil
}

func ensureDemoDepartment(ctx context.Context, store demoIdentityRepository, expected identity.Department) error {
	items, err := store.ListDepartments(ctx, expected.TenantID, expected.ID, "")
	if err != nil {
		return fmt.Errorf("read demo department %q: %w", expected.ID, err)
	}
	if len(items) != 0 {
		if items[0].Status != "active" || items[0].TenantID != expected.TenantID {
			return fmt.Errorf("demo department %q exists outside its active scope", expected.ID)
		}
		return nil
	}
	if err := store.CreateDepartment(ctx, expected); err != nil {
		return fmt.Errorf("seed demo department %q: %w", expected.ID, err)
	}
	return nil
}

func ensureDemoApplication(ctx context.Context, store demoIdentityRepository, expected identity.Application) error {
	items, err := store.ListApplications(ctx, expected.TenantID, expected.DepartmentID, expected.ID, "")
	if err != nil {
		return fmt.Errorf("read demo application %q: %w", expected.ID, err)
	}
	if len(items) != 0 {
		if items[0].Status != "active" || items[0].TenantID != expected.TenantID || items[0].DepartmentID != expected.DepartmentID {
			return fmt.Errorf("demo application %q exists outside its active scope", expected.ID)
		}
		return nil
	}
	if err := store.CreateApplication(ctx, expected); err != nil {
		return fmt.Errorf("seed demo application %q: %w", expected.ID, err)
	}
	return nil
}
