package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/identity"
)

type memoryDemoIdentityStore struct {
	tenants      map[string]identity.Tenant
	departments  map[string]identity.Department
	applications map[string]identity.Application
	principals   map[string]identity.Principal
}

func newMemoryDemoIdentityStore() *memoryDemoIdentityStore {
	return &memoryDemoIdentityStore{
		tenants: map[string]identity.Tenant{}, departments: map[string]identity.Department{},
		applications: map[string]identity.Application{}, principals: map[string]identity.Principal{},
	}
}

func (s *memoryDemoIdentityStore) ListTenants(_ context.Context, id, _ string) ([]identity.Tenant, error) {
	if value, ok := s.tenants[id]; ok {
		return []identity.Tenant{value}, nil
	}
	return nil, nil
}

func (s *memoryDemoIdentityStore) ListDepartments(_ context.Context, tenantID, id, _ string) ([]identity.Department, error) {
	if value, ok := s.departments[id]; ok && value.TenantID == tenantID {
		return []identity.Department{value}, nil
	}
	return nil, nil
}

func (s *memoryDemoIdentityStore) ListApplications(_ context.Context, tenantID, departmentID, id, _ string) ([]identity.Application, error) {
	if value, ok := s.applications[id]; ok && value.TenantID == tenantID && value.DepartmentID == departmentID {
		return []identity.Application{value}, nil
	}
	return nil, nil
}

func (s *memoryDemoIdentityStore) CreateTenant(_ context.Context, value identity.Tenant) error {
	if _, ok := s.tenants[value.ID]; ok {
		return identity.ErrIdentityConflict
	}
	s.tenants[value.ID] = value
	return nil
}

func (s *memoryDemoIdentityStore) CreateDepartment(_ context.Context, value identity.Department) error {
	if _, ok := s.departments[value.ID]; ok {
		return identity.ErrIdentityConflict
	}
	s.departments[value.ID] = value
	return nil
}

func (s *memoryDemoIdentityStore) CreateApplication(_ context.Context, value identity.Application) error {
	if _, ok := s.applications[value.ID]; ok {
		return identity.ErrIdentityConflict
	}
	s.applications[value.ID] = value
	return nil
}

func (s *memoryDemoIdentityStore) CreatePrincipal(_ context.Context, value identity.Principal) error {
	key := string(value.Type) + ":" + value.ID
	if _, ok := s.principals[key]; ok {
		return identity.ErrIdentityConflict
	}
	s.principals[key] = value
	return nil
}

func (s *memoryDemoIdentityStore) GetPrincipal(_ context.Context, typ identity.PrincipalType, id string) (identity.Principal, error) {
	if value, ok := s.principals[string(typ)+":"+id]; ok {
		return value, nil
	}
	return identity.Principal{}, identity.ErrPrincipalNotFound
}

func TestSeedModularDemoIdentitiesIsIdempotentAndNeverRestoresRoles(t *testing.T) {
	store := newMemoryDemoIdentityStore()
	if err := seedModularDemoIdentities(context.Background(), store); err != nil {
		t.Fatalf("initial seed: %v", err)
	}
	if len(store.tenants) != 1 || len(store.departments) != 2 || len(store.applications) != 2 || len(store.principals) != 5 {
		t.Fatalf("unexpected seed cardinality: tenants=%d departments=%d applications=%d principals=%d", len(store.tenants), len(store.departments), len(store.applications), len(store.principals))
	}
	for _, id := range []string{"system.admin", "permission.admin", "demo.go.user", "demo.python.user", "demo.java.user"} {
		principal := store.principals["user:"+id]
		if principal.ID != id || len(principal.Roles) != 0 || principal.TenantID != "tenant-demo" {
			t.Fatalf("demo identity %q inherited implicit privileges: %+v", id, principal)
		}
	}
	adminKey := "user:permission.admin"
	admin := store.principals[adminKey]
	admin.Roles = []string{"operator"}
	store.principals[adminKey] = admin
	if err := seedModularDemoIdentities(context.Background(), store); err != nil {
		t.Fatalf("idempotent reseed: %v", err)
	}
	if got := store.principals[adminKey].Roles; len(got) != 1 || got[0] != "operator" {
		t.Fatalf("bootstrap restored or replaced persisted roles: %v", got)
	}
}

type failingDemoIdentityStore struct{ *memoryDemoIdentityStore }

func (f failingDemoIdentityStore) ListTenants(context.Context, string, string) ([]identity.Tenant, error) {
	return nil, errors.New("database unavailable")
}

func TestSeedModularDemoIdentitiesFailsClosedOnStoreError(t *testing.T) {
	err := seedModularDemoIdentities(context.Background(), failingDemoIdentityStore{newMemoryDemoIdentityStore()})
	if err == nil {
		t.Fatal("expected bootstrap database error")
	}
}
