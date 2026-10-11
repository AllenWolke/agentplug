package modelgovernance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelcapacity"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func postgresGovernanceFixture(t *testing.T) (*SQLStore, string) {
	t.Helper()
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect fixture: %T", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := NewSQLStore(db)
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := modelcapacity.NewSQLProvider(db).EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s, fmt.Sprintf("pg-%d", time.Now().UnixNano())
}

func seedPostgresModel(t *testing.T, s *SQLStore, key string) string {
	t.Helper()
	ctx := context.Background()
	p := Provider{ID: key + "p", ProviderKey: key, Type: ProviderOnPrem, TrustZone: TrustLocal, EndpointRef: "service://models", SecretRef: "secret://provider.key", Capabilities: []byte(`{}`), Status: StatusDraft, HealthStatus: "unknown", Revision: 1}
	if err := s.CreateProvider(ctx, &p); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateProvider(ctx, &p); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate provider: %v", err)
	}
	if err := s.UpdateProviderStatus(ctx, p.ID, 1, StatusApproved); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateProviderStatus(ctx, p.ID, 1, StatusApproved); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale provider CAS: %v", err)
	}
	d := ModelDefinition{ID: key + "d", ProviderID: p.ID, ModelKey: "fixture", Kind: ModelKindChat, Capabilities: []byte(`{}`), LifecycleStatus: StatusDraft, Revision: 1}
	if err := s.CreateDefinition(ctx, &d); err != nil {
		t.Fatal(err)
	}
	v := ModelVersion{ID: key + "v", DefinitionID: d.ID, SemanticVersion: "1.0.0", Status: StatusDraft, Revision: 1}
	if err := s.CreateVersion(ctx, &v); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveVersion(ctx, v.ID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetApprovedProvider(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetApprovedModel(ctx, v.ID); err != nil {
		t.Fatal(err)
	}
	return v.ID
}

func TestPostgresGovernanceConcurrentPriceIntervals(t *testing.T) {
	s, key := postgresGovernanceFixture(t)
	version := seedPostgresModel(t, s, key)
	ctx := context.Background()
	start := make(chan struct{})
	results := make(chan error, 8)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			<-start
			p := PriceVersion{ID: fmt.Sprintf("%s-price-%d", key, i), ModelVersionID: version, Currency: "USD", InputMicrosPer1K: int64(i + 1), OutputMicrosPer1K: 2, EffectiveFrom: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Status: priceStatusDraft, Revision: 1, CreatedBy: "fixture.admin"}
			if err := assignPriceContentHash(&p); err != nil {
				results <- err
				return
			}
			results <- s.CreatePriceVersion(ctx, &p)
		}(i)
	}
	close(start)
	workers.Wait()
	close(results)
	ok, overlap := 0, 0
	for err := range results {
		if err == nil {
			ok++
		} else if errors.Is(err, ErrPriceOverlap) {
			overlap++
		} else {
			t.Errorf("price insertion: %v", err)
		}
	}
	if ok != 1 || overlap != 7 {
		t.Fatalf("overlapping prices: success=%d overlap=%d", ok, overlap)
	}
	prices, err := s.ListPriceVersions(ctx, version, 10)
	if err != nil || len(prices) != 1 {
		t.Fatalf("prices=%+v err=%v", prices, err)
	}
	if err := s.ApprovePriceVersion(ctx, prices[0].ID, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.ApprovePriceVersion(ctx, prices[0].ID, 1); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale price CAS: %v", err)
	}
	resolved, err := s.ResolvePrice(ctx, version, prices[0].EffectiveFrom.Add(time.Hour))
	if err != nil || resolved.ID != prices[0].ID || resolved.ContentHash != prices[0].ContentHash {
		t.Fatalf("price snapshot lost: %+v %v", resolved, err)
	}
}

func TestPostgresGovernanceDeploymentCapacityAtomicity(t *testing.T) {
	s, key := postgresGovernanceFixture(t)
	version := seedPostgresModel(t, s, key)
	ctx := context.Background()
	scope := Scope{TenantID: key, DepartmentID: "department", ApplicationID: "application"}
	d := Deployment{ID: key + "dep", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ModelVersionID: version, EndpointRef: "service://models", ResourceProfile: []byte(`{}`), Capacity: []byte(`{"max_concurrent_requests":3}`), HealthStatus: "unknown", Status: "pending", Revision: 1}
	for _, q := range []string{
		`CREATE FUNCTION fail_capacity_registration_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture capacity failure'; END $$`,
		`CREATE TRIGGER fail_capacity_registration BEFORE INSERT ON platform_model_capacity_pool FOR EACH ROW EXECUTE FUNCTION fail_capacity_registration_fn()`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = s.db.ExecContext(ctx, `DROP FUNCTION IF EXISTS fail_capacity_registration_fn() CASCADE`)
	})
	if err := s.CreateDeployment(ctx, &d); sqlutil.SQLState(err) != "P0001" {
		t.Fatalf("expected injected PostgreSQL failure, got %v", err)
	}
	if _, err := s.GetDeployment(ctx, scope, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orphan deployment: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `DROP TRIGGER fail_capacity_registration ON platform_model_capacity_pool`); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateDeployment(ctx, &d); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateDeploymentHealth(ctx, scope, d.ID, 1, "ready", "ready"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateDeploymentHealth(ctx, scope, d.ID, 1, "ready", "ready"); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale deployment CAS: %v", err)
	}
	observed, err := s.GetDeployment(ctx, scope, d.ID)
	if err != nil || observed.ObservedRevision != 1 || observed.Revision != 2 || observed.HealthStatus != "ready" {
		t.Fatalf("trusted observation was not persisted atomically or stale CAS changed it: %+v %v", observed, err)
	}
	capacity := modelcapacity.NewSQLProvider(s.db)
	capacity.SetDeploymentReader(s)
	runtimeScope := sharedkernel.Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID}
	if _, err := capacity.ResolveReadyDeployment(ctx, runtimeScope, version); err != nil {
		t.Fatal(err)
	}
	foreign := scope
	foreign.ApplicationID = "foreign"
	if _, err := s.GetDeployment(ctx, foreign, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross application deployment: %v", err)
	}
	if err := s.UpdateDeploymentHealth(ctx, scope, d.ID, 2, "draining", "draining"); err != nil {
		t.Fatal(err)
	}
	observed, err = s.GetDeployment(ctx, scope, d.ID)
	if err != nil || observed.ObservedRevision != 2 || observed.Revision != 3 || observed.HealthStatus != "draining" {
		t.Fatalf("new trusted observation did not advance with exact CAS revision: %+v %v", observed, err)
	}
	if _, err := capacity.ResolveReadyDeployment(ctx, runtimeScope, version); !errors.Is(err, modelcapacity.ErrUnavailable) {
		t.Fatalf("draining admitted: %v", err)
	}
}

func TestPostgresExternalEmbeddingInputOnlyPricing(t *testing.T) {
	s, key := postgresGovernanceFixture(t)
	ctx := context.Background()
	provider := Provider{ID: key + "p", ProviderKey: key, Type: ProviderExternalManaged, TrustZone: TrustExternal, EndpointRef: "service://embeddings", SecretRef: "secret://embedding.key", Capabilities: []byte(`{}`), Status: StatusDraft, HealthStatus: "unknown", Revision: 1}
	if err := s.CreateProvider(ctx, &provider); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateProviderStatus(ctx, provider.ID, 1, StatusApproved); err != nil {
		t.Fatal(err)
	}
	definition := ModelDefinition{ID: key + "d", ProviderID: provider.ID, ModelKey: "embedding", Kind: ModelKindEmbedding, Capabilities: []byte(`{}`), LifecycleStatus: StatusDraft, Revision: 1}
	if err := s.CreateDefinition(ctx, &definition); err != nil {
		t.Fatal(err)
	}
	version := ModelVersion{ID: key + "v", DefinitionID: definition.ID, SemanticVersion: "1.0.0", Status: StatusDraft, Revision: 1}
	if err := s.CreateVersion(ctx, &version); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveVersion(ctx, version.ID, 1); err != nil {
		t.Fatal(err)
	}
	resolved, err := s.GetResolvedVersion(ctx, version.ID)
	if err != nil || resolved.Kind != ModelKindEmbedding {
		t.Fatalf("resolved kind: %+v %v", resolved, err)
	}
	price := PriceVersion{ID: key + "price", ModelVersionID: version.ID, Currency: "CNY", InputMicrosPer1K: 500, OutputMicrosPer1K: 0, EffectiveFrom: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Status: priceStatusDraft, Revision: 1, CreatedBy: "fixture.admin"}
	if err := assignPriceContentHash(&price); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePriceVersion(ctx, &price); err != nil {
		t.Fatal(err)
	}
	if err := s.ApprovePriceVersion(ctx, price.ID, 1); err != nil {
		t.Fatal(err)
	}
	measured, err := s.ResolvePrice(ctx, version.ID, price.EffectiveFrom.Add(time.Hour))
	if err != nil || measured.InputMicrosPer1K != 500 || measured.OutputMicrosPer1K != 0 {
		t.Fatalf("input-only catalog: %+v %v", measured, err)
	}
}
