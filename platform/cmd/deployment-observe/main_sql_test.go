package main

import (
	"context"
	"github.com/lexagent/platform/internal/sqlutil"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelcapacity"
	"github.com/lexagent/platform/internal/modelgovernance"
)

func TestSQLModelObservationUpdatesHealthAndCapacityWithRevision(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture required")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store := modelgovernance.NewSQLStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := modelcapacity.NewSQLProvider(db).EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	// Fixture source facts only; the observation uses actual governance/capacity ports.
	_, err = db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_deployment (id,tenant_id,department_id,application_id,model_version_id,environment,endpoint_ref,runtime_kind,resource_profile_json,min_replicas,max_replicas,capacity_json,health_status,status,observed_revision,revision,created_at,updated_at) VALUES ('controller-deployment','t','d','a','model-v1','fixture','http://fixture.invalid','http','{}',1,1,'{"units":2}','unknown','pending',0,1,clock_timestamp(),clock_timestamp())`))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := modelcapacity.RegisterPoolTx(tx, modelcapacity.Deployment{ID: "controller-deployment", TenantID: "t", DepartmentID: "d", ApplicationID: "a", ModelVersionID: "model-v1", CapacityUnits: 2}, time.Now().UTC()); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	o := observation{Kind: "model", TenantID: "t", DepartmentID: "d", ApplicationID: "a", DeploymentID: "controller-deployment", Revision: 1, Health: "degraded"}
	p, err := observe(ctx, nil, store, o, false, "")
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.GetDeployment(ctx, modelgovernance.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a"}, o.DeploymentID)
	if err != nil || before.Revision != 1 || before.HealthStatus != "unknown" {
		t.Fatal("preview wrote", before, err)
	}
	if _, err := observe(ctx, nil, store, o, true, p.SourceHash); err != nil {
		t.Fatal(err)
	}
	after, err := store.GetDeployment(ctx, modelgovernance.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a"}, o.DeploymentID)
	if err != nil || after.Revision != 2 || after.HealthStatus != "degraded" || after.Status != "ready" {
		t.Fatal("actual degraded health transition failed", after, err)
	}
	var health, status string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT health_status,deployment_status FROM platform_model_capacity_pool WHERE deployment_id='controller-deployment'`)).Scan(&health, &status); err != nil || health != "degraded" || status != "ready" {
		t.Fatal("capacity pool disagrees with governance", health, status, err)
	}
	if _, err := observe(ctx, nil, store, o, true, p.SourceHash); err == nil {
		t.Fatal("old controller revision accepted")
	}
	o.ApplicationID = "other"
	if _, err := observe(ctx, nil, store, o, false, ""); err == nil {
		t.Fatal("cross application observation accepted")
	}
}
