package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/modelgovernance"
)

type observationFixture struct {
	installation catalog.Installation
	deployments  []catalog.Deployment
	model        modelgovernance.Deployment
	writes       int
}

func (f *observationFixture) GetInstallation(context.Context, string) (catalog.Installation, error) {
	return f.installation, nil
}
func (f *observationFixture) ListDeployments(context.Context, string, string, string, string, int) ([]catalog.Deployment, error) {
	return f.deployments, nil
}
func (f *observationFixture) ObserveDeployment(context.Context, string, string, string, string, string, uint64, catalog.DeploymentStatus) error {
	f.writes++
	return nil
}
func (f *observationFixture) GetDeployment(_ context.Context, s modelgovernance.Scope, _ string) (modelgovernance.Deployment, error) {
	if s.TenantID != f.model.TenantID || s.DepartmentID != f.model.DepartmentID || s.ApplicationID != f.model.ApplicationID {
		return modelgovernance.Deployment{}, modelgovernance.ErrNotFound
	}
	return f.model, nil
}
func (f *observationFixture) UpdateDeploymentHealth(_ context.Context, _ modelgovernance.Scope, _ string, _ uint64, health, status string) error {
	expected, valid := modelgovernance.DeploymentStatusForHealth(health)
	if !valid || expected != status {
		return errors.New("health/status mismatch")
	}
	f.writes++
	return nil
}

func TestObservationPreviewRequiresExactScopeRevisionAndSource(t *testing.T) {
	for _, kind := range []string{"catalog", "model"} {
		t.Run(kind, func(t *testing.T) {
			f := &observationFixture{installation: catalog.Installation{ID: "i", TenantID: "t", DepartmentID: "d", ApplicationID: "a", VersionID: "v1", Status: catalog.InstallationProvisioning}, deployments: []catalog.Deployment{{ID: "dep", AgentInstallationID: "i", AgentVersionID: "v1", DesiredRevision: 2}}, model: modelgovernance.Deployment{ID: "dep", TenantID: "t", DepartmentID: "d", ApplicationID: "a", ModelVersionID: "m1", Revision: 2, Status: modelgovernance.DeploymentPending}}
			o := observation{Kind: kind, TenantID: "t", DepartmentID: "d", ApplicationID: "a", DeploymentID: "dep", Revision: 2, Health: "ready"}
			if kind == "catalog" {
				o.InstallationID = "i"
			}
			p, err := observe(context.Background(), f, f, o, false, "")
			if err != nil || p.Apply || f.writes != 0 || len(p.SourceHash) != 64 {
				t.Fatal("preview wrote or failed", p, err)
			}
			for _, hash := range []string{"", "wrong"} {
				if _, err := observe(context.Background(), f, f, o, true, hash); err == nil {
					t.Fatal("apply without current hash")
				}
			}
			changed := o
			changed.ApplicationID = "other"
			if _, err := observe(context.Background(), f, f, changed, true, p.SourceHash); err == nil {
				t.Fatal("cross application observation")
			}
			changed = o
			changed.Revision = 1
			if _, err := observe(context.Background(), f, f, changed, true, p.SourceHash); err == nil {
				t.Fatal("old revision observation")
			}
			changed = o
			changed.Health = "unavailable"
			if kind == "catalog" {
				changed.Health = "failed"
			}
			if _, err := observe(context.Background(), f, f, changed, true, p.SourceHash); err == nil {
				t.Fatal("health result changed after preview")
			}
			if f.writes != 0 {
				t.Fatal("denied observation wrote")
			}
			if _, err := observe(context.Background(), f, f, o, true, p.SourceHash); err != nil || f.writes != 1 {
				t.Fatal("confirmed observation failed", err)
			}
		})
	}
}

func TestObservationInputCannotAssertHumanIdentityOrAppendJSON(t *testing.T) {
	valid := `{"kind":"model","tenant_id":"t","department_id":"d","application_id":"a","deployment_id":"dep","revision":1,"health":"ready"}`
	for _, body := range []string{strings.TrimSuffix(valid, "}") + `,"principal_id":"system.admin"}`, valid + ` {}`, strings.Replace(valid, `"revision":1`, `"revision":0`, 1), strings.Replace(valid, `"health":"ready"`, `"health":"invented"`, 1), strings.Replace(valid, `"kind":"model"`, `"kind":"unknown"`, 1)} {
		if _, err := decodeObservation(strings.NewReader(body)); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	if _, err := decodeObservation(strings.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeObservation(strings.NewReader(valid + strings.Repeat(" ", 16384) + "{}")); err == nil {
		t.Fatal("oversized trailing input accepted")
	}
}
