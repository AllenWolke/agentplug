// deployment-observe is a platform controller command, not a business Agent API.
// Only an operator/controller with the platform database credential can run it.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/schemaversion"
	"github.com/lexagent/platform/internal/sqlutil"
)

type observation struct {
	Kind           string `json:"kind"`
	TenantID       string `json:"tenant_id"`
	DepartmentID   string `json:"department_id"`
	ApplicationID  string `json:"application_id"`
	InstallationID string `json:"installation_id,omitempty"`
	DeploymentID   string `json:"deployment_id"`
	Revision       uint64 `json:"revision"`
	Health         string `json:"health"`
}

type catalogObserver interface {
	GetInstallation(context.Context, string) (catalog.Installation, error)
	ListDeployments(context.Context, string, string, string, string, int) ([]catalog.Deployment, error)
	ObserveDeployment(context.Context, string, string, string, string, string, uint64, catalog.DeploymentStatus) error
}
type modelObserver interface {
	GetDeployment(context.Context, modelgovernance.Scope, string) (modelgovernance.Deployment, error)
	UpdateDeploymentHealth(context.Context, modelgovernance.Scope, string, uint64, string, string) error
}

type plan struct {
	Observation     observation `json:"observation"`
	ResourceVersion string      `json:"resource_version"`
	SourceHash      string      `json:"source_hash"`
	Apply           bool        `json:"applied"`
}

func decodeObservation(input io.Reader) (observation, error) {
	var o observation
	raw, err := io.ReadAll(io.LimitReader(input, 16385))
	if err != nil || len(raw) > 16384 {
		return o, errors.New("observation exceeds the input limit")
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(&o); err != nil {
		return o, errors.New("invalid observation")
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return o, errors.New("observation must contain one JSON object")
	}
	for _, v := range []string{o.TenantID, o.DepartmentID, o.ApplicationID, o.DeploymentID} {
		if v == "" || len(v) > 128 || strings.TrimSpace(v) != v || strings.ContainsAny(v, "\x00\r\n") {
			return o, errors.New("invalid observation scope")
		}
	}
	if o.Revision == 0 {
		return o, errors.New("positive revision required")
	}
	switch o.Kind {
	case "catalog":
		if o.InstallationID == "" || len(o.InstallationID) > 128 || (o.Health != "ready" && o.Health != "failed") {
			return o, errors.New("invalid catalog observation")
		}
	case "model":
		if o.InstallationID != "" {
			return o, errors.New("model observation cannot claim an installation")
		}
		if _, ok := modelgovernance.DeploymentStatusForHealth(o.Health); !ok {
			return o, errors.New("invalid model health")
		}
	default:
		return o, errors.New("unknown observation kind")
	}
	return o, nil
}

func observe(ctx context.Context, c catalogObserver, m modelObserver, o observation, apply bool, expected string) (plan, error) {
	p := plan{Observation: o}
	var source any
	if o.Kind == "catalog" {
		i, err := c.GetInstallation(ctx, o.InstallationID)
		if err != nil {
			return p, err
		}
		if i.TenantID != o.TenantID || i.DepartmentID != o.DepartmentID || i.ApplicationID != o.ApplicationID || (i.Status != catalog.InstallationProvisioning && i.Status != catalog.InstallationActive && i.Status != catalog.InstallationSuspended) {
			return p, catalog.ErrScopeReference
		}
		rows, err := c.ListDeployments(ctx, o.TenantID, o.DepartmentID, o.ApplicationID, o.InstallationID, 100)
		if err != nil {
			return p, err
		}
		if len(rows) == 0 {
			return p, catalog.ErrRevisionConflict
		}
		d := rows[0] // Only the latest desired rollout can make the installation ready.
		if d.ID != o.DeploymentID || d.DesiredRevision != o.Revision || d.ObservedRevision >= o.Revision || d.AgentVersionID != i.VersionID || d.AgentInstallationID != i.ID {
			return p, catalog.ErrRevisionConflict
		}
		p.ResourceVersion = d.AgentVersionID
		source = struct {
			Installation catalog.Installation
			Deployment   catalog.Deployment
		}{i, d}
	} else {
		scope := modelgovernance.Scope{TenantID: o.TenantID, DepartmentID: o.DepartmentID, ApplicationID: o.ApplicationID}
		d, err := m.GetDeployment(ctx, scope, o.DeploymentID)
		if err != nil {
			return p, err
		}
		if d.Revision != o.Revision || d.Status == modelgovernance.DeploymentDisabled {
			return p, modelgovernance.ErrRevisionConflict
		}
		p.ResourceVersion = d.ModelVersionID
		source = d
	}
	raw, err := json.Marshal(struct {
		Observation observation
		Source      any
	}{o, source})
	if err != nil {
		return p, err
	}
	p.SourceHash = fmt.Sprintf("%x", sha256.Sum256(raw))
	if !apply {
		return p, nil
	}
	if expected == "" || expected != p.SourceHash {
		return p, errors.New("observation preview changed or expected hash missing")
	}
	if o.Kind == "catalog" {
		err = c.ObserveDeployment(ctx, o.TenantID, o.DepartmentID, o.ApplicationID, o.InstallationID, o.DeploymentID, o.Revision, catalog.DeploymentStatus(o.Health))
	} else {
		status, _ := modelgovernance.DeploymentStatusForHealth(o.Health)
		err = m.UpdateDeploymentHealth(ctx, modelgovernance.Scope{TenantID: o.TenantID, DepartmentID: o.DepartmentID, ApplicationID: o.ApplicationID}, o.DeploymentID, o.Revision, o.Health, status)
	}
	if err != nil {
		return p, err
	}
	p.Apply = true
	return p, nil
}

func run(args []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("deployment-observe", flag.ContinueOnError)
	apply := flags.Bool("apply", false, "commit a controller observation using the current preview hash")
	expected := flags.String("expected-source-hash", "", "exact hash returned by the current preview")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(flags.Args()) != 0 {
		return errors.New("unexpected arguments")
	}
	o, err := decodeObservation(input)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, err := pgx.ParseConfig(os.Getenv("DB_DSN"))
	if err != nil || strings.TrimSpace(os.Getenv("DB_DSN")) == "" || cfg.Database == "" {
		return errors.New("safe platform database configuration required")
	}

	db, err := sqlutil.OpenPostgres(ctx, cfg.ConnString())
	if err != nil {
		return err
	}
	defer db.Close()
	if err := schemaversion.Check(ctx, db); err != nil {
		return err
	}
	p, err := observe(ctx, catalog.NewSQLStore(db, "pgx"), modelgovernance.NewSQLStore(db), o, *apply, *expected)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(p)
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		// Database/transport errors may contain credentials or endpoint details.
		fmt.Fprintln(os.Stderr, "deployment observation failed; verify input, preview hash, schema and controller database access")
		os.Exit(1)
	}
}
