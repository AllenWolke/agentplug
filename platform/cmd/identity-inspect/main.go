// identity-inspect inventories IAM facts without changing the database.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lexagent/platform/cmd/internal/permissionresources"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/schemaversion"
	"github.com/lexagent/platform/internal/sqlutil"
)

func main() {
	if os.Getenv("DB_DSN") == "" {
		fmt.Fprintln(os.Stderr, "DB_DSN is required; supply it through the environment, never a command-line argument")
		os.Exit(1)
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "identity inventory failed; verify database connectivity and read permissions")
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet("identity-inspect", flag.ContinueOnError)
	subjectFile := flags.String("migration-subjects", "", "JSON subject selection; requires explicitly migrated database copy")
	mappingFile := flags.String("migration-mapping", "", "explicit target mappings and diagnostic query samples; preview only")
	verifyResources := flags.Bool("verify-resources", false, "verify current organization and published resources for mapping preview")
	tenant := flags.String("tenant", "", "tenant for migration source selection")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || (*subjectFile == "") != (*tenant == "") || (*mappingFile != "" && *subjectFile == "") || (*verifyResources && *mappingFile == "") {
		return errors.New("migration subject selection and tenant must be supplied together")
	}
	var subjects []identity.MigrationSubject
	if *subjectFile != "" {
		file, err := os.Open(*subjectFile)
		if err != nil {
			return err
		}
		subjects, err = readMigrationSubjects(file)
		file.Close()
		if err != nil {
			return err
		}
	}
	var mappings []migrationMappingSelection
	if *mappingFile != "" {
		file, err := os.Open(*mappingFile)
		if err != nil {
			return err
		}
		mappings, err = readMigrationMappings(file)
		file.Close()
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	config, err := pgx.ParseConfig(os.Getenv("DB_DSN"))
	if err != nil || strings.TrimSpace(os.Getenv("DB_DSN")) == "" || config.Database == "" {
		return errors.New("safe database configuration is required")
	}

	db, err := sqlutil.OpenPostgres(ctx, config.ConnString())
	if err != nil {
		return err
	}
	defer db.Close()
	store := identity.NewSQLStore(db)
	if *verifyResources {
		catalogStore := catalog.NewSQLStore(db, "pgx")
		store.SetPermissionResourceResolver(permissionresources.NewVerifiedInstallationResolver(catalogStore, catalogStore))
		store.SetCapabilityResourceResolver(permissionresources.NewPublishedResolver(catalogStore, policyasset.NewSQLResolver(db)))
	}
	var inventory any
	if *subjectFile != "" {
		if err := schemaversion.Check(ctx, db); err != nil {
			return err
		}
		var batch identity.MigrationSourceBatch
		batch, err = store.InspectMigrationSources(ctx, *tenant, subjects)
		inventory = batch
		if err == nil && *mappingFile != "" {
			var previews []identity.MigrationMappingPreview
			previews, err = previewMigrationBatch(batch, mappings)
			if err == nil && *verifyResources {
				for i := range previews {
					previews[i], err = store.ValidateMigrationMappingResources(ctx, previews[i])
					if err != nil {
						break
					}
				}
			}
			inventory = previews
		}
	} else {
		inventory, err = store.InspectPermissionInventory(ctx)
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(inventory)
}

type migrationMappingSelection struct {
	Subject identity.MigrationSubject  `json:"subject"`
	Mapping identity.MigrationMapping  `json:"mapping"`
	Queries []identity.PermissionQuery `json:"query_samples,omitempty"`
}

func readMigrationMappings(reader io.Reader) ([]migrationMappingSelection, error) {
	const maxBytes = 32 << 20
	raw, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBytes {
		return nil, errors.New("migration mapping is too large")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var selections []migrationMappingSelection
	if err := decoder.Decode(&selections); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("unexpected trailing migration mapping")
	}
	if len(selections) == 0 || len(selections) > 1000 {
		return nil, errors.New("select 1 to 1000 mappings")
	}
	return selections, nil
}

func previewMigrationBatch(batch identity.MigrationSourceBatch, selections []migrationMappingSelection) ([]identity.MigrationMappingPreview, error) {
	if len(selections) != len(batch.Sources) {
		return nil, errors.New("mapping must cover every selected subject exactly once")
	}
	index := map[identity.MigrationSubject]migrationMappingSelection{}
	for _, selection := range selections {
		if _, duplicate := index[selection.Subject]; duplicate {
			return nil, errors.New("duplicate mapping subject")
		}
		index[selection.Subject] = selection
	}
	previews := []identity.MigrationMappingPreview{}
	for _, source := range batch.Sources {
		selection, exists := index[identity.MigrationSubject{Type: source.Snapshot.Principal.Type, ID: source.Snapshot.Principal.ID}]
		if !exists {
			return nil, errors.New("selected subject has no mapping")
		}
		preview, err := identity.PreviewMigrationMapping(source, selection.Mapping, selection.Queries, batch.ReadAt)
		if err != nil {
			return nil, err
		}
		previews = append(previews, preview)
	}
	return previews, nil
}

func readMigrationSubjects(reader io.Reader) ([]identity.MigrationSubject, error) {
	const maxBytes = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBytes {
		return nil, errors.New("subject selection is too large")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var subjects []identity.MigrationSubject
	if err := decoder.Decode(&subjects); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("unexpected trailing subject selection")
	}
	if len(subjects) == 0 || len(subjects) > 1000 {
		return nil, errors.New("select 1 to 1000 subjects")
	}
	return subjects, nil
}
