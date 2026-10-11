// migrate-permissions submits explicitly reviewed mappings, never infers roles.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
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
	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/schemaversion"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type mappingFile struct {
	Mappings      []identity.MigrationMapping `json:"mappings"`
	ShadowQueries []subjectShadowQueries      `json:"shadow_queries,omitempty"`
}

// Samples are diagnostic input, never a commit authorization or resource proof.
type subjectShadowQueries struct {
	Type    identity.PrincipalType     `json:"principal_type"`
	ID      string                     `json:"subject_id"`
	Queries []identity.PermissionQuery `json:"queries"`
}

func (f mappingFile) queriesFor(p identity.Principal) []identity.PermissionQuery {
	for _, samples := range f.ShadowQueries {
		if samples.Type == p.Type && samples.ID == p.ID {
			return samples.Queries
		}
	}
	return nil
}

type batchResult struct {
	InputDigest   string                                `json:"input_digest"`
	Applied       bool                                  `json:"apply_requested"`
	Complete      bool                                  `json:"complete"`
	Receipts      []identity.AuthorizationChangeReceipt `json:"receipts,omitempty"`
	Previews      []identity.MigrationMappingPreview    `json:"previews,omitempty"`
	FailedSubject string                                `json:"failed_subject,omitempty"`
	FailureStage  string                                `json:"failure_stage,omitempty"`
	FailureCode   string                                `json:"failure_code,omitempty"`
}

func migrationFailureCode(err error) string {
	switch {
	case errors.Is(err, identity.ErrPermissionPlanStale):
		return "PLAN_STALE"
	case errors.Is(err, identity.ErrInvalidResource):
		return "INVALID_RESOURCE"
	case errors.Is(err, identity.ErrPermissionDenied):
		return "PERMISSION_DENIED"
	default:
		return "MIGRATION_UNAVAILABLE"
	}
}

func readMappingFile(input io.Reader) (mappingFile, string, error) {
	var file mappingFile
	raw, err := io.ReadAll(io.LimitReader(input, (32<<20)+1))
	if err != nil || len(raw) > 32<<20 {
		return file, "", identity.ErrInvalidResource
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&file) != nil || d.Decode(new(any)) != io.EOF || len(file.Mappings) == 0 || len(file.Mappings) > 1000 {
		return file, "", identity.ErrInvalidResource
	}
	seen := map[string]bool{}
	for _, m := range file.Mappings {
		p := m.Target.Principal
		key := string(p.Type) + "\x00" + p.ID
		if p.ID == "" || (p.Type != identity.PrincipalUser && p.Type != identity.PrincipalServicePrincipal) || seen[key] {
			return file, "", identity.ErrInvalidResource
		}
		seen[key] = true
	}
	samplesSeen := map[string]bool{}
	queryCount := 0
	for _, samples := range file.ShadowQueries {
		key := string(samples.Type) + "\x00" + samples.ID
		queryCount += len(samples.Queries)
		if !seen[key] || samplesSeen[key] || len(samples.Queries) == 0 || queryCount > 1000 {
			return file, "", identity.ErrInvalidResource
		}
		samplesSeen[key] = true
		for _, query := range samples.Queries {
			if query.Action == "" || query.Scope.Validate() != nil {
				return file, "", identity.ErrInvalidResource
			}
		}
	}
	return file, fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

func run(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("migrate-permissions", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	actions := flags.Bool("permission-actions", false, "print the current canonical action catalogue without database access")
	path := flags.String("mapping-file", "", "explicit reviewed targets JSON")
	tenant := flags.String("tenant", "", "source tenant")
	department := flags.String("department", "", "operator department")
	application := flags.String("application", "", "operator application")
	actorID := flags.String("actor", "", "existing verified v2 global administrator")
	batchID := flags.String("batch", "", "stable migration batch identifier")
	apply := flags.Bool("apply", false, "submit each subject atomically; retries reuse committed receipts")
	expected := flags.String("expected-input-digest", "", "exact input digest returned by preview")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *actions {
		if flags.NArg() != 0 || flags.NFlag() != 1 {
			return identity.ErrInvalidResource
		}
		return json.NewEncoder(output).Encode(identity.BuiltinPermissionActions())
	}
	actor := sharedkernel.Scope{TenantID: *tenant, DepartmentID: *department, ApplicationID: *application, PrincipalType: "user", PrincipalID: *actorID}
	if flags.NArg() != 0 || *path == "" || actor.Validate() != nil || *batchID == "" {
		return identity.ErrInvalidResource
	}
	input, err := os.Open(*path)
	if err != nil {
		return identity.ErrInvalidResource
	}
	file, digest, err := readMappingFile(input)
	input.Close()
	if err != nil {
		return err
	}
	// A shadow report can require further review. It is not an apply plan;
	// reject mixing the two rather than silently ignoring its unresolved samples.
	if *apply && len(file.ShadowQueries) != 0 {
		return identity.ErrInvalidResource
	}
	if *apply && (*expected == "" || *expected != digest) {
		return identity.ErrPermissionPlanStale
	}
	cfg, err := pgx.ParseConfig(os.Getenv("DB_DSN"))
	if err != nil || strings.TrimSpace(os.Getenv("DB_DSN")) == "" || cfg.Database == "" {
		return errors.New("safe database configuration required")
	}

	db, err := sqlutil.OpenPostgres(ctx, cfg.ConnString())
	if err != nil {
		return err
	}
	defer db.Close()
	if err := schemaversion.Check(ctx, db); err != nil {
		return err
	}
	store := identity.NewSQLStore(db)
	catalogStore := catalog.NewSQLStore(db, "pgx")
	store.SetPermissionResourceResolver(permissionresources.NewVerifiedInstallationResolver(catalogStore, catalogStore))
	store.SetCapabilityResourceResolver(permissionresources.NewPublishedResolver(catalogStore, policyasset.NewSQLResolver(db)))
	result := batchResult{InputDigest: digest, Applied: *apply}
	if *apply {
		recorder := audit.NewSQLStoreWithOutbox(db, notification.NewSQLStore(db))
		store.SetAuthorizationChangeRecorder(func(_ context.Context, tx *sql.Tx, scope sharedkernel.Scope, r identity.AuthorizationChangeReceipt) error {
			return recorder.RecordTx(tx, audit.Event{ID: r.ID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorType: "user", ActorID: r.ActorID, TraceID: scope.TraceID, AggregateType: "identity_authorization_change", AggregateID: r.SubjectID, Action: "authorization.migrated", Outcome: "success", Summary: r.Reason, CreatedAt: r.OccurredAt})
		})
		// Per-subject transactions intentionally allow resumable batches, not a
		// claim of all-or-nothing atomicity across an entire database migration.
		for _, mapping := range file.Mappings {
			receipt, err := store.CommitMigrationMapping(ctx, actor, *batchID, mapping)
			if err != nil {
				result.FailedSubject = mapping.Target.Principal.ID
				json.NewEncoder(output).Encode(result)
				return err
			}
			result.Receipts = append(result.Receipts, receipt)
		}
	} else {
		subjects := make([]identity.MigrationSubject, 0, len(file.Mappings))
		for _, mapping := range file.Mappings {
			subjects = append(subjects, identity.MigrationSubject{Type: mapping.Target.Principal.Type, ID: mapping.Target.Principal.ID})
		}
		sources, err := store.InspectMigrationSources(ctx, *tenant, subjects)
		if err != nil {
			return err
		}
		byID := map[string]identity.MigrationSource{}
		for _, source := range sources.Sources {
			p := source.Snapshot.Principal
			byID[string(p.Type)+"\x00"+p.ID] = source
		}
		for _, mapping := range file.Mappings {
			p := mapping.Target.Principal
			preview, err := identity.PreviewMigrationMapping(byID[string(p.Type)+"\x00"+p.ID], mapping, file.queriesFor(p), time.Now().UTC())
			if err != nil {
				result.FailedSubject, result.FailureStage, result.FailureCode = p.ID, "shadow_preview", migrationFailureCode(err)
				json.NewEncoder(output).Encode(result)
				return err
			}
			preview, err = store.ValidateMigrationMappingResources(ctx, preview)
			if err != nil {
				result.FailedSubject, result.FailureStage, result.FailureCode = p.ID, "resource_validation", migrationFailureCode(err)
				json.NewEncoder(output).Encode(result)
				return err
			}
			result.Previews = append(result.Previews, preview)
		}
	}
	result.Complete = true
	return json.NewEncoder(output).Encode(result)
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "permission migration failed; inspect the structured result and verify reviewed source, administrator, resources and database access")
		os.Exit(1)
	}
}
