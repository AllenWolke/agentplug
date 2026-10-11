// migrate-permission-requests converts explicitly previewed pending requests.
// It never installs schemas, seeds identities, approves requests or grants access.
package main

import (
	"bytes"
	"context"
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
	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/schemaversion"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type requestImporter interface {
	ImportLegacyPermissionRequestFromPlan(context.Context, sharedkernel.Scope, identity.LegacyRequestMigrationEntry, string) (identity.PermissionRequest, error)
}

type result struct {
	ID       string `json:"id"`
	Outcome  string `json:"outcome"`
	Status   string `json:"request_status,omitempty"`
	Revision uint64 `json:"request_revision,omitempty"`
}
type report struct {
	PlanDigest  string   `json:"plan_digest"`
	Results     []result `json:"results"`
	NextAfterID string   `json:"next_after_id"`
	Remaining   int      `json:"remaining"`
	Blocked     int      `json:"blocked"`
	Complete    bool     `json:"complete"`
}

func applyPlan(ctx context.Context, store requestImporter, actor sharedkernel.Scope, plan identity.LegacyRequestMigrationPlan, reason, after string, limit int) (report, error) {
	receipt := report{PlanDigest: plan.Digest, Results: []result{}, NextAfterID: after, Remaining: len(plan.Entries)}
	if plan.Validate() != nil || actor.Validate() != nil || actor.PrincipalType != "user" || actor.PrincipalID != plan.ActorID || actor.TenantID != plan.Scope.TenantID || actor.DepartmentID != plan.Scope.DepartmentID || actor.ApplicationID != plan.Scope.ApplicationID || strings.TrimSpace(reason) == "" || len(reason) > 1000 || limit < 1 || limit > 1000 {
		return receipt, identity.ErrInvalidResource
	}
	start := 0
	if after != "" {
		found := false
		for i, e := range plan.Entries {
			if e.Source.ID == after {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return receipt, identity.ErrInvalidResource
		}
	}
	for _, entry := range plan.Entries {
		if entry.Disposition != "ready" {
			receipt.Blocked++
		}
	}
	count := 0
	for index := start; index < len(plan.Entries); index++ {
		e := plan.Entries[index]
		if count >= limit {
			receipt.Remaining = len(plan.Entries) - index
			return receipt, nil
		}
		if e.Disposition != "ready" {
			receipt.Results = append(receipt.Results, result{ID: e.Source.ID, Outcome: e.Disposition})
		} else {
			request, err := store.ImportLegacyPermissionRequestFromPlan(ctx, actor, e, reason)
			if err != nil {
				code := "failed"
				if errors.Is(err, identity.ErrIdentityConflict) {
					code = "source_conflict"
				} else if errors.Is(err, identity.ErrPermissionDenied) {
					code = "permission_denied"
				}
				receipt.Results = append(receipt.Results, result{ID: e.Source.ID, Outcome: code})
				receipt.Remaining = len(plan.Entries) - index
				return receipt, err
			}
			receipt.Results = append(receipt.Results, result{ID: request.ID, Outcome: "verified", Status: request.Status, Revision: request.Revision})
			count++
		}
		receipt.NextAfterID = e.Source.ID
		receipt.Remaining = len(plan.Entries) - index - 1
	}
	receipt.Remaining = 0
	receipt.Complete = receipt.Blocked == 0
	return receipt, nil
}

func loadPlan(path string) (identity.LegacyRequestMigrationPlan, error) {
	var plan identity.LegacyRequestMigrationPlan
	file, err := os.Open(path)
	if err != nil {
		return plan, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, (32<<20)+1))
	if err != nil || len(raw) > 32<<20 {
		return plan, identity.ErrInvalidResource
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&plan) != nil || decoder.Decode(new(any)) != io.EOF || plan.Validate() != nil {
		return plan, identity.ErrInvalidResource
	}
	return plan, nil
}

func run(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("migrate-permission-requests", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	actorID := flags.String("actor", "", "existing v2 administrator principal ID")
	tenant := flags.String("tenant", "", "tenant ID")
	department := flags.String("department", "", "department ID")
	application := flags.String("application", "", "application ID")
	apply := flags.Bool("apply", false, "apply a previously saved plan")
	path := flags.String("plan", "", "saved migration plan")
	reason := flags.String("reason", "", "audited migration reason")
	after := flags.String("after-id", "", "last verified ID from the same plan")
	limit := flags.Int("limit", 100, "maximum imports per invocation")
	pageSize := flags.Int("page-size", 100, "snapshot keyset page size")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *limit < 1 || *limit > 1000 || *pageSize < 1 || *pageSize > 1000 {
		return identity.ErrInvalidResource
	}
	actor := sharedkernel.Scope{PrincipalType: "user", PrincipalID: *actorID, TenantID: *tenant, DepartmentID: *department, ApplicationID: *application, TraceID: "permission-request-migration"}
	if actor.Validate() != nil || !*apply && (*path != "" || *after != "" || *reason != "") || *apply && (*path == "" || *reason == "") {
		return identity.ErrInvalidResource
	}
	var plan identity.LegacyRequestMigrationPlan
	var err error
	if *apply {
		plan, err = loadPlan(*path)
		if err != nil {
			return err
		}
	}
	dsn := os.Getenv("DB_DSN")
	config, err := pgx.ParseConfig(dsn)
	if err != nil || dsn == "" || config.Database == "" {
		return identity.ErrInvalidResource
	}
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(4)
	if err := schemaversion.Check(ctx, db); err != nil {
		return err
	}
	store := identity.NewSQLStore(db)
	if err := store.AuthorizeLegacyRequestMigration(ctx, actor); err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if !*apply {
		plan, err = store.PlanLegacyPermissionRequests(ctx, actor, *pageSize)
		if err != nil {
			return err
		}
		return encoder.Encode(plan)
	}
	recorder := audit.NewSQLStoreWithOutbox(db, notification.NewSQLStore(db))
	store.SetAdministrativeRecorder(func(_ context.Context, tx *sql.Tx, scope sharedkernel.Scope, e identity.AdministrativeEvent) error {
		return recorder.RecordTx(tx, audit.Event{ID: e.ID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorType: scope.PrincipalType, ActorID: scope.PrincipalID, TraceID: scope.TraceID, AggregateType: "identity_permission_request_migration", AggregateID: e.SubjectID, Action: e.Action, Outcome: "success", Summary: e.Reason, CreatedAt: e.OccurredAt})
	})
	receipt, applyErr := applyPlan(ctx, store, actor, plan, *reason, *after, *limit)
	if err := encoder.Encode(receipt); err != nil {
		return err
	}
	return applyErr
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "permission request migration failed; inspect the JSON receipt, current authorization, source conflict and schema; database credentials are never printed")
		os.Exit(1)
	}
}
