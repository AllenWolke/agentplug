// Private deployment maintenance through Identity and Catalog owning ports.
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

type workload struct {
	Creation      identity.WorkloadCreationCommand    `json:"creation"`
	Secret        string                              `json:"client_secret"`
	Authorization identity.AuthorizationChangeCommand `json:"authorization"`
	Binding       identity.WorkloadBindingCommand     `json:"binding"`
}
type inputFile struct {
	Password  string     `json:"operator_password"`
	Workloads []workload `json:"workloads"`
}
type receipt struct {
	PrincipalID     string `json:"principal_id"`
	CreationID      string `json:"creation_id,omitempty"`
	AuthorizationID string `json:"authorization_id,omitempty"`
	BindingID       string `json:"binding_id,omitempty"`
}
type result struct {
	Digest          string    `json:"input_digest"`
	Applied         bool      `json:"apply_requested"`
	Complete        bool      `json:"complete"`
	Receipts        []receipt `json:"receipts"`
	FailedPrincipal string    `json:"failed_principal,omitempty"`
}

func run(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("configure-workloads", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	actorID := flags.String("actor", "", "verified existing administrator")
	apply := flags.Bool("apply", false, "create, grant and bind explicit workloads")
	expected := flags.String("expected-input-digest", "", "exact preview input digest")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *actorID == "" {
		return identity.ErrInvalidResource
	}
	raw, err := io.ReadAll(io.LimitReader(input, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return identity.ErrInvalidResource
	}
	var f inputFile
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&f) != nil || d.Decode(new(any)) != io.EOF || f.Password == "" || len(f.Password) > 128 || len(f.Workloads) == 0 || len(f.Workloads) > 100 {
		return identity.ErrInvalidResource
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	if *apply && *expected != digest {
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
	iam := identity.NewSQLStore(db)
	credential, err := iam.VerifyEnrollmentCredentials(ctx, *actorID, f.Password)
	if err != nil {
		return identity.ErrPermissionDenied
	}
	actor := sharedkernel.Scope{TenantID: credential.TenantID, DepartmentID: credential.DepartmentID, ApplicationID: credential.ApplicationID, PrincipalType: "user", PrincipalID: credential.PrincipalID}
	catalogStore := catalog.NewSQLStore(db, "pgx")
	installations := permissionresources.NewVerifiedInstallationResolver(catalogStore, catalogStore)
	resources := permissionresources.NewPublishedResolver(catalogStore, policyasset.NewSQLResolver(db))
	iam.SetPermissionResourceResolver(installations)
	iam.SetCapabilityResourceResolver(resources)
	fresh := func(target identity.ManagementScope, action string) error {
		if _, err := iam.ValidateEnrollmentSession(ctx, actor.PrincipalID, identity.EnrollmentScope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}, credential.AuthRevision); err != nil {
			return identity.ErrPermissionDenied
		}
		snapshot, err := iam.PermissionSnapshot(ctx, identity.PrincipalUser, actor.PrincipalID)
		if err != nil {
			return err
		}
		decision, err := identity.EvaluatePermission(snapshot, identity.PermissionQuery{Action: action, Scope: target, Now: time.Now().UTC()})
		if err != nil {
			return err
		}
		if snapshot.Mode != "v2" || target.TenantID != actor.TenantID || !decision.Allowed {
			return identity.ErrPermissionDenied
		}
		return nil
	}
	seen := map[string]bool{}
	for _, w := range f.Workloads {
		c, b, a := w.Creation, w.Binding.Binding, w.Authorization
		if c.PrincipalID == "" || seen[c.PrincipalID] || len(w.Secret) < 32 || len(w.Secret) > 512 || c.Scope.Type != "application" || c.Scope.Validate() != nil || c.Scope.TenantID != b.TenantID || c.Scope.DepartmentID != b.DepartmentID || c.Scope.ApplicationID != b.ApplicationID || c.PrincipalID != b.PrincipalID || a.SubjectType != identity.PrincipalServicePrincipal || a.SubjectID != c.PrincipalID || a.ExpectedRevision != 1 || len(a.Grants) == 0 || len(a.Bindings) != 0 || a.Preset != nil || len(a.Memberships) != 0 || len(a.Assignments) != 0 || len(a.RevokeGrantIDs) != 0 || len(a.RevokeBindingIDs) != 0 || len(a.RevokeAssignmentIDs) != 0 || w.Binding.Revoke || w.Binding.ExpectedRevision != 0 {
			return identity.ErrInvalidResource
		}
		seen[c.PrincipalID] = true
		for _, action := range []string{"machine.manage", "authorization.change"} {
			if err := fresh(c.Scope, action); err != nil {
				return err
			}
		}
		installation, err := catalogStore.GetInstallation(ctx, b.InstallationID)
		if err != nil || installation.AgentID != b.AgentID || installation.VersionID != b.AgentVersionID {
			return identity.ErrInvalidResource
		}
		scope := sharedkernel.Scope{TenantID: b.TenantID, DepartmentID: b.DepartmentID, ApplicationID: b.ApplicationID, AgentInstanceID: b.InstallationID, InstallationID: b.InstallationID, PrincipalType: "service_principal", PrincipalID: c.PrincipalID}
		if _, err := installations.ResolveAgentInstallation(ctx, scope, b.InstallationID); err != nil {
			return err
		}
		for _, g := range a.Grants {
			if g.SubjectType != identity.PrincipalServicePrincipal || g.SubjectID != c.PrincipalID || g.TenantID != b.TenantID || g.DepartmentID != b.DepartmentID || g.ApplicationID != b.ApplicationID || g.AgentInstanceID != b.InstallationID || g.Effect != "allow" || g.Status != identity.GrantActive {
				return identity.ErrInvalidResource
			}
			if _, err := resources.ResolvePermissionResource(ctx, scope, g.ResourceType, g.ResourceID); err != nil {
				return err
			}
		}
	}
	recorder := audit.NewSQLStoreWithOutbox(db, notification.NewSQLStore(db))
	iam.SetAdministrativeRecorder(func(_ context.Context, tx *sql.Tx, s sharedkernel.Scope, e identity.AdministrativeEvent) error {
		return recorder.RecordTx(tx, audit.Event{ID: e.ID, TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, ActorType: "user", ActorID: e.ActorID, AggregateType: "identity_administration", AggregateID: e.SubjectID, Action: e.Action, Outcome: "success", Summary: e.Reason, CreatedAt: e.OccurredAt})
	})
	iam.SetAuthorizationChangeRecorder(func(_ context.Context, tx *sql.Tx, s sharedkernel.Scope, r identity.AuthorizationChangeReceipt) error {
		return recorder.RecordTx(tx, audit.Event{ID: r.ID, TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, ActorType: "user", ActorID: r.ActorID, AggregateType: "identity_authorization_change", AggregateID: r.SubjectID, Action: "authorization.changed", Outcome: "success", Summary: r.Reason, CreatedAt: r.OccurredAt})
	})
	res := result{Digest: digest, Applied: *apply, Receipts: []receipt{}}
	fail := func(id string, err error) error {
		res.FailedPrincipal = id
		json.NewEncoder(output).Encode(res)
		return err
	}
	for _, w := range f.Workloads {
		item := receipt{PrincipalID: w.Creation.PrincipalID}
		if *apply {
			if err := fresh(w.Creation.Scope, "machine.manage"); err != nil {
				return fail(item.PrincipalID, err)
			}
			w.Creation.ClientSecret = w.Secret
			created, err := iam.CreatePermissionWorkload(ctx, actor, w.Creation)
			if err != nil {
				return fail(item.PrincipalID, err)
			}
			item.CreationID = created.ID
			if err := fresh(w.Creation.Scope, "authorization.change"); err != nil {
				return fail(item.PrincipalID, err)
			}
			// An exact saved receipt can be read without replanning against its own
			// changed revision. A first request still requires the normal live plan.
			changed, err := iam.CommitAuthorizationChange(ctx, actor, w.Authorization)
			if errors.Is(err, identity.ErrPermissionPlanStale) {
				plan, planErr := iam.PreviewAuthorizationChange(ctx, actor, w.Authorization)
				if planErr != nil {
					return fail(item.PrincipalID, planErr)
				}
				w.Authorization.PlanDigest, w.Authorization.PlanExpiresAt = plan.Digest, plan.ExpiresAt
				changed, err = iam.CommitAuthorizationChange(ctx, actor, w.Authorization)
			}
			if err != nil {
				return fail(item.PrincipalID, err)
			}
			item.AuthorizationID = changed.ID
			if err := fresh(w.Creation.Scope, "machine.manage"); err != nil {
				return fail(item.PrincipalID, err)
			}
			bound, err := iam.ChangeWorkloadBinding(ctx, actor, w.Binding)
			if err != nil {
				return fail(item.PrincipalID, err)
			}
			item.BindingID = bound.ID
		}
		res.Receipts = append(res.Receipts, item)
	}
	res.Complete = true
	return json.NewEncoder(output).Encode(res)
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if run(ctx, os.Args[1:], os.Stdin, os.Stdout) != nil {
		fmt.Fprintln(os.Stderr, "workload configuration failed; sensitive diagnostics suppressed")
		os.Exit(1)
	}
}
