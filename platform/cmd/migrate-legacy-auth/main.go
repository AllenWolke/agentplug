// migrate-legacy-auth imports reviewed legacy credentials through a private
// maintenance process. Secrets arrive only on stdin and never in its output.
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
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
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

type accountInput struct {
	Request  identity.LegacyLocalAuthenticationMigration `json:"request"`
	Password string                                      `json:"password"`
}
type inputFile struct {
	Accounts []accountInput `json:"accounts"`
}
type result struct {
	InputDigest   string                                `json:"input_digest"`
	Applied       bool                                  `json:"apply_requested"`
	Complete      bool                                  `json:"complete"`
	Verified      []string                              `json:"verified_accounts"`
	Receipts      []identity.AuthorizationChangeReceipt `json:"receipts,omitempty"`
	FailedSubject string                                `json:"failed_subject,omitempty"`
}

func readInput(in io.Reader) (inputFile, string, error) {
	var file inputFile
	raw, err := io.ReadAll(io.LimitReader(in, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return file, "", identity.ErrInvalidResource
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&file) != nil || d.Decode(new(any)) != io.EOF || len(file.Accounts) == 0 || len(file.Accounts) > 1000 {
		return file, "", identity.ErrInvalidResource
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	seen := map[string]bool{}
	for i := range file.Accounts {
		a := &file.Accounts[i]
		if a.Request.PrincipalID == "" || seen[a.Request.PrincipalID] || a.Password == "" || len(a.Password) > 128 || a.Request.ConfigurationDigest != "" {
			return inputFile{}, "", identity.ErrInvalidResource
		}
		seen[a.Request.PrincipalID] = true
		a.Request.Password = a.Password
		a.Request.ConfigurationDigest = digest
	}
	return file, digest, nil
}

func authenticationVerifier(origin string) (identity.LegacyAuthenticationVerifier, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, identity.ErrInvalidResource
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
		return nil, identity.ErrInvalidResource
	}
	u.Path = "/auth/login"
	return func(ctx context.Context, r identity.LegacyLocalAuthenticationMigration) (identity.LegacyAuthenticationEvidence, error) {
		jar, _ := cookiejar.New(nil)
		client := &http.Client{Timeout: 15 * time.Second, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		body, _ := json.Marshal(map[string]string{"username": r.PrincipalID, "password": r.Password})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
		if err != nil {
			return identity.LegacyAuthenticationEvidence{}, identity.ErrPermissionDenied
		}
		req.Header.Set("Content-Type", "application/json")
		response, err := client.Do(req)
		if err != nil {
			return identity.LegacyAuthenticationEvidence{}, identity.ErrPermissionDenied
		}
		defer response.Body.Close()
		// Always remove the temporary verification session, including malformed
		// success responses. Refuse to proceed when logout cannot be confirmed.
		logout := *u
		logout.Path = "/auth/logout"
		cleanup := func() error {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			request, _ := http.NewRequestWithContext(cleanupCtx, http.MethodPost, logout.String(), nil)
			request.Header.Set("Origin", u.Scheme+"://"+u.Host)
			out, err := client.Do(request)
			if err != nil {
				return identity.ErrPermissionDenied
			}
			defer out.Body.Close()
			io.Copy(io.Discard, io.LimitReader(out.Body, 4096))
			if out.StatusCode < 200 || out.StatusCode >= 300 {
				return identity.ErrPermissionDenied
			}
			return nil
		}
		var claims struct {
			Username      string `json:"username"`
			TenantID      string `json:"tenant_id"`
			DepartmentID  string `json:"department_id"`
			ApplicationID string `json:"application_id"`
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
		valid := response.StatusCode == 200 && readErr == nil && len(raw) <= 16<<10 && json.Unmarshal(raw, &claims) == nil && claims.Username == r.PrincipalID && claims.TenantID == r.TenantID && claims.DepartmentID == r.DepartmentID && claims.ApplicationID == r.ApplicationID
		if cleanup() != nil || !valid {
			return identity.LegacyAuthenticationEvidence{}, identity.ErrPermissionDenied
		}
		return identity.LegacyAuthenticationEvidence{PrincipalID: claims.Username, TenantID: claims.TenantID, DepartmentID: claims.DepartmentID, ApplicationID: claims.ApplicationID, ConfigurationDigest: r.ConfigurationDigest, Authenticated: true, VerifiedAt: time.Now().UTC()}, nil
	}, nil
}

func run(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	f := flag.NewFlagSet("migrate-legacy-auth", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	origin := f.String("authentication-origin", "", "trusted original gateway origin")
	actorID := f.String("actor", "", "existing administrator")
	tenant := f.String("tenant", "", "operator tenant")
	department := f.String("department", "", "operator department")
	application := f.String("application", "", "operator application")
	first := f.String("first-administrator", "", "explicitly approved existing account; never inferred from roles")
	apply := f.Bool("apply", false, "apply per account with resumable receipts")
	expected := f.String("expected-input-digest", "", "exact preview input digest")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return identity.ErrInvalidResource
	}
	actor := sharedkernel.Scope{TenantID: *tenant, DepartmentID: *department, ApplicationID: *application, PrincipalID: *actorID, PrincipalType: "user"}
	if actor.Validate() != nil {
		return identity.ErrInvalidResource
	}
	file, digest, err := readInput(input)
	if err != nil {
		return err
	}
	if *apply && *expected != digest {
		return identity.ErrPermissionPlanStale
	}
	for i, a := range file.Accounts {
		if a.Request.AppointFirstSuperAdministrator && (*first == "" || a.Request.PrincipalID != *first || *first != actor.PrincipalID || i != 0) {
			return identity.ErrPermissionDenied
		}
	}
	verify, err := authenticationVerifier(strings.TrimSpace(*origin))
	if err != nil {
		return err
	}
	r := result{InputDigest: digest, Applied: *apply}
	// Verify every account before any database write. Each submission verifies
	// again immediately before its transaction; evidence cannot be user supplied.
	for _, a := range file.Accounts {
		if _, err := verify(ctx, a.Request); err != nil {
			r.FailedSubject = a.Request.PrincipalID
			json.NewEncoder(output).Encode(r)
			return err
		}
		r.Verified = append(r.Verified, a.Request.PrincipalID)
	}
	if *apply {
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
		recorder := audit.NewSQLStoreWithOutbox(db, notification.NewSQLStore(db))
		store.SetAuthorizationChangeRecorder(func(_ context.Context, tx *sql.Tx, scope sharedkernel.Scope, receipt identity.AuthorizationChangeReceipt) error {
			return recorder.RecordTx(tx, audit.Event{ID: receipt.ID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorID: receipt.ActorID, ActorType: "user", AggregateType: "identity_authentication_migration", AggregateID: receipt.SubjectID, Action: "authentication.migrated", Outcome: "success", Summary: receipt.Reason, CreatedAt: receipt.OccurredAt})
		})
		for _, a := range file.Accounts {
			receipt, err := store.MigrateLegacyLocalAuthentication(ctx, actor, a.Request, verify)
			if err != nil {
				r.FailedSubject = a.Request.PrincipalID
				json.NewEncoder(output).Encode(r)
				return err
			}
			r.Receipts = append(r.Receipts, receipt)
		}
	}
	r.Complete = true
	return json.NewEncoder(output).Encode(r)
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if run(ctx, os.Args[1:], os.Stdin, os.Stdout) != nil {
		fmt.Fprintln(os.Stderr, "legacy authentication migration failed; inspect the redacted result and approved authentication source")
		os.Exit(1)
	}
}
