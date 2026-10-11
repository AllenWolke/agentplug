// publish-policies is a private maintenance command. It calls owning-module
// publication ports, never direct cross-module SQL or development seeding.
package main

import (
	"bytes"
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
	"github.com/lexagent/platform/cmd/internal/permissionresources"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/schemaversion"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type inputFile struct {
	OperatorPassword string                         `json:"operator_password"`
	Publications     []policyasset.DraftPublication `json:"publications"`
}
type assetResult struct {
	ID       string                `json:"id"`
	Type     policyasset.AssetType `json:"type"`
	Revision uint64                `json:"revision"`
	Hash     string                `json:"content_hash"`
}
type publicationResult struct {
	InstallationID string        `json:"installation_id"`
	Assets         []assetResult `json:"assets"`
	Revision       uint64        `json:"snapshot_revision,omitempty"`
	Hash           string        `json:"snapshot_hash,omitempty"`
}
type result struct {
	InputDigest        string              `json:"input_digest"`
	Applied            bool                `json:"apply_requested"`
	Complete           bool                `json:"complete"`
	Publications       []publicationResult `json:"publications"`
	FailedInstallation string              `json:"failed_installation,omitempty"`
}

func readInput(input io.Reader, actorID string) (inputFile, string, error) {
	var f inputFile
	raw, err := io.ReadAll(io.LimitReader(input, (4<<20)+1))
	if err != nil || len(raw) > 4<<20 {
		return f, "", policyasset.ErrInvalidSnapshot
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&f) != nil || d.Decode(new(any)) != io.EOF || f.OperatorPassword == "" || len(f.OperatorPassword) > 128 || len(f.Publications) == 0 || len(f.Publications) > 100 {
		return f, "", policyasset.ErrInvalidSnapshot
	}
	seen := map[string]bool{}
	for _, p := range f.Publications {
		key := p.Scope.TenantID + "\x00" + p.Scope.DepartmentID + "\x00" + p.Scope.ApplicationID + "\x00" + p.Scope.AgentID + "\x00" + p.Scope.AgentVersionID
		if seen[key] {
			return f, "", policyasset.ErrInvalidSnapshot
		}
		seen[key] = true
		if _, err := policyasset.PreparePublication(p, actorID); err != nil {
			return f, "", err
		}
	}
	return f, fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

func authorize(ctx context.Context, store *identity.SQLStore, actor sharedkernel.Scope, target policyasset.Scope, action string, authRevision uint64) error {
	if _, err := store.ValidateEnrollmentSession(ctx, actor.PrincipalID, identity.EnrollmentScope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}, authRevision); err != nil {
		return identity.ErrPermissionDenied
	}
	if target.TenantID != actor.TenantID {
		return identity.ErrPermissionDenied
	}
	snapshot, err := store.PermissionSnapshot(ctx, identity.PrincipalUser, actor.PrincipalID)
	if err != nil {
		return err
	}
	if snapshot.Mode != "v2" {
		return identity.ErrPermissionDenied
	}
	decision, err := store.ResolvePermission(ctx, identity.PrincipalUser, actor.PrincipalID, identity.PermissionQuery{Action: action, Scope: identity.ManagementScope{Type: "application", TenantID: target.TenantID, DepartmentID: target.DepartmentID, ApplicationID: target.ApplicationID}, Now: time.Now().UTC()})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return identity.ErrPermissionDenied
	}
	return nil
}

func run(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("publish-policies", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	actorID := flags.String("actor", "", "existing verified administrator")
	apply := flags.Bool("apply", false, "publish through owning-module ports")
	expected := flags.String("expected-input-digest", "", "exact preview stdin digest")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return policyasset.ErrInvalidSnapshot
	}
	file, digest, err := readInput(input, *actorID)
	if err != nil {
		return err
	}
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
	credential, err := iam.VerifyEnrollmentCredentials(ctx, *actorID, file.OperatorPassword)
	if err != nil {
		return identity.ErrPermissionDenied
	}
	actor := sharedkernel.Scope{TenantID: credential.TenantID, DepartmentID: credential.DepartmentID, ApplicationID: credential.ApplicationID, PrincipalType: "user", PrincipalID: credential.PrincipalID}
	catalogStore := catalog.NewSQLStore(db, "pgx")
	installations := permissionresources.NewVerifiedInstallationResolver(catalogStore, catalogStore)
	store := policyasset.NewSQLStore(db)
	prepared := make([][]policyasset.Asset, 0, len(file.Publications))
	// Preflight the entire input before any write. No health or model readiness
	// is inferred from catalog/policy publication.
	for _, p := range file.Publications {
		scope := sharedkernel.Scope{TenantID: p.Scope.TenantID, DepartmentID: p.Scope.DepartmentID, ApplicationID: p.Scope.ApplicationID, PrincipalType: "user", PrincipalID: actor.PrincipalID, AgentID: p.Scope.AgentID, AgentVersionID: p.Scope.AgentVersionID, AgentInstanceID: p.InstallationID, InstallationID: p.InstallationID}
		if _, err := installations.ResolveAgentInstallation(ctx, scope, p.InstallationID); err != nil {
			return err
		}
		installation, err := catalogStore.GetInstallation(ctx, p.InstallationID)
		if err != nil || installation.AgentID != p.Scope.AgentID || installation.VersionID != p.Scope.AgentVersionID {
			return policyasset.ErrInvalidScope
		}
		for _, action := range []string{"policy.manage", "prompt.manage", "tool.manage"} {
			if err := authorize(ctx, iam, actor, p.Scope, action, credential.AuthRevision); err != nil {
				return err
			}
		}
		assets, err := policyasset.PreparePublication(p, actor.PrincipalID)
		if err != nil {
			return err
		}
		prepared = append(prepared, assets)
		current, err := store.GetSnapshot(ctx, p.Scope)
		if errors.Is(err, policyasset.ErrPolicyNotFound) {
			if p.ExpectedRevision != 0 {
				return policyasset.ErrAssetConflict
			}
		} else if err != nil {
			return err
		} else if current.Revision != p.ExpectedRevision && current.Revision != p.ExpectedRevision+1 {
			return policyasset.ErrAssetConflict
		}
	}
	r := result{InputDigest: digest, Applied: *apply, Publications: []publicationResult{}}
	for index, p := range file.Publications {
		item := publicationResult{InstallationID: p.InstallationID, Assets: []assetResult{}}
		refs := map[policyasset.AssetType]policyasset.AssetRef{}
		publishedAssets := map[policyasset.AssetType]policyasset.Asset{}
		for _, draft := range prepared[index] {
			if *apply {
				action := "policy.manage"
				if draft.Type == policyasset.AssetPrompt {
					action = "prompt.manage"
				}
				if draft.Type == policyasset.AssetTool {
					action = "tool.manage"
				}
				if err := authorize(ctx, iam, actor, p.Scope, action, credential.AuthRevision); err != nil {
					return writeFailure(output, &r, item, err)
				}
				current, err := store.GetAsset(ctx, p.Scope, draft.Type, draft.ID, 0)
				if errors.Is(err, policyasset.ErrAssetNotFound) {
					if err = store.CreateAsset(ctx, draft); err != nil {
						return writeFailure(output, &r, item, err)
					}
					current = draft
				} else if err != nil {
					return writeFailure(output, &r, item, err)
				}
				if current.Hash != draft.Hash {
					return writeFailure(output, &r, item, policyasset.ErrAssetConflict)
				}
				if current.Status == policyasset.AssetDraft {
					if err := authorize(ctx, iam, actor, p.Scope, action, credential.AuthRevision); err != nil {
						return writeFailure(output, &r, item, err)
					}
					current, err = store.PublishAsset(ctx, p.Scope, draft.Type, draft.ID, current.Revision)
					if err != nil {
						return writeFailure(output, &r, item, err)
					}
				}
				if current.Status != policyasset.AssetPublished {
					return writeFailure(output, &r, item, policyasset.ErrAssetConflict)
				}
				refs[draft.Type] = policyasset.AssetRef{ID: current.ID, Revision: current.Revision}
				publishedAssets[draft.Type] = current
				item.Assets = append(item.Assets, assetResult{current.ID, current.Type, current.Revision, current.Hash})
			} else {
				item.Assets = append(item.Assets, assetResult{draft.ID, draft.Type, 1, draft.Hash})
			}
		}
		if *apply {
			if err := authorize(ctx, iam, actor, p.Scope, "policy.manage", credential.AuthRevision); err != nil {
				return writeFailure(output, &r, item, err)
			}
			// Snapshot publication uses the store's CAS and immutable revision
			// transaction. Component operations remain separate resumable commits.
			request := policyasset.PublishSnapshotRequest{Scope: p.Scope, ExpectedRevision: p.ExpectedRevision, Assets: refs, Rule: p.Rule}
			snapshot, err := store.GetSnapshot(ctx, p.Scope)
			if err != nil && !errors.Is(err, policyasset.ErrPolicyNotFound) {
				return writeFailure(output, &r, item, err)
			}
			if err != nil || !policyasset.PublicationMatchesSnapshot(snapshot, request, publishedAssets) {
				snapshot, err = store.PublishSnapshot(ctx, request)
			}
			if err != nil {
				return writeFailure(output, &r, item, err)
			}
			item.Revision, item.Hash = snapshot.Revision, snapshot.Hash
		}
		r.Publications = append(r.Publications, item)
	}
	r.Complete = true
	return json.NewEncoder(output).Encode(r)
}

func writeFailure(out io.Writer, r *result, item publicationResult, err error) error {
	r.FailedInstallation = item.InstallationID
	r.Publications = append(r.Publications, item)
	json.NewEncoder(out).Encode(r)
	return err
}
func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if run(ctx, os.Args[1:], os.Stdin, os.Stdout) != nil {
		fmt.Fprintln(os.Stderr, "policy publication failed; inspect redacted receipts and approved actor, scope, input and database")
		os.Exit(1)
	}
}
